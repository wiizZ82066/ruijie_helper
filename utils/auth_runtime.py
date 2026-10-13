"""Run the compatibility-patched authentication core without terminating it."""
from pathlib import Path
import base64
import json
import subprocess
import time
import psutil
from dataclasses import dataclass
from uuid import UUID

from utils.campus_connection import CampusConnectionManager


def same_path(first, second):
    return str(Path(first).resolve()).casefold() == str(Path(second).resolve()).casefold()


@dataclass(frozen=True)
class CoreSession:
    pid: int
    created_at: float


def _running_core(core):
    # psutil caches Process objects (including create_time) across scans. Drop
    # that cache so PID reuse cannot retain a previous authentication session.
    clear_cache = getattr(psutil.process_iter, "cache_clear", None)
    if clear_cache:
        clear_cache()
    found = None
    for process in psutil.process_iter(["name", "exe", "create_time"]):
        try:
            if str(process.info.get("name", "")).casefold() != "8021x.exe":
                continue
            executable = process.info.get("exe")
            if executable and same_path(executable, core):
                if found is not None:
                    raise RuntimeError("同一目录有多个认证核心正在运行，无法确认认证结果对应的会话。")
                found = CoreSession(process.pid, process.info.get("create_time") or process.create_time())
            else:
                raise RuntimeError("另一目录的认证客户端正在运行，或无法核实路径，请先从其界面退出后重试。")
        except psutil.NoSuchProcess:
            continue
    return found


def start_core(client_dir: Path, log=lambda _: None):
    core = client_dir / "8021x.exe"
    session = _running_core(core)
    if session:
        log("兼容认证核心已在运行，无需结束或重启。")
        return session
    process = subprocess.Popen([str(core), "-ssbero2008d"], cwd=str(client_dir), shell=False,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    # A successful CreateProcess is not enough: configuration/mutex failures may exit.
    time.sleep(1.5)
    session = _running_core(core)
    if session is None:
        raise RuntimeError(f"认证核心启动后退出（退出码 {process.poll()}），请查看客户端配置或恢复原版。")
    log("认证核心已启动，登录和心跳将持续运行；如未自动登录，请在认证窗口中登录。")
    return session


def result_snapshot(client_dir: Path):
    return CampusConnectionManager._snapshot(client_dir / "SupplicantResult.ini")


_ETHERNET_INTERNET_SCRIPT = r'''
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
$wanted=[Guid]$data.guid
$adapters=@(Get-NetAdapter -IncludeHidden | Where-Object {
 [Guid]$_.InterfaceGuid -eq $wanted -and $_.HardwareInterface -and
 $_.InterfaceType -eq 6 -and $_.Status -eq 'Up'
})
$online=$false
if ($adapters.Count -eq 1) {
 $null=Add-Type -AssemblyName System.Runtime.WindowsRuntime
 $network=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
 $profiles=@($network::GetConnectionProfiles() | Where-Object {
  $null -ne $_.NetworkAdapter -and $_.NetworkAdapter.NetworkAdapterId -eq $wanted -and
  $_.NetworkAdapter.IanaInterfaceType -eq 6 -and
  $_.GetNetworkConnectivityLevel().ToString() -eq 'InternetAccess'
 })
 $online=$profiles.Count -gt 0
}
@{online=[bool]$online} | ConvertTo-Json -Compress
'''


def _ethernet_has_internet(ethernet_adapter_guid: str) -> bool:
    """Read only the selected physical Ethernet profile, never a TUN default."""
    guid = str(UUID(str(ethernet_adapter_guid).strip().strip("{}")))
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand",
             base64.b64encode(_ETHERNET_INTERNET_SCRIPT.encode("utf-16le")).decode("ascii")],
            input=json.dumps({"guid": guid}), capture_output=True, encoding="utf-8",
            errors="replace", timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            return False
        value = json.loads(result.stdout)
        return isinstance(value, dict) and value.get("online") is True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False  # An unavailable profile is not evidence of authentication.


def wait_authentication(client_dir: Path, before, started: float, cancel, timeout=120, session=None,
                        ethernet_adapter_guid=None):
    end = time.monotonic() + timeout
    next_profile_check = 0.0
    saw_fresh_failure = False
    while time.monotonic() < end:
        if cancel.is_set():
            return False
        path = client_dir / "SupplicantResult.ini"
        if session is not None:
            active = _running_core(client_dir / "8021x.exe")
            if active != session:
                raise RuntimeError("认证核心进程已退出或被替换，未将旧认证结果视为本次成功。")
            try:
                if path.stat().st_mtime_ns <= session.created_at * 1e9:
                    cancel.wait(0.5)
                    continue
            except FileNotFoundError:
                cancel.wait(0.5)
                continue
        result = CampusConnectionManager._fresh_result(path, before, max(started, session.created_at) if session else started)
        if result is True:
            return True
        if result is False:
            # The native core may publish a temporary failure before its own
            # reconnect succeeds. Observe this session until success, timeout,
            # or cancellation; do not restart it or submit credentials again.
            # Once this attempt failed, an older success cannot rescue it even
            # if the result is temporarily absent during a later rewrite.
            saw_fresh_failure = True
        # The service can authenticate before the delayed logon task opens this
        # UI. Reuse only this still-running session's success, with current
        # Internet connectivity on the explicitly selected physical Ethernet.
        # A stale Succeed after a disconnect must not suffice on its own.
        if (not saw_fresh_failure and session is not None
                and session.created_at < started and ethernet_adapter_guid):
            candidate = result_snapshot(client_dir)
            session_result = CampusConnectionManager._fresh_result(path, None, session.created_at)
            if (session_result is True and candidate and candidate[0] > session.created_at * 1e9
                    and result_snapshot(client_dir) == candidate
                    and time.monotonic() >= next_profile_check):
                next_profile_check = time.monotonic() + 5.0
                online = _ethernet_has_internet(ethernet_adapter_guid)
                if cancel.is_set():
                    return False
                if _running_core(client_dir / "8021x.exe") != session:
                    raise RuntimeError("认证核心进程已退出或被替换，未将旧认证结果视为本次成功。")
                if online and result_snapshot(client_dir) == candidate:
                    return True
        cancel.wait(0.5)
    return False

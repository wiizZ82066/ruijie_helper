"""Run the compatibility-patched authentication core without terminating it."""
from pathlib import Path
import base64
import configparser
from datetime import datetime
import json
import subprocess
import time
import psutil
from dataclasses import dataclass
from uuid import UUID

from utils.campus_connection import CampusConnectionManager
from utils.auth_log import AuthLogObserver


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


def _result_event_time(path, expected_result=None):
    """Read only the timestamp of a result already validated by _fresh_result."""
    try:
        raw = path.read_bytes()
        encodings = ("utf-16",) if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else (
            ("utf-16-le",) if b"\x00" in raw[:80] else ("utf-8-sig", "gb18030"))
        for encoding in encodings:
            try:
                text = raw.decode(encoding)
                break
            except UnicodeError:
                continue
        else:
            return None
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(text)
        if expected_result is not None:
            word = parser.get("Supplicant", "Result").strip().casefold()
            actual = True if word == "succeed" else False if word in {"fail", "failed", "failure", "error"} else None
            if actual is not expected_result:
                return None
        return datetime.strptime(parser.get("Supplicant", "Time"), "%Y-%m-%d %H:%M:%S").timestamp()
    except (OSError, ValueError, configparser.Error):
        return None


def wait_authentication(client_dir: Path, before, started: float, cancel, timeout=120, session=None,
                        ethernet_adapter_guid=None, log_before=None):
    end = time.monotonic() + timeout
    next_profile_check = 0.0
    saw_fresh_failure = False
    saw_result_failure = False
    latest_failure_time = None
    latest_log_failure_time = None
    observer = (AuthLogObserver(client_dir, log_before, max(started, session.created_at), pid=session.pid)
                if log_before is not None and session is not None else None)
    while time.monotonic() < end:
        if cancel.is_set():
            return False
        path = client_dir / "SupplicantResult.ini"
        file_current = True
        if session is not None:
            active = _running_core(client_dir / "8021x.exe")
            if active != session:
                raise RuntimeError("认证核心进程已退出或被替换，未将旧认证结果视为本次成功。")
            try:
                if path.stat().st_mtime_ns <= session.created_at * 1e9:
                    file_current = False
            except FileNotFoundError:
                file_current = False
        if not file_current and observer is None:
            cancel.wait(0.5)
            continue
        result = (CampusConnectionManager._fresh_result(
            path, before, max(started, session.created_at) if session else started) if file_current else None)
        log_result = observer.poll() if observer is not None else None
        log_time = observer.event_time if observer is not None else None
        result_time = (_result_event_time(path, result) if observer is not None and
                       (result is False or result is True and
                        (log_result is False or latest_log_failure_time is not None)) else None)
        if result is False:
            # The native core may publish a temporary failure before its own
            # reconnect succeeds. Observe this session until success, timeout,
            # or cancellation; do not restart it or submit credentials again.
            # Once this attempt failed, an older success cannot rescue it even
            # if the result is temporarily absent during a later rewrite.
            saw_fresh_failure = True
            saw_result_failure = True
            latest_failure_time = result_time or latest_failure_time
        if log_result is False:
            saw_fresh_failure = True
            if log_time is not None:
                latest_log_failure_time = max(latest_log_failure_time or log_time, log_time)
        elif log_result is True and log_time is not None and (
                latest_log_failure_time is None or log_time >= latest_log_failure_time):
            latest_log_failure_time = None
        # The native AUTH_SUCCESS notification can leave Result.ini empty.
        # Only new complete log records after the pre-launch baseline qualify.
        # If two sources disagree, a success must be unambiguously newer than
        # the failure (INI timestamps have only whole-second precision).
        log_success = (log_result is True and log_time is not None and
            latest_log_failure_time is None and
            (not saw_result_failure or latest_failure_time is not None and log_time > latest_failure_time + 1))
        if result is False:
            log_success = bool(log_success and result_time is not None and log_time > result_time + 1)
        result_success = result is True and (latest_log_failure_time is None or
            result_time is not None and result_time > latest_log_failure_time)
        if result_success:
            if observer is not None and _running_core(client_dir / "8021x.exe") != session:
                raise RuntimeError("认证核心进程已退出或被替换，未将旧认证结果视为本次成功。")
            return True
        if log_success:
            if cancel.is_set():
                return False
            if _running_core(client_dir / "8021x.exe") != session:
                raise RuntimeError("认证核心进程已退出或被替换，未将旧认证结果视为本次成功。")
            # Include a final read so an appended failure/logoff while checking
            # the process cannot be hidden by a previous success observation.
            if observer.poll() is True:
                final_result = CampusConnectionManager._fresh_result(
                    path, before, max(started, session.created_at))
                if final_result is not False:
                    return True
                final_time = _result_event_time(path, False)
                if final_time is not None and observer.event_time > final_time + 1:
                    return True
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

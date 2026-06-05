"""
移动热点管理器 — MyPublicWiFi 风格三层降级方案

策略（依次降级）：
  1. hostednetwork + ICS  —— netsh wlan 创建虚拟热点 + HNetCfg 手动配置共享（主力）
  2. TetheringManager      —— WinRT API（备选，Windows 10+）
  3. netsh only            —— 仅启动 hostednetwork，不配置 ICS（最终备选）

参考 MyPublicWiFi：使用 netsh wlan hostednetwork 绕开 TetheringManager
的自动共享失败问题，并手动配置 ICS 确保手机端有网络。
"""

import subprocess
import time
import platform
from typing import Optional

from utils.supplicant import SupplicantConfig
from utils.ics_manager import ICSManager

CREATE_NO_WINDOW = 0x08000000


class HotspotManager:
    """移动热点管理器。提供与旧版兼容的接口 (load/save_config, get_status, start/stop)。"""

    # ── 配置管理（与旧版兼容）────────────────────────────────

    @staticmethod
    def load_config() -> dict:
        full = SupplicantConfig.load()
        config = full.get("hotspot_config")
        if not isinstance(config, dict):
            config = {}
        return {
            "ssid": config.get("ssid", "test"),
            "password": config.get("password", "12345678"),
            "band": config.get("band", "2.4GHz"),
        }

    @staticmethod
    def save_config(hotspot_config: dict):
        full = SupplicantConfig.load()
        full["hotspot_config"] = hotspot_config
        SupplicantConfig.save(full)

    # ── PowerShell 执行器 ──────────────────────────────────

    @staticmethod
    def _run_powershell(script: str, timeout: int = 25) -> tuple[int, str, str]:
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle", "Hidden",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", script,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=timeout,
                startupinfo=startupinfo,
                creationflags=CREATE_NO_WINDOW,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "PowerShell 命令超时"
        except Exception as e:
            return -1, "", str(e)

    # ── 方案1: hostednetwork + ICS（MyPublicWiFi 主力方案）──

    @staticmethod
    def _is_hostednetwork_supported() -> bool:
        """检查系统是否支持 hostednetwork（驱动层面）。"""
        script = 'netsh wlan show drivers | Select-String "Hosted network supported"'
        rc, out, _ = HotspotManager._run_powershell(script, timeout=5)
        return "Yes" in out or "是" in out

    @staticmethod
    def _hostednetwork_status() -> Optional[str]:
        """查询 hostednetwork 状态。返回 None/STARTED/STOPPED/NOT_SUPPORTED。"""
        script = '''$info = netsh wlan show hostednetwork
$statusLine = $info | Select-String "Hosted network status"
if (-not $statusLine) { Write-Output "NOT_SUPPORTED"; exit 0 }
if ($statusLine -match "Started|已启动") { Write-Output "STARTED" }
else { Write-Output "STOPPED" }
'''
        rc, out, _ = HotspotManager._run_powershell(script, timeout=5)
        if rc != 0:
            return None
        return out

    @staticmethod
    def _start_hostednetwork(ssid: str, key: str) -> tuple[bool, str]:
        ssid_safe = ssid.replace('"', '""')
        key_safe = key.replace('"', '""')

        script = f'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
netsh wlan set hostednetwork mode=allow ssid="{ssid_safe}" key="{key_safe}"
if ($LASTEXITCODE -ne 0) {{ Write-Output "FAIL:设置 hostednetwork 失败"; exit 1 }}
netsh wlan start hostednetwork
if ($LASTEXITCODE -ne 0) {{
    $err = netsh wlan show hostednetwork | Select-String "Hosted network status"
    Write-Output "FAIL:启动失败: $($err.Line)"
    exit 1
}}
Write-Output "OK"
'''
        rc, out, err = HotspotManager._run_powershell(script, timeout=15)
        if out == "OK":
            return True, ""
        fail_msg = out if out.startswith("FAIL:") else (err or "未知错误")
        return False, fail_msg

    @staticmethod
    def _stop_hostednetwork() -> tuple[bool, str]:
        script = '''netsh wlan stop hostednetwork
Write-Output "OK"
'''
        rc, out, err = HotspotManager._run_powershell(script, timeout=10)
        if rc == 0:
            return True, ""
        return False, err or "停止 hostednetwork 失败"

    # ── 方案2: TetheringManager（备选）──────────────────────

    @staticmethod
    def _tethering_status() -> Optional[str]:
        script = '''$ProgressPreference = 'SilentlyContinue'
$null = Add-Type -AssemblyName System.Runtime.WindowsRuntime
$cp = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
if ($null -eq $cp) { Write-Output "UNAVAILABLE"; exit 0 }
$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($cp)
if ($null -eq $mgr) { Write-Output "UNAVAILABLE"; exit 0 }
Write-Output $mgr.TetheringOperationalState
'''
        rc, out, _ = HotspotManager._run_powershell(script, timeout=10)
        if rc != 0:
            return None
        raw = out.strip().lower()
        mapping = {"off": "未启动", "on": "已启动", "intransition": "正在切换"}
        return mapping.get(raw, f"Unknown({raw})")

    @staticmethod
    def _start_tethering(ssid: str, key: str, band: str) -> tuple[bool, str]:
        band_value = 0
        if "5" in band:
            band_value = 2
        elif "2.4" in band:
            band_value = 1

        script = f'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$null = Add-Type -AssemblyName System.Runtime.WindowsRuntime
$cp = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
if ($null -eq $cp) {{ Write-Output "FAIL:无网络连接"; exit 1 }}
$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($cp)
if ($null -eq $mgr) {{ Write-Output "FAIL:无法获取管理器"; exit 1 }}
$config = $mgr.GetCurrentAccessPointConfiguration()
$config.Ssid = "{ssid}"
$config.Passphrase = "{key}"
$config.Band = {band_value}
try {{
    $null = $mgr.ConfigureAccessPointAsync($config)
}} catch {{}}
try {{
    $null = $mgr.StartTetheringAsync()
    Write-Output "OK"
}} catch {{
    Write-Output "FAIL:" + $_.Exception.Message
    exit 1
}}
'''
        rc, out, err = HotspotManager._run_powershell(script, timeout=15)
        if out == "OK":
            time.sleep(3)
            if not ICSManager.get_ics_status().get("sharing_enabled"):
                ICSManager.repair_ics()
            return True, ""
        fail_msg = out.replace("FAIL:", "").strip() if out.startswith("FAIL:") else (err or "未知错误")
        return False, fail_msg

    @staticmethod
    def _stop_tethering() -> tuple[bool, str]:
        script = '''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$null = Add-Type -AssemblyName System.Runtime.WindowsRuntime
$cp = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
if ($null -eq $cp) { Write-Output "FAIL:无网络连接"; exit 1 }
$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($cp)
if ($null -eq $mgr) { Write-Output "FAIL:无法获取管理器"; exit 1 }
try {{
    $null = $mgr.StopTetheringAsync()
    Write-Output "OK"
}} catch {{
    Write-Output "FAIL:" + $_.Exception.Message
    exit 1
}}
'''
        rc, out, err = HotspotManager._run_powershell(script, timeout=10)
        if out == "OK":
            return True, ""
        return False, err or "停止 Tethering 失败"

    # ── 统一状态查询 ────────────────────────────────────────

    @staticmethod
    def get_hotspot_status() -> str:
        """返回："已启动" / "未启动" / "不支持" """
        hn_status = HotspotManager._hostednetwork_status()
        if hn_status == "STARTED":
            return "已启动"
        if hn_status == "STOPPED":
            return "未启动"

        tm_status = HotspotManager._tethering_status()
        if tm_status and tm_status not in ("UNAVAILABLE", "不支持"):
            return tm_status

        return "不支持"

    # ── 启动热点（三层降级）────────────────────────────────

    @staticmethod
    def start_hotspot(ssid: str = None, key: str = None, band: str = None) -> tuple[bool, str]:
        if ssid is None or key is None or band is None:
            config = HotspotManager.load_config()
            ssid = config.get("ssid", "test")
            key = config.get("password", "12345678")
            band = config.get("band", "2.4GHz")

        if HotspotManager.get_hotspot_status() == "已启动":
            return True, "热点已在运行"

        errors = []

        # 方案1: hostednetwork + ICS（主力）
        supported = HotspotManager._is_hostednetwork_supported()
        if supported:
            ok, msg = HotspotManager._start_hostednetwork(ssid, key)
            if ok:
                time.sleep(2)
                ics_ok, ics_msg = ICSManager.repair_ics()
                if ics_ok:
                    return True, "热点已启动 (hostednetwork + ICS)"
                return True, f"热点已启动 (hostednetwork, ICS: {ics_msg})"
            errors.append(f"方案1失败: {msg}")
        else:
            errors.append("方案1: 系统不支持 hostednetwork")

        # 方案2: TetheringManager
        ok, msg = HotspotManager._start_tethering(ssid, key, band)
        if ok:
            return True, "热点已启动 (TetheringManager)"
        errors.append(f"方案2失败: {msg}")

        # 方案3: hostednetwork only
        if supported:
            ok, msg = HotspotManager._start_hostednetwork(ssid, key)
            if ok:
                return True, "热点已启动 (hostednetwork, 未配 ICS)"
            errors.append(f"方案3失败: {msg}")

        return False, f"所有方案均失败: {'; '.join(errors)}"

    # ── 停止热点 ────────────────────────────────────────────

    @staticmethod
    def stop_hotspot() -> tuple[bool, str]:
        if HotspotManager.get_hotspot_status() == "未启动":
            return True, ""

        ICSManager.disable_all_ics()

        ok, _ = HotspotManager._stop_hostednetwork()
        if ok:
            return True, "已停止"

        ok, msg = HotspotManager._stop_tethering()
        if ok:
            return True, "已停止"

        return False, msg or "停止失败"

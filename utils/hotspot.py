"""
移动热点管理器 — 多模式支持

网络访问模式：
  - nat (路由器模式): WinNAT + 静态 IP (192.168.137.1) — 主力
  - ics (共享模式): HNetCfg.HNetShare COM — 传统
  - bridge (桥接模式): 网络桥接 — 同子网

互联网连接：
  - automatic: 自动检测当前联网网卡
  - 手动选择: 用户指定网卡
"""

import subprocess
import time
import platform
from typing import Optional

from utils.supplicant import SupplicantConfig
from utils.nat_manager import NATManager
from utils.bridge_manager import BridgeManager

CREATE_NO_WINDOW = 0x08000000

# 支持的网络访问模式
NETWORK_ACCESS_MODES = {
    "nat": "路由器模式 (NAT)",
    "ics": "共享模式 (ICS)",
    "bridge": "桥接模式 (Bridge)",
}


class HotspotManager:
    """移动热点管理器。支持三种网络访问模式和互联网网卡选择。"""

    # ── 配置管理 ────────────────────────────────────

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
            "network_access": config.get("network_access", "nat"),
            "internet_adapter": config.get("internet_adapter", "automatic"),
        }

    @staticmethod
    def save_config(hotspot_config: dict):
        full = SupplicantConfig.load()
        full["hotspot_config"] = hotspot_config
        SupplicantConfig.save(full)

    # ── PowerShell 执行器 ──────────────────────────

    @staticmethod
    def _run_powershell(script: str, timeout: int = 25) -> tuple[int, str, str]:
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                 "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="ignore",
                timeout=timeout, startupinfo=startupinfo, creationflags=CREATE_NO_WINDOW,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "PowerShell 命令超时"
        except Exception as e:
            return -1, "", str(e)

    # ── HostedNetwork 操作 ─────────────────────────

    @staticmethod
    def _is_hostednetwork_supported() -> bool:
        script = 'netsh wlan show drivers | Select-String "Hosted network supported"'
        rc, out, _ = HotspotManager._run_powershell(script, timeout=5)
        return "Yes" in out or "是" in out

    @staticmethod
    def _hostednetwork_status() -> Optional[str]:
        script = '''$info = netsh wlan show hostednetwork
$statusLine = $info | Select-String "Hosted network status"
if (-not $statusLine) { Write-Output "NOT_SUPPORTED"; exit 0 }
if ($statusLine -match "Started|已启动") { Write-Output "STARTED" }
else { Write-Output "STOPPED" }
'''
        rc, out, _ = HotspotManager._run_powershell(script, timeout=5)
        if rc != 0: return None
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

    @staticmethod
    def _find_hotspot_adapter() -> Optional[str]:
        """自动检测热点虚拟网卡名称。"""
        script = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# netsh 检测
$info = netsh wlan show hostednetwork
if ($info -match "Name\\s*[:：]\\s*(.+)$") {
    Write-Output $matches[1].Trim()
    exit 0
}
# 按名称查找
$ad = Get-NetAdapter | Where-Object { $_.Name -like "本地连接*" -or $_.Name -like "*Hosted*" } | Select-Object -First 1
if ($ad) { Write-Output $ad.Name; exit 0 }
Write-Output ""
'''
        rc, out, _ = HotspotManager._run_powershell(script, timeout=5)
        if rc == 0 and out:
            return out
        return None

    # ── 互联网网卡检测 ─────────────────────────────

    @staticmethod
    def get_internet_adapters() -> list:
        """获取所有有互联网连接的网卡列表。"""
        script = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$result = @()
# 默认网关路由
$routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.NextHop -ne "0.0.0.0" }
foreach ($route in $routes) {
    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    if ($adapter -and $adapter.Status -eq "Up") {
        $ip = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $result += @{ name=$adapter.Name; status=$adapter.Status; ip=if($ip){$ip.IPAddress}else{$null}; gateway=$route.NextHop; speed=$adapter.LinkSpeed; hasInternet=$true }
    }
}
# 补充其他活跃网卡
$allUp = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -notlike "*本地连接**" -and $_.Name -notlike "*Virtual*" -and $_.Name -notlike "*Bluetooth*" }
$checked = @{}
foreach ($r in $result) { $checked[$r.name] = $true }
foreach ($ad in $allUp) {
    if (-not $checked.ContainsKey($ad.Name)) {
        $ip = Get-NetIPAddress -InterfaceIndex $ad.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $result += @{ name=$ad.Name; status=$ad.Status; ip=if($ip){$ip.IPAddress}else{$null}; gateway=$null; speed=$ad.LinkSpeed; hasInternet=$false }
    }
}
$result | ConvertTo-Json -Compress
'''
        rc, out, _ = HotspotManager._run_powershell(script, timeout=10)
        import json
        if rc == 0 and out:
            try:
                return json.loads(out) if out else []
            except:
                return []
        return []

    @staticmethod
    def get_network_access_modes() -> list:
        """获取当前系统支持的网络访问模式列表。"""
        modes = []
        supported = HotspotManager._is_hostednetwork_supported()
        if not supported:
            return [{"id": "tethering", "name": "系统热点 (Tethering)", "available": True}]

        for mode_id, mode_name in NETWORK_ACCESS_MODES.items():
            modes.append({
                "id": mode_id,
                "name": mode_name,
                "available": True,
            })
        return modes

    # ── 连接设备查询 ─────────────────────────────

    @staticmethod
    def get_connected_devices() -> dict:
        """获取已连接设备数量和列表。"""
        devices = NATManager.get_connected_devices()
        hstatus = HotspotManager.get_hotspot_status()
        return {
            "count": len(devices),
            "devices": devices,
            "hotspot_running": hstatus == "已启动",
        }

    # ── 统一状态查询 ────────────────────────────────

    @staticmethod
    def get_hotspot_status() -> str:
        hn_status = HotspotManager._hostednetwork_status()
        if hn_status == "STARTED":
            return "已启动"
        if hn_status == "STOPPED":
            return "未启动"
        return "不支持"

    # ── 启动热点 ──────────────────────────────────────

    @staticmethod
    def start_hotspot(ssid: str = None, key: str = None, band: str = None,
                      network_access: str = None, internet_adapter: str = None) -> tuple[bool, str]:
        """
        启动热点 — 多模式支持。

        参数：
            ssid/key/band: 热点配置
            network_access: "nat" / "ics" / "bridge" (None=使用配置)
            internet_adapter: 网卡名 or "automatic" (None=使用配置)
        """
        config = HotspotManager.load_config()
        if ssid is None: ssid = config.get("ssid", "test")
        if key is None: key = config.get("password", "12345678")
        if band is None: band = config.get("band", "2.4GHz")
        if network_access is None: network_access = config.get("network_access", "nat")
        if internet_adapter is None: internet_adapter = config.get("internet_adapter", "automatic")

        if HotspotManager.get_hotspot_status() == "已启动":
            return True, "热点已在运行"

        # 检查 hostednetwork 支持
        if not HotspotManager._is_hostednetwork_supported():
            return False, "系统不支持 hostednetwork，请使用系统热点功能"

        # 启动 hostednetwork
        ok, msg = HotspotManager._start_hostednetwork(ssid, key)
        if not ok:
            return False, f"热点启动失败: {msg}"

        time.sleep(2)  # 等待虚拟网卡就绪

        # 获取热点网卡
        hotspot_adapter = HotspotManager._find_hotspot_adapter()
        if not hotspot_adapter:
            return True, "热点已启动，但未检测到虚拟网卡"

        # 确定互联网网卡
        actual_internet_adapter = internet_adapter
        if internet_adapter == "automatic":
            adapters = HotspotManager.get_internet_adapters()
            # 找到有互联网的网卡
            for ad in adapters:
                if ad.get("hasInternet") or ad.get("gateway"):
                    actual_internet_adapter = ad["name"]
                    break
            if not actual_internet_adapter or actual_internet_adapter == "automatic":
                actual_internet_adapter = None

        # 根据选择的模式配置网络访问
        if network_access == "nat":
            ok, msg = NATManager.enable_nat(hotspot_adapter, actual_internet_adapter)
            if ok:
                return True, f"热点已启动 (路由器模式 NAT) ✓"
            return True, f"热点已启动 (NAT 配置: {msg})"

        elif network_access == "ics":
            # ICS 模式
            from utils.ics_manager import ICSManager
            ok, msg = ICSManager.enable_ics(actual_internet_adapter or "", hotspot_adapter)
            if ok:
                return True, f"热点已启动 (共享模式 ICS) ✓"
            return True, f"热点已启动 (ICS 配置: {msg})"

        elif network_access == "bridge":
            # 桥接模式
            if not actual_internet_adapter:
                return True, "热点已启动 (桥接模式需选择互联网网卡)"
            bridges = [actual_internet_adapter, hotspot_adapter]
            ok, msg = BridgeManager.create_bridge(bridges)
            if ok:
                return True, f"热点已启动 (桥接模式) ✓"
            return True, f"热点已启动 (桥接配置: {msg})"

        return True, "热点已启动"

    # ── 停止热点 ──────────────────────────────────────

    @staticmethod
    def stop_hotspot() -> tuple[bool, str]:
        if HotspotManager.get_hotspot_status() == "未启动":
            return True, ""

        # 清理所有网络配置
        NATManager.disable_nat()
        BridgeManager.remove_bridge()
        from utils.ics_manager import ICSManager
        ICSManager.disable_all_ics()

        # 停止 hostednetwork
        ok, msg = HotspotManager._stop_hostednetwork()
        if ok:
            return True, "已停止"

        return False, msg or "停止失败"

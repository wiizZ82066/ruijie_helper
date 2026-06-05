"""
WinNAT 路由器模式管理器
使用 Windows NAT (New-NetNat) 创建真正的 NAT 路由器，
替代传统的 ICS (HNetCfg.HNetShare) 方式。

路由器模式原理：
  热点适配器 (192.168.137.1/24)
      ↓ NAT (New-NetNat)
  互联网网卡 (自动/手动选择)
      ↓
  手机/设备 (192.168.137.x)

可靠性和灵活性比 ICS 更好。
"""

import subprocess
import platform
from typing import Optional

CREATE_NO_WINDOW = 0x08000000


class NATManager:
    """通过 Windows NAT (NetNat) 创建路由器模式共享。"""

    HOTSPOT_SUBNET = "192.168.137.0/24"
    HOTSPOT_GATEWAY = "192.168.137.1"

    @staticmethod
    def _run_powershell(script: str, timeout: int = 20) -> tuple[int, str, str]:
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

    @staticmethod
    def enable_nat(hotspot_adapter: str, internet_adapter: str = None) -> tuple[bool, str]:
        """
        启用 WinNAT 路由器模式。
        1. 配置热点适配器静态 IP (192.168.137.1/24)
        2. 创建/更新 NAT 表
        3. 启用 IP 转发

        参数：
            hotspot_adapter: 热点虚拟网卡名称 (如 "本地连接* 10")
            internet_adapter: 互联网网卡名称 (自动检测时为 None)
        返回：
            (成功标志, 消息)
        """
        adapter_safe = hotspot_adapter.replace("'", "''")

        script = f'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$hotspotName = '{adapter_safe}'

# 1. 检查热点网卡是否存在
$adapter = Get-NetAdapter -Name $hotspotName -ErrorAction SilentlyContinue
if (-not $adapter) {{
    # 尝试模糊匹配
    $adapter = Get-NetAdapter | Where-Object {{ $_.Name -like "*$hotspotName*" }} | Select-Object -First 1
}}
if (-not $adapter) {{
    Write-Output "FAIL:找不到热点网卡: $hotspotName"
    exit 1
}}

$realName = $adapter.Name
Write-Output "STEP:找到热点网卡: $realName"

# 2. 移除旧 IP (避免冲突)
try {{
    Remove-NetIPAddress -InterfaceAlias $realName -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
}} catch {{}}

# 3. 设置静态 IP
try {{
    New-NetIPAddress -InterfaceAlias $realName -IPAddress {NATManager.HOTSPOT_GATEWAY} -PrefixLength 24 -ErrorAction Stop
    Write-Output "STEP:IP 已设为 {NATManager.HOTSPOT_GATEWAY}/24"
}} catch {{
    Write-Output "WARN:IP 配置: $($_.Exception.Message)"
}}

# 4. 移除旧 NAT
try {{
    Remove-NetNat -Name HotspotNAT -Confirm:$false -ErrorAction SilentlyContinue
}} catch {{}}

# 5. 创建新 NAT
try {{
    New-NetNat -Name HotspotNAT -InternalIPInterfaceAddressPrefix {NATManager.HOTSPOT_SUBNET} -ErrorAction Stop
    Write-Output "STEP:NAT 已创建: {NATManager.HOTSPOT_SUBNET}"
}} catch {{
    Write-Output "FAIL:NAT 创建失败: $($_.Exception.Message)"
    exit 1
}}

# 6. 启用 IP 转发
try {{
    Set-NetIPInterface -InterfaceAlias $realName -Forwarding Enabled -ErrorAction SilentlyContinue
}} catch {{}}

# 7. 如果有指定互联网网卡，也启用转发
$internetName = '{internet_adapter or ""}'
if ($internetName) {{
    try {{
        Set-NetIPInterface -InterfaceAlias $internetName -Forwarding Enabled -ErrorAction SilentlyContinue
    }} catch {{}}
}}

Write-Output "OK:NAT 配置完成"
'''
        rc, out, err = NATManager._run_powershell(script, timeout=30)
        if "OK:NAT" in out:
            return True, "NAT 路由器模式已启用"
        fail_msg = out.replace("FAIL:", "").strip() if "FAIL:" in out else (err or "未知错误")
        return False, fail_msg

    @staticmethod
    def disable_nat() -> tuple[bool, str]:
        """移除 WinNAT 配置，恢复热点网卡 IP。"""
        script = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# 移除 NAT
Remove-NetNat -Name HotspotNAT -Confirm:$false -ErrorAction SilentlyContinue

# 查找热点网卡并释放 IP
$hotspot = Get-NetAdapter | Where-Object { $_.Name -like "本地连接*" -or $_.Name -like "*Hosted*" -or $_.Name -like "*Virtual*" }
foreach ($ad in $hotspot) {
    Remove-NetIPAddress -InterfaceAlias $ad.Name -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
    Set-NetIPInterface -InterfaceAlias $ad.Name -Forwarding Disabled -ErrorAction SilentlyContinue
}

Write-Output "OK"
'''
        rc, out, err = NATManager._run_powershell(script, timeout=15)
        return rc == 0, ""

    @staticmethod
    def get_nat_status() -> dict:
        """查询当前 NAT 配置状态。"""
        script = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$nat = Get-NetNat -Name HotspotNAT -ErrorAction SilentlyContinue
if ($nat) {
    $result = @{
        enabled = $true
        subnet = $nat.InternalIPInterfaceAddressPrefix
        name = $nat.Name
    }
} else {
    $result = @{ enabled = $false }
}
# 检查热点网卡 IP
$adapter = Get-NetAdapter | Where-Object { $_.Name -like "本地连接*" } | Select-Object -First 1
if ($adapter) {
    $ip = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    $result.hotspotAdapter = $adapter.Name
    $result.hotspotIP = if ($ip) { $ip.IPAddress } else { $null }
    $result.forwarding = $adapter.ForwardingEnabled
}
$result | ConvertTo-Json -Compress
'''
        rc, out, err = NATManager._run_powershell(script, timeout=10)
        import json
        if rc == 0 and out:
            try:
                return json.loads(out)
            except:
                pass
        return {"enabled": False, "error": err}

    @staticmethod
    def get_connected_devices() -> list:
        """
        通过 netsh wlan show hostednetwork 获取已连接设备列表。
        返回：[{"mac": "xx-xx-xx-xx-xx-xx", "authState": "..."}, ...]
        """
        script = '''$info = netsh wlan show hostednetwork
$lines = $info -split "`n"
$inClients = $false
$clients = @()
foreach ($line in $lines) {
    if ($line -match "Station list|已连接工作站列表") { $inClients = $true; continue }
    if ($inClients -and $line -match "^\\s*$") { break }
    if ($inClients -and $line -match "([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})") {
        $clients += @{ mac = $matches[1]; authState = "已认证" }
    }
}
# 如果没有hostednetwork客户端，尝试通过 ARP 表查找活跃设备
if ($clients.Count -eq 0) {
    $arp = arp -a | Select-String "192.168.137."
    foreach ($entry in $arp) {
        if ($entry -match "(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})") {
            $clients += @{ ip = $matches[1]; mac = $matches[2]; authState = "活跃" }
        }
    }
}
$clients | ConvertTo-Json -Compress
'''
        rc, out, err = NATManager._run_powershell(script, timeout=10)
        import json
        if rc == 0 and out:
            try:
                return json.loads(out)
            except:
                return []
        return []

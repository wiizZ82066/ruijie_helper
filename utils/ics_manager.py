"""
Internet Connection Sharing (ICS) 管理器
通过 PowerShell 调用 HNetCfg.HNetShare COM 接口手动配置 ICS，
类似 MyPublicWiFi 的核心实现 —— 绕开 TetheringManager 的自动共享失败问题。

用法：
    from utils.ics_manager import ICSManager
    status = ICSManager.get_ics_status()          # 诊断 ICS 状态
    ICSManager.enable_ics("以太网", "本地连接* 10")  # 手动配置共享
    ICSManager.repair_ics()                         # 自动修复
"""

import subprocess
import platform
import re
from typing import Optional

CREATE_NO_WINDOW = 0x08000000


class ICSManager:
    """通过 HNetCfg.HNetShare COM 接口管理 Internet Connection Sharing。"""

    # 热点虚拟网卡名称关键词（用于自动检测）
    HOTSPOT_KEYWORDS = [
        "本地连接*", "Local Area Connection*",
        "Microsoft Wi-Fi Direct", "Microsoft Hosted",
        "Virtual", "vEthernet",
    ]

    @staticmethod
    def _run_powershell(script: str, timeout: int = 20) -> tuple[int, str, str]:
        """静默执行 PowerShell 脚本。"""
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

    # ── ICS 状态诊断 ────────────────────────────────────────

    @staticmethod
    def get_ics_status() -> dict:
        """
        诊断系统中所有网卡的 ICS 配置状态。
        返回：
        {
            "sharing_enabled": bool,   # 是否存在有效的 ICS 配置
            "public_connection": str|None,   # 设为共享源的网卡名
            "private_connection": str|None,  # 设为共享目标的网卡名
            "connections": [...]       # 所有网卡详情
        }
        """
        script = r'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    $mgr = New-Object -ComObject HNetCfg.HNetShare
} catch {
    Write-Output "ERROR:无法创建 HNetCfg 对象: $($_.Exception.Message)"
    exit 1
}

$result = @()
$sharingPublic = $null
$sharingPrivate = $null

$connections = $mgr.EnumEveryConnection
foreach ($conn in $connections) {
    try {
        $props = $mgr.NetConnectionProps($conn)
        $config = $mgr.INetSharingConfigurationForINetConnection($conn)
        $sharingEnabled = $config.SharingEnabled
        $sharingType = if ($sharingEnabled) { $config.SharingConnectionType } else { -1 }
    } catch {
        $props = @{ Name = "unknown" }
        $sharingEnabled = $false
        $sharingType = -1
    }

    $entry = @{
        name = $props.Name
        deviceName = $props.DeviceName
        status = $props.Status
        sharingEnabled = $sharingEnabled
        sharingType = $sharingType
    }
    $result += $entry

    if ($sharingEnabled) {
        if ($sharingType -eq 0) { $sharingPublic = $props.Name }
        if ($sharingType -eq 1) { $sharingPrivate = $props.Name }
    }
}

$json = @{
    public_connection = $sharingPublic
    private_connection = $sharingPrivate
    connections = $result
} | ConvertTo-Json -Compress -Depth 10

Write-Output $json
'''
        returncode, stdout, stderr = ICSManager._run_powershell(script)
        if returncode != 0 or not stdout:
            return {"error": stderr or "查询 ICS 状态失败", "connections": []}

        import json
        try:
            data = json.loads(stdout)
            connections = data.get("connections", [])
            has_public = any(c.get("sharingType") == 0 for c in connections)
            has_private = any(c.get("sharingType") == 1 for c in connections)
            data["sharing_enabled"] = has_public and has_private
            return data
        except json.JSONDecodeError:
            return {"error": f"JSON 解析失败: {stdout[:200]}", "connections": []}

    # ── 自动检测互联网网卡 ──────────────────────────────────

    @staticmethod
    def find_internet_connection() -> Optional[str]:
        """
        检测有互联网访问的网卡名称。
        通过测试 ping 或检查网关可达性判断。
        """
        script = '''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# 方法1: 通过网络路由表找默认网关对应的网卡
$route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.NextHop -ne "0.0.0.0" } | Select-Object -First 1
if ($route) {
    $ifIndex = $route.InterfaceIndex
    $adapter = Get-NetAdapter -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue
    if ($adapter -and $adapter.Status -eq "Up") {
        Write-Output $adapter.Name
        exit 0
    }
}

# 方法2: 遍历所有已连网网卡
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.MediaType -ne "Wireless" -or ($_.MediaType -eq "Wireless" -and $_.Status -eq "Up") }
foreach ($ad in $adapters) {
    $ip = Get-NetIPAddress -InterfaceIndex $ad.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ip) {
        Write-Output $ad.Name
        exit 0
    }
}

Write-Output ""
'''
        returncode, stdout, stderr = ICSManager._run_powershell(script, timeout=10)
        if returncode == 0 and stdout:
            return stdout
        return None

    # ── 检测热点虚拟网卡 ────────────────────────────────────

    @staticmethod
    def find_hotspot_adapter() -> Optional[str]:
        """
        检测热点虚拟网卡名称。
        通过 hostednetwork 状态和关键词匹配。
        """
        # 方法1: 通过 netsh wlan show hostednetwork
        script1 = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$info = netsh wlan show hostednetwork | Select-String "Hosted network status"
if ($info -match "Started") {
    $adapter = netsh wlan show hostednetwork | Select-String "Name" | Select-Object -First 1
    if ($adapter -match ":\\s*(.+)$") {
        Write-Output $matches[1].Trim()
        exit 0
    }
}
# 备用：找虚拟网卡
$virtual = Get-NetAdapter | Where-Object { $_.Name -match "Local Area Connection\\*|Microsoft Wi-Fi Direct|Virtual|Hosted" -and $_.Status -eq "Up" } | Select-Object -First 1
if ($virtual) {
    Write-Output $virtual.Name
    exit 0
}
Write-Output ""
'''
        returncode, stdout, stderr = ICSManager._run_powershell(script1, timeout=10)
        if returncode == 0 and stdout:
            return stdout
        return None

    # ── 配置 ICS ────────────────────────────────────────────

    @staticmethod
    def enable_ics(public_connection: str, private_connection: str) -> tuple[bool, str]:
        """
        配置 ICS：将 public_connection 设为共享源，private_connection 设为共享目标。
        参数：
            public_connection: 有互联网的网卡名称（如 "以太网"）
            private_connection: 热点虚拟网卡名称（如 "本地连接* 10"）
        返回：
            (成功标志, 错误信息)
        """
        # 避免 PowerShell 注入：转义单引号
        public_safe = public_connection.replace("'", "''")
        private_safe = private_connection.replace("'", "''")

        script = f'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {{
    $mgr = New-Object -ComObject HNetCfg.HNetShare
}} catch {{
    Write-Output "FAIL:无法创建 HNetCfg 对象: $($_.Exception.Message)"
    exit 1
}}

$publicConn = $null
$privateConn = $null

$connections = $mgr.EnumEveryConnection
foreach ($conn in $connections) {{
    try {{
        $props = $mgr.NetConnectionProps($conn)
        if ($props.Name -eq '{public_safe}') {{ $publicConn = $conn }}
        if ($props.Name -eq '{private_safe}') {{ $privateConn = $conn }}
    }} catch {{}}
}}

if (-not $publicConn) {{
    Write-Output "FAIL:未找到连接: '{public_safe}'"
    exit 1
}}
if (-not $privateConn) {{
    Write-Output "FAIL:未找到连接: '{private_safe}'"
    exit 1
}}

# 先禁用所有现有共享
foreach ($conn in $connections) {{
    try {{
        $cfg = $mgr.INetSharingConfigurationForINetConnection($conn)
        if ($cfg.SharingEnabled) {{
            $cfg.DisableSharing()
        }}
    }} catch {{}}
}}

Start-Sleep -Milliseconds 500

# 启用公共共享（互联网网卡 -> PUBLIC）
try {{
    $pubCfg = $mgr.INetSharingConfigurationForINetConnection($publicConn)
    $pubCfg.EnableSharing(0)
}} catch {{
    Write-Output "FAIL:设置公共共享失败: $($_.Exception.Message)"
    exit 1
}}

Start-Sleep -Milliseconds 500

# 启用专用共享（热点网卡 -> PRIVATE）
try {{
    $privCfg = $mgr.INetSharingConfigurationForINetConnection($privateConn)
    $privCfg.EnableSharing(1)
}} catch {{
    # 回滚公共共享
    try {{ $pubCfg.DisableSharing() }} catch {{}}
    Write-Output "FAIL:设置专用共享失败: $($_.Exception.Message)"
    exit 1
}}

Write-Output "OK"
'''
        returncode, stdout, stderr = ICSManager._run_powershell(script, timeout=30)
        if returncode == 0 and stdout == "OK":
            return True, ""
        err = stdout.replace("FAIL:", "").strip() if stdout.startswith("FAIL:") else (stdout or stderr)
        return False, err

    @staticmethod
    def disable_all_ics() -> bool:
        """禁用所有网卡的 ICS 共享。"""
        script = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try {
    $mgr = New-Object -ComObject HNetCfg.HNetShare
    $connections = $mgr.EnumEveryConnection
    foreach ($conn in $connections) {
        try {
            $cfg = $mgr.INetSharingConfigurationForINetConnection($conn)
            if ($cfg.SharingEnabled) { $cfg.DisableSharing() }
        } catch {}
    }
    Write-Output "OK"
} catch {
    Write-Output "FAIL:$($_.Exception.Message)"
}
'''
        returncode, stdout, stderr = ICSManager._run_powershell(script)
        if stdout == "OK":
            return True
        return False

    # ── 一键修复 ICS ────────────────────────────────────────

    @staticmethod
    def repair_ics() -> tuple[bool, str]:
        """
        自动检测并修复 ICS 配置。
        1. 找到有互联网的网卡
        2. 找到热点虚拟网卡
        3. 配置 ICS
        返回：
            (成功标志, 消息)
        """
        import json

        # 先看当前 ICS 状态
        status = ICSManager.get_ics_status()
        if status.get("sharing_enabled"):
            pub = status.get("public_connection")
            priv = status.get("private_connection")
            return True, f"ICS 已正常配置: {pub} → {priv}"

        # 检测互联网网卡
        public_conn = ICSManager.find_internet_connection()
        if not public_conn:
            return False, "未检测到有互联网连接的网卡"

        # 检测热点网卡
        private_conn = ICSManager.find_hotspot_adapter()
        if not private_conn:
            return False, "未检测到热点虚拟网卡，请先启动热点"

        # 配置 ICS
        ok, msg = ICSManager.enable_ics(public_conn, private_conn)
        if ok:
            return True, f"ICS 配置成功: {public_conn} → {private_conn}"
        else:
            return False, f"ICS 配置失败: {msg}"

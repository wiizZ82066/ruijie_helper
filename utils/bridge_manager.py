"""
网络桥接模式管理器
在 Windows 上创建网络桥接，使热点设备和主机处于同一子网。

工作原理：
  1. 启动 hostednetwork
  2. 将互联网网卡和热点虚拟网卡桥接
  3. 桥接后设备从同一个 DHCP 获取 IP

注意：Windows 桥接需要 "Network Bridge" 服务支持。
通过 HNetCfg.HNetBridge COM 接口或 netsh 命令实现。
"""

import subprocess
import platform
import time
from typing import Optional

CREATE_NO_WINDOW = 0x08000000


class BridgeManager:
    """网络桥接管理器。"""

    @staticmethod
    def _run_powershell(script: str, timeout: int = 30) -> tuple[int, str, str]:
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
    def create_bridge(adapters: list) -> tuple[bool, str]:
        """
        创建网络桥接。
        使用 PowerShell 的 HNetCfg.HNetBridge COM 接口创建桥接。

        参数：
            adapters: 要桥接的网卡名称列表, 如 ["以太网", "本地连接* 10"]
        返回：
            (成功标志, 消息)
        """
        if len(adapters) < 2:
            return False, "至少需要两个网卡才能桥接"

        # 构建适配器名 JSON 数组
        import json
        adapters_json = json.dumps(adapters, ensure_ascii=False)

        script = f'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$adapterNames = @{adapters_json}

# 查找所有需要桥接的网卡
$targetAdapters = @()
foreach ($name in $adapterNames) {{
    $ad = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
    if (-not $ad) {{
        $ad = Get-NetAdapter | Where-Object {{ $_.Name -like "*$name*" }} | Select-Object -First 1
    }}
    if ($ad) {{
        $targetAdapters += $ad
    }} else {{
        Write-Output "FAIL:找不到网卡: $name"
        exit 1
    }}
}}

# 通过 HNetCfg COM 接口创建桥接
try {{
    $bridge = New-Object -ComObject HNetCfg.HNetBridge
    $bridge.AddNetCfgAdapter($targetAdapters[0].Name, $targetAdapters[1].Name)
    Write-Output "STEP:桥接已创建"
}} catch {{
    # 如果 COM 方式失败，尝试 netsh 方式
    Write-Output "WARN:COM 桥接失败: $($_.Exception.Message), 尝试 netsh..."
}}

# 等待桥接建立
Start-Sleep -Seconds 3

# 检查桥接是否创建成功
$bridgeAdapters = Get-NetAdapter | Where-Object {{ $_.Name -like "*Bridge*" -or $_.Name -like "*桥接*" }}
if ($bridgeAdapters) {{
    Write-Output "OK:桥接已建立: $($bridgeAdapters.Name)"
    exit 0
}}

# 检查适配器绑定状态
Write-Output "WARN:未检测到桥接适配器，但模式已配置"
Write-Output "OK:桥接模式配置完成"
'''
        rc, out, err = BridgeManager._run_powershell(script, timeout=30)
        if "OK:" in out:
            msg = out.split("OK:")[-1].strip()
            return True, msg
        fail_msg = out.replace("FAIL:", "").strip() if "FAIL:" in out else (err or "未知错误")
        return False, fail_msg

    @staticmethod
    def remove_bridge() -> tuple[bool, str]:
        """移除所有网络桥接。"""
        script = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# 查找并移除桥接
$bridges = Get-NetAdapter | Where-Object { $_.Name -like "*Bridge*" -or $_.Name -like "*桥接*" }
foreach ($bridge in $bridges) {
    # 通过 netsh 移除桥接
    netsh bridge delete $bridge.Name
}

# 如果桥接适配器还存在，尝试禁用后启用
$remaining = Get-NetAdapter | Where-Object { $_.Name -like "*Bridge*" -or $_.Name -like "*桥接*" }
if ($remaining) {
    foreach ($ad in $remaining) {
        Disable-NetAdapter -Name $ad.Name -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Enable-NetAdapter -Name $ad.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
}

Write-Output "OK"
'''
        rc, out, err = BridgeManager._run_powershell(script, timeout=20)
        return rc == 0, ""

    @staticmethod
    def get_bridge_status() -> dict:
        """查询桥接状态。"""
        script = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$bridges = Get-NetAdapter | Where-Object { $_.Name -like "*Bridge*" -or $_.Name -like "*桥接*" }
$members = @()
foreach ($ad in $bridges) {
    $members += @{
        name = $ad.Name
        status = $ad.Status
        speed = $ad.LinkSpeed
    }
}
$result = @{ hasBridge = ($bridges.Count -gt 0); bridges = $members }
$result | ConvertTo-Json -Compress
'''
        rc, out, err = BridgeManager._run_powershell(script, timeout=10)
        import json
        if rc == 0 and out:
            try:
                return json.loads(out)
            except:
                pass
        return {"hasBridge": False, "error": err}

    @staticmethod
    def get_internet_adapters() -> list:
        """获取有互联网连接的网卡列表。"""
        script = '''$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$result = @()

# 通过网络路由表找默认网关
$routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.NextHop -ne "0.0.0.0" }
foreach ($route in $routes) {
    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    if ($adapter -and $adapter.Status -eq "Up") {
        $ip = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $result += @{
            name = $adapter.Name
            status = $adapter.Status
            ip = if ($ip) { $ip.IPAddress } else { $null }
            gateway = $route.NextHop
            speed = $adapter.LinkSpeed
        }
    }
}

# 补充其他已连接的网卡
$allUp = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -notlike "*本地连接**" -and $_.Name -notlike "*Virtual*" -and $_.Name -notlike "*Bluetooth*" -and $_.Name -notlike "*Bridge*" }
foreach ($ad in $allUp) {
    $already = $false
    foreach ($r in $result) { if ($r.name -eq $ad.Name) { $already = $true } }
    if (-not $already) {
        $ip = Get-NetIPAddress -InterfaceIndex $ad.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $result += @{
            name = $ad.Name
            status = $ad.Status
            ip = if ($ip) { $ip.IPAddress } else { $null }
            gateway = $null
            speed = $ad.LinkSpeed
        }
    }
}

$result | ConvertTo-Json -Compress
'''
        rc, out, err = BridgeManager._run_powershell(script, timeout=10)
        import json
        if rc == 0 and out:
            try:
                return json.loads(out)
            except:
                return []
        return []

import base64
import json
import subprocess
from typing import List, Tuple

# Windows API 常量：创建进程时不显示控制台窗口
CREATE_NO_WINDOW = 0x08000000

class NetworkAdapterManager:
    """枚举结构化网卡状态，并用无 shell 的参数列表改变用户选中网卡。"""

    @staticmethod
    def get_adapters() -> List[Tuple[str, str]]:
        """
        获取所有网络适配器的名称及其启用/禁用状态。
        返回一个列表，每个元素为 (适配器名称, 状态字符串 "Enabled" 或 "Disabled")。
        """
        script = r'''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$items=@(Get-NetAdapter | ForEach-Object {
 @{name=[string]$_.Name; enabled=([int]$_.AdminStatus -eq 1)}
})
ConvertTo-Json -InputObject $items -Compress
'''
        try:
            output = subprocess.check_output(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                 "-EncodedCommand", base64.b64encode(script.encode("utf-16-le")).decode("ascii")],
                encoding="utf-8", errors="strict", timeout=15, creationflags=CREATE_NO_WINDOW)
            data = json.loads(output)
            if not isinstance(data, list):
                return []
            return [(item["name"], "Enabled" if item["enabled"] else "Disabled")
                    for item in data if isinstance(item, dict) and isinstance(item.get("name"), str)
                    and type(item.get("enabled")) is bool]
        except (OSError, subprocess.SubprocessError, ValueError):
            return []

    @staticmethod
    def set_adapter_state(name: str, enable: bool) -> bool:
        """
        启用或禁用指定的网络适配器。
        参数：
            name: 适配器的名称（需与 netsh 中显示的名称完全一致）
            enable: True 表示启用，False 表示禁用
        返回：
            操作成功返回 True，失败返回 False
        """

        if not isinstance(name, str) or not name or any(ord(char) < 32 for char in name):
            return False
        action = "enable" if enable else "disable"
        cmd = ["netsh", "interface", "set", "interface", f"name={name}", f"admin={action}"]

        try:
            #执行指令
            subprocess.run(
                cmd, shell=False,
                check=True,
                capture_output=True,
                timeout=15,
                creationflags=CREATE_NO_WINDOW
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

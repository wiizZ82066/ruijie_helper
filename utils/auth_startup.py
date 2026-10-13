"""Visible current-user logon task for the compatibility authenticator."""
import base64
import json
from pathlib import Path
import subprocess
import sys


def set_startup(enabled: bool):
    if getattr(sys, "frozen", False):
        executable, arguments = sys.executable, "--connect --minimized"
    else:
        executable = sys.executable
        arguments = subprocess.list2cmdline([str(Path(__file__).resolve().parents[1] / "campus_authenticator.py"), "--connect", "--minimized"])
    script = r'''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name='CampusLogin-' + $sid
if ($data.enabled) {
 $action=New-ScheduledTaskAction -Execute $data.executable -Argument $data.arguments -WorkingDirectory $data.directory
 $trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid
 $trigger.Delay='PT30S'
 $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
 $null=Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description '校园网兼容认证器：当前用户登录后启动并按设置开启热点。' -Force
} elseif (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
 Unregister-ScheduledTask -TaskName $name -Confirm:$false
}
@{enabled=[bool]$data.enabled;name=$name} | ConvertTo-Json -Compress
'''
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand",
         base64.b64encode(script.encode("utf-16le")).decode("ascii")],
        input=json.dumps({"enabled": enabled, "executable": executable, "arguments": arguments,
                          "directory": str(Path(executable).parent)}, ensure_ascii=True),
        capture_output=True, encoding="utf-8", errors="replace", timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "自启动设置失败")
    return json.loads(result.stdout)

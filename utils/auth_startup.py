"""Visible current-user logon task for the compatibility authenticator."""
import base64
import json
from pathlib import Path
import subprocess
import sys


def set_startup(enabled: bool, *, entry_script=None, remove_only_matching=False):
    if getattr(sys, "frozen", False):
        executable, arguments = sys.executable, "--connect --minimized"
    else:
        executable = sys.executable
        entry = Path(entry_script).resolve() if entry_script is not None else Path(__file__).resolve().parents[1] / "campus_authenticator.py"
        arguments = subprocess.list2cmdline([str(entry), "--connect", "--minimized"])
    script = r'''$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name='CampusLogin-' + $sid
$scheduler=New-Object -ComObject Schedule.Service
$scheduler.Connect()
$folder=$scheduler.GetFolder('\')
function Read-OwnTask {
 try { return $folder.GetTask($name) }
 catch {
  if ($_.Exception.GetBaseException().HResult -eq -2147024894) { return $null }
  throw
 }
}
if ($data.enabled) {
 $action=New-ScheduledTaskAction -Execute $data.executable -Argument $data.arguments -WorkingDirectory $data.directory
 $trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid
 $trigger.Delay='PT30S'
 $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
 $null=Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description '校园网兼容认证器：当前用户登录后启动并按设置开启热点。' -Force
} elseif (Read-OwnTask) {
 $previous=Read-OwnTask
 if ($data.remove_only_matching -and
     -not [string]::Equals($previous.Definition.Actions.Item(1).Path, $data.executable, [StringComparison]::OrdinalIgnoreCase)) {
  @{enabled=[bool]$previous.Enabled; preserved=$true} | ConvertTo-Json -Compress; exit
 }
 $folder.DeleteTask($name, 0)
}
$actual=Read-OwnTask
if ($data.enabled) {
 if (-not $actual -or -not $actual.Enabled) { throw 'Startup registration not confirmed' }
} elseif ($actual) { throw 'Startup removal not confirmed' }
@{enabled=[bool]($actual -and $actual.Enabled)} | ConvertTo-Json -Compress
'''
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand",
         base64.b64encode(script.encode("utf-16le")).decode("ascii")],
        input=json.dumps({"enabled": enabled, "executable": executable, "arguments": arguments,
                          "directory": str(Path(executable).parent),
                          "remove_only_matching": remove_only_matching}, ensure_ascii=True),
        capture_output=True, encoding="utf-8", errors="replace", timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError("无法更新自启动任务，请以管理员身份运行后重试。")
    value=json.loads(result.stdout)
    if remove_only_matching and not enabled and value.get('preserved') is True:
        return value
    if type(value.get('enabled')) is not bool or value['enabled'] != enabled:
        raise RuntimeError('自启动状态未确认，请重试。')
    return value

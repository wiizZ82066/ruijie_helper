"""Selected physical Ethernet configuration; no routes, DNS or adapters changed."""
import base64
import ipaddress
import json
import subprocess
from uuid import UUID
from utils.campus_connection import WindowsOperations


def _run(script, timeout=20):
    prefix = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
    try:
        result = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-WindowStyle','Hidden',
            '-EncodedCommand',base64.b64encode((prefix+script).encode('utf-16le')).decode('ascii')],
            capture_output=True, encoding='utf-8', errors='replace', timeout=timeout,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    except subprocess.TimeoutExpired:
        raise RuntimeError('网络服务尚未就绪，请稍后重试。') from None
    if result.returncode:
        raise RuntimeError('无法读取所选有线网卡，请检查网线和网卡状态。')
    return json.loads(result.stdout)


def config(guid):
    identifier = str(UUID(str(guid).strip('{}')))
    value = _run(r"""
$a=@(Get-NetAdapter -Physical | Where-Object { [guid]$_.InterfaceGuid -eq [guid]'GUID' -and $_.InterfaceType -eq 6 -and $_.Status -eq 'Up' })
if ($a.Count -ne 1) { throw 'adapter unavailable' }; $a=$a[0]
$ips=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' })
@{guid=[string]$a.InterfaceGuid;mac=$a.MacAddress;permanentMac=$a.PermanentAddress;index=$a.ifIndex;
 addresses=@($ips.IPAddress);prefixes=@($ips.PrefixLength);
 dhcp=[string](Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4).Dhcp;
 gateways=@((Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric).NextHop | Select-Object -Unique);
 dns=@((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)} | ConvertTo-Json -Compress
""".replace('GUID',identifier))
    value['guid'] = str(UUID(value['guid'].strip('{}')))
    value['mac_bytes'] = bytes.fromhex(value['mac'].replace('-','').replace(':',''))
    if value['guid'] != identifier or len(value['mac_bytes'])!=6 or value['mac_bytes'][0]&1:
        raise RuntimeError('所选有线网卡身份校验失败。')
    for address in value['addresses']+value['gateways']+value['dns']:
        ipaddress.IPv4Address(address)
    return value


def has_lease(cfg):
    return (len(cfg['addresses'])==1 and len(cfg['prefixes'])==1 and
            len(cfg['gateways'])==1 and bool(cfg['dns']))


def same_interface(original, current):
    if original['guid'] != current['guid'] or original['mac_bytes'] != current['mac_bytes']:
        raise RuntimeError('有线网卡已改变，请重新连接。')


def link_up(guid):
    return any(str(row.get('guid','')).casefold()==str(guid).casefold() and
        row.get('status')=='Up' and row.get('if_type')==6 and row.get('hardware_interface') is True
        for row in WindowsOperations().list_adapters())


def acquire_lease(guid):
    identifier=str(UUID(str(guid).strip('{}')))
    result=_run("$a=@(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { [guid]$_.SettingID -eq [guid]'"+identifier+"' -and $_.DHCPEnabled });"
        "if($a.Count -ne 1){throw 'DHCP adapter unavailable'};"
        "$r=Invoke-CimMethod -InputObject $a[0] -MethodName RenewDHCPLease;@{ok=($r.ReturnValue -eq 0 -or $r.ReturnValue -eq 1)}|ConvertTo-Json -Compress",15)
    if result.get('ok') is not True:
        raise RuntimeError('认证已通过，但未取得网络地址，请检查校园网 DHCP 服务。')

"""Control Windows mobile hotspot through the supported WinRT tethering API."""

import base64
import gzip
import json
import platform
import re
import subprocess
import time
import uuid

from utils.hotspot_validation import assess_sharing
from utils.supplicant import SupplicantConfig

CREATE_NO_WINDOW = 0x08000000


def select_hotspot_source(inventory, ethernet_adapter_guid=None):
    """Plan a source from read-only evidence, without changing Windows networking.

    Ethernet is the authentication base. With Mihomo/Clash, tether the unique
    active TUN so ICS does not enable forwarding on its physical egress.
    """
    def guid(value):
        try:
            return str(uuid.UUID(str(value)))
        except (ValueError, TypeError, AttributeError):
            return None

    if not isinstance(inventory, dict) or inventory.get("errors"):
        raise ValueError("无法读取完整的热点来源信息；请以管理员身份重新启动后重试。")
    adapters = inventory.get("adapters", [])
    profiles = inventory.get("profiles", [])
    routes = inventory.get("routes", [])
    wanted = guid(ethernet_adapter_guid) if ethernet_adapter_guid else None

    def connected_profiles(adapter_guid):
        return [p for p in profiles if guid(p.get("guid")) == adapter_guid
                and p.get("connectivity") in ("LocalAccess", "ConstrainedInternetAccess", "InternetAccess")]

    if ethernet_adapter_guid:
        physical = [a for a in adapters if guid(a.get("guid")) == wanted
                    and a.get("status") == "Up" and a.get("if_type") == 6
                    and a.get("hardware_interface") is True]
        if not wanted or len(physical) != 1 or not connected_profiles(wanted):
            raise ValueError("选定的实体有线网卡未连接，或没有可用的连接配置；请先完成校园网认证。")

    tunnels = [a for a in adapters if a.get("status") == "Up" and a.get("if_type") == 53
               and a.get("hardware_interface") is False
               and re.search(r"meta\s*tunnel|mihomo|clash", str(a.get("name", "")) + " " +
                             str(a.get("description", "")), re.IGNORECASE)]
    if len(tunnels) > 1:
        raise ValueError("检测到多个活动的 Clash/Mihomo TUN，无法确定安全的热点来源；请仅保留要使用的一个 TUN 后重试。")
    if tunnels:
        tunnel = tunnels[0]
        source_guid = guid(tunnel.get("guid"))
        has_default = any(r.get("index") == tunnel.get("index") and r.get("prefix") == "0.0.0.0/0"
                          for r in routes)
        if not source_guid or not has_default:
            raise ValueError("检测到活动的 Clash/Mihomo TUN，但它没有 IPv4 默认路由；为避免电脑断网，热点尚未启动。")
        candidates = connected_profiles(source_guid)
        if not any(p.get("capability") == "Enabled" for p in candidates):
            raise ValueError("活动的 Clash/Mihomo TUN 没有可共享的 Windows 连接配置；请确认 TUN 正常联网后重试，热点尚未启动。")
        return {"source_adapter_guid": source_guid, "source_kind": "tun"}

    source_guid = wanted or guid(inventory.get("default_profile_guid"))
    if not source_guid or not any(p.get("capability") == "Enabled" for p in connected_profiles(source_guid)):
        raise ValueError("选定连接没有可用的热点共享配置；请确认有线网络已联网且系统允许移动热点。")
    return {"source_adapter_guid": source_guid, "source_kind": "ethernet" if wanted else "default"}


def select_hotspot_private_adapter(inventory):
    """Select one physical Wi-Fi device, deduplicating saved connection profiles."""
    profiles = {HotspotManager._adapter_guid(p.get("guid")) for p in inventory.get("profiles", []) if p.get("guid")}
    candidates = {HotspotManager._adapter_guid(a.get("guid")) for a in inventory.get("adapters", [])
                  if a.get("if_type") == 71 and a.get("hardware_interface") is True
                  and a.get("status") not in ("Disabled", "Not Present", "NotPresent") and a.get("guid")}
    if len(candidates) > 1:
        raise ValueError("检测到多张实体无线网卡，无法确定热点使用的设备；请仅保留要使用的一张无线网卡后重试。")
    if not candidates or not candidates.issubset(profiles):
        raise ValueError("没有可用于热点的实体无线网卡连接配置；请确认无线网卡已启用后重试。")
    return next(iter(candidates))

# Credentials travel through stdin, never PowerShell source, process arguments,
# or a temporary script file.
_TETHERING_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$payload = $null
$mgr = $null
$cp = $null
$alreadyOn = $null
$initialState = $null
$selectedPrivateGuid = $null
$explicitPrivateUsed = $false
$startSucceeded = $false
try {
    $payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if ($payload.operation -eq 'start' -and $payload.inspect_sharing) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw '需要管理员权限才能检查和建立完整的互联网共享；请以管理员身份重新启动本程序。'
        }
    }
    $null = Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $network = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
    $managerType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
    $resultType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]

    if ($payload.operation -eq 'sources') {
        $default = $network::GetInternetConnectionProfile()
        $inventory = @{ adapters=@(); routes=@(); profiles=@(); errors=@{}; default_profile_guid=$null }
        if ($null -ne $default -and $null -ne $default.NetworkAdapter) {
            $inventory.default_profile_guid = $default.NetworkAdapter.NetworkAdapterId.ToString()
        }
        try {
            $inventory.adapters = @(Get-NetAdapter -IncludeHidden | ForEach-Object {
                @{guid=$_.InterfaceGuid.ToString(); name=$_.Name; index=[int]$_.InterfaceIndex;
                  description=$_.InterfaceDescription; status=$_.Status.ToString();
                  if_type=[int]$_.InterfaceType; hardware_interface=[bool]$_.HardwareInterface}
            })
        } catch { $inventory.errors.adapters = $_.Exception.GetBaseException().Message }
        try {
            $inventory.routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object {
                $_.DestinationPrefix -eq '0.0.0.0/0'
            } | ForEach-Object { @{index=[int]$_.InterfaceIndex; prefix=$_.DestinationPrefix} })
        } catch { $inventory.errors.routes = $_.Exception.GetBaseException().Message }
        try {
            $inventory.profiles = @($network::GetConnectionProfiles() | Where-Object {
                $null -ne $_.NetworkAdapter
            } | ForEach-Object {
                $capability = 'Unknown'
                try { $capability = $managerType::GetTetheringCapabilityFromConnectionProfile($_).ToString() } catch {}
                @{guid=$_.NetworkAdapter.NetworkAdapterId.ToString();
                  connectivity=$_.GetNetworkConnectivityLevel().ToString(); capability=$capability}
            })
        } catch { $inventory.errors.profiles = $_.Exception.GetBaseException().Message }
        @{ok=$true; inventory=$inventory} | ConvertTo-Json -Depth 7 -Compress
        exit 0
    }

    function Wait-WinRt($Operation, [Type]$ResultType) {
        # ConfigureAccessPointAsync is IAsyncAction; start/stop are IAsyncOperation<T>.
        $methods = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
            $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1
        }
        if ($null -eq $ResultType) {
            $method = $methods | Where-Object {
                -not $_.IsGenericMethod -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
            } | Select-Object -First 1
        } else {
            $generic = $methods | Where-Object {
                $_.IsGenericMethod -and $_.GetGenericArguments().Count -eq 1 -and
                $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
            } | Select-Object -First 1
            $method = $generic.MakeGenericMethod($ResultType)
        }
        if ($null -eq $method) { throw 'WinRT AsTask bridge unavailable' }
        $task = $method.Invoke($null, @($Operation))
        if (-not $task.Wait([int]$payload.timeout_seconds * 1000)) {
            throw 'WinRT operation timed out; check Windows mobile hotspot settings'
        }
        if ($null -ne $ResultType) { return $task.Result }
    }

    $cp = $null
    $profileFallbackUsed = $false
    $availableProfiles = @($network::GetConnectionProfiles() | Where-Object {
        $null -ne $_.NetworkAdapter
    })
    if ($payload.source_adapter_guid -or $payload.ethernet_adapter_guid) {
        $wanted = if ($payload.source_adapter_guid) { [Guid]$payload.source_adapter_guid } else { [Guid]$payload.ethernet_adapter_guid }
        # Source and authentication adapter are separate. Never substitute the
        # physical egress when an explicitly selected TUN profile disappears.
        $profiles = @($availableProfiles | Where-Object {
            $_.NetworkAdapter.NetworkAdapterId -eq $wanted -and
            ($payload.operation -ne 'start' -or
             $_.GetNetworkConnectivityLevel().ToString() -ne 'None')
        })
        if ($payload.operation -eq 'start') {
            $profiles = @($profiles | Where-Object {
                try { $managerType::GetTetheringCapabilityFromConnectionProfile($_).ToString() -eq 'Enabled' }
                catch { $false }
            })
        }
        $cp = $profiles | Sort-Object -Property @{
            Expression = { [int]$_.GetNetworkConnectivityLevel() }; Descending = $true
        } | Select-Object -First 1
        if ($null -eq $cp -and $payload.operation -eq 'start') {
            throw '选定的热点共享来源已断开；热点尚未启动，请恢复该连接后重试。'
        }
    } else {
        $cp = $network::GetInternetConnectionProfile()
    }
    if ($null -eq $cp -and $payload.operation -eq 'status' -and $payload.source_adapter_guid -and $payload.inspect_sharing) {
        throw '原热点共享来源的连接配置已不可用，不能改用其他连接验证共享状态。'
    }
    if ($null -eq $cp -and $payload.operation -in @('stop', 'status')) {
        # This fallback only locates the global hotspot for reading/stopping.
        # It must never configure an access point or start sharing another source.
        $profileFallbackUsed = $true
        $cp = $network::GetInternetConnectionProfile()
        if ($null -eq $cp) {
            $cp = $availableProfiles | Sort-Object -Property @{
                Expression = { [int]$_.GetNetworkConnectivityLevel() }; Descending = $true
            } | Select-Object -First 1
        }
    }
    if ($null -eq $cp) {
        if ($payload.operation -in @('stop', 'status')) {
            throw '没有可用于访问现有热点的连接配置；请到 Windows 设置 > 网络和 Internet > 移动热点中查看或关闭热点。'
        }
        throw 'No Internet connection profile is available'
    }
    if ($payload.operation -eq 'start') {
        # Recheck volatile facts immediately before creating/configuring an AP.
        # The first read-only pass is planned in Python and covered by tests.
        $adaptersNow = @(Get-NetAdapter -IncludeHidden)
        if ($payload.ethernet_adapter_guid) {
            $base = @($adaptersNow | Where-Object {
                [Guid]$_.InterfaceGuid -eq [Guid]$payload.ethernet_adapter_guid -and
                $_.Status -eq 'Up' -and $_.InterfaceType -eq 6 -and $_.HardwareInterface
            })
            if ($base.Count -ne 1) { throw '选定的实体有线网卡已断开；请先恢复校园网连接。' }
        }
        $tunsNow = @($adaptersNow | Where-Object {
            $_.Status -eq 'Up' -and $_.InterfaceType -eq 53 -and -not $_.HardwareInterface -and
            ($_.Name + ' ' + $_.InterfaceDescription) -match '(?i)(meta\s*tunnel|mihomo|clash)'
        })
        if ($payload.source_kind -eq 'tun') {
            if ($tunsNow.Count -ne 1 -or [Guid]$tunsNow[0].InterfaceGuid -ne [Guid]$payload.source_adapter_guid) {
                throw 'TUN 来源在启动前发生变化；热点尚未启动，请重试。'
            }
            $defaultRoutes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object {
                $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.InterfaceIndex -eq $tunsNow[0].InterfaceIndex
            })
            if ($defaultRoutes.Count -eq 0) { throw 'TUN 的 IPv4 默认路由已消失；热点尚未启动。' }
        } elseif ($tunsNow.Count -gt 0) {
            throw '启动前检测到新的活动 TUN；热点尚未启动，请重试以重新选择共享来源。'
        }
        if ($managerType::GetTetheringCapabilityFromConnectionProfile($cp).ToString() -ne 'Enabled') {
            throw '选定的热点共享来源当前不允许共享；热点尚未启动。'
        }
    }
    if ($payload.private_adapter_guid) {
        $privateProfiles = @($availableProfiles | Where-Object {
            $_.NetworkAdapter.NetworkAdapterId -eq [Guid]$payload.private_adapter_guid -and
            $_.NetworkAdapter.IanaInterfaceType -eq 71
        })
        if ($payload.operation -eq 'start') {
            $privateHardware = @($adaptersNow | Where-Object {
                [Guid]$_.InterfaceGuid -eq [Guid]$payload.private_adapter_guid -and
                $_.InterfaceType -eq 71 -and $_.HardwareInterface -and
                $_.Status -notin @('Disabled','Not Present','NotPresent')
            })
            $allWifiHardware = @($adaptersNow | Where-Object {
                $_.InterfaceType -eq 71 -and $_.HardwareInterface -and
                $_.Status -notin @('Disabled','Not Present','NotPresent')
            })
            if ($privateHardware.Count -ne 1 -or $allWifiHardware.Count -ne 1) {
                throw '热点无线设备在启动前发生变化；热点尚未启动，请重试。'
            }
        }
        if ($privateProfiles.Count -gt 0) {
            $privateAdapter = $privateProfiles[0].NetworkAdapter
            $mgr = $managerType::CreateFromConnectionProfile($cp, $privateAdapter)
            $selectedPrivateGuid = $privateAdapter.NetworkAdapterId.ToString()
            $explicitPrivateUsed = $true
        } elseif ($payload.operation -ne 'stop') {
            throw '原热点无线设备的连接配置不可用，无法确认热点状态；请到 Windows 移动热点设置中查看或关闭热点。'
        }
    } elseif ($payload.operation -eq 'start') {
        throw '尚未确定热点使用的实体无线设备；热点尚未启动。'
    }
    if ($null -eq $mgr) { $mgr = $managerType::CreateFromConnectionProfile($cp) }
    if ($null -eq $mgr) { throw 'Unable to create tethering manager' }
    $state = $mgr.TetheringOperationalState.ToString()
    $initialState = $state
    $alreadyOn = $state -eq 'On'
    if ($payload.operation -eq 'start' -and $state -notin @('Off', 'On')) {
        throw '热点正在切换或状态未知，本次未修改热点；请等待 Windows 完成当前操作后重试。'
    }
    $sourceVerified = $false
    if ($payload.operation -eq 'start' -and $alreadyOn -and $payload.ethernet_adapter_guid -and -not $payload.inspect_sharing) {
        # OperationalState can be global: an already-running hotspot does not
        # prove it is sharing the profile used to create this manager.
        try {
            $sharing = New-Object -ComObject HNetCfg.HNetShare
            $publicGuids = @($sharing.EnumEveryConnection() | ForEach-Object {
                if ($null -ne $_) {
                    $sharingConfig = $sharing.INetSharingConfigurationForINetConnection($_)
                    if ($sharingConfig.SharingEnabled -and [int]$sharingConfig.SharingConnectionType -eq 0) {
                        ($sharing.NetConnectionProps($_)).Guid
                    }
                }
            })
        } catch {
            throw '热点已经开启，但无法核实当前共享来源；请先关闭热点，再选择有线网卡启动。'
        }
        if ($publicGuids.Count -ne 1 -or [Guid]$publicGuids[0] -ne $cp.NetworkAdapter.NetworkAdapterId) {
            throw '热点已经开启，但当前共享来源与选定来源不同或无法确认；请先关闭热点再启动。'
        }
        $sourceVerified = $true
    }
    $operationStatus = 'Success'
    if ($payload.operation -eq 'start' -and $state -ne 'On') {
        $config = $mgr.GetCurrentAccessPointConfiguration()
        $config.Ssid = [string]$payload.ssid
        $config.Passphrase = [string]$payload.key
        $bandType = [Windows.Networking.NetworkOperators.TetheringWiFiBand,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
        $requestedBand = [System.Enum]::ToObject($bandType, [int]$payload.band)
        if (-not $config.IsBandSupported($requestedBand)) {
            throw 'Requested Wi-Fi frequency band is not supported'
        }
        $config.Band = $requestedBand
        Wait-WinRt ($mgr.ConfigureAccessPointAsync($config)) $null
        $result = Wait-WinRt ($mgr.StartTetheringAsync()) $resultType
        $operationStatus = $result.Status.ToString()
        if ($operationStatus -ne 'Success') {
            throw ("{0}: {1}" -f $operationStatus, $result.AdditionalErrorMessage)
        }
        $startSucceeded = $true
    } elseif ($payload.operation -eq 'stop' -and $state -ne 'Off') {
        $result = Wait-WinRt ($mgr.StopTetheringAsync()) $resultType
        $operationStatus = $result.Status.ToString()
        if ($operationStatus -ne 'Success') {
            throw ("{0}: {1}" -f $operationStatus, $result.AdditionalErrorMessage)
        }
    } elseif ($payload.operation -notin @('status', 'start', 'stop')) {
        throw 'Unsupported hotspot operation'
    }

    if ($payload.operation -ne 'status') {
        $expected = if ($payload.operation -eq 'start') { 'On' } else { 'Off' }
        $deadline = [DateTime]::UtcNow.AddSeconds([int]$payload.timeout_seconds)
        do {
            $state = $mgr.TetheringOperationalState.ToString()
            if ($state -eq $expected) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($state -ne $expected) { throw "Hotspot state did not become $expected (current: $state)" }
    }
    $snapshot = $null
    if ($payload.inspect_sharing) {
        # Read both sides of ICS. A successful WinRT start can leave only a
        # private connection, with no public connection to forward traffic.
        $snapshot = @{ state=$state; adapters=@(); sharing=@(); addresses=@();
                       routes=@(); services=@(); errors=@{}; client_count=$null }
        try { $snapshot.client_count = [int]$mgr.ClientCount } catch {}
        try {
            $snapshot.adapters = @(Get-NetAdapter -IncludeHidden | ForEach-Object {
                @{guid=$_.InterfaceGuid.ToString(); name=$_.Name; index=[int]$_.InterfaceIndex;
                  description=$_.InterfaceDescription; status=$_.Status.ToString();
                  if_type=[int]$_.InterfaceType; hardware_interface=[bool]$_.HardwareInterface}
            })
        } catch { $snapshot.errors.adapters = $_.Exception.GetBaseException().Message }
        try {
            $sharing = New-Object -ComObject HNetCfg.HNetShare
            $snapshot.sharing = @($sharing.EnumEveryConnection() | ForEach-Object {
                if ($null -ne $_) {
                    $props = $sharing.NetConnectionProps($_)
                    $config = $sharing.INetSharingConfigurationForINetConnection($_)
                    $kind = $null
                    if ($config.SharingEnabled) { $kind = [int]$config.SharingConnectionType }
                    @{guid=$props.Guid; name=$props.Name; enabled=[bool]$config.SharingEnabled; sharing_type=$kind}
                }
            })
        } catch { $snapshot.errors.sharing = $_.Exception.GetBaseException().Message }
        try {
            $snapshot.addresses = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object {
                @{index=[int]$_.InterfaceIndex; address=$_.IPAddress;
                  prefix_length=[int]$_.PrefixLength; state=[int]$_.AddressState}
            })
        } catch { $snapshot.errors.addresses = $_.Exception.GetBaseException().Message }
        try {
            $snapshot.routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | ForEach-Object {
                @{index=[int]$_.InterfaceIndex; prefix=$_.DestinationPrefix; next_hop=$_.NextHop;
                  route_metric=[int]$_.RouteMetric}
            })
        } catch { $snapshot.errors.routes = $_.Exception.GetBaseException().Message }
        try {
            $snapshot.services = @(Get-Service SharedAccess,icssvc | ForEach-Object {
                @{name=$_.Name; status=$_.Status.ToString()}
            })
        } catch { $snapshot.errors.services = $_.Exception.GetBaseException().Message }
        $state = $mgr.TetheringOperationalState.ToString()
        $snapshot.state = $state
        $publicGuids = @($snapshot.sharing | Where-Object { $_.enabled -and $_.sharing_type -eq 0 })
        $sourceVerified = -not $snapshot.errors.sharing -and $publicGuids.Count -eq 1 -and
                          [Guid]$publicGuids[0].guid -eq $cp.NetworkAdapter.NetworkAdapterId
    }
    @{ ok = $true; state = $state; status = $operationStatus; error = '';
       already_on = $alreadyOn; source_verified = $sourceVerified;
       initial_state=$initialState;
       start_succeeded=$startSucceeded;
       profile_fallback_used = $profileFallbackUsed; sharing_snapshot=$snapshot;
       source_kind=$payload.source_kind;
       explicit_private=$explicitPrivateUsed; selected_private_adapter_guid=$selectedPrivateGuid;
       selected_profile_guid=$cp.NetworkAdapter.NetworkAdapterId.ToString() } | ConvertTo-Json -Depth 8 -Compress
} catch {
    $message = $_.Exception.GetBaseException().Message
    if ($null -ne $payload -and $payload.key) {
        $message = $message.Replace([string]$payload.key, '[redacted]')
    }
    $failureState = 'Unknown'
    $failureGuid = $null
    if ($null -ne $mgr) {
        try { $failureState = $mgr.TetheringOperationalState.ToString() } catch {}
    }
    if ($null -ne $cp) { $failureGuid = $cp.NetworkAdapter.NetworkAdapterId.ToString() }
    @{ ok = $false; state = $failureState; status = 'Error'; error = $message;
       already_on=$alreadyOn; selected_profile_guid=$failureGuid;
       initial_state=$initialState;
       start_succeeded=$startSucceeded;
       explicit_private=$explicitPrivateUsed; selected_private_adapter_guid=$selectedPrivateGuid } | ConvertTo-Json -Compress
    exit 1
}
"""


class HotspotManager:
    """Authenticate through Ethernet; pin the separately selected sharing source."""

    _source_pins = {}
    _owned_sessions = {}

    @staticmethod
    def _source_inventory():
        response = HotspotManager._request("sources")
        if response.get("ok") is not True or not isinstance(response.get("inventory"), dict):
            raise ValueError(response.get("error") or "无法读取热点共享来源，热点尚未启动。")
        return response["inventory"]

    @staticmethod
    def load_config() -> dict:
        config = SupplicantConfig.load().get("hotspot_config")
        if not isinstance(config, dict):
            config = {}
        return {
            "ssid": config.get("ssid", "ovo"),
            "password": config.get("password", "12345678"),
            "band": config.get("band", "2.4GHz"),
        }

    @staticmethod
    def save_config(hotspot_config: dict):
        full = SupplicantConfig.load()
        full["hotspot_config"] = hotspot_config
        SupplicantConfig.save(full)

    @staticmethod
    def _run_powershell(script: str, timeout: int = 25, payload=None) -> tuple[int, str, str]:
        """Run a fixed script with data on stdin; return exit code/stdout/stderr."""
        if platform.system() != "Windows":
            return -1, "", "移动热点仅支持 Windows"
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        if len(encoded_script) > 28000:
            # Windows CreateProcess has a 32,767-character command-line limit.
            # Compress only the fixed source, never the stdin credentials.
            packed = base64.b64encode(gzip.compress(script.encode("utf-8"), mtime=0)).decode("ascii")
            bootstrap = (
                "$b=[Convert]::FromBase64String('" + packed + "');"
                "$m=[IO.MemoryStream]::new([byte[]]$b);"
                "$z=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);"
                "$r=[IO.StreamReader]::new($z,[Text.Encoding]::UTF8);"
                "& ([ScriptBlock]::Create($r.ReadToEnd()))"
            )
            encoded_script = base64.b64encode(bootstrap.encode("utf-16-le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                 "-WindowStyle", "Hidden", "-EncodedCommand", encoded_script],
                input=json.dumps(payload or {}, ensure_ascii=True),
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, startupinfo=startupinfo, creationflags=CREATE_NO_WINDOW,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "热点操作超时，请检查 Windows 移动热点的实际状态"
        except OSError:
            return -1, "", "无法运行 Windows PowerShell"

    @staticmethod
    def _adapter_guid(value):
        if value is None or value == "":
            return None
        try:
            return str(uuid.UUID(str(value)))
        except (ValueError, AttributeError) as exc:
            raise ValueError("有线网卡 GUID 格式不正确") from exc

    @staticmethod
    def _band_value(band):
        aliases = {
            "auto": 0, "自动": 0, "0": 0,
            "2.4ghz": 1, "2.4": 1, "1": 1,
            "5ghz": 2, "5": 2, "2": 2,
            "6ghz": 3, "6": 3, "3": 3,
        }
        if type(band) is int and band in (0, 1, 2, 3):
            return band
        if isinstance(band, str):
            value = aliases.get(band.lower().replace(" ", ""))
            if value is not None:
                return value
        raise ValueError("热点频段必须为自动、2.4GHz、5GHz 或 6GHz")

    @staticmethod
    def _validate_credentials(ssid, key):
        if not isinstance(ssid, str) or not ssid or any(ord(c) < 32 or ord(c) == 127 for c in ssid):
            raise ValueError("热点名称不能为空或包含控制字符")
        # WinRT Ssid uses the system's ANSI code page, not necessarily UTF-8.
        encoding = "mbcs" if platform.system() == "Windows" else "utf-8"
        try:
            length = len(ssid.encode(encoding, errors="strict"))
        except UnicodeError as exc:
            raise ValueError("热点名称包含当前系统编码不支持的字符") from exc
        if length > 32:
            raise ValueError("热点名称按系统编码不能超过 32 字节")
        if not isinstance(key, str) or not 8 <= len(key) <= 63 or any(not 32 <= ord(c) <= 126 for c in key):
            raise ValueError("热点密码必须为 8–63 个可打印 ASCII 字符")

    @staticmethod
    def _request(operation, ethernet_adapter_guid=None, timeout=15, **values):
        ethernet_adapter_guid = HotspotManager._adapter_guid(ethernet_adapter_guid)
        pin_key = ethernet_adapter_guid or ""
        if operation == "start":
            # Read-only preflight, before ConfigureAccessPointAsync or Start.
            inventory = HotspotManager._source_inventory()
            values.update(select_hotspot_source(inventory, ethernet_adapter_guid))
            values["private_adapter_guid"] = select_hotspot_private_adapter(inventory)
            # A new start transaction must establish fresh Off -> On evidence.
            # Windows exposes no hotspot generation token, so cached ownership
            # cannot establish the source of an already-running external AP.
            HotspotManager._owned_sessions.pop(pin_key, None)
        elif operation in ("status", "stop") and not values.get("source_adapter_guid"):
            values["source_adapter_guid"] = HotspotManager._source_pins.get(pin_key)
        session = HotspotManager._owned_sessions.get(pin_key)
        if operation in ("status", "stop") and session:
            values["private_adapter_guid"] = session["private_adapter_guid"]
        if values.get("source_adapter_guid"):
            values["source_adapter_guid"] = HotspotManager._adapter_guid(values["source_adapter_guid"])
        payload = {
            "operation": operation,
            "ethernet_adapter_guid": ethernet_adapter_guid,
            "timeout_seconds": max(1, int(timeout)),
            **values,
        }
        # Start waits for configuration, operation result, and final state in sequence.
        code, stdout, stderr = HotspotManager._run_powershell(
            _TETHERING_SCRIPT, timeout=payload["timeout_seconds"] * 3 + 10, payload=payload,
        )
        try:
            response = json.loads(stdout)
            if not isinstance(response, dict):
                raise ValueError("not an object")
        except (ValueError, TypeError):
            response = {"ok": False, "error": stderr or "Windows 未返回有效的热点操作结果"}
        if code != 0:
            response["ok"] = False
        if response.get("error") and values.get("key"):
            response["error"] = str(response["error"]).replace(values["key"], "[redacted]")
        if operation != "sources":
            response["expected_source_guid"] = values.get("source_adapter_guid")
            response["ethernet_adapter_guid"] = ethernet_adapter_guid
            response["source_kind"] = response.get("source_kind") or values.get("source_kind")
            response["expected_private_adapter_guid"] = values.get("private_adapter_guid")
        same_source = response.get("selected_profile_guid") == values.get("source_adapter_guid")
        same_private = response.get("selected_private_adapter_guid") == values.get("private_adapter_guid")
        if (operation == "start" and response.get("ok") is True and response.get("status") == "Success"
                and response.get("state") == "On" and response.get("already_on") is False
                and response.get("initial_state") == "Off"
                and response.get("start_succeeded") is True
                and response.get("explicit_private") is True and same_source and same_private
                and response.get("profile_fallback_used") is not True):
            session = {"public_guid": values["source_adapter_guid"], "private_adapter_guid": values["private_adapter_guid"]}
            HotspotManager._owned_sessions[pin_key] = session
        elif (operation != "sources" and (response.get("state") != "On" or not same_source
              or response.get("explicit_private") is not True or not same_private
              or response.get("profile_fallback_used") is True)):
            HotspotManager._owned_sessions.pop(pin_key, None)
            session = None
        if operation != "sources":
            response["owned_session"] = dict(session) if session else None
        if operation == "start" and response.get("state") == "On" and values.get("source_adapter_guid"):
            HotspotManager._source_pins[pin_key] = values["source_adapter_guid"]
        elif operation == "stop" and response.get("ok") is True and response.get("state") == "Off":
            HotspotManager._source_pins.pop(pin_key, None)
            HotspotManager._owned_sessions.pop(pin_key, None)
        return response

    @staticmethod
    def get_hotspot_status(ethernet_adapter_guid: str = None) -> str:
        """Return 已启动 / 未启动 / 正在切换, or Unknown(error)."""
        try:
            result = HotspotManager._request("status", ethernet_adapter_guid)
        except ValueError as exc:
            return f"Unknown({exc})"
        if result.get("ok") is not True:
            return f"Unknown({result.get('error') or '无法查询热点状态'})"
        return {"On": "已启动", "Off": "未启动", "InTransition": "正在切换"}.get(
            result.get("state"), "Unknown"
        )

    @staticmethod
    def _send_command_and_wait(operation: str, ssid=None, key=None, band=None, timeout=15,
                               ethernet_adapter_guid=None) -> tuple[bool, str]:
        if operation not in ("start", "stop"):
            return False, "未知热点操作"
        try:
            values = {}
            if operation == "start":
                HotspotManager._validate_credentials(ssid, key)
                values = {"ssid": ssid, "key": key, "band": HotspotManager._band_value(band)}
            result = HotspotManager._request(operation, ethernet_adapter_guid, timeout, **values)
        except ValueError as exc:
            return False, str(exc)
        if result.get("ok") is not True or result.get("status") != "Success":
            return False, result.get("error") or result.get("status") or "热点操作失败"
        if operation == "start" and result.get("profile_fallback_used") is True:
            return False, "未能固定选定共享来源，不能使用其他连接开启热点"
        if operation == "start" and ethernet_adapter_guid and result.get("already_on") is True and result.get("source_verified") is not True:
            return False, "热点已经开启，但共享来源尚未验证；请先关闭热点再启动"
        expected = "On" if operation == "start" else "Off"
        if result.get("state") != expected:
            return False, "热点状态尚未达到预期，请检查 Windows 移动热点设置"
        return True, ""

    @staticmethod
    def start_hotspot(ssid: str = None, key: str = None, band: str = None,
                      ethernet_adapter_guid: str = None) -> tuple[bool, str]:
        """Compatibility API; success means local sharing configuration is ready.

        This does not claim that a connected phone has Internet access. Use
        start_hotspot_detailed for separate AP/sharing state and diagnostics.
        """
        result = HotspotManager.start_hotspot_detailed(ssid, key, band, ethernet_adapter_guid)
        return result["ok"], result["error"]

    @staticmethod
    def _sharing_result(response, ethernet_adapter_guid=None):
        snapshot = response.get("sharing_snapshot")
        if not isinstance(snapshot, dict):
            snapshot = {"state": response.get("state")}
        expected_source = response.get("expected_source_guid") or response.get("selected_profile_guid") or ethernet_adapter_guid
        owned_session = response.get("owned_session")
        result = assess_sharing(snapshot, expected_source, owned_session=owned_session)
        result["already_on"] = response.get("already_on") is True
        result["selected_profile_guid"] = response.get("selected_profile_guid")
        result["expected_source_guid"] = expected_source
        result["ethernet_adapter_guid"] = ethernet_adapter_guid
        result["source_kind"] = response.get("source_kind")
        result["selected_private_adapter_guid"] = response.get("selected_private_adapter_guid")
        if response.get("ok") is not True or response.get("status") != "Success":
            result.update(ok=False, sharing_ready=False, error_code="windows_operation_failed",
                          error=response.get("error") or response.get("status") or "Windows 热点操作失败")
        elif response.get("profile_fallback_used") is True:
            result.update(ok=False, sharing_ready=False, error_code="sharing_source_unavailable",
                          error="未能固定选定共享来源，不能使用其他连接开启热点")
        elif expected_source and response.get("selected_profile_guid") != expected_source:
            result.update(ok=False, sharing_ready=False, error_code="sharing_source_changed",
                          error="热点共享来源在操作期间发生变化，无法确认所选来源；请关闭热点后重试。")
        elif (response.get("expected_private_adapter_guid") and
              response.get("selected_private_adapter_guid") != response["expected_private_adapter_guid"]):
            result.update(ok=False, sharing_ready=False, error_code="private_source_changed",
                          error="热点无线设备在操作期间发生变化，无法确认所选设备；请关闭热点后重试。")
        if result["ok"] and owned_session and result.get("private_guid"):
            pin_key = HotspotManager._adapter_guid(ethernet_adapter_guid) or ""
            session = HotspotManager._owned_sessions.get(pin_key)
            if session and session == owned_session:
                session["private_guid"] = result["private_guid"]
        elif result["error_code"] in {
            "sharing_source_mismatch", "sharing_source_changed", "sharing_source_unavailable",
            "modern_session_invalid", "modern_private_changed", "upstream_not_connected",
            "upstream_default_route_missing", "private_source_changed",
        }:
            HotspotManager._owned_sessions.pop(HotspotManager._adapter_guid(ethernet_adapter_guid) or "", None)
        return result

    @staticmethod
    def verify_sharing(ethernet_adapter_guid: str = None, *, source_adapter_guid: str = None) -> dict:
        """Read AP, sharing, private IP and routes using this process's evidence.

        Windows exposes no session generation token. Off or changed endpoints
        invalidate evidence; an external Off/On cycle entirely between reads
        cannot be detected reliably. A new start never reuses old ownership.
        """
        try:
            response = HotspotManager._request("status", ethernet_adapter_guid, inspect_sharing=True,
                                               source_adapter_guid=source_adapter_guid)
        except ValueError as exc:
            response = {"ok": False, "error": str(exc)}
        return HotspotManager._sharing_result(response, ethernet_adapter_guid)

    @staticmethod
    def start_hotspot_detailed(ssid: str = None, key: str = None, band: str = None,
                               ethernet_adapter_guid: str = None, *, verify_timeout: float = 8,
                               rollback_on_failure: bool = True) -> dict:
        """Start and verify local sharing instead of trusting WinRT On alone.

        Keeps credentials on stdin and preserves an already-running hotspot.
        Verification may wait briefly for the private interface/IP to become
        ready. An unready AP started by this call is stopped to restore the
        previous Off state; an already-running AP is preserved. It does not
        alter TUN, routes, DNS, firewall or unrelated ICS.
        ``client_internet_verified`` remains False: this machine cannot prove
        that a phone has received DHCP/DNS settings or can open a web page.
        """
        if ssid is None or key is None or band is None:
            config = HotspotManager.load_config()
            ssid = config["ssid"] if ssid is None else ssid
            key = config["password"] if key is None else key
            band = config["band"] if band is None else band
        try:
            HotspotManager._validate_credentials(ssid, key)
            response = HotspotManager._request(
                "start", ethernet_adapter_guid, ssid=ssid, key=key,
                band=HotspotManager._band_value(band), inspect_sharing=True,
            )
        except ValueError as exc:
            response = {"ok": False, "error": str(exc)}
        result = HotspotManager._sharing_result(response, ethernet_adapter_guid)
        source_guid = response.get("expected_source_guid") or response.get("selected_profile_guid")
        source_kind = response.get("source_kind")
        pending = {"sharing_pair_missing", "private_adapter_not_ready", "private_address_not_ready", "private_route_not_ready"}
        deadline = time.monotonic() + min(20, max(0, float(verify_timeout)))
        already_on = result["already_on"]
        while result["error_code"] in pending and time.monotonic() < deadline:
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
            result = HotspotManager.verify_sharing(ethernet_adapter_guid, source_adapter_guid=source_guid)
        result["already_on"] = already_on
        result["source_kind"] = source_kind
        result["rollback_attempted"] = False
        # A failed later status read is Unknown, not proof that our new AP
        # stopped. Still restore Off when the initial response proves ownership.
        if (not result["ok"] and result["ap_on"] is not False
                and response.get("already_on") is False and response.get("state") == "On"
                and response.get("initial_state") == "Off" and response.get("start_succeeded") is True
                and result["error_code"] not in {"sharing_source_changed", "sharing_source_mismatch",
                                                 "modern_private_changed", "private_source_changed"}
                and rollback_on_failure):
            result["rollback_attempted"] = True
            rollback = HotspotManager._request("stop", ethernet_adapter_guid, source_adapter_guid=source_guid)
            result["rollback_result"] = rollback
            result["rollback_ok"] = (rollback.get("ok") is True and rollback.get("status") == "Success"
                                     and rollback.get("state") == "Off")
            result["ap_on"] = {"On": True, "Off": False}.get(rollback.get("state"))
            if result["rollback_ok"]:
                result["error"] += " 已关闭本次热点，恢复启动前的状态。"
            else:
                result["error"] += " 未能确认热点已关闭，请到 Windows 设置 > 网络和 Internet > 移动热点中关闭。"
        return result

    @staticmethod
    def stop_hotspot(ethernet_adapter_guid: str = None) -> tuple[bool, str]:
        """Stop hotspot using the same optional source GUID as start_hotspot."""
        return HotspotManager._send_command_and_wait("stop", ethernet_adapter_guid=ethernet_adapter_guid)

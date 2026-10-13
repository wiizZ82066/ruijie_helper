"""Read-only Windows Ethernet / mobile hotspot / TUN diagnostics.

No adapters, routes, services, sharing settings, firewall rules, or proxy
configuration are changed. No account/password or proxy-provider data is read.
"""
from __future__ import annotations

import argparse
import base64
import json
import platform
import subprocess
import sys
from uuid import UUID


_READ_ONLY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$report = @{ adapters=@(); routes=@(); interfaces=@(); sharing=@(); services=@(); default_profile=$null; errors=@{} }
try {
    $report.adapters = @(Get-NetAdapter -IncludeHidden | ForEach-Object {
        @{guid=$_.InterfaceGuid.ToString(); name=$_.Name; index=[int]$_.InterfaceIndex;
          description=$_.InterfaceDescription; status=$_.Status.ToString();
          if_type=[int]$_.InterfaceType; hardware_interface=[bool]$_.HardwareInterface}
    })
} catch { $report.errors.adapters = $_.Exception.GetBaseException().Message }
try {
    $report.routes = @(Get-NetRoute -AddressFamily IPv4 | Where-Object {
        $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1')
    } | ForEach-Object {
        @{index=[int]$_.InterfaceIndex; name=$_.InterfaceAlias; prefix=$_.DestinationPrefix;
          next_hop=$_.NextHop; route_metric=$_.RouteMetric}
    })
} catch { $report.errors.routes = $_.Exception.GetBaseException().Message }
try {
    $report.interfaces = @(Get-NetIPInterface -AddressFamily IPv4 | ForEach-Object {
        @{index=[int]$_.InterfaceIndex; metric=$_.InterfaceMetric;
          connection_state=$_.ConnectionState.ToString(); forwarding=$_.Forwarding.ToString()}
    })
} catch { $report.errors.interfaces = $_.Exception.GetBaseException().Message }
try {
    $share = New-Object -ComObject HNetCfg.HNetShare
    # Some hosts suppress an access-denied property getter; use the method
    # invocation form so an unavailable enumeration remains an explicit error.
    $connections = @($share.EnumEveryConnection())
    $report.sharing = @($connections | ForEach-Object {
        if ($null -ne $_) {
            $properties = $share.NetConnectionProps($_)
            $configuration = $share.INetSharingConfigurationForINetConnection($_)
            $kind = $null
            if ($configuration.SharingEnabled) { $kind = [int]$configuration.SharingConnectionType }
            @{guid=$properties.Guid; name=$properties.Name;
              enabled=[bool]$configuration.SharingEnabled; sharing_type=$kind}
        }
    })
} catch { $report.errors.sharing = $_.Exception.GetBaseException().Message }
try {
    $report.services = @(Get-Service SharedAccess,icssvc | ForEach-Object {
        @{name=$_.Name; status=$_.Status.ToString()}
    })
} catch { $report.errors.services = $_.Exception.GetBaseException().Message }
try {
    $null = Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $network = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
    $profile = $network::GetInternetConnectionProfile()
    if ($null -ne $profile -and $null -ne $profile.NetworkAdapter) {
        $report.default_profile = @{guid=$profile.NetworkAdapter.NetworkAdapterId.ToString();
          if_type=[int]$profile.NetworkAdapter.IanaInterfaceType;
          connectivity=$profile.GetNetworkConnectivityLevel().ToString()}
    }
} catch { $report.errors.default_profile = $_.Exception.GetBaseException().Message }
$report | ConvertTo-Json -Depth 6 -Compress
"""


def _guid(value):
    return str(UUID(str(value).strip().strip("{}"))).upper()


def analyze_snapshot(snapshot: dict, ethernet_adapter_guid: str | None = None) -> dict:
    """Interpret a captured snapshot without assuming failed reads mean absence."""
    report = dict(snapshot)
    adapters = report.get("adapters") or []
    errors = report.get("errors") or {}
    candidates = [adapter for adapter in adapters if adapter.get("if_type") == 6
                  and adapter.get("hardware_interface") is True and adapter.get("status") == "Up"]
    selected = None
    findings = []
    if ethernet_adapter_guid:
        requested = _guid(ethernet_adapter_guid)
        selected = next((adapter for adapter in candidates if _guid(adapter["guid"]) == requested), None)
        if selected is None:
            findings.append({"code": "selected_ethernet_unavailable", "message": "指定的实体有线网卡未处于连接状态，请先恢复校园网认证所需的有线连接。"})
    elif len(candidates) == 1:
        selected = candidates[0]
    elif len(candidates) > 1:
        findings.append({"code": "choose_ethernet", "message": "存在多张已连接的实体有线网卡，请明确选择校园网认证使用的网卡。"})
    else:
        findings.append({"code": "no_ethernet", "message": "未找到已连接的实体有线网卡；若网卡枚举失败，状态仍未知。"})
    tun_candidates = [adapter for adapter in adapters if adapter.get("hardware_interface") is False
                      and adapter.get("status") == "Up"
                      and any(marker in (adapter.get("name", "") + " " + adapter.get("description", "")).lower()
                              for marker in ("mihomo", "clash", "wintun", "meta tunnel", "sing-box"))]
    report["ethernet_candidates"] = candidates
    report["selected_ethernet_guid"] = _guid(selected["guid"]) if selected else None
    report["tun_candidates"] = tun_candidates
    if tun_candidates:
        findings.append({"code": "tun_present", "message": "检测到活动的 TUN 候选网卡；需要分别核实共享连接、热点本地地址和转发情况，不能仅凭热点已开启判断手机能上网。"})
    profile = report.get("default_profile") or {}
    if selected and profile.get("guid") and _guid(profile["guid"]) != _guid(selected["guid"]):
        findings.append({"code": "default_profile_differs", "message": "Windows 默认互联网连接与校园网有线网卡不同；热点需要单独核实实际共享来源，活动 TUN 可能是正确来源。"})
    if "sharing" in errors:
        findings.append({"code": "ics_unknown", "message": "ICS 角色读取失败，不能确认实际共享来源；在管理员启动的助手中重新诊断。"})
    else:
        public = [item for item in report.get("sharing", []) if item.get("enabled") is True and item.get("sharing_type") == 0]
        private = [item for item in report.get("sharing", []) if item.get("enabled") is True and item.get("sharing_type") == 1]
        if selected and public and not any(_guid(item["guid"]) == _guid(selected["guid"]) for item in public):
            findings.append({"code": "ics_source_differs", "message": "当前 ICS 公共连接与校园网认证网卡不同；启用 TUN 时可能属于正常情况，应核对实际选定的热点来源。"})
        if not public or not private:
            findings.append({"code": "ics_pair_not_observed", "message": "尚未观察到完整的 ICS 公共和专用连接；热点关闭时这属于正常状态。"})
    if tun_candidates and selected:
        tun_indexes = {item["index"] for item in tun_candidates}
        tun_routes = [route for route in report.get("routes", []) if route.get("index") in tun_indexes]
        report["tun_default_routes"] = tun_routes
        if tun_routes:
            findings.append({"code": "tun_routes_present", "message": "TUN 已安装默认或分流路由；这本身不是冲突证据，手机端是否能获得地址、解析 DNS、访问网页仍需分别验证。"})
    report["findings"] = findings
    report["coexistence_verified"] = False
    return report


def collect_network_diagnostics(ethernet_adapter_guid: str | None = None) -> dict:
    """Collect local read-only data. Returns structured errors for partial access."""
    if ethernet_adapter_guid:
        ethernet_adapter_guid = _guid(ethernet_adapter_guid)
    if platform.system() != "Windows":
        raise RuntimeError("网络诊断仅支持 Windows")
    encoded = base64.b64encode(_READ_ONLY_SCRIPT.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Windows 网络诊断未完成")
    snapshot = json.loads(result.stdout)
    if not isinstance(snapshot, dict):
        raise RuntimeError("Windows 返回的网络诊断格式无效")
    return analyze_snapshot(snapshot, ethernet_adapter_guid)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="只读 Ethernet / TUN / ICS 诊断，不修改系统配置")
    parser.add_argument("--ethernet-guid")
    arguments = parser.parse_args()
    print(json.dumps(collect_network_diagnostics(arguments.ethernet_guid), ensure_ascii=False, indent=2))

"""Interpret local hotspot evidence without changing Windows networking.

An access point being On only proves that Windows accepted the radio request.
This module checks a classic sharing pair or our explicit WinRT start evidence,
and verifies the private interface separately. A complete local configuration
does not by itself prove a phone can reach the Internet.
"""
from __future__ import annotations

from ipaddress import IPv4Interface
from uuid import UUID


def _guid(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def _usable_address(item):
    # Windows NL_DAD_STATE: Preferred=4. Deprecated=3 can be a stale address
    # on a disconnected Wi-Fi Direct adapter; it is not readiness evidence.
    if item.get("state") not in (4, "Preferred"):
        return None
    try:
        interface = IPv4Interface(f"{item['address']}/{int(item['prefix_length'])}")
    except (KeyError, ValueError, TypeError):
        return None
    address = interface.ip
    if (address.is_link_local or address.is_loopback or address.is_unspecified
            or address.is_multicast or interface.network.prefixlen > 30
            or address in (interface.network.network_address, interface.network.broadcast_address)):
        return None
    return interface


def assess_sharing(snapshot: dict, expected_public_guid: str | None = None, *, owned_session: dict | None = None) -> dict:
    """Return local readiness, never infer successful client Internet access.

``snapshot`` is the safe, normalized sharing snapshot returned by the hotspot
PowerShell bridge. Error-bearing or incomplete reads fail closed rather than
pretending there are no adapters/sharing roles. No credentials are accepted.
"""
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    result = {
        "ok": False,
        "ap_on": {"On": True, "Off": False}.get(snapshot.get("state")),
        "sharing_ready": False,
        "verification_mode": None,
        "client_internet_verified": False,
        "error_code": "",
        "error": "",
        "public_guid": None,
        "private_guid": None,
        "private_ipv4": None,
        "private_subnet": None,
        "client_count": snapshot.get("client_count"),
        "warnings": [],
        "details": snapshot,
    }

    def fail(code, message):
        result.update(error_code=code, error=message)
        return result

    if result["ap_on"] is not True:
        return fail("access_point_not_on", "热点没有保持开启，手机无法通过它上网；请查看热点状态后重新启动。")
    errors = snapshot.get("errors") or {}
    if errors.get("sharing"):
        return fail("sharing_unreadable", "无线热点已开启，但无法读取互联网共享状态；请以管理员身份重新启动本程序后重试。")
    for section in ("adapters", "addresses", "routes", "services"):
        if errors.get(section) or section not in snapshot:
            return fail("network_state_unreadable", "无线热点已开启，但无法核实网卡、地址或共享服务状态；请重新诊断网络。")
    if "sharing" not in snapshot:
        return fail("sharing_unreadable", "无线热点已开启，但 Windows 未返回互联网共享状态；请以管理员身份重新启动本程序。")
    enabled = [item for item in snapshot["sharing"] if item.get("enabled") is True]
    public = [item for item in enabled if item.get("sharing_type") == 0]
    private = [item for item in enabled if item.get("sharing_type") == 1]
    by_guid = {_guid(item.get("guid")): item for item in snapshot["adapters"]}
    modern = False
    if len(public) == 1 and expected_public_guid and _guid(public[0].get("guid")) != _guid(expected_public_guid):
        return fail("sharing_source_mismatch", "热点实际共享来源与所选来源不一致；请先关闭现有热点，再从本程序重新启动。")
    if len(public) == 1 and len(private) == 1:
        result["public_guid"], result["private_guid"] = _guid(public[0].get("guid")), _guid(private[0].get("guid"))
        result["verification_mode"] = "classic_ics"
    elif not enabled and owned_session:
        # Modern WinRT tethering can work without classic COM sharing flags.
        # Only our successful Off -> On two-adapter start grants this evidence;
        # a caller merely observing global On cannot infer either endpoint.
        source = _guid(owned_session.get("public_guid"))
        physical_guid = _guid(owned_session.get("private_adapter_guid"))
        physical = by_guid.get(physical_guid)
        if (not source or source != _guid(expected_public_guid) or not physical_guid or not physical
                or physical.get("if_type") != 71 or physical.get("hardware_interface") is not True
                or physical.get("status") in ("Disabled", "Not Present", "NotPresent")):
            return fail("modern_session_invalid", "无法确认本程序启动热点时使用的共享来源和无线设备，请关闭热点后重试。")
        candidates = [a for a in snapshot["adapters"] if a.get("status") == "Up"
                      and a.get("if_type") == 71 and a.get("hardware_interface") is False
                      and "wi-fi direct" in str(a.get("description", "")).lower()]
        if len(candidates) != 1:
            return fail("private_adapter_not_ready", "无法唯一确定正在工作的 Wi-Fi Direct 热点网卡，请关闭热点后重试。")
        virtual_guid = _guid(candidates[0].get("guid"))
        if owned_session.get("private_guid") and virtual_guid != _guid(owned_session["private_guid"]):
            return fail("modern_private_changed", "热点虚拟网卡已发生变化，无法继续确认原共享会话，请关闭热点后重试。")
        result.update(public_guid=source, private_guid=virtual_guid, verification_mode="owned_winrt")
        modern = True
    else:
        return fail("sharing_pair_missing", "无线热点已开启，但无法确认共享来源和本地共享连接；请先关闭热点，再从本程序重新启动。")
    if not result["public_guid"] or not result["private_guid"] or result["public_guid"] == result["private_guid"]:
        return fail("sharing_pair_invalid", "Windows 返回的互联网共享网卡信息无效，请关闭热点后重新启动。")
    if expected_public_guid and _guid(expected_public_guid) != result["public_guid"]:
        return fail("sharing_source_mismatch", "热点实际共享来源与所选来源不一致；请先关闭现有热点，再从本程序重新启动。")
    if (owned_session and owned_session.get("private_guid") and
            _guid(owned_session["private_guid"]) != result["private_guid"]):
        return fail("modern_private_changed", "热点实际私有网卡已不同于本程序确认的共享会话，无法继续确认来源；请关闭热点后重试。")
    upstream, downstream = by_guid.get(result["public_guid"]), by_guid.get(result["private_guid"])
    if not upstream or upstream.get("status") != "Up":
        return fail("upstream_not_connected", "共享来源网卡未连接，请先恢复电脑的上网连接。")
    if (not downstream or downstream.get("status") != "Up"
            or downstream.get("if_type") != 71 or downstream.get("hardware_interface") is not False):
        return fail("private_adapter_not_ready", "Windows 显示热点已开，但热点虚拟网卡没有正常连接；请关闭热点后重新启动。")
    if modern and not any(r.get("index") == upstream.get("index") and r.get("prefix") == "0.0.0.0/0"
                          for r in snapshot["routes"]):
        return fail("upstream_default_route_missing", "热点共享来源已没有 IPv4 默认路由，请先恢复电脑的上网连接。")
    services = {item.get("name", "").lower(): item.get("status") for item in snapshot["services"]}
    if any(services.get(name) not in ("Running", 4) for name in ("sharedaccess", "icssvc")):
        return fail("sharing_service_not_running", "Windows 热点或互联网共享服务没有运行；请在系统移动热点设置中重新开启热点后重试。")
    private_addresses = [address for item in snapshot["addresses"]
                         if item.get("index") == downstream.get("index")
                         and (address := _usable_address(item)) is not None]
    if not private_addresses:
        return fail("private_address_not_ready", "热点网卡还没有可用的本地 IPv4 地址，手机可能无法获得地址；请关闭热点后重新启动。")
    connected_addresses = [address for address in private_addresses if any(
        route.get("index") == downstream.get("index")
        and route.get("prefix") == str(address.network)
        and route.get("next_hop") == "0.0.0.0"
        for route in snapshot["routes"]
    )]
    if not connected_addresses:
        return fail("private_route_not_ready", "热点本地地址存在，但对应的直连路由没有生效；手机数据无法正常转发，请关闭热点后重试。")
    if modern and len({str(a.network) for a in connected_addresses}) != 1:
        return fail("private_address_ambiguous", "热点网卡同时存在多个不同的本地网段，无法确认手机地址分配是否正常；请关闭热点后重试。")
    active_indexes = {item.get("index") for item in snapshot["adapters"] if item.get("status") == "Up"}
    address = connected_addresses[0]
    result.update(private_ipv4=str(address.ip), private_subnet=str(address.network))
    for item in snapshot["addresses"]:
        other = _usable_address(item)
        if (other and item.get("index") != downstream.get("index")
                and item.get("index") in active_indexes and other.network.overlaps(address.network)):
            return fail("private_subnet_conflict", "热点网段与另一张活动网卡重叠，无法可靠转发；请在 Windows 网络设置中调整冲突网卡的网段后重试。")
    tun = [item for item in snapshot["adapters"] if item.get("status") == "Up"
           and item.get("hardware_interface") is False
           and any(marker in (item.get("name", "") + " " + item.get("description", "")).lower()
                   for marker in ("mihomo", "clash", "wintun", "meta tunnel", "sing-box"))]
    if tun:
        result["warnings"].append("检测到活动 TUN；本地共享配置检查通过仍不代表手机端数据已能通过 TUN 转发。")
    result.update(ok=True, sharing_ready=True)
    return result

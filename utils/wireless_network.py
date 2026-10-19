"""Connect only to the saved JNU WLAN profile, without changing routes or DNS.

The live association comes from wlanapi, not the Windows network profile label.
No profile keys are requested. See Microsoft's WLAN_CONNECTION_PARAMETERS and
WLAN_CONNECTION_ATTRIBUTES contracts; the explicit pDot11Ssid restricts even a
profile that contains several SSIDs. Native polling does not launch processes.
"""
from __future__ import annotations

import base64
import ctypes
from dataclasses import dataclass
import ipaddress
import json
import math
import os
import subprocess
import time
from uuid import UUID

from utils.native_adapters import GUID, list_adapters


class WirelessError(RuntimeError):
    pass


class WirelessCancelled(WirelessError):
    pass


@dataclass(frozen=True)
class InterfaceBinding:
    index: int
    address: str
    dns: tuple[str, ...]
    guid: str
    ssid: str = "JNU"


DWORD = ctypes.c_uint32
WCHAR = ctypes.c_uint16
HANDLE = ctypes.c_void_p


class DOT11_SSID(ctypes.Structure):
    _fields_ = [("length", DWORD), ("value", ctypes.c_ubyte * 32)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("guid", GUID), ("description", WCHAR * 256), ("state", DWORD)]


class WLAN_PROFILE_INFO(ctypes.Structure):
    _fields_ = [("name", WCHAR * 256), ("flags", DWORD)]


class WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("ssid", DOT11_SSID), ("bss_type", DWORD),
                ("bssid", ctypes.c_ubyte * 6), ("phy_type", DWORD),
                ("phy_index", DWORD), ("signal", DWORD),
                ("rx_rate", DWORD), ("tx_rate", DWORD)]


class WLAN_SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("security", DWORD), ("one_x", DWORD),
                ("auth", DWORD), ("cipher", DWORD)]


class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("state", DWORD), ("mode", DWORD), ("profile", WCHAR * 256),
                ("association", WLAN_ASSOCIATION_ATTRIBUTES),
                ("security", WLAN_SECURITY_ATTRIBUTES)]


class WLAN_CONNECTION_PARAMETERS(ctypes.Structure):
    _fields_ = [("mode", DWORD), ("profile", ctypes.c_void_p),
                ("ssid", ctypes.POINTER(DOT11_SSID)), ("bssids", ctypes.c_void_p),
                ("bss_type", DWORD), ("flags", DWORD)]


def _check_layout():
    expected = [(GUID, 16), (DOT11_SSID, 36), (WLAN_INTERFACE_INFO, 532),
                (WLAN_PROFILE_INFO, 516), (WLAN_ASSOCIATION_ATTRIBUTES, 68),
                (WLAN_CONNECTION_ATTRIBUTES, 604)]
    if (any(ctypes.sizeof(kind) != size for kind, size in expected)
            or WLAN_CONNECTION_ATTRIBUTES.association.offset != 520
            or WLAN_ASSOCIATION_ATTRIBUTES.phy_type.offset != 48
            or ctypes.sizeof(WLAN_CONNECTION_PARAMETERS) !=
            (40 if ctypes.sizeof(ctypes.c_void_p) == 8 else 24)):
        raise WirelessError("Windows 无线接口结构不受支持")


def _guid(value):
    return GUID.from_buffer_copy(UUID(value).bytes_le)


def _text(value):
    raw = bytes(value).decode("utf-16-le")
    if "\0" not in raw:
        raise WirelessError("Windows 返回了无效的无线配置名称")
    return raw.split("\0", 1)[0]


def _check_cancel(cancel):
    if cancel.is_set():
        raise WirelessCancelled("已取消无线连接")


class _WlanClient:
    """One handle per operation; every native allocation has a finally release."""

    def __init__(self, api=None):
        _check_layout()
        if api is None:
            if os.name != "nt":
                raise WirelessError("无线连接仅支持 Windows")
            api = ctypes.WinDLL("wlanapi.dll", use_last_error=True, winmode=0x00000800)
        self.api = api
        signatures = {
            "WlanOpenHandle": [DWORD, ctypes.c_void_p, ctypes.POINTER(DWORD), ctypes.POINTER(HANDLE)],
            "WlanCloseHandle": [HANDLE, ctypes.c_void_p],
            "WlanEnumInterfaces": [HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            "WlanGetProfileList": [HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            "WlanQueryInterface": [HANDLE, ctypes.POINTER(GUID), DWORD, ctypes.c_void_p,
                                   ctypes.POINTER(DWORD), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(DWORD)],
            "WlanConnect": [HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(WLAN_CONNECTION_PARAMETERS), ctypes.c_void_p],
        }
        for name, signature in signatures.items():
            function = getattr(api, name)
            function.argtypes, function.restype = signature, DWORD
        api.WlanFreeMemory.argtypes, api.WlanFreeMemory.restype = [ctypes.c_void_p], None
        self.handle = HANDLE()
        version = DWORD()
        self._check(api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(self.handle)))
        if not self.handle:
            raise WirelessError("Windows 无线服务没有返回有效句柄")

    @staticmethod
    def _check(code):
        if code == 5:
            raise WirelessError("Windows 拒绝读取无线连接；请检查系统的位置访问权限")
        if code:
            raise WirelessError(f"Windows 无线服务操作失败（{int(code)}）")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.handle:
            self.api.WlanCloseHandle(self.handle, None)
            self.handle = HANDLE()

    def _list(self, function, row_type, *args):
        pointer = ctypes.c_void_p()
        try:
            self._check(function(self.handle, *args, None, ctypes.byref(pointer)))
            if not pointer:
                raise WirelessError("Windows 无线服务返回了空列表")
            count = DWORD.from_address(pointer.value).value
            if count > 4096:
                raise WirelessError("Windows 无线列表超出可处理范围")
            return [row_type.from_buffer_copy(ctypes.string_at(
                pointer.value + 8 + i * ctypes.sizeof(row_type), ctypes.sizeof(row_type)))
                for i in range(count)]
        finally:
            if pointer:
                self.api.WlanFreeMemory(pointer)

    def interfaces(self):
        return [str(UUID(bytes_le=bytes(row.guid))).upper()
                for row in self._list(self.api.WlanEnumInterfaces, WLAN_INTERFACE_INFO)]

    def has_profile(self, identifier):
        guid = _guid(identifier)
        rows = self._list(self.api.WlanGetProfileList, WLAN_PROFILE_INFO, ctypes.byref(guid))
        return any(_text(row.name) == "JNU" for row in rows)

    def ssid(self, identifier):
        guid, size, value_type, pointer = _guid(identifier), DWORD(), DWORD(), ctypes.c_void_p()
        try:
            code = self.api.WlanQueryInterface(self.handle, ctypes.byref(guid), 7, None,
                                              ctypes.byref(size), ctypes.byref(pointer), ctypes.byref(value_type))
            if code == 5023:  # ERROR_INVALID_STATE: disconnected or disconnecting.
                return None
            self._check(code)
            if not pointer or size.value < ctypes.sizeof(WLAN_CONNECTION_ATTRIBUTES):
                raise WirelessError("Windows 无线连接信息不完整")
            connection = WLAN_CONNECTION_ATTRIBUTES.from_buffer_copy(
                ctypes.string_at(pointer, ctypes.sizeof(WLAN_CONNECTION_ATTRIBUTES)))
            ssid = connection.association.ssid
            if ssid.length > 32:
                raise WirelessError("Windows 无线网络名称无效")
            return bytes(ssid.value[:ssid.length]) if connection.state == 1 else None
        finally:
            if pointer:
                self.api.WlanFreeMemory(pointer)

    def connect(self, identifier):
        guid = _guid(identifier)
        ssid = DOT11_SSID()
        ssid.length = 3
        ssid.value[:3] = b"JNU"
        profile = (WCHAR * 4)(ord("J"), ord("N"), ord("U"), 0)
        parameters = WLAN_CONNECTION_PARAMETERS(0, ctypes.cast(profile, ctypes.c_void_p),
                                                 ctypes.pointer(ssid), None, 1, 0)
        self._check(self.api.WlanConnect(self.handle, ctypes.byref(guid), ctypes.byref(parameters), None))


def _physical_wifi():
    try:
        return {str(UUID(row["guid"])).upper() for row in list_adapters()
                if row.get("if_type") == 71 and row.get("hardware_interface") is True
                and row.get("enabled") is True}
    except (OSError, ValueError, KeyError):
        raise WirelessError("无法读取物理无线网卡，请检查系统网络服务") from None


def current_jnu() -> list[str]:
    """Return GUIDs actually associated with exact SSID JNU; no subprocess/scan."""
    physical = _physical_wifi()
    if not physical:
        return []
    with _WlanClient() as wlan:
        return [guid for guid in wlan.interfaces() if guid in physical and wlan.ssid(guid) == b"JNU"]


_IP_QUERY = r'''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
$deadline=[DateTime]::UtcNow.AddSeconds([double]$data.wait)
do {
 $adapters=@(Get-NetAdapter -IncludeHidden | Where-Object { [guid]$_.InterfaceGuid -eq [guid]$data.guid })
 if ($adapters.Count -ne 1) { throw 'Wireless interface is unavailable' }
 $idx=[int]$adapters[0].ifIndex
 $addresses=@(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource -and
   $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -notlike '127.*' })
 if ($addresses.Count -gt 0) {
  $dns=@((Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4).ServerAddresses)
  @{index=$idx; addresses=@($addresses.IPAddress); dns=$dns} | ConvertTo-Json -Compress
  exit
 }
 Start-Sleep -Milliseconds 200
} while ([DateTime]::UtcNow -lt $deadline)
@{index=$idx;addresses=@();dns=@()} | ConvertTo-Json -Compress
'''


def _parse_binding(output, guid):
    try:
        value = json.loads(output.lstrip("\ufeff"))
        index = value["index"]
        if type(index) is not int or not 0 < index <= 0xFFFFFFFF:
            raise ValueError()
        addresses = value["addresses"]
        dns = value["dns"]
        if not isinstance(addresses, list) or not isinstance(dns, list):
            raise ValueError()
        def valid_ip(raw):
            address = ipaddress.IPv4Address(raw)
            if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast:
                raise ValueError()
            return str(address)
        addresses = list(dict.fromkeys(valid_ip(item) for item in addresses))
        resolvers = tuple(dict.fromkeys(valid_ip(item) for item in dns))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise WirelessError("无线网卡地址信息无效") from None
    if len(addresses) != 1:
        raise WirelessError("JNU 尚未获得唯一可用的 IPv4 地址，请稍后重试")
    if not resolvers:
        raise WirelessError("JNU 尚未获得 DNS 配置，请稍后重试")
    return InterfaceBinding(index, addresses[0], resolvers, guid)


def _read_binding(guid, cancel, remaining):
    _check_cancel(cancel)
    deadline = time.monotonic() + remaining
    command = base64.b64encode(_IP_QUERY.encode("utf-16-le")).decode("ascii")
    process = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", command],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    initial = json.dumps({"guid": str(UUID(guid)), "wait": max(0, remaining - 2)})
    try:
        while True:
            _check_cancel(cancel)
            left = deadline - time.monotonic()
            if left <= 0:
                raise WirelessError("等待 JNU 获取网络地址超时，请稍后重试")
            try:
                output, _ = process.communicate(initial, timeout=min(left, .2))
                break
            except subprocess.TimeoutExpired:
                initial = None
        _check_cancel(cancel)
        if process.returncode:
            raise WirelessError("读取 JNU 网卡地址失败，请检查无线连接")
        return _parse_binding(output, guid)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def ensure_jnu(cancel, *, timeout=15.0) -> InterfaceBinding:
    """Reuse JNU or connect its existing profile; bounded, cancelable DHCP wait.

    No profile is created or modified. This identifies a link, not a successful
    campus login; the caller must validate the portal result separately.
    """
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("无线连接等待时间无效")
    _check_cancel(cancel)
    deadline = time.monotonic() + timeout
    physical = _physical_wifi()
    if not physical:
        raise WirelessError("未找到可用的物理无线网卡，请先开启 Wi-Fi")
    with _WlanClient() as wlan:
        candidates = [guid for guid in wlan.interfaces() if guid in physical]
        if not candidates:
            raise WirelessError("未找到可用的物理无线网卡，请先开启 Wi-Fi")
        connected = [guid for guid in candidates if wlan.ssid(guid) == b"JNU"]
        if len(connected) > 1:
            raise WirelessError("多张无线网卡连接了 JNU，请保留一张后重试")
        if connected:
            selected = connected[0]
        else:
            profiles = [guid for guid in candidates if wlan.has_profile(guid)]
            if not profiles:
                raise WirelessError("没有已保存的 JNU 无线配置，请先在 Windows 中连接一次 JNU")
            if len(profiles) > 1:
                raise WirelessError("多张无线网卡保存了 JNU，请先在 Windows 中选择要连接的网卡")
            selected = profiles[0]
            _check_cancel(cancel)
            if time.monotonic() >= deadline:
                raise WirelessError("连接 JNU 超时，请稍后重试")
            wlan.connect(selected)
        while True:
            _check_cancel(cancel)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WirelessError("连接 JNU 超时，请检查无线信号")
            if wlan.ssid(selected) == b"JNU":
                binding = _read_binding(selected, cancel, remaining)
                _check_cancel(cancel)
                if wlan.ssid(selected) != b"JNU":
                    raise WirelessError("无线网络已改变，请重新连接 JNU")
                return binding
            cancel.wait(min(.25, remaining))

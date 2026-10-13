"""Read-only IP Helper adapter enumeration; never changes network state.

Layouts follow Microsoft's netioapi.h MIB_IF_ROW2 / MIB_IF_TABLE2 and
ifdef.h (IF_MAX_STRING_SIZE=256, IF_MAX_PHYS_ADDRESS_LENGTH=32).
https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getiftable2

Fixed-width Windows types keep ABI checks meaningful in offline tests too.
No MAC address, network address, or counter is exposed to the caller.
"""
from __future__ import annotations

import ctypes
import os
from uuid import UUID


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]


class MIB_IF_ROW2(ctypes.Structure):
    _pack_ = 8
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceGuid", GUID),
        ("Alias", ctypes.c_uint16 * 257),
        ("Description", ctypes.c_uint16 * 257),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TunnelType", ctypes.c_uint32),
        ("MediaType", ctypes.c_uint32),
        ("PhysicalMediumType", ctypes.c_uint32),
        ("AccessType", ctypes.c_uint32),
        ("DirectionType", ctypes.c_uint32),
        # Eight BOOLEAN bitfields occupy one byte in the Windows ABI.
        # Decode bit zero explicitly; do not infer hardware from adapter names.
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", ctypes.c_uint32),
        ("AdminStatus", ctypes.c_uint32),
        ("MediaConnectState", ctypes.c_uint32),
        ("NetworkGuid", GUID),
        ("ConnectionType", ctypes.c_uint32),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
    ] + [(name, ctypes.c_uint64) for name in (
        "InOctets", "InUcastPkts", "InNUcastPkts", "InDiscards", "InErrors",
        "InUnknownProtos", "InUcastOctets", "InMulticastOctets", "InBroadcastOctets",
        "OutOctets", "OutUcastPkts", "OutNUcastPkts", "OutDiscards", "OutErrors",
        "OutUcastOctets", "OutMulticastOctets", "OutBroadcastOctets", "OutQLen",
    )]


class MIB_IF_TABLE2(ctypes.Structure):
    _pack_ = 8
    _fields_ = [("NumEntries", ctypes.c_uint32), ("Table", MIB_IF_ROW2 * 1)]


MAX_INTERFACES = 16384


def _check_layout():
    offsets = {"InterfaceGuid": 12, "Alias": 28, "Description": 542,
               "Type": 1128, "InterfaceAndOperStatusFlags": 1152,
               "OperStatus": 1156, "AdminStatus": 1160,
               "NetworkGuid": 1168, "TransmitLinkSpeed": 1192}
    if (ctypes.sizeof(GUID) != 16 or ctypes.sizeof(MIB_IF_ROW2) != 1352
            or ctypes.alignment(MIB_IF_ROW2) != 8 or MIB_IF_TABLE2.Table.offset != 8
            or any(getattr(MIB_IF_ROW2, name).offset != offset for name, offset in offsets.items())):
        raise OSError("Windows 网卡结构布局不受支持")


def _wide_string(value):
    text = bytes(value).decode("utf-16-le")
    if "\0" not in text:
        raise ValueError("Windows 网卡名称未正确终止")
    return text.split("\0", 1)[0]


def _row_to_dict(row):
    identifier = UUID(bytes_le=bytes(row.InterfaceGuid))
    if not identifier.int:
        raise ValueError("Windows 返回了无效的网卡标识")
    if row.AdminStatus not in (1, 2, 3) or row.OperStatus not in range(1, 8):
        raise ValueError("Windows 返回了未知的网卡状态")
    # Match the Status script property shipped in NetAdapter.Types.ps1xml:
    # admin/media conditions describe an operationally Down interface only.
    # In particular, an absent interface must remain Not Present.
    if row.OperStatus == 2:
        if row.AdminStatus == 2:
            status = "Disabled"
        else:
            reasons = [(0x08, "Not Authenticated"), (0x10, "Disconnected"),
                       (0x40, "Low Power State")]
            status = ", ".join(label for bit, label in reasons
                               if row.InterfaceAndOperStatusFlags & bit) or "Down"
    else:
        status = {1: "Up", 3: "Testing", 4: "Unknown", 5: "Dormant",
                  6: "Not Present", 7: "Lower Layer Down"}[row.OperStatus]
    return {"guid": str(identifier).upper(), "name": _wide_string(row.Alias),
            "enabled": row.AdminStatus == 1, "status": status,
            "interface_description": _wide_string(row.Description),
            "if_type": int(row.Type),
            "hardware_interface": bool(row.InterfaceAndOperStatusFlags & 0x01)}


def list_adapters(*, api=None) -> list[dict]:
    """Return adapter metadata, or raise for the caller's PowerShell fallback.

    ``api`` is a fake DLL seam for offline tests. Production loads only the
    Windows system DLL. Every non-null API allocation is released in finally.
    """
    _check_layout()
    if api is None:
        if os.name != "nt":
            raise OSError("原生网卡枚举仅支持 Windows")
        api = ctypes.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x00000800)
    pointer_type = ctypes.POINTER(MIB_IF_TABLE2)
    get_table = api.GetIfTable2
    get_table.argtypes = [ctypes.POINTER(pointer_type)]
    get_table.restype = ctypes.c_uint32
    free_table = api.FreeMibTable
    free_table.argtypes = [ctypes.c_void_p]
    free_table.restype = None
    table = pointer_type()
    try:
        error = get_table(ctypes.byref(table))
        if error:
            raise OSError(int(error), "Windows 原生网卡枚举失败")
        if not table:
            raise OSError("Windows 原生网卡表为空")
        count = int(table.contents.NumEntries)
        if count > MAX_INTERFACES:
            raise OSError("Windows 原生网卡数量超出可处理范围")
        base = ctypes.addressof(table.contents) + MIB_IF_TABLE2.Table.offset
        result, seen = [], set()
        for index in range(count):
            row = MIB_IF_ROW2.from_address(base + index * ctypes.sizeof(MIB_IF_ROW2))
            # IP Helper also lists loopback and filter-layer interfaces, which
            # are not configurable adapters in Get-NetAdapter's inventory.
            if row.Type == 24 or row.InterfaceAndOperStatusFlags & 0x02:
                continue
            item = _row_to_dict(row)
            if item["guid"] in seen:
                raise ValueError("Windows 网卡标识重复，无法确认接口")
            seen.add(item["guid"])
            result.append(item)
        return result
    finally:
        if table:
            free_table(ctypes.cast(table, ctypes.c_void_p))

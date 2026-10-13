"""IP Helper ABI and ownership tests backed only by synthetic ctypes memory."""
import ctypes
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from utils import native_adapters as native
from utils.campus_connection import WindowsOperations


# Deliberately synthetic identities; never copied from a host.
FIRST_GUID = "11111111-1111-4111-8111-111111111111"
SECOND_GUID = "22222222-2222-4222-8222-222222222222"


def set_wide(field, text):
    content = text.encode("utf-16-le") + b"\0\0"
    if len(content) > ctypes.sizeof(field):
        raise ValueError("Synthetic field exceeds the Windows ABI buffer")
    ctypes.memmove(ctypes.addressof(field), content, len(content))


def synthetic_row(guid=FIRST_GUID, *, flags=1, name="Synthetic 网卡 🌐"):
    row = native.MIB_IF_ROW2()
    ctypes.memmove(ctypes.addressof(row.InterfaceGuid), UUID(guid).bytes_le, 16)
    row.InterfaceIndex = 7
    row.Type = 6
    row.InterfaceAndOperStatusFlags = flags
    row.AdminStatus = row.OperStatus = row.MediaConnectState = 1
    set_wide(row.Alias, name)
    set_wide(row.Description, "Synthetic Ethernet description")
    return row


class FakeIpHelper:
    def __init__(self, rows=(), *, error=0, null=False, count=None):
        offset, size = native.MIB_IF_TABLE2.Table.offset, ctypes.sizeof(native.MIB_IF_ROW2)
        self.storage = ctypes.create_string_buffer(offset + size * max(1, len(rows)))
        self.address = ctypes.addressof(self.storage)
        self.table = ctypes.cast(self.storage, ctypes.POINTER(native.MIB_IF_TABLE2))
        self.table.contents.NumEntries = len(rows) if count is None else count
        for index, row in enumerate(rows):
            ctypes.memmove(self.address + offset + size * index, ctypes.byref(row), size)

        def get_table(output):
            if not null:
                ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(native.MIB_IF_TABLE2)))[0] = self.table
            return error

        self.GetIfTable2 = Mock(side_effect=get_table)
        self.FreeMibTable = Mock()


class NativeAdapterTests(unittest.TestCase):
    def setUp(self):
        for patcher in (patch("ctypes.WinDLL", side_effect=AssertionError("Real DLL loading is forbidden"), create=True),
                        patch("subprocess.run", side_effect=AssertionError("Real commands are forbidden")),
                        patch("subprocess.Popen", side_effect=AssertionError("Real processes are forbidden"))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_freed_once(self, api):
        api.FreeMibTable.assert_called_once()
        self.assertEqual(api.FreeMibTable.call_args.args[0].value, api.address)

    def test_fixed_width_windows_abi_matches_ip_helper_contract(self):
        native._check_layout()
        self.assertEqual(ctypes.sizeof(native.GUID), 16)
        self.assertEqual(ctypes.sizeof(native.MIB_IF_ROW2), 1352)
        self.assertEqual(ctypes.alignment(native.MIB_IF_ROW2), 8)
        self.assertEqual(native.MIB_IF_TABLE2.Table.offset, 8)
        self.assertEqual(ctypes.sizeof(native.MIB_IF_ROW2().Alias), 514)
        expected_offsets = {"InterfaceGuid": 12, "Alias": 28, "Description": 542,
                            "Type": 1128, "InterfaceAndOperStatusFlags": 1152,
                            "OperStatus": 1156, "AdminStatus": 1160,
                            "NetworkGuid": 1168, "TransmitLinkSpeed": 1192, "OutQLen": 1344}
        for name, offset in expected_offsets.items():
            self.assertEqual(getattr(native.MIB_IF_ROW2, name).offset, offset, name)

    def test_multiple_rows_decode_utf16_guid_byte_order_and_hardware_flag(self):
        physical = synthetic_row(name="Synthetic Mihomo label")
        virtual = synthetic_row(SECOND_GUID, flags=0, name="Synthetic physical Ethernet 🌐")
        api = FakeIpHelper([physical, virtual])
        result = native.list_adapters(api=api)
        self.assertEqual([item["guid"] for item in result], [FIRST_GUID, SECOND_GUID])
        self.assertEqual([item["hardware_interface"] for item in result], [True, False])
        self.assertEqual(result[1]["name"], "Synthetic physical Ethernet 🌐")
        self.assertEqual(set(result[0]), {"guid", "name", "enabled", "status", "interface_description",
                                          "if_type", "hardware_interface"})
        self.assert_freed_once(api)

    def test_admin_operational_and_media_states_map_without_name_heuristics(self):
        # Match NetAdapter.Types.ps1xml: operational status takes priority,
        # and MediaConnectState does not determine this derived Status field.
        cases = [(1, 1, 2, "Up", True), (2, 1, 2, "Up", False),
                 (2, 2, 1, "Disabled", False), (2, 6, 2, "Not Present", False),
                 (1, 2, 2, "Down", True), (1, 6, 2, "Not Present", True),
                 (3, 3, 2, "Testing", False), (3, 2, 2, "Down", False),
                 (1, 4, 2, "Unknown", True), (1, 5, 2, "Dormant", True),
                 (1, 7, 2, "Lower Layer Down", True)]
        for admin, operational, media, status, enabled in cases:
            with self.subTest(admin=admin, operational=operational, media=media):
                row = synthetic_row()
                row.AdminStatus, row.OperStatus, row.MediaConnectState = admin, operational, media
                item = native._row_to_dict(row)
                self.assertEqual((item["status"], item["enabled"]), (status, enabled))

    def test_down_interface_flags_combine_in_windows_display_order(self):
        cases = [(0x00, "Down"), (0x08, "Not Authenticated"), (0x10, "Disconnected"),
                 (0x40, "Low Power State"), (0x18, "Not Authenticated, Disconnected"),
                 (0x48, "Not Authenticated, Low Power State"),
                 (0x50, "Disconnected, Low Power State"),
                 (0x58, "Not Authenticated, Disconnected, Low Power State")]
        for flags, expected in cases:
            with self.subTest(flags=flags):
                row = synthetic_row(flags=flags | 1)
                row.OperStatus, row.MediaConnectState = 2, 2
                item = native._row_to_dict(row)
                self.assertEqual(item["status"], expected)
                self.assertTrue(item["enabled"])
                self.assertTrue(item["hardware_interface"])
                row.AdminStatus = 2
                self.assertEqual(native._row_to_dict(row)["status"], "Disabled")
        for operational, expected in ((1, "Up"), (6, "Not Present")):
            row = synthetic_row(flags=0x59)
            row.AdminStatus, row.OperStatus = 2, operational
            self.assertEqual(native._row_to_dict(row)["status"], expected)

    def test_loopback_and_filter_interfaces_are_excluded_before_adapter_validation(self):
        loopback = native.MIB_IF_ROW2()
        loopback.Type = 24
        filter_row = native.MIB_IF_ROW2()
        filter_row.InterfaceAndOperStatusFlags = 2
        api = FakeIpHelper([loopback, filter_row, synthetic_row()])
        self.assertEqual(len(native.list_adapters(api=api)), 1)
        self.assert_freed_once(api)

    def test_empty_allocated_table_is_valid_and_freed(self):
        api = FakeIpHelper()
        self.assertEqual(native.list_adapters(api=api), [])
        self.assert_freed_once(api)

    def test_api_error_releases_non_null_allocation_and_null_is_never_freed(self):
        for null, error in ((False, 5), (True, 5), (True, 0)):
            with self.subTest(null=null, error=error):
                api = FakeIpHelper(error=error, null=null)
                with self.assertRaises(OSError):
                    native.list_adapters(api=api)
                if null:
                    api.FreeMibTable.assert_not_called()
                else:
                    self.assert_freed_once(api)

    def test_oversized_count_is_rejected_before_rows_are_accessed_and_freed(self):
        api = FakeIpHelper(count=native.MAX_INTERFACES + 1)
        with patch.object(native, "_row_to_dict") as convert:
            with self.assertRaises(OSError):
                native.list_adapters(api=api)
        convert.assert_not_called()
        self.assert_freed_once(api)

    def test_invalid_or_duplicate_rows_always_release_table(self):
        invalid_guid = synthetic_row()
        invalid_guid.InterfaceGuid = native.GUID()
        invalid_admin = synthetic_row()
        invalid_admin.AdminStatus = 0
        invalid_operational = synthetic_row()
        invalid_operational.OperStatus = 8
        unterminated = synthetic_row()
        for index in range(len(unterminated.Alias)):
            unterminated.Alias[index] = ord("x")
        cases = {"zero_guid": [invalid_guid], "unknown_admin": [invalid_admin],
                 "unknown_operational": [invalid_operational], "unterminated_utf16": [unterminated],
                 "duplicate_guid": [synthetic_row(), synthetic_row()]}
        for reason, rows in cases.items():
            with self.subTest(reason=reason):
                api = FakeIpHelper(rows)
                with self.assertRaises(ValueError):
                    native.list_adapters(api=api)
                self.assert_freed_once(api)

    def test_unexpected_parser_exception_still_releases_table(self):
        api = FakeIpHelper([synthetic_row()])
        with patch.object(native, "_row_to_dict", side_effect=RuntimeError("synthetic parser failure")):
            with self.assertRaises(RuntimeError):
                native.list_adapters(api=api)
        self.assert_freed_once(api)

    def test_layout_failure_occurs_before_api_allocation(self):
        api = FakeIpHelper()
        with patch.object(native, "_check_layout", side_effect=OSError("synthetic ABI mismatch")):
            with self.assertRaises(OSError):
                native.list_adapters(api=api)
        api.GetIfTable2.assert_not_called()
        api.FreeMibTable.assert_not_called()

    def test_native_success_including_empty_inventory_does_not_fallback(self):
        for result in ([], [{"guid": FIRST_GUID, "name": "Synthetic adapter"}]):
            with self.subTest(empty=not result), \
                 patch.object(native, "list_adapters", return_value=result) as read, \
                 patch.object(WindowsOperations, "_list_adapters_powershell") as fallback:
                self.assertIs(WindowsOperations().list_adapters(), result)
                read.assert_called_once_with()
                fallback.assert_not_called()

    def test_native_api_compatibility_failures_use_injected_powershell_fallback(self):
        result = [{"guid": FIRST_GUID, "name": "Synthetic fallback adapter"}]
        for error in (OSError, ValueError, AttributeError, ImportError):
            with self.subTest(error=error.__name__), \
                 patch.object(native, "list_adapters", side_effect=error("synthetic unavailable")), \
                 patch.object(WindowsOperations, "_list_adapters_powershell", return_value=result) as fallback:
                self.assertIs(WindowsOperations().list_adapters(), result)
                fallback.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

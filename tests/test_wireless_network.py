"""Offline WLAN ABI, allocation lifetime and exact-network selection tests."""
import ctypes
import json
import subprocess
import threading
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from utils import wireless_network as wifi


GUID = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
BINDING = wifi.InterfaceBinding(7, "192.0.2.10", ("192.0.2.1",), GUID)


def put_wide(field, value):
    data = value.encode("utf-16-le") + b"\0\0"
    ctypes.memmove(ctypes.addressof(field), data, len(data))


class FakeWlan:
    def __init__(self):
        self.allocations = []
        self.ssid = b"JNU"
        self.query_code = 0
        self.query_size = ctypes.sizeof(wifi.WLAN_CONNECTION_ATTRIBUTES)
        self.profile = "JNU"
        self.request = None
        def opened(_, __, version, handle):
            ctypes.cast(version, ctypes.POINTER(wifi.DWORD))[0] = 2
            ctypes.cast(handle, ctypes.POINTER(wifi.HANDLE))[0] = wifi.HANDLE(123)
            return 0
        self.WlanOpenHandle = Mock(side_effect=opened)
        self.WlanCloseHandle = Mock(return_value=0)
        self.WlanFreeMemory = Mock()
        self.WlanEnumInterfaces = Mock(side_effect=self.interfaces)
        self.WlanGetProfileList = Mock(side_effect=self.profiles)
        self.WlanQueryInterface = Mock(side_effect=self.query)
        self.WlanConnect = Mock(side_effect=self.connect)

    def allocate(self, payload, output):
        allocation = ctypes.create_string_buffer(payload)
        self.allocations.append(allocation)
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(allocation)

    def interfaces(self, handle, reserved, output):
        item = wifi.WLAN_INTERFACE_INFO()
        item.guid = wifi._guid(GUID)
        self.allocate(bytes(wifi.DWORD(1)) + bytes(wifi.DWORD(0)) + bytes(item), output)
        return 0

    def profiles(self, handle, guid, reserved, output):
        item = wifi.WLAN_PROFILE_INFO()
        put_wide(item.name, self.profile)
        self.allocate(bytes(wifi.DWORD(1)) + bytes(wifi.DWORD(0)) + bytes(item), output)
        return 0

    def query(self, handle, guid, opcode, reserved, size, output, value_type):
        assert opcode == 7
        item = wifi.WLAN_CONNECTION_ATTRIBUTES()
        item.state = 1
        # Profile label intentionally differs from the actual SSID.
        put_wide(item.profile, "JNU-Secure")
        item.association.ssid.length = len(self.ssid)
        item.association.ssid.value[:len(self.ssid)] = self.ssid
        self.allocate(bytes(item), output)
        ctypes.cast(size, ctypes.POINTER(wifi.DWORD))[0] = self.query_size
        return self.query_code

    def connect(self, handle, guid, parameters, reserved):
        value = ctypes.cast(parameters, ctypes.POINTER(wifi.WLAN_CONNECTION_PARAMETERS)).contents
        ssid = value.ssid.contents
        self.request = (value.mode, ctypes.string_at(value.profile, 8),
                        bytes(ssid.value[:ssid.length]), value.bss_type, value.flags, value.bssids)
        return 0


class OfflineTest(unittest.TestCase):
    def setUp(self):
        for target in ("ctypes.WinDLL", "subprocess.Popen", "subprocess.run"):
            guard = patch(target, side_effect=AssertionError("Live network access forbidden"), create=True)
            guard.start()
            self.addCleanup(guard.stop)


class NativeContractTests(OfflineTest):
    def test_abi_and_exact_connection_parameters(self):
        wifi._check_layout()
        self.assertEqual(wifi.WLAN_CONNECTION_ATTRIBUTES.security.offset, 588)
        self.assertEqual(wifi.WLAN_INTERFACE_INFO.state.offset, 528)
        fake = FakeWlan()
        with wifi._WlanClient(fake) as client:
            self.assertEqual(client.interfaces(), [GUID])
            self.assertTrue(client.has_profile(GUID))
            self.assertEqual(client.ssid(GUID), b"JNU")
            client.connect(GUID)
        self.assertEqual(fake.request, (0, b"J\0N\0U\0\0\0", b"JNU", 1, 0, None))
        self.assertEqual(fake.WlanFreeMemory.call_count, 3)
        fake.WlanCloseHandle.assert_called_once()

    def test_disconnected_and_error_allocations_freed(self):
        for code in (5023, 5, 123):
            with self.subTest(code=code):
                fake = FakeWlan()
                fake.query_code = code
                with wifi._WlanClient(fake) as client:
                    if code == 5023:
                        self.assertIsNone(client.ssid(GUID))
                    else:
                        with self.assertRaises(wifi.WirelessError):
                            client.ssid(GUID)
                fake.WlanFreeMemory.assert_called_once()
                fake.WlanCloseHandle.assert_called_once()

    def test_reject_truncated_connection(self):
        fake = FakeWlan()
        fake.query_size = 16
        with wifi._WlanClient(fake) as client:
            with self.assertRaises(wifi.WirelessError):
                client.ssid(GUID)
        fake.WlanFreeMemory.assert_called_once()

    def test_profile_name_match_is_exact(self):
        for name in ("JNU-Secure", "JNU ", "jnu"):
            fake = FakeWlan()
            fake.profile = name
            with wifi._WlanClient(fake) as client:
                self.assertFalse(client.has_profile(GUID))


class EnsureTests(OfflineTest):
    def setUp(self):
        super().setUp()
        self.cancel = threading.Event()
        self.client = Mock()
        self.client.__enter__ = Mock(return_value=self.client)
        self.client.__exit__ = Mock(return_value=False)
        self.client.interfaces.return_value = [GUID]
        self.client.ssid.return_value = b"JNU"
        self.client.has_profile.return_value = True
        for target, value in (("_WlanClient", self.client), ("_physical_wifi", {GUID}),
                              ("_read_binding", BINDING)):
            guard = patch.object(wifi, target, return_value=value)
            setattr(self, target, guard.start())
            self.addCleanup(guard.stop)

    def test_existing_real_jnu_does_not_reconnect(self):
        self.assertEqual(wifi.ensure_jnu(self.cancel), BINDING)
        self.client.connect.assert_not_called()
        self.client.has_profile.assert_not_called()
        self._read_binding.assert_called_once()

    def test_secure_or_similar_ssid_is_not_success(self):
        for wrong in (b"JNU-Secure", b"JNU ", b"jnu"):
            self.client.reset_mock()
            self.client.ssid.side_effect = [wrong, b"JNU", b"JNU"]
            self.assertEqual(wifi.ensure_jnu(self.cancel), BINDING)
            self.client.connect.assert_called_once_with(GUID)

    def test_network_change_while_reading_ip_fails(self):
        self.client.ssid.side_effect = [b"JNU", b"JNU", b"JNU-Secure"]
        with self.assertRaisesRegex(wifi.WirelessError, "已改变"):
            wifi.ensure_jnu(self.cancel)

    def test_missing_profile_does_not_create_or_connect(self):
        self.client.ssid.return_value = None
        self.client.has_profile.return_value = False
        with self.assertRaisesRegex(wifi.WirelessError, "没有已保存"):
            wifi.ensure_jnu(self.cancel)
        self.client.connect.assert_not_called()
        self._read_binding.assert_not_called()

    def test_disabled_or_virtual_adapter_excluded(self):
        self._physical_wifi.return_value = set()
        with self.assertRaisesRegex(wifi.WirelessError, "物理无线"):
            wifi.ensure_jnu(self.cancel)
        self.client.connect.assert_not_called()

    def test_multiple_associations_are_ambiguous(self):
        self.client.interfaces.return_value = [GUID, OTHER]
        self._physical_wifi.return_value = {GUID, OTHER}
        with self.assertRaisesRegex(wifi.WirelessError, "多张"):
            wifi.ensure_jnu(self.cancel)
        self._read_binding.assert_not_called()

    def test_cancellation_before_any_native_read(self):
        self.cancel.set()
        with self.assertRaises(wifi.WirelessCancelled):
            wifi.ensure_jnu(self.cancel)
        self._WlanClient.assert_not_called()

    def test_cancellation_after_connect_prevents_address_read(self):
        self.client.ssid.return_value = None
        self.client.connect.side_effect = lambda _: self.cancel.set()
        with self.assertRaises(wifi.WirelessCancelled):
            wifi.ensure_jnu(self.cancel)
        self._read_binding.assert_not_called()

    def test_timeout_does_not_treat_other_network_as_success(self):
        self.client.ssid.return_value = b"OTHER"
        with patch.object(wifi.time, "monotonic", side_effect=[0, 1, 16]):
            with self.assertRaisesRegex(wifi.WirelessError, "超时"):
                wifi.ensure_jnu(self.cancel)
        self.client.connect.assert_called_once()
        self._read_binding.assert_not_called()

    def test_snapshot_uses_native_association_only(self):
        self.assertEqual(wifi.current_jnu(), [GUID])
        self.client.ssid.return_value = b"JNU-Secure"
        self.assertEqual(wifi.current_jnu(), [])
        self._read_binding.assert_not_called()
        self.client.connect.assert_not_called()


class BindingTests(OfflineTest):
    def test_valid_binding_and_invalid_addresses(self):
        good = {"index": 7, "addresses": ["192.0.2.10"], "dns": ["192.0.2.1"]}
        self.assertEqual(wifi._parse_binding(json.dumps(good), GUID), BINDING)
        invalid = [{"addresses": []}, {"addresses": ["169.254.1.2"]},
                   {"addresses": ["127.0.0.1"]}, {"addresses": ["0.0.0.0"]},
                   {"addresses": ["192.0.2.10", "192.0.2.11"]},
                   {"dns": []}, {"dns": ["::1"]}, {"index": True}, {"index": -1}]
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(wifi.WirelessError):
                wifi._parse_binding(json.dumps(good | change), GUID)

    def test_physical_matching_is_not_based_on_adapter_name(self):
        row = {"guid": GUID, "if_type": 71, "hardware_interface": True, "enabled": True}
        for change, expected in (({}, {GUID}), ({"enabled": False}, set()),
                                 ({"if_type": 6}, set()), ({"hardware_interface": False}, set())):
            with patch.object(wifi, "list_adapters", return_value=[row | change]):
                self.assertEqual(wifi._physical_wifi(), expected)

    def process(self):
        process = Mock()
        process.returncode = 0
        process.poll.return_value = 0
        process.communicate.return_value = (
            json.dumps({"index": 7, "addresses": ["192.0.2.10"], "dns": ["192.0.2.1"]}), "")
        return process

    def test_binding_uses_one_structured_read_only_process(self):
        process = self.process()
        with patch.object(wifi.subprocess, "Popen", return_value=process) as spawn:
            self.assertEqual(wifi._read_binding(GUID, threading.Event(), 10), BINDING)
        spawn.assert_called_once()
        self.assertNotIn(GUID, " ".join(spawn.call_args.args[0]))
        supplied = json.loads(process.communicate.call_args.args[0])
        self.assertEqual(supplied["guid"], GUID.lower())
        self.assertIn("Get-NetIPAddress", wifi._IP_QUERY)
        self.assertNotIn("Set-", wifi._IP_QUERY)
        process.kill.assert_not_called()

    def test_binding_query_normalizes_braced_windows_adapter_guid(self):
        # NetAdapter.InterfaceGuid can be a braced string; PowerShell equality
        # coerces the RHS to the LHS type, so both operands must be GUID values.
        self.assertEqual(UUID("{" + GUID.lower() + "}"), UUID(GUID))
        self.assertIn("[guid]$_.InterfaceGuid -eq [guid]$data.guid", wifi._IP_QUERY)
        self.assertNotIn("{ $_.InterfaceGuid -eq [guid]$data.guid", wifi._IP_QUERY)

    def test_cancel_kills_only_own_address_query(self):
        process, cancel = self.process(), threading.Event()
        process.poll.return_value = None
        def first(*args, **kwargs):
            cancel.set()
            raise subprocess.TimeoutExpired("synthetic", .2)
        calls = 0
        def communicate(*args, **kwargs):
            nonlocal calls
            calls += 1
            return first() if calls == 1 else ("", "")
        process.communicate.side_effect = communicate
        with patch.object(wifi.subprocess, "Popen", return_value=process):
            with self.assertRaises(wifi.WirelessCancelled):
                wifi._read_binding(GUID, cancel, 10)
        process.kill.assert_called_once()
        self.assertEqual(process.communicate.call_count, 2)

    def test_address_query_deadline_kills_child_and_sanitizes_errors(self):
        process = self.process()
        process.poll.return_value = None
        with patch.object(wifi.subprocess, "Popen", return_value=process), \
             patch.object(wifi.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(wifi.WirelessError, "超时"):
                wifi._read_binding(GUID, threading.Event(), 10)
        process.kill.assert_called_once()
        process = self.process()
        process.returncode = 1
        process.communicate.return_value = ("", "synthetic private diagnostic")
        with patch.object(wifi.subprocess, "Popen", return_value=process):
            with self.assertRaises(wifi.WirelessError) as caught:
                wifi._read_binding(GUID, threading.Event(), 10)
        self.assertNotIn("private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

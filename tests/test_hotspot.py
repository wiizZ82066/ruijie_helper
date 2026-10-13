"""Hotspot regression tests; no network operations or real subprocesses run."""

import base64
import copy
import gzip
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from utils.hotspot import HotspotManager, _TETHERING_SCRIPT, select_hotspot_source, select_hotspot_private_adapter


# Synthetic UUIDs and RFC 5737 documentation subnets; no host identifiers.
GUID = "12345678-1234-5678-90ab-123456789abc"
PRIVATE = "22345678-1234-5678-90ab-123456789abc"
TUN = "32345678-1234-5678-90ab-123456789abc"
WIFI = "42345678-1234-5678-90ab-123456789abc"


def source_inventory(tun=False):
    result = {
        "errors": {}, "default_profile_guid": GUID,
        "adapters": [{"guid": GUID, "index": 21, "status": "Up", "if_type": 6, "hardware_interface": True},
                     {"guid": WIFI, "index": 22, "status": "Disconnected", "if_type": 71, "hardware_interface": True}],
        "profiles": [{"guid": GUID, "connectivity": "InternetAccess", "capability": "Enabled"},
                     {"guid": WIFI, "connectivity": "None", "capability": "Enabled"}],
        "routes": [{"index": 21, "prefix": "0.0.0.0/0"}],
    }
    if tun:
        result["adapters"].append({"guid": TUN, "index": 60, "status": "Up", "if_type": 53,
                                   "hardware_interface": False, "name": "Mihomo", "description": "Meta Tunnel"})
        result["profiles"].append({"guid": TUN, "connectivity": "InternetAccess", "capability": "Enabled"})
        result["routes"].append({"index": 60, "prefix": "0.0.0.0/0"})
        result["default_profile_guid"] = TUN
    return result


def reply(state="On", status="Success", ok=True, error="", code=0,
          already_on=False, source_verified=False, profile_fallback_used=False, source_guid=GUID, modern=False):
    snapshot = {
        "state": state, "errors": {},
        "sharing": [{"guid": source_guid, "enabled": True, "sharing_type": 0},
                    {"guid": PRIVATE, "enabled": True, "sharing_type": 1}],
        "adapters": [{"guid": source_guid, "index": 21, "status": "Up", "if_type": 6, "hardware_interface": True},
                     {"guid": PRIVATE, "index": 5, "status": "Up", "if_type": 71, "hardware_interface": False,
                      "description": "Microsoft Wi-Fi Direct Virtual Adapter #2"},
                     {"guid": WIFI, "index": 22, "status": "Disconnected", "if_type": 71, "hardware_interface": True}],
        "addresses": [{"index": 5, "address": "203.0.113.1", "prefix_length": 24, "state": 4}],
        "routes": [{"index": 5, "prefix": "203.0.113.0/24", "next_hop": "0.0.0.0"},
                   {"index": 21, "prefix": "0.0.0.0/0", "next_hop": "192.0.2.1"}],
        "services": [{"name": "SharedAccess", "status": "Running"}, {"name": "icssvc", "status": "Running"}],
    }
    if modern:
        snapshot["sharing"] = []
    return code, json.dumps({"ok": ok, "state": state, "status": status, "error": error,
                            "already_on": already_on, "source_verified": source_verified,
                            "initial_state": "On" if already_on else "Off",
                            "start_succeeded": not already_on and state == "On" and status == "Success" and ok,
                            "profile_fallback_used": profile_fallback_used,
                            "explicit_private": True, "selected_private_adapter_guid": WIFI,
                            "selected_profile_guid": source_guid, "sharing_snapshot": snapshot}), ""


class HotspotTests(unittest.TestCase):
    def setUp(self):
        HotspotManager._source_pins.clear()
        self.addCleanup(HotspotManager._source_pins.clear)
        HotspotManager._owned_sessions.clear()
        self.addCleanup(HotspotManager._owned_sessions.clear)
        inventory = patch.object(HotspotManager, "_source_inventory", return_value=source_inventory())
        self.inventory = inventory.start()
        self.addCleanup(inventory.stop)
        self.runner = patch.object(HotspotManager, "_run_powershell", return_value=reply())
        self.run = self.runner.start()
        self.addCleanup(self.runner.stop)

    def test_tun_source_is_distinct_from_physical_authentication_adapter(self):
        self.inventory.return_value = source_inventory(tun=True)
        self.run.return_value = reply(source_guid=TUN)
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID)
        self.assertTrue(result["ok"])
        self.assertFalse(result["client_internet_verified"])
        self.assertEqual((result["source_kind"], result["selected_profile_guid"]), ("tun", TUN))
        payload = self.run.call_args.kwargs["payload"]
        self.assertEqual((payload["ethernet_adapter_guid"], payload["source_adapter_guid"]), (GUID, TUN))
        self.assertEqual(payload["private_adapter_guid"], WIFI)
        self.assertEqual(HotspotManager.get_hotspot_status(GUID), "已启动")
        self.assertEqual(self.run.call_args.kwargs["payload"]["source_adapter_guid"], TUN)
        self.run.return_value = reply(state="Off", source_guid=TUN)
        self.assertTrue(HotspotManager.stop_hotspot(GUID)[0])
        self.assertEqual(self.run.call_args.kwargs["payload"]["source_adapter_guid"], TUN)
        self.assertNotIn(GUID, HotspotManager._source_pins)
        self.assertNotIn(GUID, HotspotManager._owned_sessions)

    def test_own_explicit_start_accepts_modern_sharing_without_classic_flags(self):
        self.run.return_value = reply(modern=True)
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID)
        self.assertTrue(result["ok"])
        self.assertFalse(result["rollback_attempted"])
        self.assertEqual(result["verification_mode"], "owned_winrt")
        self.assertEqual(result["selected_private_adapter_guid"], WIFI)
        self.assertFalse(result["client_internet_verified"])
        self.assertTrue(HotspotManager.verify_sharing(GUID)["ok"])
        self.assertEqual(self.run.call_args.kwargs["payload"]["private_adapter_guid"], WIFI)
        self.assertEqual(HotspotManager._owned_sessions[GUID]["private_guid"], PRIVATE)

    def test_preexisting_modern_hotspot_has_no_source_ownership(self):
        self.run.return_value = reply(already_on=True, modern=True)
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID, verify_timeout=0)
        self.assertFalse(result["ok"])
        self.assertFalse(result["rollback_attempted"])
        self.assertNotIn(GUID, HotspotManager._owned_sessions)
        self.run.return_value = reply(state="Off", modern=True)
        self.assertTrue(HotspotManager.stop_hotspot(GUID)[0])

    def test_repeated_start_cannot_reuse_old_ownership_for_external_on(self):
        self.run.return_value = reply(modern=True)
        self.assertTrue(HotspotManager.start_hotspot("Campus", "password", "5GHz", GUID)[0])
        self.run.return_value = reply(already_on=True, modern=True)
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID, verify_timeout=0)
        self.assertFalse(result["ok"])
        self.assertFalse(result["rollback_attempted"])
        self.assertNotIn(GUID, HotspotManager._owned_sessions)

    def test_observed_off_invalidates_modern_session_evidence(self):
        self.run.return_value = reply(modern=True)
        self.assertTrue(HotspotManager.start_hotspot("Campus", "password", "5GHz", GUID)[0])
        self.run.return_value = reply(state="Off", modern=True)
        self.assertEqual(HotspotManager.get_hotspot_status(GUID), "未启动")
        self.assertNotIn(GUID, HotspotManager._owned_sessions)
        self.run.return_value = reply(already_on=True, modern=True)
        self.assertFalse(HotspotManager.verify_sharing(GUID)["ok"])

    def test_transitioning_start_cannot_create_modern_ownership(self):
        response = json.loads(reply(modern=True)[1])
        response["initial_state"] = "InTransition"
        self.run.return_value = 0, json.dumps(response), ""
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID,
                                                       verify_timeout=0)
        self.assertFalse(result["ok"])
        self.assertNotIn(GUID, HotspotManager._owned_sessions)
        self.assertFalse(result["rollback_attempted"])
        self.assertEqual(self.run.call_count, 1)

    def test_failed_start_followed_by_on_does_not_own_or_stop_external_ap(self):
        response = json.loads(reply(modern=True)[1])
        response.update(ok=False, status="Error", error="Start failed", start_succeeded=False)
        self.run.return_value = 1, json.dumps(response), ""
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID, verify_timeout=0)
        self.assertFalse(result["ok"])
        self.assertFalse(result["rollback_attempted"])
        self.assertNotIn(GUID, HotspotManager._owned_sessions)
        self.assertEqual(self.run.call_count, 1)

    def test_modern_session_rejects_changed_response_source(self):
        self.run.return_value = reply(modern=True)
        self.assertTrue(HotspotManager.start_hotspot("Campus", "password", "5GHz", GUID)[0])
        self.run.return_value = reply(source_guid=TUN, modern=True)
        result = HotspotManager.verify_sharing(GUID)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "sharing_source_changed")
        self.assertNotIn(GUID, HotspotManager._owned_sessions)

    def test_modern_session_does_not_override_explicit_classic_source_mismatch(self):
        self.run.return_value = reply(modern=True)
        self.assertTrue(HotspotManager.start_hotspot("Campus", "password", "5GHz", GUID)[0])
        response = json.loads(reply()[1])
        response["sharing_snapshot"]["sharing"][0]["guid"] = TUN
        self.run.return_value = 0, json.dumps(response), ""
        self.assertEqual(HotspotManager.verify_sharing(GUID)["error_code"], "sharing_source_mismatch")

    def test_failed_modern_address_validation_rolls_back_only_own_new_ap(self):
        response = json.loads(reply(modern=True)[1])
        response["sharing_snapshot"]["addresses"][0]["address"] = "169.254.1.1"
        self.run.side_effect = [(0, json.dumps(response), ""), reply(state="Off", modern=True)]
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID, verify_timeout=0)
        self.assertFalse(result["ok"])
        self.assertTrue(result["rollback_ok"])
        self.assertEqual(result["error_code"], "private_address_not_ready")
        self.assertNotIn(GUID, HotspotManager._owned_sessions)

    def test_tun_validation_retry_and_rollback_keep_actual_source(self):
        self.inventory.return_value = source_inventory(tun=True)
        response = json.loads(reply(source_guid=TUN)[1])
        response["sharing_snapshot"]["sharing"][0]["enabled"] = False
        self.run.side_effect = [(0, json.dumps(response), ""), (-1, "", "timeout"), reply(state="Off", source_guid=TUN)]
        with patch("utils.hotspot.time.sleep"):
            result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID)
        self.assertFalse(result["ok"])
        self.assertTrue(result["rollback_ok"])
        self.assertEqual([c.kwargs["payload"]["source_adapter_guid"] for c in self.run.call_args_list], [TUN] * 3)
        self.assertEqual([c.kwargs["payload"]["operation"] for c in self.run.call_args_list], ["start", "status", "stop"])

    def test_tun_missing_profile_fails_before_any_hotspot_operation(self):
        self.inventory.return_value = source_inventory(tun=True)
        self.inventory.return_value["profiles"].pop()
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID)
        self.assertFalse(result["ok"])
        self.assertIn("TUN", result["error"])
        self.assertFalse(result["rollback_attempted"])
        self.run.assert_not_called()

    def test_retry_cannot_accept_silently_changed_profile(self):
        self.inventory.return_value = source_inventory(tun=True)
        response = json.loads(reply(source_guid=TUN)[1])
        response["sharing_snapshot"]["sharing"][0]["enabled"] = False
        self.run.side_effect = [(0, json.dumps(response), ""), reply(), reply(state="Off", source_guid=TUN)]
        with patch("utils.hotspot.time.sleep"):
            result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "sharing_source_changed")
        self.assertFalse(result["rollback_attempted"])
        self.assertEqual(self.run.call_count, 2)

    def test_new_start_replans_after_previous_tun_disappears(self):
        self.inventory.return_value = source_inventory(tun=True)
        self.run.return_value = reply(source_guid=TUN)
        self.assertTrue(HotspotManager.start_hotspot("Campus", "password", "5GHz", GUID)[0])
        self.inventory.return_value = source_inventory()
        self.run.return_value = reply()
        self.assertTrue(HotspotManager.start_hotspot("Campus", "password", "5GHz", GUID)[0])
        self.assertEqual(self.run.call_args.kwargs["payload"]["source_adapter_guid"], GUID)

    def test_explicit_settings_survive_partial_defaults(self):
        with patch.object(HotspotManager, "load_config", return_value={
            "ssid": "saved", "password": "savedpass", "band": "2.4GHz",
        }):
            self.assertEqual(HotspotManager.start_hotspot(ssid="custom", band="5GHz"), (True, ""))
        payload = self.run.call_args.kwargs["payload"]
        self.assertEqual((payload["ssid"], payload["key"], payload["band"]), ("custom", "savedpass", 2))

    def test_guid_selects_same_source_for_start_stop_and_status(self):
        self.assertTrue(HotspotManager.start_hotspot("Campus", "password", "2.4GHz", "{" + GUID.upper() + "}")[0])
        self.assertEqual(self.run.call_args.kwargs["payload"]["ethernet_adapter_guid"], GUID)
        self.run.return_value = reply(state="Off")
        self.assertEqual(HotspotManager.stop_hotspot(GUID), (True, ""))
        self.assertEqual(self.run.call_args.kwargs["payload"]["ethernet_adapter_guid"], GUID)
        self.assertEqual(HotspotManager.get_hotspot_status(GUID), "未启动")
        self.assertEqual(self.run.call_args.kwargs["payload"]["ethernet_adapter_guid"], GUID)

    def test_omitted_guid_preserves_default_profile(self):
        self.assertEqual(HotspotManager.start_hotspot("Campus", "password", "自动"), (True, ""))
        self.assertIsNone(self.run.call_args.kwargs["payload"]["ethernet_adapter_guid"])

    def test_invalid_guid_does_not_invoke_windows(self):
        ok, error = HotspotManager.start_hotspot("Campus", "password", "2.4GHz", "$(bad)")
        self.assertFalse(ok)
        self.assertIn("GUID", error)
        self.run.assert_not_called()

    def test_correct_band_values_and_reject_ambiguous_names(self):
        for band, expected in [("2.4GHz", 1), ("5GHz", 2), ("6GHz", 3), ("Auto", 0), (1, 1)]:
            with self.subTest(band=band):
                self.assertTrue(HotspotManager.start_hotspot("Campus", "password", band)[0])
                self.assertEqual(self.run.call_args.kwargs["payload"]["band"], expected)
        self.run.reset_mock()
        for band in ("not-5GHz", 2.5, True, 4):
            self.assertFalse(HotspotManager.start_hotspot("Campus", "password", band)[0])
        self.run.assert_not_called()

    def test_invalid_credentials_fail_before_windows(self):
        for ssid, key in [("", "password"), ("a" * 33, "password"), ("a\n", "password"),
                          ("Campus", "short"), ("Campus", "p" * 64), ("Campus", "校园网密码1234"),
                          ("Campus", "password\n")]:
            with self.subTest(ssid=ssid, key_length=len(key)):
                self.assertFalse(HotspotManager.start_hotspot(ssid, key, "2.4GHz")[0])
        self.run.assert_not_called()

    def test_ssid_limit_counts_encoded_bytes(self):
        with patch("utils.hotspot.platform.system", return_value="Linux"):
            self.assertTrue(HotspotManager.start_hotspot("网" * 10, "password", "2.4GHz")[0])
            self.run.reset_mock()
            self.assertFalse(HotspotManager.start_hotspot("网" * 11, "password", "2.4GHz")[0])
            self.run.assert_not_called()

    def test_shell_metacharacters_remain_literal_data(self):
        ssid, key = 'campus";$(bad)`', 'pass";$(bad)`1234'
        self.assertTrue(HotspotManager.start_hotspot(ssid, key, "2.4GHz")[0])
        payload = self.run.call_args.kwargs["payload"]
        self.assertEqual((payload["ssid"], payload["key"]), (ssid, key))
        self.assertNotIn(ssid, self.run.call_args.args[0])
        self.assertNotIn(key, self.run.call_args.args[0])

    def test_failed_async_result_is_not_success_even_when_hotspot_on(self):
        self.run.return_value = reply(state="On", status="WiFiDeviceOff", error="Wi-Fi radio disabled")
        ok, error = HotspotManager.start_hotspot("Campus", "password", "5GHz")
        self.assertFalse(ok)
        self.assertTrue(error.startswith("Wi-Fi radio disabled"))

    def test_successful_result_requires_expected_final_state(self):
        self.run.return_value = reply(state="InTransition")
        self.assertFalse(HotspotManager.start_hotspot("Campus", "password", "5GHz")[0])
        self.assertEqual(HotspotManager.get_hotspot_status(), "正在切换")

    def test_already_running_hotspot_requires_verified_explicit_source(self):
        for verified, expected in [(False, False), (True, True)]:
            with self.subTest(source_verified=verified):
                response = json.loads(reply()[1])
                response.update(already_on=True, source_verified=verified)
                if not verified:
                    response["sharing_snapshot"]["sharing"][0]["guid"] = "32345678-1234-5678-90ab-123456789abc"
                self.run.return_value = 0, json.dumps(response), ""
                self.assertEqual(HotspotManager.start_hotspot("Campus", "password", "5GHz", GUID)[0], expected)

    def test_new_hotspot_on_without_public_ics_does_not_claim_success(self):
        response = json.loads(reply()[1])
        response["sharing_snapshot"]["sharing"][0]["enabled"] = False
        self.run.return_value = 0, json.dumps(response), ""
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID, verify_timeout=0,
                                                       rollback_on_failure=False)
        self.assertFalse(result["ok"])
        self.assertTrue(result["ap_on"])
        self.assertEqual(result["error_code"], "sharing_pair_missing")
        self.assertFalse(result["client_internet_verified"])

    def test_failed_new_ap_is_rolled_back_without_leaving_host_disconnected(self):
        response = json.loads(reply()[1])
        response["sharing_snapshot"]["sharing"][0]["enabled"] = False
        self.run.side_effect = [(0, json.dumps(response), ""), reply(state="Off")]
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID, verify_timeout=0)
        self.assertFalse(result["ok"])
        self.assertFalse(result["ap_on"])
        self.assertTrue(result["rollback_ok"])
        self.assertEqual(result["error_code"], "sharing_pair_missing")
        self.assertEqual(self.run.call_args.kwargs["payload"]["operation"], "stop")

    def test_existing_ap_is_not_stopped_when_its_sharing_cannot_be_verified(self):
        response = json.loads(reply(already_on=True)[1])
        response["sharing_snapshot"]["errors"]["sharing"] = "E_ACCESSDENIED"
        self.run.return_value = 0, json.dumps(response), ""
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID)
        self.assertFalse(result["ok"])
        self.assertTrue(result["ap_on"])
        self.assertFalse(result["rollback_attempted"])
        self.assertEqual(self.run.call_count, 1)

    def test_later_status_timeout_still_rolls_back_owned_new_ap(self):
        response = json.loads(reply()[1])
        response["sharing_snapshot"]["sharing"][0]["enabled"] = False
        self.run.side_effect = [(0, json.dumps(response), ""), (-1, "", "timeout"), reply(state="Off")]
        with patch("utils.hotspot.time.sleep"):
            result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID)
        self.assertFalse(result["ok"])
        self.assertTrue(result["rollback_ok"])
        self.assertFalse(result["ap_on"])

    def test_failed_rollback_is_unknown_not_false_success(self):
        response = json.loads(reply()[1])
        response["sharing_snapshot"]["sharing"][0]["enabled"] = False
        self.run.side_effect = [(0, json.dumps(response), ""), (-1, "", "timeout")]
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID, verify_timeout=0)
        self.assertFalse(result["ok"])
        self.assertFalse(result["rollback_ok"])
        self.assertIsNone(result["ap_on"])
        self.assertIn("Windows 设置", result["error"])

    def test_partial_sharing_can_finish_then_is_verified(self):
        response = json.loads(reply()[1])
        response["sharing_snapshot"]["sharing"][0]["enabled"] = False
        self.run.side_effect = [(0, json.dumps(response), ""), reply()]
        with patch("utils.hotspot.time.sleep"):
            result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID)
        self.assertTrue(result["ok"])
        self.assertEqual(self.run.call_args.kwargs["payload"]["operation"], "status")

    def test_verification_only_reads_and_never_infers_phone_connectivity(self):
        result = HotspotManager.verify_sharing(GUID)
        self.assertTrue(result["sharing_ready"])
        self.assertFalse(result["client_internet_verified"])
        self.assertEqual(self.run.call_args.kwargs["payload"]["operation"], "status")
        self.assertTrue(self.run.call_args.kwargs["payload"]["inspect_sharing"])

    def test_verification_access_denied_is_actionable_without_retry(self):
        response = json.loads(reply()[1])
        response["sharing_snapshot"]["errors"]["sharing"] = "E_ACCESSDENIED"
        self.run.return_value = 0, json.dumps(response), ""
        result = HotspotManager.start_hotspot_detailed("Campus", "password", "5GHz", GUID,
                                                       rollback_on_failure=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "sharing_unreadable")
        self.assertIn("管理员", result["error"])
        self.assertEqual(self.run.call_count, 1)

    def test_disconnected_source_allows_fallback_only_for_stop_and_status(self):
        # A manager created from a remaining profile may read/stop the global
        # hotspot after its selected Ethernet profile has disappeared.
        self.run.return_value = reply(state="Off", profile_fallback_used=True)
        self.assertEqual(HotspotManager.stop_hotspot(GUID), (True, ""))
        self.assertEqual(self.run.call_args.kwargs["payload"]["operation"], "stop")
        self.run.return_value = reply(state="On", profile_fallback_used=True)
        self.assertEqual(HotspotManager.get_hotspot_status(GUID), "已启动")
        self.assertEqual(self.run.call_args.kwargs["payload"]["operation"], "status")
        ok, error = HotspotManager.start_hotspot("Campus", "password", "5GHz", GUID)
        self.assertFalse(ok)
        self.assertIn("不能使用其他连接", error)

    def test_no_profile_keeps_manual_windows_shutdown_instruction(self):
        message = "没有可用连接配置；请到 Windows 设置 > 网络和 Internet > 移动热点中关闭热点。"
        self.run.return_value = reply(ok=False, code=1, state="Unknown", error=message)
        self.assertEqual(HotspotManager.stop_hotspot(GUID), (False, message))
        self.assertIn("Windows 设置", HotspotManager.get_hotspot_status(GUID))

    def test_errors_and_invalid_responses_are_not_success(self):
        for response in [reply(code=1), (0, "CMD_SENT", ""), (0, "[]", ""), (-1, "", "PowerShell unavailable")]:
            with self.subTest(response=response):
                self.run.return_value = response
                self.assertFalse(HotspotManager.stop_hotspot()[0])
                self.assertTrue(HotspotManager.get_hotspot_status().startswith("Unknown"))

    def test_error_messages_redact_password(self):
        self.run.return_value = reply(state="Unknown", ok=False, error="Invalid passphrase: password")
        self.assertEqual(HotspotManager.start_hotspot("Campus", "password", "5GHz"), (False, "Invalid passphrase: [redacted]"))


class SourcePlanningTests(unittest.TestCase):
    def test_private_adapter_deduplicates_saved_profiles_by_guid(self):
        inventory = source_inventory()
        inventory["profiles"].extend([dict(inventory["profiles"][-1])] * 3)
        self.assertEqual(select_hotspot_private_adapter(inventory), WIFI)

    def test_private_adapter_needs_one_physical_wifi_with_a_profile(self):
        for change in ("missing_profile", "multiple_hardware", "only_virtual", "disabled"):
            with self.subTest(change=change):
                inventory = source_inventory()
                if change == "missing_profile":
                    inventory["profiles"].pop()
                elif change == "multiple_hardware":
                    extra = dict(inventory["adapters"][-1], guid=PRIVATE, index=23)
                    inventory["adapters"].append(extra)
                elif change == "only_virtual":
                    inventory["adapters"][-1]["hardware_interface"] = False
                else:
                    inventory["adapters"][-1]["status"] = "Disabled"
                with self.assertRaises(ValueError):
                    select_hotspot_private_adapter(inventory)

    def test_physical_only_and_unique_tun(self):
        self.assertEqual(select_hotspot_source(source_inventory(), GUID),
                         {"source_adapter_guid": GUID, "source_kind": "ethernet"})
        self.assertEqual(select_hotspot_source(source_inventory(tun=True), GUID),
                         {"source_adapter_guid": TUN, "source_kind": "tun"})

    def test_tun_does_not_replace_required_physical_authentication_base(self):
        for change in ({"status": "Down"}, {"hardware_interface": False}, {"if_type": 71}):
            with self.subTest(change=change):
                inventory = source_inventory(tun=True)
                inventory["adapters"][0].update(change)
                with self.assertRaisesRegex(ValueError, "实体有线"):
                    select_hotspot_source(inventory, GUID)

    def test_multiple_tuns_are_ambiguous_even_with_one_working_profile(self):
        inventory = source_inventory(tun=True)
        duplicate = copy.deepcopy(inventory["adapters"][-1])
        duplicate.update(guid=PRIVATE, index=61, name="Clash")
        inventory["adapters"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "多个"):
            select_hotspot_source(inventory, GUID)

    def test_active_tun_without_default_route_never_falls_back(self):
        inventory = source_inventory(tun=True)
        inventory["routes"].pop()
        with self.assertRaisesRegex(ValueError, "默认路由"):
            select_hotspot_source(inventory, GUID)

    def test_active_tun_requires_connected_and_enabled_profile(self):
        for change in ({"connectivity": "None"}, {"capability": "DisabledByHardwareLimitation"},
                       {"capability": "Unknown"}):
            with self.subTest(change=change):
                inventory = source_inventory(tun=True)
                inventory["profiles"][-1].update(change)
                with self.assertRaisesRegex(ValueError, "TUN"):
                    select_hotspot_source(inventory, GUID)

    def test_down_or_unrelated_virtual_adapters_are_not_tuns(self):
        for change in ({"status": "Down"}, {"hardware_interface": True}, {"if_type": 6},
                       {"name": "Other VPN", "description": "Other tunnel"}):
            with self.subTest(change=change):
                inventory = source_inventory(tun=True)
                inventory["adapters"][-1].update(change)
                self.assertEqual(select_hotspot_source(inventory, GUID)["source_adapter_guid"], GUID)

    def test_tun_name_variants_and_guid_normalization(self):
        for name in ("Mihomo", "Clash", "MetaTunnel", "Meta Tunnel"):
            with self.subTest(name=name):
                inventory = source_inventory(tun=True)
                inventory["adapters"][0]["guid"] = "{" + GUID.upper() + "}"
                inventory["adapters"][-1].update(name=name, description="", guid="{" + TUN.upper() + "}")
                self.assertEqual(select_hotspot_source(inventory, "{" + GUID.upper() + "}")["source_adapter_guid"], TUN)

    def test_incomplete_inventory_never_guesses_source(self):
        inventory = source_inventory(tun=True)
        inventory["errors"]["routes"] = "access denied"
        with self.assertRaisesRegex(ValueError, "无法读取"):
            select_hotspot_source(inventory, GUID)


class PowerShellTransportTests(unittest.TestCase):
    def test_full_script_fits_windows_process_command_limit(self):
        with patch("utils.hotspot.platform.system", return_value="Windows"), \
             patch.object(subprocess, "STARTUPINFO", create=True, return_value=SimpleNamespace(dwFlags=0)), \
             patch.object(subprocess, "STARTF_USESHOWWINDOW", 1, create=True), \
             patch.object(subprocess, "SW_HIDE", 0, create=True), \
             patch("utils.hotspot.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="{}", stderr="")) as run:
            HotspotManager._run_powershell(_TETHERING_SCRIPT, payload={"key": "private-passphrase"})
        command = run.call_args.args[0]
        self.assertLess(len(subprocess.list2cmdline(command)), 32767)
        bootstrap = base64.b64decode(command[-1]).decode("utf-16-le")
        compressed = bootstrap.split("FromBase64String('", 1)[1].split("')", 1)[0]
        self.assertEqual(gzip.decompress(base64.b64decode(compressed)).decode("utf-8"), _TETHERING_SCRIPT)
        self.assertNotIn("private-passphrase", bootstrap)
        self.assertEqual(json.loads(run.call_args.kwargs["input"])["key"], "private-passphrase")

    def test_credentials_are_json_data_not_command_or_source(self):
        ssid = 'campus";$(bad)`'
        key = 'key";$(bad)`1234'
        completed = SimpleNamespace(returncode=0, stdout=reply()[1], stderr="")
        # Patch Windows startup primitives too, so tests are portable.
        with patch("utils.hotspot.platform.system", return_value="Windows"), \
             patch.object(subprocess, "STARTUPINFO", create=True, return_value=SimpleNamespace(dwFlags=0)), \
             patch.object(subprocess, "STARTF_USESHOWWINDOW", 1, create=True), \
             patch.object(subprocess, "SW_HIDE", 0, create=True), \
             patch("utils.hotspot.subprocess.run", return_value=completed) as run:
            result = HotspotManager._run_powershell("$data = [Console]::In.ReadToEnd() | ConvertFrom-Json", payload={"ssid": ssid, "key": key})
        self.assertEqual(result[0], 0)
        command = run.call_args.args[0]
        source = base64.b64decode(command[-1]).decode("utf-16-le")
        self.assertNotIn(key, " ".join(command))
        self.assertNotIn(ssid, source)
        self.assertNotIn(key, source)
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), {"ssid": ssid, "key": key})

    def test_timeout_does_not_echo_process_arguments_or_input(self):
        with patch("utils.hotspot.platform.system", return_value="Windows"), \
             patch.object(subprocess, "STARTUPINFO", create=True, return_value=SimpleNamespace(dwFlags=0)), \
             patch.object(subprocess, "STARTF_USESHOWWINDOW", 1, create=True), \
             patch.object(subprocess, "SW_HIDE", 0, create=True), \
             patch("utils.hotspot.subprocess.run", side_effect=subprocess.TimeoutExpired("sensitive", 10)):
            code, stdout, stderr = HotspotManager._run_powershell("fixed script", payload={"key": "sensitive"})
        self.assertEqual((code, stdout), (-1, ""))
        self.assertIn("超时", stderr)
        self.assertNotIn("sensitive", stderr)


if __name__ == "__main__":
    unittest.main()

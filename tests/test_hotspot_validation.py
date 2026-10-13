"""Sharing checks use synthetic data only, never the host's network."""
import copy
import unittest

from utils.hotspot_validation import assess_sharing


# Synthetic UUIDs and RFC 5737 documentation subnets; no host identifiers.
PUBLIC = "12345678-1234-5678-90ab-123456789abc"
PRIVATE = "22345678-1234-5678-90ab-123456789abc"
TUN = "32345678-1234-5678-90ab-123456789abc"
WIFI = "42345678-1234-5678-90ab-123456789abc"


def ready_snapshot():
    return {
        "state": "On", "errors": {}, "client_count": 1,
        "sharing": [
            {"guid": PUBLIC, "enabled": True, "sharing_type": 0},
            {"guid": PRIVATE, "enabled": True, "sharing_type": 1},
        ],
        "adapters": [
            {"guid": PUBLIC, "index": 21, "name": "Ethernet", "description": "USB GbE",
             "status": "Up", "if_type": 6, "hardware_interface": True},
            {"guid": PRIVATE, "index": 5, "name": "Local*10", "description": "Wi-Fi Direct",
             "status": "Up", "if_type": 71, "hardware_interface": False},
            {"guid": TUN, "index": 60, "name": "Mihomo", "description": "Meta Tunnel",
             "status": "Up", "if_type": 53, "hardware_interface": False},
            {"guid": WIFI, "index": 22, "name": "Wi-Fi", "description": "Physical Wi-Fi",
             "status": "Disconnected", "if_type": 71, "hardware_interface": True},
        ],
        "addresses": [
            {"index": 5, "address": "203.0.113.1", "prefix_length": 24, "state": 4},
            {"index": 21, "address": "192.0.2.35", "prefix_length": 24, "state": 4},
            {"index": 60, "address": "198.51.100.1", "prefix_length": 30, "state": 4},
        ],
        "routes": [
            {"index": 5, "prefix": "203.0.113.0/24", "next_hop": "0.0.0.0"},
            {"index": 60, "prefix": "0.0.0.0/0", "next_hop": "198.51.100.2"},
        ],
        "services": [{"name": "SharedAccess", "status": "Running"},
                     {"name": "icssvc", "status": "Running"}],
    }


class SharingValidationTests(unittest.TestCase):
    def modern_snapshot(self):
        snapshot = ready_snapshot()
        snapshot["sharing"] = []
        return snapshot

    def modern_evidence(self):
        return {"public_guid": TUN, "private_adapter_guid": WIFI}

    def test_modern_empty_classic_flags_need_owned_explicit_session(self):
        snapshot = self.modern_snapshot()
        self.assertFalse(assess_sharing(snapshot, TUN)["ok"])
        result = assess_sharing(snapshot, TUN, owned_session=self.modern_evidence())
        self.assertTrue(result["ok"])
        self.assertEqual(result["verification_mode"], "owned_winrt")
        self.assertFalse(result["client_internet_verified"])
        self.assertEqual(result["private_guid"], PRIVATE)

    def test_modern_rejects_other_or_missing_physical_wifi(self):
        snapshot = self.modern_snapshot()
        for physical in (PUBLIC, PRIVATE, None):
            with self.subTest(physical=physical):
                evidence = self.modern_evidence()
                evidence["private_adapter_guid"] = physical
                self.assertEqual(assess_sharing(snapshot, TUN, owned_session=evidence)["error_code"], "modern_session_invalid")

    def test_modern_requires_unique_up_wifi_direct_not_any_virtual_wifi(self):
        snapshot = self.modern_snapshot()
        fake = copy.deepcopy(snapshot["adapters"][1])
        fake.update(guid="52345678-1234-5678-90ab-123456789abc", index=7, description="VMware Virtual Wi-Fi")
        snapshot["adapters"].append(fake)
        self.assertTrue(assess_sharing(snapshot, TUN, owned_session=self.modern_evidence())["ok"])
        fake["description"] = "Microsoft Wi-Fi Direct Virtual Adapter"
        self.assertEqual(assess_sharing(snapshot, TUN, owned_session=self.modern_evidence())["error_code"], "private_adapter_not_ready")
        snapshot["adapters"][1]["description"] = "VMware Wi-Fi"
        fake["description"] = "VMware Wi-Fi"
        self.assertFalse(assess_sharing(snapshot, TUN, owned_session=self.modern_evidence())["ok"])

    def test_modern_rejects_changed_virtual_adapter_or_public_source(self):
        snapshot = self.modern_snapshot()
        evidence = self.modern_evidence()
        evidence["private_guid"] = PUBLIC
        self.assertEqual(assess_sharing(snapshot, TUN, owned_session=evidence)["error_code"], "modern_private_changed")
        evidence = self.modern_evidence()
        evidence["public_guid"] = PUBLIC
        self.assertEqual(assess_sharing(snapshot, TUN, owned_session=evidence)["error_code"], "modern_session_invalid")

    def test_modern_cannot_ignore_real_classic_public_mismatch_or_partial_pair(self):
        snapshot = self.modern_snapshot()
        snapshot["sharing"] = [{"guid": PUBLIC, "enabled": True, "sharing_type": 0}]
        self.assertEqual(assess_sharing(snapshot, TUN, owned_session=self.modern_evidence())["error_code"], "sharing_source_mismatch")
        snapshot["sharing"] = [{"guid": PRIVATE, "enabled": True, "sharing_type": 1}]
        self.assertEqual(assess_sharing(snapshot, TUN, owned_session=self.modern_evidence())["error_code"], "sharing_pair_missing")

    def test_classic_pair_must_not_override_owned_private_pin(self):
        snapshot = ready_snapshot()
        evidence = {"public_guid": PUBLIC, "private_adapter_guid": WIFI,
                    "private_guid": "52345678-1234-5678-90ab-123456789abc"}
        result = assess_sharing(snapshot, PUBLIC, owned_session=evidence)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "modern_private_changed")

    def test_modern_apipa_route_service_and_read_error_fail_closed(self):
        cases = [("addresses", lambda s: s["addresses"][0].update(address="169.254.1.1"), "private_address_not_ready"),
                 ("private_route", lambda s: s["routes"].pop(0), "private_route_not_ready"),
                 ("public_route", lambda s: s["routes"].pop(), "upstream_default_route_missing"),
                 ("service", lambda s: s["services"][0].update(status="Stopped"), "sharing_service_not_running"),
                 ("error", lambda s: s["errors"].update(sharing="denied"), "sharing_unreadable")]
        for name, change, expected in cases:
            with self.subTest(case=name):
                snapshot = self.modern_snapshot()
                change(snapshot)
                self.assertEqual(assess_sharing(snapshot, TUN, owned_session=self.modern_evidence())["error_code"], expected)

    def test_modern_different_local_subnets_do_not_hide_stale_configuration(self):
        snapshot = self.modern_snapshot()
        snapshot["addresses"].append({"index": 5, "address": "198.51.100.129", "prefix_length": 25, "state": 4})
        snapshot["routes"].append({"index": 5, "prefix": "198.51.100.128/25", "next_hop": "0.0.0.0"})
        self.assertEqual(assess_sharing(snapshot, TUN, owned_session=self.modern_evidence())["error_code"], "private_address_ambiguous")

    def test_ready_sharing_with_tun_does_not_claim_phone_internet(self):
        snapshot = ready_snapshot()
        original = copy.deepcopy(snapshot)
        result = assess_sharing(snapshot, "{" + PUBLIC.upper() + "}")
        self.assertTrue(result["ok"])
        self.assertEqual(result["private_subnet"], "203.0.113.0/24")
        self.assertFalse(result["client_internet_verified"])
        self.assertTrue(result["warnings"])
        self.assertEqual(snapshot, original)

    def test_live_failure_private_only_is_not_success(self):
        snapshot = ready_snapshot()
        snapshot["sharing"][0]["enabled"] = False
        # Synthetic regression: two local IPs, AP On, phone associated,
        # TUN still Up; all insufficient when ICS has no public source.
        snapshot["addresses"].append({"index": 5, "address": "198.51.100.129", "prefix_length": 25, "state": 4})
        snapshot["routes"].append({"index": 5, "prefix": "198.51.100.128/25", "next_hop": "0.0.0.0"})
        result = assess_sharing(snapshot, PUBLIC)
        self.assertEqual(result["error_code"], "sharing_pair_missing")
        self.assertTrue(result["ap_on"])
        self.assertFalse(result["sharing_ready"])

    def test_off_state_is_reported_before_stale_ips(self):
        snapshot = ready_snapshot()
        snapshot["state"] = "Off"
        self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "access_point_not_on")

    def test_access_denied_never_means_no_sharing(self):
        snapshot = ready_snapshot()
        snapshot["errors"]["sharing"] = "E_ACCESSDENIED"
        snapshot["sharing"] = []
        result = assess_sharing(snapshot, PUBLIC)
        self.assertEqual(result["error_code"], "sharing_unreadable")
        self.assertIn("管理员", result["error"])

    def test_incomplete_snapshot_does_not_verify(self):
        snapshot = ready_snapshot()
        del snapshot["routes"]
        self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "network_state_unreadable")

    def test_changed_source_is_not_silently_accepted(self):
        snapshot = ready_snapshot()
        snapshot["sharing"][0]["guid"] = TUN
        self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "sharing_source_mismatch")

    def test_disconnected_private_with_stale_ip_fails(self):
        snapshot = ready_snapshot()
        snapshot["adapters"][1]["status"] = "Disconnected"
        self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "private_adapter_not_ready")

    def test_physical_wifi_is_not_mistaken_for_hotspot_private(self):
        snapshot = ready_snapshot()
        snapshot["adapters"][1]["hardware_interface"] = True
        self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "private_adapter_not_ready")

    def test_sharedaccess_stopped_is_not_ready(self):
        snapshot = ready_snapshot()
        snapshot["services"][0]["status"] = "Stopped"
        self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "sharing_service_not_running")

    def test_bad_or_stale_private_addresses_are_rejected(self):
        for address, state in [("169.254.1.1", 4), ("203.0.113.1", 3),
                               ("127.0.0.1", 4), ("203.0.113.255", 4), ("not-ip", 4)]:
            with self.subTest(address=address, state=state):
                snapshot = ready_snapshot()
                snapshot["addresses"][0].update(address=address, state=state)
                self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "private_address_not_ready")

    def test_missing_connected_route_cannot_use_tun_default(self):
        snapshot = ready_snapshot()
        snapshot["routes"] = snapshot["routes"][1:]
        self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "private_route_not_ready")

    def test_active_conflicting_subnet_is_reported(self):
        snapshot = ready_snapshot()
        snapshot["addresses"][1].update(address="203.0.113.2", prefix_length=24)
        self.assertEqual(assess_sharing(snapshot, PUBLIC)["error_code"], "private_subnet_conflict")

    def test_multiple_ips_on_same_private_interface_are_not_cross_adapter_conflict(self):
        snapshot = ready_snapshot()
        snapshot["addresses"].append({"index": 5, "address": "198.51.100.129", "prefix_length": 25, "state": 4})
        self.assertTrue(assess_sharing(snapshot, PUBLIC)["ok"])


if __name__ == "__main__":
    unittest.main()

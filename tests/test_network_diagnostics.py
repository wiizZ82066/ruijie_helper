import unittest
from utils.network_diagnostics import analyze_snapshot

# Deliberately synthetic adapter identities; no live collection is performed.
ETHERNET = "12345678-1234-5678-90AB-123456789ABC"
TUN = "12345678-1234-5678-90AB-123456789ABD"


class NetworkDiagnosticsTests(unittest.TestCase):
    def snapshot(self):
        return {"adapters": [
            {"guid": ETHERNET, "name": "Ethernet", "description": "USB LAN", "index": 21,
             "if_type": 6, "hardware_interface": True, "status": "Up"},
            {"guid": TUN, "name": "Mihomo", "description": "Meta Tunnel", "index": 60,
             "if_type": 53, "hardware_interface": False, "status": "Up"},
        ], "routes": [{"index": 60, "prefix": "0.0.0.0/0"}], "sharing": [], "errors": {}}

    def test_tun_is_never_automatically_selected_as_ethernet(self):
        result = analyze_snapshot(self.snapshot())
        self.assertEqual(result["selected_ethernet_guid"], ETHERNET)
        self.assertEqual(len(result["tun_candidates"]), 1)
        self.assertFalse(result["coexistence_verified"])

    def test_explicit_missing_source_does_not_silently_fallback(self):
        result = analyze_snapshot(self.snapshot(), TUN)
        self.assertIsNone(result["selected_ethernet_guid"])
        self.assertIn("selected_ethernet_unavailable", [finding["code"] for finding in result["findings"]])

    def test_access_denied_is_unknown_not_no_sharing(self):
        snapshot = self.snapshot()
        snapshot["errors"]["sharing"] = "E_ACCESSDENIED"
        result = analyze_snapshot(snapshot)
        codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("ics_unknown", codes)
        self.assertNotIn("ics_pair_not_observed", codes)

    def test_detects_ics_source_and_default_profile_mismatch(self):
        snapshot = self.snapshot()
        snapshot["default_profile"] = {"guid": TUN}
        snapshot["sharing"] = [{"guid": TUN, "enabled": True, "sharing_type": 0}]
        codes = [finding["code"] for finding in analyze_snapshot(snapshot)["findings"]]
        self.assertIn("default_profile_differs", codes)
        self.assertIn("ics_source_differs", codes)


if __name__ == "__main__":
    unittest.main()

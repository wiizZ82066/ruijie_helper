"""Legacy UI boundaries tested in process, using synthetic files and mocks."""
import base64
import importlib.util
import json
import os
import unittest
from unittest.mock import patch

from fixture_support import fixture_directory
from utils.campus_connection import CampusConnectionConfig
from utils.network_adapter import NetworkAdapterManager
from utils import supplicant


TOKEN = "synthetic-session-token-for-offline-tests-only"
GUID = "11111111-1111-4111-8111-111111111111"
API_TESTS_AVAILABLE = all(importlib.util.find_spec(name) is not None
                         for name in ("fastapi", "uvicorn", "httpx"))
if API_TESTS_AVAILABLE:
    from fastapi.testclient import TestClient
    # Importing the backend must not consume a real inherited session token.
    with patch.dict(os.environ, {"CAMPUS_AUTH_SESSION_TOKEN": TOKEN}):
        from backend import server


class OfflineBoundaryFixtures:
    def mocked(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def setUp(self):
        self.root = fixture_directory(self, "legacy-security")
        for target in ("subprocess.run", "subprocess.Popen", "subprocess.check_output",
                       "psutil.process_iter"):
            self.mocked(target, side_effect=AssertionError("Real OS operations are forbidden"))
        self.load = self.mocked("utils.supplicant.SupplicantConfig.load", return_value={})
        self.save = self.mocked("utils.supplicant.SupplicantConfig.save")
        self.mocked("utils.supplicant.RECORD_FILE", new=self.root / "data" / "config.json")


class OfflineBoundaryTests(OfflineBoundaryFixtures, unittest.TestCase):
    def test_default_quarantine_is_in_current_data_directory_without_reading_real_config(self):
        self.assertEqual(supplicant.SupplicantConfig.get_target_folder(),
                         str(self.root / "data" / "quarantine"))
        self.save.assert_not_called()
        self.assertFalse((self.root / "data").exists())

    def test_default_client_is_discovered_but_adapter_requires_explicit_selection(self):
        config = CampusConnectionConfig()
        self.assertEqual((config.client_path, config.ethernet_guid), ("", ""))
        client = self.root / "RuijieSupplicant.exe"
        client.write_bytes(b"synthetic client; never execute")
        with patch("utils.client_discovery.discover_client_dir", return_value=str(self.root)):
            with self.assertRaisesRegex(ValueError, "实体有线网卡"):
                config.validate()
            config.ethernet_guid = GUID
            config.validate()
        self.assertEqual(config.client_path, str(client))

    def test_adapter_shell_metacharacters_remain_one_literal_argument(self):
        name = 'Synthetic " & echo fixture | more'
        with patch("utils.network_adapter.subprocess.run") as run:
            self.assertTrue(NetworkAdapterManager.set_adapter_state(name, False))
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["netsh", "interface", "set", "interface",
                                  "name=" + name, "admin=disable"])
        self.assertIs(kwargs["shell"], False)

    def test_invalid_adapter_names_never_reach_os(self):
        with patch("utils.network_adapter.subprocess.run") as run:
            for name in (None, "", "fake\nname", "fake\0name"):
                self.assertFalse(NetworkAdapterManager.set_adapter_state(name, True))
        run.assert_not_called()

    def test_adapter_enumeration_uses_structured_status_and_fixed_script(self):
        payload = [{"name": "Synthetic 网卡", "enabled": True},
                   {"name": "Synthetic disabled", "enabled": False},
                   {"name": "invalid status", "enabled": "False"}]
        with patch("utils.network_adapter.subprocess.check_output", return_value=json.dumps(payload)) as run:
            result = NetworkAdapterManager.get_adapters()
        self.assertEqual(result, [("Synthetic 网卡", "Enabled"), ("Synthetic disabled", "Disabled")])
        command = run.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertIn("-EncodedCommand", command)
        script = base64.b64decode(command[-1]).decode("utf-16-le")
        self.assertIn("ConvertTo-Json", script)
        self.assertNotIn("Synthetic", script)
        self.assertFalse(run.call_args.kwargs.get("shell", False))


@unittest.skipUnless(API_TESTS_AVAILABLE, "Legacy API tests need fastapi, uvicorn and httpx")
class LegacyApiTests(OfflineBoundaryFixtures, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.client_dir = self.root / "synthetic installed client"
        self.client_dir.mkdir()
        self.core = self.client_dir / "8021x.exe"
        self.core.write_bytes(b"synthetic core; never execute")
        self.mocked("backend.server.SESSION_TOKEN", new=TOKEN)
        self.discovery = self.mocked("backend.server.discover_client_dir", return_value=str(self.client_dir))
        self.start = self.mocked("backend.server.SupplicantManager.start_exe", return_value=True)
        self.load_hotspot = self.mocked("backend.server.HotspotManager.load_config", return_value={})
        self.save_hotspot = self.mocked("backend.server.HotspotManager.save_config")
        self.adapter_change = self.mocked("backend.server.NetworkAdapterManager.set_adapter_state", return_value=True)
        self.http = TestClient(server.app)
        self.addCleanup(self.http.close)
        self.authorization = {"Authorization": "Bearer " + TOKEN}

    def test_unauthorized_requests_are_rejected_before_config_reads_or_changes(self):
        for headers in ({}, {"Authorization": "Bearer wrong-synthetic-token"}):
            for method, url, body in (("GET", "/api/config/hotspot", None),
                                      ("PUT", "/api/config/hotspot", {"ssid": "Fake", "password": "FakePass9", "band": "2.4GHz"}),
                                      ("POST", "/api/adapter/Synthetic/disable", None),
                                      ("POST", "/api/process/start", {})):
                with self.subTest(method=method, url=url):
                    response = self.http.request(method, url, json=body, headers=headers)
                    self.assertEqual(response.status_code, 401)
        for mock in (self.load, self.save, self.load_hotspot, self.save_hotspot,
                     self.adapter_change, self.discovery, self.start):
            mock.assert_not_called()

    def test_missing_session_fails_closed_and_valid_health_is_not_cached_or_cross_origin(self):
        with patch("backend.server.SESSION_TOKEN", ""):
            self.assertEqual(self.http.get("/api/health").status_code, 503)
        response = self.http.get("/api/health", headers={**self.authorization, "Origin": "https://example.invalid"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_only_discovered_core_can_be_started_using_json_body(self):
        for payload in ({}, {"exe_path": str(self.core)}):
            with self.subTest(explicit=bool(payload)):
                self.start.reset_mock()
                response = self.http.post("/api/process/start", json=payload, headers=self.authorization)
                self.assertEqual(response.status_code, 200)
                self.start.assert_called_once_with(str(self.core.resolve()))

    def test_arbitrary_executables_and_query_only_requests_never_start_processes(self):
        for path in (self.root / "unrelated.exe", self.root / "another client" / "8021x.exe"):
            response = self.http.post("/api/process/start", json={"exe_path": str(path)}, headers=self.authorization)
            self.assertEqual(response.status_code, 400)
        response = self.http.post("/api/process/start", params={"exe_path": str(self.core)}, headers=self.authorization)
        self.assertEqual(response.status_code, 422)
        self.start.assert_not_called()

    def test_missing_installation_never_starts_processes(self):
        self.discovery.return_value = None
        self.assertEqual(self.http.post("/api/process/start", json={}, headers=self.authorization).status_code, 400)
        self.start.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Offline safety/flow regression tests. No real Windows operation is invoked."""

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch
from fixture_support import fixture_directory

from utils.campus_connection import (
    CampusConnectionConfig, CampusConnectionManager, WindowsOperations,
)


# Deliberately synthetic adapter identities; never copied from a host.
ETHERNET = "11111111-1111-4111-8111-111111111111"
WIFI = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
DISABLED = "11111111-2222-3333-4444-555555555555"


class FakeOperations:
    def __init__(self, root):
        self.root = root
        self.events = []
        self.authenticate = True
        self.on_start = None
        self.disable_error = False
        self.hotspot_ok = True

    def list_adapters(self):
        return [
            {"guid": ETHERNET, "name": "Ethernet", "enabled": True,
             "if_type": 6, "hardware_interface": True, "status": "Up"},
            {"guid": WIFI, "name": "Wi-Fi", "enabled": True},
            {"guid": DISABLED, "name": "Already disabled", "enabled": False},
        ]

    def set_adapter_enabled(self, guid, enabled):
        self.events.append(("adapter", guid, enabled))
        if not enabled and self.disable_error:
            raise RuntimeError("simulated disable failure")

    def start_client(self, path):
        self.events.append(("client", str(path)))
        if self.on_start:
            self.on_start()
        if self.authenticate:
            write_result(path.parent / "SupplicantResult.ini", "Succeed", time.time())

    def stop_exact_executable(self, path):
        self.events.append(("stop_exact", str(path)))
        return 1

    def start_hotspot(self, guid):
        self.events.append(("hotspot", guid))
        return self.hotspot_ok, "simulated hotspot error" if not self.hotspot_ok else ""


def write_result(path, result, timestamp):
    when = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    path.write_text(f"[Supplicant]\nResult={result}\nTime={when}\nUser=PRIVATE\n", encoding="utf-8")


class CampusConnectionTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, "campus-connection")
        self.install = self.root / "installed client"
        self.install.mkdir()
        self.client = self.install / "RuijieSupplicant.exe"
        self.client.write_bytes(b"fake client; never execute")
        self.component = self.install / "8021x.exe"
        self.component.write_bytes(b"fake component; never execute")
        self.config = CampusConnectionConfig(
            client_path=str(self.client), ethernet_guid=ETHERNET,
            disable_adapter_guids=[WIFI, DISABLED], auth_timeout=0.05,
        )
        self.operations = FakeOperations(self.root)
        self.logs = []
        self.manager = CampusConnectionManager(
            self.config, self.logs.append, data_dir=self.root / "data",
            operations=self.operations,
        )

    def test_success_restores_only_previously_enabled_adapters_before_hotspot(self):
        result = self.manager.connect()
        self.assertTrue(result.success, result.message)
        self.assertTrue(result.authenticated)
        self.assertTrue(result.hotspot_started)
        events = self.operations.events
        self.assertIn(("adapter", WIFI, False), events)
        self.assertIn(("adapter", WIFI, True), events)
        self.assertFalse(any(event[0] == "adapter" and event[1] in (ETHERNET, DISABLED) for event in events))
        self.assertLess(events.index(("adapter", WIFI, True)), events.index(("hotspot", ETHERNET)))
        self.assertFalse(self.component.exists())
        record = self.manager.recovery_status()["checker"]
        self.assertEqual(record["state"], "quarantined")
        self.assertEqual(Path(record["moved_to"]).read_bytes(), b"fake component; never execute")
        self.assertNotIn("PRIVATE", "\n".join(self.logs))

    def test_stale_success_is_rejected_and_adapter_restored(self):
        write_result(self.install / "SupplicantResult.ini", "Succeed", time.time() - 60)
        self.operations.authenticate = False
        result = self.manager.connect()
        self.assertFalse(result.success)
        self.assertFalse(result.authenticated)
        self.assertTrue(self.component.exists())
        self.assertIn(("adapter", WIFI, True), self.operations.events)
        self.assertFalse(any(event[0] in ("stop_exact", "hotspot") for event in self.operations.events))

    def test_touching_old_success_is_not_authentication(self):
        path = self.install / "SupplicantResult.ini"
        write_result(path, "Succeed", time.time())
        before = self.manager._snapshot(path)
        started = time.time()
        os.utime(path, (started + 0.1, started + 0.1))
        self.assertIsNone(self.manager._fresh_result(path, before, started))

    def test_future_status_is_rejected(self):
        path = self.install / "SupplicantResult.ini"
        started = time.time()
        write_result(path, "Succeed", started + 3600)
        self.assertIsNone(self.manager._fresh_result(path, None, started))

    def test_fresh_failure_does_not_quarantine_component(self):
        self.operations.authenticate = False
        self.operations.on_start = lambda: write_result(
            self.install / "SupplicantResult.ini", "Failed", time.time()
        )
        result = self.manager.connect()
        self.assertFalse(result.success)
        self.assertFalse(result.authenticated)
        self.assertTrue(self.component.exists())
        self.assertIn(("adapter", WIFI, True), self.operations.events)

    def test_disable_failure_still_runs_recorded_recovery(self):
        self.operations.disable_error = True
        result = self.manager.connect()
        self.assertFalse(result.success)
        self.assertEqual(self.operations.events, [("adapter", WIFI, False), ("adapter", WIFI, True)])
        self.assertEqual(self.manager.recovery_status()["adapters"], [])

    def test_cannot_disable_authentication_ethernet(self):
        self.config.disable_adapter_guids = [ETHERNET]
        result = self.manager.connect()
        self.assertFalse(result.success)
        self.assertEqual(self.operations.events, [])

    def test_cancel_restores_adapters_without_stopping_client(self):
        cancel = threading.Event()
        self.operations.authenticate = False
        self.operations.on_start = cancel.set
        result = self.manager.connect(cancel)
        self.assertFalse(result.success)
        self.assertTrue(self.component.exists())
        self.assertIn(("adapter", WIFI, True), self.operations.events)
        self.assertFalse(any(event[0] == "stop_exact" for event in self.operations.events))

    def test_restore_checks_hash_and_does_not_overwrite(self):
        self.assertTrue(self.manager.connect().success)
        record = self.manager.recovery_status()["checker"]
        moved = Path(record["moved_to"])
        self.component.write_bytes(b"another file")
        with self.assertRaisesRegex(RuntimeError, "不同文件"):
            self.manager.restore_checker()
        self.assertEqual(self.component.read_bytes(), b"another file")
        self.assertTrue(moved.exists())

    def test_restore_and_next_login_restore_before_launch(self):
        self.assertTrue(self.manager.connect().success)
        self.assertFalse(self.component.exists())
        self.operations.on_start = lambda: self.assertTrue(self.component.exists())
        # Give the next result different contents even if two logins share a second.
        (self.install / "SupplicantResult.ini").unlink()
        self.assertTrue(self.manager.connect().success)
        self.manager.restore_checker()
        self.assertEqual(self.component.read_bytes(), b"fake component; never execute")

    def test_existing_legacy_moved_record_is_imported_and_restored(self):
        destination = self.root / "legacy backup" / "8021x.exe"
        destination.parent.mkdir()
        self.component.rename(destination)
        self.manager.data_dir.mkdir()
        (self.manager.data_dir / "config.json").write_text(json.dumps({"move_record": {
            "action": "kill_and_move", "original_path": str(self.component),
            "moved_to": str(destination),
        }}), encoding="utf-8")
        self.operations.on_start = lambda: self.assertTrue(self.component.exists())
        self.assertTrue(self.manager.connect().success)
        self.assertFalse(destination.exists())
        self.assertEqual(self.manager.recovery_status()["checker"]["state"], "quarantined")

    def test_missing_component_continues_with_warning(self):
        self.component.unlink()
        result = self.manager.connect()
        self.assertTrue(result.success)
        self.assertTrue(any("未找到" in warning for warning in result.warnings))
        self.assertFalse(any(event[0] == "stop_exact" for event in self.operations.events))

    def test_hotspot_failure_preserves_authentication_result(self):
        self.operations.hotspot_ok = False
        result = self.manager.connect()
        self.assertFalse(result.success)
        self.assertTrue(result.authenticated)
        self.assertFalse(result.hotspot_started)

    def test_move_never_overwrites_destination(self):
        destination = self.root / "existing"
        destination.write_bytes(b"keep me")
        digest = hashlib.sha256(self.component.read_bytes()).hexdigest()
        with self.assertRaises(FileExistsError):
            self.manager._move_no_overwrite(self.component, destination, digest)
        self.assertTrue(self.component.exists())
        self.assertEqual(destination.read_bytes(), b"keep me")

    def test_client_is_started_with_explicit_working_directory(self):
        with patch("utils.campus_connection.subprocess.Popen") as popen:
            WindowsOperations.start_client(self.client)
        self.assertEqual(popen.call_args.args[0], [str(self.client)])
        self.assertEqual(popen.call_args.kwargs["cwd"], str(self.install))
        self.assertFalse(popen.call_args.kwargs["shell"])

    def test_wireless_authentication_source_is_refused_before_changes(self):
        self.operations.list_adapters = lambda: [
            {"guid": ETHERNET, "name": "Wi-Fi", "enabled": True,
             "if_type": 71, "hardware_interface": True, "status": "Up"},
        ]
        result = self.manager.connect()
        self.assertFalse(result.success)
        self.assertEqual(self.operations.events, [])

    def test_disconnected_ethernet_times_out_without_disabling_other_adapters(self):
        self.operations.list_adapters = lambda: [
            {"guid": ETHERNET, "name": "Ethernet", "enabled": True,
             "if_type": 6, "hardware_interface": True, "status": "Disconnected"},
        ]
        result = self.manager.connect()
        self.assertFalse(result.success)
        self.assertEqual(self.operations.events, [])

    def test_recovery_record_is_saved_before_stopping_component(self):
        def stop(path):
            record = self.manager.recovery_status()["checker"]
            self.assertEqual(record["state"], "planned")
            self.assertEqual(record["original_path"], str(self.component))
            self.assertEqual(record["sha256"], hashlib.sha256(self.component.read_bytes()).hexdigest())
            return 1
        self.operations.stop_exact_executable = stop
        self.assertTrue(self.manager.connect().success)

    def test_exact_process_path_only(self):
        selected = Mock(info={"exe": str(self.component)})
        other = Mock(info={"exe": str(self.root / "unrelated" / "8021x.exe")})
        class AccessDenied(Exception):
            pass
        class NoSuchProcess(Exception):
            pass
        fake = types.SimpleNamespace(
            process_iter=lambda attrs: [other, selected], wait_procs=lambda procs, timeout: (procs, []),
            AccessDenied=AccessDenied, NoSuchProcess=NoSuchProcess,
        )
        with patch.dict("sys.modules", {"psutil": fake}):
            self.assertEqual(WindowsOperations.stop_exact_executable(self.component), 1)
        selected.terminate.assert_called_once()
        other.terminate.assert_not_called()
        other.kill.assert_not_called()
        selected.terminate.side_effect = AccessDenied()
        with patch.dict("sys.modules", {"psutil": fake}):
            with self.assertRaisesRegex(RuntimeError, "无法结束"):
                WindowsOperations.stop_exact_executable(self.component)


if __name__ == "__main__":
    unittest.main()

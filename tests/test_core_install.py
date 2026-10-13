"""Isolated installer tests: fake executables, service API, and patch bytes only."""
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from fixture_support import fixture_directory

from utils.core_install import CoreInstaller, InstallOperations, ServiceStopRejected
from types import SimpleNamespace


ORIGINAL = b"test-only original binary, never execute"
PATCHED = b"test-only patched binary, never execute"
ORIGINAL_HASH = hashlib.sha256(ORIGINAL).hexdigest()


def fake_patch(data):
    if data != ORIGINAL:
        raise ValueError("wrong original version")
    return PATCHED, {"original_sha256": ORIGINAL_HASH,
                     "patched_sha256": hashlib.sha256(PATCHED).hexdigest(), "patches": []}


class FakeOperations:
    def __init__(self, client_dir):
        self.snapshot = {"name": "RJSuService", "state": "RUNNING", "start_type": 2,
                         "delayed_auto_start": True, "pid": 123,
                         "image_path": '"' + str(client_dir / "suservice.exe") + '"'}
        self.process_path = str(client_dir / "suservice.exe")
        self.events = []
        self.refuse_stop = False
        self.other_paths = []
        self.start_failures = 0
        self.stop_observer = None

    def service_snapshot(self):
        return dict(self.snapshot)

    def other_core_paths(self, target):
        return list(self.other_paths)

    def stop_service(self):
        if self.stop_observer:
            self.stop_observer()
        self.events.append(("stop_service",))
        if self.refuse_stop:
            raise ServiceStopRejected("test-only refusal")
        self.snapshot.update(state="STOPPED", pid=0)

    def start_service(self):
        self.events.append(("start_service",))
        if self.start_failures:
            self.start_failures -= 1
            raise RuntimeError("test-only start failure")
        self.snapshot.update(state="RUNNING", pid=456)

    def set_service_start_type(self, value, delayed=False):
        self.events.append(("start_type", value, delayed))
        self.snapshot.update(start_type=value, delayed_auto_start=delayed)

    def process_executable(self, pid):
        self.events.append(("inspect_pid", pid))
        return self.process_path

    def terminate_service_pid(self, pid, expected):
        self.events.append(("terminate_service_pid", pid, str(expected)))
        self.snapshot.update(state="STOPPED", pid=0)

    def stop_exact_core(self, target):
        self.events.append(("stop_exact_core", str(target)))


class CoreInstallTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, "core-install")
        self.client_dir = self.root / "fake installed client"
        self.client_dir.mkdir()
        self.target = self.client_dir / "8021x.exe"
        self.target.write_bytes(ORIGINAL)
        (self.client_dir / "suservice.exe").write_bytes(b"not executable")
        self.patches = [patch("utils.core_install.core_patch.ORIGINAL_SHA256", ORIGINAL_HASH),
                        patch("utils.core_install.core_patch.patch_bytes", fake_patch)]
        for mocked in self.patches:
            mocked.start()
            self.addCleanup(mocked.stop)
        self.ops = FakeOperations(self.client_dir)
        self.installer = CoreInstaller(self.client_dir, self.root / "backup", self.ops)

    def test_status_is_read_only_and_known_original(self):
        self.assertEqual(self.installer.status()["state"], "original")
        self.assertFalse(self.installer.data_dir.exists())
        self.assertEqual(self.ops.events, [])

    def test_install_backs_up_and_journals_before_any_service_change(self):
        def observe():
            self.assertEqual(self.installer.backup_path.read_bytes(), ORIGINAL)
            journal = json.loads(self.installer.journal_path.read_text(encoding="utf-8"))
            self.assertEqual(journal["phase"], "prepared")
            self.assertEqual(journal["service_before"]["pid"], 123)
        self.ops.stop_observer = observe
        result = self.installer.install()
        self.assertTrue(result["success"])
        self.assertEqual(self.target.read_bytes(), PATCHED)
        self.assertEqual(self.installer.status()["state"], "patched")
        self.assertEqual(self.ops.snapshot["state"], "RUNNING")
        self.assertEqual(self.ops.snapshot["start_type"], 2)
        self.assertTrue(self.ops.snapshot["delayed_auto_start"])
        self.assertIn(("stop_exact_core", str(self.target)), self.ops.events)

    def test_restore_returns_exact_original_and_preserves_backup(self):
        self.installer.install()
        self.installer.restore()
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.installer.backup_path.read_bytes(), ORIGINAL)
        self.assertEqual(self.installer.status()["state"], "original")

    def test_second_install_is_noop(self):
        self.installer.install()
        self.ops.events.clear()
        self.installer.install()
        self.assertEqual(self.ops.events, [])

    def test_unknown_core_is_never_overwritten(self):
        self.target.write_bytes(b"unknown version")
        self.assertEqual(self.installer.status()["state"], "unknown")
        with self.assertRaises(ValueError):
            self.installer.install()
        self.assertEqual(self.target.read_bytes(), b"unknown version")
        self.assertEqual(self.ops.events, [])

    def test_restore_rejects_modified_installed_core(self):
        self.installer.install()
        self.target.write_bytes(b"third-party changed file")
        self.ops.events.clear()
        with self.assertRaisesRegex(RuntimeError, "拒绝覆盖"):
            self.installer.restore()
        self.assertEqual(self.target.read_bytes(), b"third-party changed file")
        self.assertEqual(self.ops.events, [])

    def test_refused_stop_uses_only_verified_service_pid_and_restores_start_type(self):
        self.ops.refuse_stop = True
        self.installer.install()
        self.assertIn(("start_type", 4, False), self.ops.events)
        self.assertIn(("inspect_pid", 123), self.ops.events)
        self.assertIn(("terminate_service_pid", 123, str(self.client_dir / "suservice.exe")), self.ops.events)
        self.assertEqual(self.ops.snapshot["state"], "RUNNING")
        self.assertEqual(self.ops.snapshot["start_type"], 2)
        self.assertTrue(self.ops.snapshot["delayed_auto_start"])

    def test_pid_path_mismatch_aborts_and_restores_configuration(self):
        self.ops.refuse_stop = True
        self.ops.process_path = str(self.root / "unrelated" / "suservice.exe")
        with self.assertRaisesRegex(RuntimeError, "路径核验失败"):
            self.installer.install()
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.ops.snapshot["state"], "RUNNING")
        self.assertEqual(self.ops.snapshot["start_type"], 2)
        self.assertFalse(any(event[0] == "terminate_service_pid" for event in self.ops.events))

    def test_registered_service_path_mismatch_aborts_before_stop(self):
        self.ops.snapshot["image_path"] = str(self.root / "unrelated" / "suservice.exe")
        with self.assertRaisesRegex(RuntimeError, "服务注册路径"):
            self.installer.install()
        self.assertEqual(self.ops.events, [])
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_other_directory_core_is_not_terminated(self):
        self.ops.other_paths = [str(self.root / "unrelated" / "8021x.exe")]
        with self.assertRaisesRegex(RuntimeError, "其他目录"):
            self.installer.install()
        self.assertEqual(self.ops.events, [])

    def test_write_failure_restores_service_and_original(self):
        original_write = self.installer._atomic_write
        def fail_core_write(path, data):
            if path == self.target:
                raise OSError("test-only replace failure")
            original_write(path, data)
        with patch.object(self.installer, "_atomic_write", fail_core_write):
            with self.assertRaisesRegex(RuntimeError, "replace failure"):
                self.installer.install()
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.ops.snapshot["state"], "RUNNING")
        self.assertEqual(self.installer._journal()["phase"], "rolled_back")

    def test_start_failure_rolls_file_back_and_retries_service_recovery(self):
        self.ops.start_failures = 1
        with self.assertRaisesRegex(RuntimeError, "start failure"):
            self.installer.install()
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.ops.snapshot["state"], "RUNNING")
        self.assertEqual(self.installer._journal()["phase"], "rolled_back")

    def test_previously_stopped_service_stays_stopped(self):
        self.ops.snapshot.update(state="STOPPED", pid=0, start_type=3, delayed_auto_start=False)
        self.installer.install()
        self.assertEqual(self.ops.snapshot["state"], "STOPPED")
        self.assertEqual(self.ops.snapshot["start_type"], 3)
        self.assertFalse(any(event[0] in ("start_service", "stop_service", "terminate_service_pid") for event in self.ops.events))

    def test_corrupt_backup_is_never_replaced(self):
        self.installer.data_dir.mkdir()
        self.installer.backup_path.write_bytes(b"unexpected backup content")
        with self.assertRaises(ValueError):
            self.installer.install()
        self.assertEqual(self.installer.backup_path.read_bytes(), b"unexpected backup content")
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.ops.events, [])

    def test_interrupted_fallback_restores_remembered_service_settings(self):
        self.installer.data_dir.mkdir()
        self.installer.backup_path.write_bytes(ORIGINAL)
        remembered = self.ops.service_snapshot()
        self.ops.snapshot.update(state="STOPPED", pid=0, start_type=4, delayed_auto_start=False)
        self.installer._save_journal({"version": 1, "target": str(self.target),
                                      "phase": "service_temporarily_disabled", "service_before": remembered})
        self.installer.install()
        self.assertEqual(self.ops.snapshot["state"], "RUNNING")
        self.assertEqual(self.ops.snapshot["start_type"], 2)
        self.assertTrue(self.ops.snapshot["delayed_auto_start"])

    def test_access_denied_does_not_authorize_fallback(self):
        native = InstallOperations()
        with patch.object(native, "_sc", return_value=SimpleNamespace(returncode=5)):
            with self.assertRaises(RuntimeError) as caught:
                native.stop_service()
        self.assertNotIsInstance(caught.exception, ServiceStopRejected)

    def test_scm_control_refusal_is_classified_for_fallback(self):
        native = InstallOperations()
        with patch.object(native, "_sc", return_value=SimpleNamespace(returncode=1052)):
            with self.assertRaises(ServiceStopRejected):
                native.stop_service()

    def test_running_service_with_disabled_start_setting_is_preserved(self):
        self.ops.snapshot.update(start_type=4, delayed_auto_start=False)
        self.installer.install()
        self.assertEqual(self.ops.snapshot["state"], "RUNNING")
        self.assertEqual(self.ops.snapshot["start_type"], 4)

    def test_failure_after_service_restart_stops_before_file_rollback(self):
        save = self.installer._save_journal
        def fail_once(journal):
            if journal["phase"] == "complete":
                raise OSError("test-only final journal failure")
            save(journal)
        with patch.object(self.installer, "_save_journal", fail_once):
            with self.assertRaisesRegex(RuntimeError, "final journal failure"):
                self.installer.install()
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.ops.snapshot["state"], "RUNNING")
        self.assertEqual(sum(event[0] == "stop_service" for event in self.ops.events), 2)


if __name__ == "__main__":
    unittest.main()

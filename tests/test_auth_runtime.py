"""Authentication-session regression tests; no real processes or network calls."""
from pathlib import Path
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from utils import auth_runtime
from fixture_support import fixture_directory


# Deliberately synthetic adapter identity; never copied from a host.
GUID = "11111111-1111-4111-8111-111111111111"


class AuthRuntimeTests(unittest.TestCase):
    def mocked(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def setUp(self):
        self.client_dir = fixture_directory(self, "auth-runtime") / "mock-client"
        self.core = self.client_dir / "8021x.exe"
        self.processes = self.mocked("utils.auth_runtime.psutil.process_iter", return_value=[])
        # Every process boundary is replaced before the functions under test run.
        self.spawn = self.mocked("utils.auth_runtime.subprocess.Popen")
        self.mocked("utils.auth_runtime.subprocess.run",
                    side_effect=AssertionError("Real commands are forbidden in offline tests"))
        self.sleep = self.mocked("utils.auth_runtime.time.sleep")
        self.session = auth_runtime.CoreSession(pid=1234, created_at=200.25)
        self.cancel = Mock()
        self.cancel.is_set.return_value = False
        self.cancel.wait.return_value = False

    def process(self, path=None, pid=1234, created_at=200.25):
        return SimpleNamespace(pid=pid, info={
            "name": "8021x.exe", "exe": str(path or self.core),
            "create_time": created_at,
        })

    def test_immediate_exit_is_not_reported_as_running(self):
        self.processes.side_effect = [[], []]
        self.spawn.return_value.poll.return_value = 7
        messages = []

        with self.assertRaisesRegex(RuntimeError, "启动后退出"):
            auth_runtime.start_core(self.client_dir, messages.append)

        self.spawn.assert_called_once()
        self.spawn.return_value.poll.assert_called_once()
        self.assertEqual(messages, [])

    def test_another_directory_core_is_rejected_before_launch(self):
        other = self.client_dir.parent / "another-client" / "8021x.exe"
        self.processes.return_value = [self.process(path=other)]

        with self.assertRaisesRegex(RuntimeError, "另一目录"):
            auth_runtime.start_core(self.client_dir)

        self.spawn.assert_not_called()
        self.sleep.assert_not_called()

    def test_live_exact_path_session_is_reused_without_restart(self):
        self.processes.return_value = [self.process()]

        self.assertEqual(auth_runtime.start_core(self.client_dir), self.session)

        self.spawn.assert_not_called()
        self.sleep.assert_not_called()
        self.processes.cache_clear.assert_called_once()

    def test_two_matching_core_processes_are_ambiguous(self):
        self.processes.return_value = [self.process(), self.process(pid=5678, created_at=201.0)]
        with self.assertRaisesRegex(RuntimeError, "多个认证核心"):
            auth_runtime.start_core(self.client_dir)
        self.spawn.assert_not_called()

    def test_new_session_is_returned_only_when_core_survives(self):
        self.processes.side_effect = [[], [self.process()]]

        self.assertEqual(auth_runtime.start_core(self.client_dir), self.session)

        self.spawn.assert_called_once()
        self.sleep.assert_called_once()

    def test_replaced_or_exited_session_cannot_reuse_success(self):
        # Creation time is checked as well as PID, including Windows PID reuse.
        replacements = [None,
                        auth_runtime.CoreSession(pid=5678, created_at=201.0),
                        auth_runtime.CoreSession(pid=1234, created_at=201.0)]
        with patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", return_value=True) as fresh:
            for replacement in replacements:
                with self.subTest(active=replacement), \
                     patch.object(auth_runtime, "_running_core", return_value=replacement):
                    with self.assertRaisesRegex(RuntimeError, "已退出或被替换"):
                        auth_runtime.wait_authentication(
                            self.client_dir, None, 190.0, self.cancel, session=self.session)
            fresh.assert_not_called()
        self.spawn.assert_not_called()

    def test_pre_session_mtime_is_rejected_even_when_result_says_success(self):
        # The old client wrote Succeed after the GUI started but before it was
        # stopped for installation. Its timestamp cannot authenticate a new PID.
        old_status = SimpleNamespace(st_mtime_ns=200_000_000_000)
        with patch.object(auth_runtime, "_running_core", return_value=self.session), \
             patch.object(Path, "stat", return_value=old_status), \
             patch.object(auth_runtime.time, "monotonic", side_effect=[0.0, 0.0, 121.0]), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", return_value=True) as fresh:
            self.assertFalse(auth_runtime.wait_authentication(
                self.client_dir, None, 190.0, self.cancel, session=self.session))
            fresh.assert_not_called()
        self.cancel.wait.assert_called_once()
        self.spawn.assert_not_called()

    def test_current_session_fresh_success_is_accepted(self):
        status = SimpleNamespace(st_mtime_ns=201_000_000_000)
        baseline = (190_000_000_000, 20, "old-result-hash")
        with patch.object(auth_runtime, "_running_core", return_value=self.session), \
             patch.object(Path, "stat", return_value=status), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", return_value=True) as fresh:
            self.assertTrue(auth_runtime.wait_authentication(
                self.client_dir, baseline, 190.0, self.cancel, session=self.session))
            fresh.assert_called_once_with(self.client_dir / "SupplicantResult.ini",
                                          baseline, self.session.created_at)
        self.spawn.assert_not_called()

    def test_cancellation_does_not_check_or_launch_any_process(self):
        self.cancel.is_set.return_value = True
        with patch.object(auth_runtime, "_running_core") as active, \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result") as fresh:
            self.assertFalse(auth_runtime.wait_authentication(
                self.client_dir, None, 190.0, self.cancel, session=self.session))
            active.assert_not_called()
            fresh.assert_not_called()
        self.spawn.assert_not_called()

    def test_temporary_failure_then_fresh_success_waits_without_restarting(self):
        status = SimpleNamespace(st_mtime_ns=301_000_000_000)
        baseline = (300_000_000_000, 20, "old-result-hash")
        with patch.object(auth_runtime.time, "monotonic", side_effect=[0, 0, 0.5]), \
             patch.object(auth_runtime, "_running_core", return_value=self.session) as active, \
             patch.object(Path, "stat", return_value=status), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", side_effect=[False, True]) as fresh, \
             patch.object(auth_runtime, "result_snapshot") as history, \
             patch.object(auth_runtime, "_ethernet_has_internet") as connectivity:
            self.assertTrue(auth_runtime.wait_authentication(
                self.client_dir, baseline, 300.0, self.cancel, session=self.session,
                ethernet_adapter_guid=GUID))
            self.assertEqual(fresh.call_count, 2)
            self.assertEqual(active.call_count, 2)
            history.assert_not_called()
            connectivity.assert_not_called()
        self.cancel.wait.assert_called_once_with(0.5)
        self.spawn.assert_not_called()

    def test_persistent_fresh_failure_waits_until_timeout(self):
        status = SimpleNamespace(st_mtime_ns=301_000_000_000)
        with patch.object(auth_runtime.time, "monotonic", side_effect=[0, 0, 0.5, 1.0, 1.5, 2.0]), \
             patch.object(auth_runtime, "_running_core", return_value=self.session) as active, \
             patch.object(Path, "stat", return_value=status), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", return_value=False) as fresh:
            self.assertFalse(auth_runtime.wait_authentication(
                self.client_dir, None, 300.0, self.cancel, timeout=2, session=self.session))
            self.assertEqual(fresh.call_count, 4)
            self.assertEqual(active.call_count, 4)
        self.assertEqual(self.cancel.wait.call_count, 4)
        self.spawn.assert_not_called()

    def test_cancellation_after_temporary_failure_stops_waiting(self):
        status = SimpleNamespace(st_mtime_ns=301_000_000_000)
        self.cancel.is_set.side_effect = [False, True]
        with patch.object(auth_runtime.time, "monotonic", side_effect=[0, 0, 0.5]), \
             patch.object(auth_runtime, "_running_core", return_value=self.session) as active, \
             patch.object(Path, "stat", return_value=status), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", side_effect=[False, True]) as fresh:
            self.assertFalse(auth_runtime.wait_authentication(
                self.client_dir, None, 300.0, self.cancel, session=self.session))
            fresh.assert_called_once()
            active.assert_called_once()
        self.cancel.wait.assert_called_once_with(0.5)
        self.spawn.assert_not_called()

    def test_failure_then_missing_result_cannot_reuse_historical_success(self):
        status = SimpleNamespace(st_mtime_ns=301_000_000_000)
        with patch.object(auth_runtime.time, "monotonic", side_effect=[0, 0, 0.5, 1.0]), \
             patch.object(auth_runtime, "_running_core", return_value=self.session), \
             patch.object(Path, "stat", return_value=status), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", side_effect=[False, None]) as fresh, \
             patch.object(auth_runtime, "result_snapshot") as history, \
             patch.object(auth_runtime, "_ethernet_has_internet") as connectivity:
            self.assertFalse(auth_runtime.wait_authentication(
                self.client_dir, None, 300.0, self.cancel, timeout=1, session=self.session,
                ethernet_adapter_guid=GUID))
            self.assertEqual(fresh.call_count, 2)
            history.assert_not_called()
            connectivity.assert_not_called()
        self.spawn.assert_not_called()

    def test_session_replaced_after_failure_is_rejected_before_later_success(self):
        status = SimpleNamespace(st_mtime_ns=301_000_000_000)
        replacement = auth_runtime.CoreSession(self.session.pid, 300.0)
        with patch.object(auth_runtime.time, "monotonic", side_effect=[0, 0, 0.5]), \
             patch.object(auth_runtime, "_running_core", side_effect=[self.session, replacement]), \
             patch.object(Path, "stat", return_value=status), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", side_effect=[False, True]) as fresh:
            with self.assertRaisesRegex(RuntimeError, "已退出或被替换"):
                auth_runtime.wait_authentication(
                    self.client_dir, None, 300.0, self.cancel, session=self.session)
            fresh.assert_called_once()
        self.spawn.assert_not_called()

    def wait_with_existing_success(self, *, online=True, changed_session=False, changed_result=False):
        """An already authenticated service predates the GUI by a minute."""
        candidate = (220_000_000_000, 60, "this-session-success")
        status = SimpleNamespace(st_mtime_ns=candidate[0])
        sessions = [self.session, auth_runtime.CoreSession(5678, 301.0)] if changed_session else None
        snapshots = [candidate, candidate, (301_000_000_000, 60, "failure")] if changed_result else None
        # deadline, first loop, profile due, next profile, second loop expires
        with patch.object(auth_runtime.time, "monotonic", side_effect=[0, 0, 0, 0, 121]), \
             patch.object(auth_runtime, "_running_core", return_value=self.session, side_effect=sessions), \
             patch.object(Path, "stat", return_value=status), \
             patch.object(auth_runtime, "result_snapshot", return_value=candidate, side_effect=snapshots), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", side_effect=[None, True]) as fresh, \
             patch.object(auth_runtime, "_ethernet_has_internet", return_value=online) as connectivity:
            result = auth_runtime.wait_authentication(
                self.client_dir, candidate, 300.0, self.cancel, session=self.session,
                ethernet_adapter_guid=GUID)
            fresh.assert_any_call(self.client_dir / "SupplicantResult.ini", None, self.session.created_at)
            connectivity.assert_called_once_with(GUID)
            return result

    def test_existing_same_session_success_and_selected_ethernet_online_is_accepted(self):
        self.assertTrue(self.wait_with_existing_success())
        self.spawn.assert_not_called()

    def test_stale_success_after_ethernet_disconnect_is_not_accepted(self):
        self.assertFalse(self.wait_with_existing_success(online=False))

    def test_core_replacement_during_connectivity_check_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "已退出或被替换"):
            self.wait_with_existing_success(changed_session=True)

    def test_result_change_during_connectivity_check_is_not_accepted(self):
        self.assertFalse(self.wait_with_existing_success(changed_result=True))

    def test_old_result_timestamp_cannot_be_rescued_by_online_ethernet(self):
        candidate = (220_000_000_000, 60, "prior-session-success")
        with patch.object(auth_runtime.time, "monotonic", side_effect=[0, 0, 121]), \
             patch.object(auth_runtime, "_running_core", return_value=self.session), \
             patch.object(Path, "stat", return_value=SimpleNamespace(st_mtime_ns=candidate[0])), \
             patch.object(auth_runtime, "result_snapshot", return_value=candidate), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", return_value=None), \
             patch.object(auth_runtime, "_ethernet_has_internet") as connectivity:
            self.assertFalse(auth_runtime.wait_authentication(
                self.client_dir, candidate, 300.0, self.cancel, session=self.session,
                ethernet_adapter_guid=GUID))
            connectivity.assert_not_called()

    def test_connectivity_uses_selected_profile_and_unknown_is_not_online(self):
        with patch.object(auth_runtime.subprocess, "run") as command:
            command.return_value = SimpleNamespace(returncode=0, stdout='{"online":true}')
            self.assertTrue(auth_runtime._ethernet_has_internet(GUID))
            self.assertEqual(json.loads(command.call_args.kwargs["input"])["guid"], GUID.lower())
            command.return_value = SimpleNamespace(returncode=0, stdout='{"online":null}')
            self.assertFalse(auth_runtime._ethernet_has_internet(GUID))
            command.return_value = SimpleNamespace(returncode=1, stdout='{"online":true}')
            self.assertFalse(auth_runtime._ethernet_has_internet(GUID))
        self.assertNotIn("GetInternetConnectionProfile", auth_runtime._ETHERNET_INTERNET_SCRIPT)
        self.assertIn("NetworkAdapterId -eq $wanted", auth_runtime._ETHERNET_INTERNET_SCRIPT)


if __name__ == "__main__":
    unittest.main()

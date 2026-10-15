"""Authentication-session regression tests; no real processes or network calls."""
from pathlib import Path
from contextlib import contextmanager, ExitStack
from datetime import datetime
import itertools
import json
import os
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

    @contextmanager
    def log_observations(self, events, *, results=(None,), result_times=(None,), missing=False,
                         sessions=None):
        """Drive real wait logic with incremental observer states, never host logs.

        A poll retains its last complete notification until another record arrives;
        setting event_time with each poll models the actual observer contract.
        """
        def retain_last(values):
            values = list(values)
            return itertools.chain(values, itertools.repeat(values[-1]))

        event_sequence = retain_last(events)
        observer = Mock(spec=auth_runtime.AuthLogObserver)
        observer.event_time = None

        def poll():
            state, observer.event_time = next(event_sequence)
            return state

        observer.poll.side_effect = poll
        baseline = object()
        with ExitStack() as stack:
            constructor = stack.enter_context(patch.object(
                auth_runtime, "AuthLogObserver", return_value=observer))
            stack.enter_context(patch.object(auth_runtime.time, "monotonic",
                                            side_effect=itertools.count(0, .5)))
            active = stack.enter_context(patch.object(auth_runtime, "_running_core",
                side_effect=retain_last(sessions or [self.session])))
            stack.enter_context(patch.object(Path, "stat",
                side_effect=FileNotFoundError if missing else None,
                return_value=SimpleNamespace(st_mtime_ns=301_000_000_000)))
            fresh = stack.enter_context(patch.object(auth_runtime.CampusConnectionManager,
                "_fresh_result", side_effect=retain_last(results)))
            timestamp = stack.enter_context(patch.object(auth_runtime, "_result_event_time",
                side_effect=retain_last(result_times)))
            connectivity = stack.enter_context(patch.object(auth_runtime, "_ethernet_has_internet"))
            yield SimpleNamespace(observer=observer, constructor=constructor, active=active,
                fresh=fresh, timestamp=timestamp, connectivity=connectivity,
                wait=lambda: auth_runtime.wait_authentication(
                    self.client_dir, None, 300.0, self.cancel, timeout=2,
                    session=self.session, log_before=baseline), baseline=baseline)
        self.spawn.assert_not_called()

    def test_new_log_success_accepts_empty_or_missing_ini_for_same_session(self):
        for missing in (False, True):
            with self.subTest(missing=missing), self.log_observations(
                    [(True, 301.0)], missing=missing) as case:
                self.assertTrue(case.wait())
                case.constructor.assert_called_once_with(
                    self.client_dir, case.baseline, 300.0, pid=self.session.pid)
                self.assertEqual(case.observer.poll.call_count, 2)
                self.assertEqual(case.active.call_count, 2)
                case.connectivity.assert_not_called()

    def test_log_failure_then_new_success_with_empty_ini_does_not_restart_core(self):
        with self.log_observations([(False, 301.0), (True, 302.0)]) as case:
            self.assertTrue(case.wait())
            self.assertEqual(case.observer.poll.call_count, 3)
            self.cancel.wait.assert_called_once_with(.5)
            case.connectivity.assert_not_called()

    def test_no_new_log_notification_times_out_without_reusing_old_success(self):
        with self.log_observations([(None, None)]) as case:
            self.assertFalse(case.wait())
            self.assertEqual(case.observer.poll.call_count, 3)
            self.assertEqual(self.cancel.wait.call_count, 3)
            case.connectivity.assert_not_called()

    def test_conflicting_sources_require_success_newer_than_failure(self):
        cases = (
            # INI, its timestamp, native notification, timestamp, expected.
            (True, 301.0, False, 302.0, False),
            (True, 302.0, False, 302.0, False),
            (True, 303.0, False, 302.0, True),
            (False, 302.0, True, 301.0, False),
            (False, 302.0, True, 302.0, False),
            (False, 301.0, True, 303.0, True),
            # An unreadable failure time cannot prove ordering.
            (False, None, True, 303.0, False),
        )
        for result, result_time, event, event_time, expected in cases:
            with self.subTest(ini=result, ini_time=result_time, log=event,
                              log_time=event_time), self.log_observations(
                    [(event, event_time)], results=[result], result_times=[result_time]) as case:
                self.assertIs(case.wait(), expected)
                case.connectivity.assert_not_called()

    def test_disappearing_ini_failure_cannot_be_rescued_by_older_log_success(self):
        with self.log_observations([(None, None), (True, 301.0)],
                                  results=[False, None], result_times=[302.0]) as case:
            self.assertFalse(case.wait())

    def test_later_log_success_can_follow_a_now_missing_ini_failure(self):
        with self.log_observations([(None, None), (True, 304.0)],
                                  results=[False, None], result_times=[302.0]) as case:
            self.assertTrue(case.wait())

    def test_core_replacement_during_log_success_verification_is_rejected(self):
        replacement = auth_runtime.CoreSession(self.session.pid, 301.5)
        with self.log_observations([(True, 301.0)],
                                  sessions=[self.session, replacement]) as case:
            with self.assertRaisesRegex(RuntimeError, "已退出或被替换"):
                case.wait()
            case.observer.poll.assert_called_once()

    def test_cancel_between_log_success_and_verification_returns_false(self):
        self.cancel.is_set.side_effect = [False, True]
        with self.log_observations([(True, 301.0)]) as case:
            self.assertFalse(case.wait())
            case.observer.poll.assert_called_once()
            case.active.assert_called_once()

    def test_logoff_appended_during_final_verification_rejects_success(self):
        with self.log_observations([(True, 301.0), (False, 302.0)]) as case:
            self.assertFalse(case.wait())
            self.assertGreaterEqual(case.observer.poll.call_count, 2)

    def test_new_ini_failure_during_final_log_verification_rejects_success(self):
        with self.log_observations([(True, 301.0)],
                                  results=[None, False], result_times=[302.0]) as case:
            self.assertFalse(case.wait())
            self.assertGreaterEqual(case.fresh.call_count, 2)

    def test_lost_log_continuity_during_final_verification_rejects_success(self):
        with self.log_observations([(True, 301.0), (None, None)]) as case:
            self.assertFalse(case.wait())

    def test_lost_log_continuity_cannot_revive_ini_success_older_than_seen_log_failure(self):
        with self.log_observations([(False, 302.0), (None, None)],
                                  results=[True], result_times=[301.0]) as case:
            self.assertFalse(case.wait())

    def test_new_ini_success_can_follow_seen_log_failure_after_log_continuity_loss(self):
        with self.log_observations([(False, 302.0), (None, None)],
                                  results=[True], result_times=[301.0, 303.0]) as case:
            self.assertTrue(case.wait())
            self.cancel.wait.assert_called_once_with(.5)

    def test_ini_rewrite_cannot_combine_old_success_with_new_failure_timestamp(self):
        # Native Result.ini can be rewritten between the status read and source
        # arbitration. Exercise actual bytes, hashes and times in a temp folder.
        self.client_dir.mkdir()
        path = self.client_dir / "SupplicantResult.ini"
        started = datetime(2025, 1, 2, 12, 0, 0).timestamp()

        def write_result(result, timestamp):
            date = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
            path.write_text(f"[Supplicant]\nResult={result}\nTime={date}\n", encoding="utf-8")
            os.utime(path, (timestamp, timestamp))

        write_result("Succeed", started + 1)
        self.assertIs(auth_runtime.CampusConnectionManager._fresh_result(path, None, started), True)
        observer = Mock(spec=auth_runtime.AuthLogObserver)
        observer.event_time = started + 2

        def poll():
            write_result("Failed", started + 3)
            return False

        observer.poll.side_effect = poll
        with patch.object(auth_runtime, "AuthLogObserver", return_value=observer), \
             patch.object(auth_runtime, "_running_core", return_value=self.session), \
             patch.object(auth_runtime.time, "monotonic", side_effect=itertools.count(0, .5)):
            self.assertFalse(auth_runtime.wait_authentication(
                self.client_dir, None, started, self.cancel, timeout=2,
                session=self.session, log_before=object()))
        self.spawn.assert_not_called()

    def test_log_notifications_are_not_used_without_a_core_session(self):
        with patch.object(auth_runtime, "AuthLogObserver") as observer, \
             patch.object(auth_runtime.time, "monotonic", side_effect=[0, 0, 3]), \
             patch.object(auth_runtime.CampusConnectionManager, "_fresh_result", return_value=None):
            self.assertFalse(auth_runtime.wait_authentication(
                self.client_dir, None, 300.0, self.cancel, timeout=2, log_before=object()))
            observer.assert_not_called()

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

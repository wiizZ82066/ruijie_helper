"""Synthetic append-only native logs; no host logs, credentials, or processes."""
from datetime import datetime
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from fixture_support import fixture_directory
from utils import auth_log


SUCCESS = "CSupplicantDlg::OnNotifyAuthResult AUTH_SUCCESS"
LOGOFF = "CSupplicantDlg::OnNotifyAuthResult AUTH_ALREADY_LOGOFF"
FAILURE = ("CSupplicantDlg::OnAuthenticateFail : the m_bHasStartAuth =1"
           " and set it false,the m_authSuccess= 0 set false")
DISCONNECT = ("CSupplicantDlg::OnDisconnect : the m_bHasStartAuth =1"
              " and set false,the m_authSuccess= 1 set it false")


class AuthLogTests(unittest.TestCase):
    def setUp(self):
        self.directory = fixture_directory(self, "auth-log")
        self.logs = self.directory / "logs"
        self.logs.mkdir()
        self.ui = self.logs / "ui.log"
        self.eap = self.logs / "eappeap.log"
        self.now = datetime(2025, 1, 2, 12, 30, 10).timestamp()
        self.started = self.now - 5.25
        self.pid = 12345
        self.tid = 67890
        self.thread_owner = Mock(side_effect=lambda tid: self.pid if tid == self.tid else self.pid + 1)
        self.clock = patch.object(auth_log.time, "time", return_value=self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def line(self, message=SUCCESS, *, when=None, tid=None):
        date = datetime.fromtimestamp(self.now if when is None else when).strftime("%Y-%m-%d %H:%M:%S")
        return (f"[{date}][T:123][P:{self.tid if tid is None else tid}][info]:"
                f"{message}\r\n").encode("ascii")

    def observer(self, baseline=None, *, pid=None):
        return auth_log.AuthLogObserver(self.directory,
            baseline if baseline is not None else auth_log.capture_auth_log(self.directory),
            self.started, pid=self.pid if pid is None else pid, thread_owner=self.thread_owner)

    def append(self, path, content):
        with path.open("ab") as stream:
            stream.write(content)

    def test_existing_success_is_never_reused_even_when_timestamp_and_pid_match(self):
        self.eap.write_bytes(self.line())
        observer = self.observer()
        self.assertIsNone(observer.poll())
        self.assertIsNone(observer.event_time)

    def test_new_exact_success_with_same_pid_has_timestamp_and_persists(self):
        self.eap.write_bytes(b"synthetic pre-start history\r\n")
        observer = self.observer()
        self.append(self.eap, self.line())
        self.assertIs(observer.poll(), True)
        self.assertEqual(observer.event_time, self.now)
        self.assertIs(observer.poll(), True)

    def test_header_p_is_a_thread_owned_by_pid_not_the_process_id_itself(self):
        self.assertNotEqual(self.pid, self.tid)
        observer = self.observer()
        self.append(self.eap, self.line())
        self.assertIs(observer.poll(), True)
        self.thread_owner.assert_called_with(self.tid)

    def test_unknown_thread_cannot_establish_success_but_verified_exited_thread_can_revoke(self):
        observer = self.observer()
        self.thread_owner.side_effect = None
        self.thread_owner.return_value = None
        self.append(self.eap, self.line())
        self.assertIsNone(observer.poll())
        self.thread_owner.return_value = self.pid
        self.append(self.eap, self.line(when=self.now + 1))
        self.assertIs(observer.poll(), True)
        self.thread_owner.return_value = None
        self.append(self.eap, self.line(LOGOFF, when=self.now + 2))
        self.assertIs(observer.poll(), False)

    def test_corrupt_thread_integer_does_not_raise_or_wrap_to_a_valid_windows_id(self):
        observer = self.observer()
        for bad in (b"9" * 5000, b"4294967296", b"0"):
            self.append(self.eap, self.line().replace(b"[P:67890]", b"[P:" + bad + b"]"))
            self.assertIsNone(observer.poll())
        self.thread_owner.assert_not_called()

    def test_thread_owner_native_lookup_is_read_only_and_closes_handle_on_every_path(self):
        api = Mock()
        api.OpenThread.return_value = 44
        api.GetProcessIdOfThread.return_value = self.pid
        with patch.object(auth_log.ctypes, "WinDLL", return_value=api, create=True):
            self.assertEqual(auth_log._thread_owner_pid(self.tid), self.pid)
            api.OpenThread.assert_called_once_with(0x0800, False, self.tid)
            api.CloseHandle.assert_called_once_with(44)
            api.CloseHandle.reset_mock()
            api.GetProcessIdOfThread.side_effect = OSError("Synthetic closed thread")
            self.assertIsNone(auth_log._thread_owner_pid(self.tid))
            api.CloseHandle.assert_called_once_with(44)
            api.CloseHandle.reset_mock()
            api.OpenThread.return_value = 0
            self.assertIsNone(auth_log._thread_owner_pid(self.tid))
            api.CloseHandle.assert_not_called()
    def test_initially_absent_log_can_be_created_by_the_new_core(self):
        observer = self.observer()
        self.eap.write_bytes(self.line())
        self.assertIs(observer.poll(), True)

    def test_unknown_negative_thread_revokes_other_file_success_until_new_verified_success(self):
        observer = self.observer()
        self.append(self.eap, self.line())
        self.assertIs(observer.poll(), True)
        self.thread_owner.side_effect = lambda tid: self.pid if tid == self.tid else None
        self.append(self.ui, self.line(FAILURE, when=self.now + 1, tid=self.tid + 1))
        self.assertIs(observer.poll(), False)
        self.assertIs(observer.poll(), False)
        self.assertEqual(observer.event_time, self.now + 1)
        self.append(self.eap, self.line(when=self.now + 2))
        self.assertIs(observer.poll(), True)

    def test_negative_record_owned_by_a_known_different_process_is_ignored(self):
        observer = self.observer()
        self.append(self.eap, self.line())
        self.assertIs(observer.poll(), True)
        self.append(self.ui, self.line(FAILURE, when=self.now + 1, tid=self.tid + 1))
        self.assertIs(observer.poll(), True)

    def test_native_level_label_accepts_lower_and_uppercase(self):
        for level in (b"info", b"INFO", b"Info"):
            observer = self.observer()
            self.append(self.eap, self.line().replace(b"[info]", b"[" + level + b"]"))
            self.assertIs(observer.poll(), True)

    def test_new_partial_line_requires_its_newline_before_authentication(self):
        observer = self.observer()
        complete = self.line()
        self.eap.write_bytes(complete[:-2])
        self.assertIsNone(observer.poll())
        self.append(self.eap, b"\r\n")
        self.assertIs(observer.poll(), True)

    def test_line_started_before_baseline_is_discarded_when_completed(self):
        complete = self.line()
        self.eap.write_bytes(complete[:-4])
        observer = self.observer()
        self.append(self.eap, complete[-4:])
        self.assertIsNone(observer.poll())
        self.append(self.eap, self.line(when=self.now + 1))
        self.assertIs(observer.poll(), True)

    def test_wrong_thread_owner_missing_header_and_imprecise_success_strings_are_ignored(self):
        observer = self.observer()
        rejected = [self.line(tid=self.tid + 1),
                    self.line("CAuthDialog::DoWithAuthSuccess AUTH_SUCCESS"),
                    self.line("prefix " + SUCCESS), self.line(SUCCESS + " suffix"),
                    self.line("CSupplicantDlg::OnNotifyAuthResult AUTH_SUCCESSFUL"),
                    self.line().replace(b"[P:67890]", b""),
                    self.line().replace(b"[2025-", b"[invalid-")]
        for line in rejected:
            with self.subTest(case=rejected.index(line)):
                self.append(self.eap, line)
                self.assertIsNone(observer.poll())
        no_pid = auth_log.AuthLogObserver(self.directory, auth_log.capture_auth_log(self.directory),
                                        self.started, thread_owner=self.thread_owner)
        self.append(self.eap, self.line())
        self.assertIsNone(no_pid.poll())

    def test_old_or_implausibly_future_timestamp_cannot_be_a_new_success(self):
        observer = self.observer()
        for when in (self.started - 10, self.now + 60):
            self.append(self.eap, self.line(when=when))
            self.assertIsNone(observer.poll())

    def test_second_precision_can_accept_the_process_start_second(self):
        observer = self.observer()
        self.append(self.eap, self.line(when=self.started))
        self.assertIs(observer.poll(), True)

    def test_precise_negative_notifications_invalidate_then_new_success_recovers(self):
        for message in (LOGOFF, FAILURE, DISCONNECT):
            with self.subTest(event=message.split()[0]):
                observer = self.observer()
                self.append(self.eap, self.line())
                self.assertIs(observer.poll(), True)
                self.append(self.eap, self.line(message, when=self.now + 1))
                self.assertIs(observer.poll(), False)
                self.assertEqual(observer.event_time, self.now + 1)
                self.append(self.eap, self.line(when=self.now + 2))
                self.assertIs(observer.poll(), True)

    def test_single_file_sequence_orders_failure_before_success_in_same_second(self):
        observer = self.observer()
        self.append(self.eap, self.line(FAILURE) + self.line())
        self.assertIs(observer.poll(), True)

    def test_cross_file_same_second_conflict_is_conservative_but_later_success_wins(self):
        observer = self.observer()
        self.append(self.ui, self.line(FAILURE))
        self.append(self.eap, self.line())
        self.assertIs(observer.poll(), False)
        self.append(self.eap, self.line(when=self.now + 1))
        self.assertIs(observer.poll(), True)

    def test_out_of_order_older_success_cannot_cover_a_later_disconnect(self):
        observer = self.observer()
        self.append(self.eap, self.line(DISCONNECT) + self.line(when=self.now - 1))
        self.assertIs(observer.poll(), False)

    def test_file_replacement_discards_old_evidence_and_rebased_contents(self):
        observer = self.observer()
        self.eap.write_bytes(self.line())
        self.assertIs(observer.poll(), True)
        replacement = self.logs / "synthetic-replacement.log"
        replacement.write_bytes(self.line(when=self.now + 1))
        replacement.replace(self.eap)
        self.assertIsNone(observer.poll())
        self.append(self.eap, self.line(when=self.now + 2))
        self.assertIs(observer.poll(), True)

    def test_truncation_and_regrowth_beyond_old_size_are_not_mistaken_for_append(self):
        self.eap.write_bytes(b"old historical filler\r\n" * 10)
        observer = self.observer()
        self.eap.write_bytes(self.line())
        self.assertIsNone(observer.poll())
        self.eap.write_bytes(b"different filler\r\n" * 30 + self.line())
        self.assertIsNone(observer.poll())
        self.append(self.eap, self.line(when=self.now + 1))
        self.assertIs(observer.poll(), True)

    def test_unreadable_baseline_never_becomes_zero_offset_history(self):
        self.eap.write_bytes(self.line())
        actual_open = Path.open

        def inaccessible(path, *args, **kwargs):
            if path.name == "eappeap.log":
                raise PermissionError("Synthetic access failure")
            return actual_open(path, *args, **kwargs)

        with patch.object(Path, "open", inaccessible):
            baseline = auth_log.capture_auth_log(self.directory)
        observer = self.observer(baseline)
        self.assertIsNone(observer.poll())
        self.append(self.eap, self.line(when=self.now + 1))
        self.assertIs(observer.poll(), True)

    def test_disappearance_or_read_error_invalidates_cached_success(self):
        observer = self.observer()
        self.eap.write_bytes(self.line())
        self.assertIs(observer.poll(), True)
        self.eap.unlink()
        self.assertIsNone(observer.poll())
        self.assertIsNone(observer.event_time)
        self.eap.write_bytes(self.line())
        self.assertIsNone(observer.poll())
        self.append(self.eap, self.line(when=self.now + 1))
        self.assertIs(observer.poll(), True)
        with patch.object(Path, "open", side_effect=PermissionError("Synthetic access failure")):
            self.assertIsNone(observer.poll())

    def test_large_unobserved_region_is_not_allowed_to_hide_a_later_disconnect(self):
        observer = self.observer()
        self.eap.write_bytes(self.line() + b"x" * (auth_log._MAX_READ + 1))
        self.assertIsNone(observer.poll())
        self.assertIsNone(observer.event_time)

    def test_append_during_read_retries_before_accepting_earlier_success(self):
        self.eap.write_bytes(b"")
        observer = self.observer()
        self.append(self.eap, self.line())
        actual_stat = auth_log.os.fstat
        calls = 0

        def append_before_final_stat(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.append(self.eap, self.line(DISCONNECT, when=self.now + 1))
            return actual_stat(fd)

        with patch.object(auth_log.os, "fstat", side_effect=append_before_final_stat):
            self.assertIsNone(observer.poll())
        self.assertIs(observer.poll(), False)
        self.assertEqual(observer.event_time, self.now + 1)


if __name__ == "__main__":
    unittest.main()

import ctypes
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import psutil

from utils.instance_guard import (InstanceGuard, InstanceGuardError, WindowsInstanceOperations,
                                  _lock_content, _lock_owner)


class FakeOperations:
    def __init__(self, content=None, *, running=False, existing_mutex=False):
        self.content = content
        self.running = running
        self.existing_mutex = existing_mutex
        self.closed = []
        self.removed = []
        self.created = []
        self.checked_pids = []
        self.change_before_remove = False
        self.fail_create = False

    def identity(self):
        return 4242, "SyntheticApp", "TEST-HOST"

    def create_mutex(self, name):
        self.mutex_name = name
        return 101, self.existing_mutex

    def close_handle(self, handle):
        self.closed.append(handle)

    def read_lock(self, path):
        return self.content

    def pid_running(self, pid):
        self.checked_pids.append(pid)
        return self.running

    def remove_lock_if_unchanged(self, path, expected):
        if self.change_before_remove:
            self.content = b"Changed record"
        if self.content != expected:
            return False
        self.removed.append(self.content)
        self.content = None
        return True

    def create_lock(self, path, content):
        if self.fail_create or self.content is not None:
            raise OSError("synthetic private diagnostic must not escape")
        self.content = content
        self.created.append(content)
        return 201


class InstanceGuardTests(unittest.TestCase):
    def setUp(self):
        for target in ("ctypes.WinDLL", "subprocess.run", "subprocess.Popen"):
            patcher = patch(target, side_effect=AssertionError("Live boundary forbidden"), create=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def guard(self, operations):
        # Pure in-memory fake; neither this directory nor a native mutex exists.
        return InstanceGuard(Path("synthetic-instance-tests") / "data", operations=operations)

    def test_record_is_compatible_five_line_utf8_and_without_exe_extension(self):
        content = _lock_content(4242, "SyntheticApp", "TEST-HOST")
        self.assertEqual(content, b"4242\nSyntheticApp\nTEST-HOST\n\n\n")
        self.assertEqual(_lock_owner(content, "test-host"), 4242)
        self.assertEqual(_lock_owner(b"4242\nSyntheticApp\n\n", "TEST-HOST"), 4242)

    def test_fresh_acquisition_holds_both_handles_until_release(self):
        operations = FakeOperations()
        guard = self.guard(operations)
        self.assertTrue(guard.acquire())
        self.assertTrue(guard.acquired)
        self.assertTrue(guard.acquire())
        self.assertEqual(len(operations.created), 1)
        self.assertEqual(operations.closed, [])
        guard.release()
        self.assertEqual(operations.closed, [201, 101])
        self.assertIsNone(operations.content)
        self.assertFalse(guard.acquired)
        guard.release()
        self.assertEqual(operations.closed, [201, 101])

    def test_existing_named_mutex_blocks_without_reading_or_touching_old_lock(self):
        operations = FakeOperations(b"private unknown", existing_mutex=True)
        operations.read_lock = Mock(side_effect=AssertionError("Must not read"))
        self.assertFalse(self.guard(operations).acquire())
        self.assertEqual(operations.closed, [101])
        self.assertEqual(operations.content, b"private unknown")

    def test_live_legacy_pid_blocks_even_if_application_name_is_unfamiliar(self):
        content = b"2000\nUnfamiliarApplication\nTEST-HOST\n\n\n"
        operations = FakeOperations(content, running=True)
        self.assertFalse(self.guard(operations).acquire())
        self.assertEqual(operations.checked_pids, [2000])
        self.assertEqual(operations.content, content)
        self.assertEqual(operations.closed, [101])
        self.assertEqual(operations.removed, [])

    def test_dead_legacy_pid_record_is_removed_only_if_unchanged(self):
        content = b"2000\nOldQt\nTEST-HOST\n\n\n"
        operations = FakeOperations(content, running=False)
        guard = self.guard(operations)
        self.assertTrue(guard.acquire())
        self.assertEqual(operations.removed, [content])
        self.assertEqual(operations.content, _lock_content(*operations.identity()))
        guard.release()

    def test_unknown_pid_state_fails_closed_without_removal(self):
        operations = FakeOperations(b"2000\nOldQt\nTEST-HOST\n", running=None)
        with self.assertRaises(InstanceGuardError):
            self.guard(operations).acquire()
        self.assertEqual(operations.removed, [])
        self.assertEqual(operations.closed, [101])

    def test_malformed_foreign_and_oversized_records_are_never_removed(self):
        for content in (b"", b"2000\n", b"0\nOldQt\nTEST-HOST\n",
                        b"-1\nOldQt\nTEST-HOST\n", b"4294967296\nQt\nTEST-HOST\n",
                        b"2000\nOldQt\nOTHER-HOST\n", b"\xff\nOldQt\nTEST-HOST\n",
                        b"x" * 16385):
            with self.subTest(size=len(content)):
                operations = FakeOperations(content)
                with self.assertRaises(InstanceGuardError):
                    self.guard(operations).acquire()
                self.assertEqual(operations.removed, [])
                self.assertEqual(operations.checked_pids, [])
                self.assertEqual(operations.closed, [101])

    def test_changed_record_is_not_deleted_or_claimed(self):
        operations = FakeOperations(b"2000\nOldQt\nTEST-HOST\n")
        operations.change_before_remove = True
        with self.assertRaises(InstanceGuardError):
            self.guard(operations).acquire()
        self.assertEqual(operations.content, b"Changed record")
        self.assertEqual(operations.created, [])
        self.assertEqual(operations.closed, [101])

    def test_file_creation_error_releases_mutex_and_sanitizes_error(self):
        operations = FakeOperations()
        operations.fail_create = True
        with self.assertRaises(InstanceGuardError) as error:
            self.guard(operations).acquire()
        self.assertNotIn("private diagnostic", str(error.exception))
        self.assertEqual(operations.closed, [101])

    def test_release_never_removes_a_replaced_record(self):
        operations = FakeOperations()
        guard = self.guard(operations)
        self.assertTrue(guard.acquire())
        operations.content = b"Another instance's record"
        guard.release()
        self.assertEqual(operations.content, b"Another instance's record")
        self.assertEqual(operations.removed, [])
        self.assertEqual(operations.closed, [201, 101])

    def test_identity_failure_cannot_leave_a_mutex_handle(self):
        operations = FakeOperations()
        operations.identity = Mock(side_effect=psutil.AccessDenied(4242))
        with self.assertRaises(InstanceGuardError):
            self.guard(operations).acquire()
        self.assertEqual(operations.closed, [101])

    def test_psutil_unreadable_is_unknown_and_absent_is_dead(self):
        operations = object.__new__(WindowsInstanceOperations)
        with patch("utils.instance_guard.psutil.Process", side_effect=psutil.AccessDenied(2000)):
            self.assertIsNone(operations.pid_running(2000))
        with patch("utils.instance_guard.psutil.Process", side_effect=psutil.NoSuchProcess(2000)):
            self.assertIs(operations.pid_running(2000), False)
        with patch("utils.instance_guard.psutil.Process") as process:
            process.return_value.is_running.return_value = True
            self.assertIs(operations.pid_running(2000), True)

    def test_native_file_mode_matches_qlockfile_and_partial_writes_are_refused(self):
        operations = object.__new__(WindowsInstanceOperations)
        operations.api = Mock()
        operations.api.CreateFileW.return_value = 201
        operations.api.FlushFileBuffers.return_value = 1
        operations.api.CloseHandle.return_value = 1
        operations.remove_lock_if_unchanged = Mock(return_value=False)
        content = _lock_content(4242, "SyntheticApp", "TEST-HOST")
        def write(handle, data, length, written, overlapped):
            ctypes.cast(written, ctypes.POINTER(ctypes.c_uint32)).contents.value = length
            return 1
        operations.api.WriteFile.side_effect = write
        with patch.object(Path, "mkdir"):
            self.assertEqual(operations.create_lock(Path("synthetic.lock"), content), 201)
            args = operations.api.CreateFileW.call_args.args
            self.assertEqual(args[1:6], (0xC0000000, 1, None, 1, 0x80))
            operations.api.WriteFile.side_effect = lambda *_: 1
            with self.assertRaises(InstanceGuardError):
                operations.create_lock(Path("synthetic.lock"), content)
        operations.api.CloseHandle.assert_called_once_with(201)


if __name__ == "__main__":
    unittest.main()

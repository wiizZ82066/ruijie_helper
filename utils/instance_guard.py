"""Single-instance guard interoperable with the existing Windows Qt launcher.

The mutex protects new launchers. The held CREATE_NEW file with FILE_SHARE_READ
also protects against Qt's QLockFile, including when its PID check is uncertain.
The five UTF-8 lines follow Qt's PID/name/hostname/machine-id/boot-id format;
empty optional machine/boot IDs are supported by Qt. Nothing is acquired on
import. Unreadable, foreign-host or malformed existing files fail closed.

References: qtbase/src/corelib/io/qlockfile{,_win}.cpp (Qt 6.8).
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import re
import socket

import psutil


class InstanceGuardError(RuntimeError):
    """A fixed non-sensitive startup error; never contains process/path data."""


_MAX_LOCK_BYTES = 16384


def _lock_owner(content: bytes, hostname: str) -> int:
    try:
        if not isinstance(content, bytes) or not content or len(content) > _MAX_LOCK_BYTES:
            raise ValueError
        lines = content.decode("utf-8").splitlines()
        if len(lines) < 3 or not re.fullmatch(r"[1-9][0-9]{0,9}", lines[0]):
            raise ValueError
        pid = int(lines[0])
        if pid > 0xFFFFFFFF or (lines[2] and lines[2].casefold() != hostname.casefold()):
            raise ValueError
        return pid
    except (UnicodeError, ValueError, TypeError, AttributeError):
        raise InstanceGuardError("无法确认已有程序锁的状态，请先关闭其他版本后重试。") from None


def _lock_content(pid: int, name: str, hostname: str) -> bytes:
    if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
        raise InstanceGuardError("无法确认当前程序身份。")
    if any(not isinstance(value, str) or not value or any(c in value for c in "\r\n\0")
           for value in (name, hostname)):
        raise InstanceGuardError("无法确认当前程序身份。")
    content = f"{pid}\n{name}\n{hostname}\n\n\n".encode("utf-8")
    if len(content) > _MAX_LOCK_BYTES:
        raise InstanceGuardError("无法确认当前程序身份。")
    return content


class WindowsInstanceOperations:
    """The only native boundary, replaceable in offline tests."""
    def __init__(self):
        if os.name != "nt":
            raise InstanceGuardError("此程序的单实例保护仅支持 Windows。")
        api = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x00000800)
        api.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        api.CreateMutexW.restype = ctypes.c_void_p
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        api.CloseHandle.restype = ctypes.c_int
        api.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        api.CreateFileW.restype = ctypes.c_void_p
        api.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                 ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        api.WriteFile.restype = ctypes.c_int
        api.FlushFileBuffers.argtypes = [ctypes.c_void_p]
        api.FlushFileBuffers.restype = ctypes.c_int
        self.api = api

    def identity(self):
        pid = os.getpid()
        # Match Qt's module basename without its final extension.
        name = Path(psutil.Process(pid).exe()).stem
        hostname = os.environ.get("COMPUTERNAME") or socket.gethostname()
        return pid, name, hostname

    def create_mutex(self, name):
        ctypes.set_last_error(0)
        handle = self.api.CreateMutexW(None, False, name)
        error = ctypes.get_last_error()
        if not handle:
            raise InstanceGuardError("无法建立单实例保护，请稍后重试。")
        # No initial ownership: the existence of our held handle is the gate.
        return handle, error == 183

    def close_handle(self, handle):
        if handle and not self.api.CloseHandle(handle):
            raise InstanceGuardError("无法释放程序锁。")

    def read_lock(self, path):
        try:
            with path.open("rb") as stream:
                content = stream.read(_MAX_LOCK_BYTES + 1)
            if len(content) > _MAX_LOCK_BYTES:
                raise InstanceGuardError("已有程序锁的格式异常，未修改。")
            return content
        except FileNotFoundError:
            return None

    def pid_running(self, pid):
        try:
            return psutil.Process(pid).is_running()
        except psutil.NoSuchProcess:
            return False
        except (psutil.AccessDenied, OSError):
            return None

    def remove_lock_if_unchanged(self, path, expected):
        if self.read_lock(path) != expected:
            return False
        # Windows refuses deletion if a Qt/new launcher holds its native
        # FILE_SHARE_READ handle, even if a stale-file read raced its startup.
        path.unlink()
        return True

    def create_lock(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.api.CreateFileW(str(path), 0x80000000 | 0x40000000,
                                     1, None, 1, 0x80, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise InstanceGuardError("无法取得程序锁，其他版本可能仍在运行。")
        written = ctypes.c_uint32()
        data = ctypes.create_string_buffer(content)
        try:
            if (not self.api.WriteFile(handle, data, len(content), ctypes.byref(written), None)
                    or written.value != len(content) or not self.api.FlushFileBuffers(handle)):
                raise InstanceGuardError("无法保存程序锁，未继续启动。")
            return handle
        except BaseException:
            self.close_handle(handle)
            # Only a complete record that is still ours may be removed.
            # A partial/unknown record is retained and fails closed next time.
            try:
                self.remove_lock_if_unchanged(path, content)
            except (OSError, InstanceGuardError):
                pass
            raise


class InstanceGuard:
    """Call acquire before launching UI/work and keep this object alive.

    acquire() returns False for an identifiable live instance; uncertainty
    raises InstanceGuardError. release() runs only after workers have stopped.
    Inject operations for tests; it must implement WindowsInstanceOperations.
    """
    def __init__(self, data_dir, *, operations=None):
        self.path = Path(data_dir).resolve() / "authenticator.lock"
        digest = hashlib.sha256(str(self.path).casefold().encode("utf-8")).hexdigest()[:32]
        self.mutex_name = "Local\\CampusLogin-" + digest
        self.operations = operations
        self._mutex = None
        self._file = None
        self._content = None

    @property
    def acquired(self):
        return self._file is not None and self._mutex is not None

    def acquire(self) -> bool:
        if self.acquired:
            return True
        try:
            if self.operations is None:
                self.operations = WindowsInstanceOperations()
            ops = self.operations
            handle, exists = ops.create_mutex(self.mutex_name)
            if exists:
                ops.close_handle(handle)
                return False
            self._mutex = handle
            pid, name, hostname = ops.identity()
            self._content = _lock_content(pid, name, hostname)
            previous = ops.read_lock(self.path)
            if previous is not None:
                owner = _lock_owner(previous, hostname)
                running = ops.pid_running(owner)
                if running is True:
                    self.release()
                    return False
                if running is not False:
                    raise InstanceGuardError("无法确认其他版本是否已退出，未继续启动。")
                if not ops.remove_lock_if_unchanged(self.path, previous):
                    raise InstanceGuardError("程序锁已发生变化，请稍后重试。")
            self._file = ops.create_lock(self.path, self._content)
            if self._file is None:
                raise InstanceGuardError("无法取得程序锁，未继续启动。")
            return True
        except BaseException as exc:
            try:
                self.release()
            except (OSError, InstanceGuardError):
                pass
            if isinstance(exc, (KeyboardInterrupt, SystemExit, InstanceGuardError)):
                raise
            raise InstanceGuardError("无法确认程序运行状态，未继续启动。") from None

    def release(self) -> None:
        ops = self.operations
        if ops is None:
            return
        try:
            if self._file is not None:
                handle, self._file = self._file, None
                ops.close_handle(handle)
                ops.remove_lock_if_unchanged(self.path, self._content)
        except (OSError, InstanceGuardError):
            raise InstanceGuardError("程序锁未能完整清理，请在退出后重试。") from None
        finally:
            if self._mutex is not None:
                handle, self._mutex = self._mutex, None
                ops.close_handle(handle)
            self._content = None

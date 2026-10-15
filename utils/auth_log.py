"""Observe this core session's new native authentication notifications.

Only a caller-captured pre-start byte boundary, a thread owned by the current
core PID, and a complete native notification can establish a log result. No log text escapes
this module. Replacement, truncation, or unreadable files invalidate evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import ctypes
import hashlib
import math
import os
from pathlib import Path
import re
import time


_NAMES = ("ui.log", "eappeap.log")
_ANCHOR_BYTES = 256
_MAX_READ = 1024 * 1024
_HEADER = re.compile(
    rb"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]"
    rb"\[T:(\d+)\]\[P:(\d{1,10})\]\[[A-Za-z]+\]:(.*)\r?$"
)
_SUCCESS = b"CSupplicantDlg::OnNotifyAuthResult AUTH_SUCCESS"
_LOGOFF = b"CSupplicantDlg::OnNotifyAuthResult AUTH_ALREADY_LOGOFF"
_FAILURE = re.compile(
    rb"CSupplicantDlg::OnAuthenticateFail : the m_bHasStartAuth =\d+"
    rb" and set it false,the m_authSuccess= \d+ set false"
)
_DISCONNECT = re.compile(
    rb"CSupplicantDlg::OnDisconnect : the m_bHasStartAuth =\d+"
    rb" and set false,the m_authSuccess= \d+ set it false"
)


def _thread_owner_pid(thread_id: int) -> int | None:
    """Native [P:n] is GetCurrentThreadId, despite its misleading label."""
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        return None
    try:
        api = loader("kernel32", use_last_error=True)
        api.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint32]
        api.OpenThread.restype = ctypes.c_void_p
        api.GetProcessIdOfThread.argtypes = [ctypes.c_void_p]
        api.GetProcessIdOfThread.restype = ctypes.c_uint32
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        api.CloseHandle.restype = ctypes.c_int32
        handle = api.OpenThread(0x0800, False, thread_id)  # THREAD_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            owner = api.GetProcessIdOfThread(handle)
            return int(owner) if owner else None
        finally:
            api.CloseHandle(handle)
    except (OSError, AttributeError):
        return None


@dataclass(frozen=True)
class LogPosition:
    name: str
    identity: tuple[int, int] | None
    offset: int
    anchor: bytes = field(repr=False)
    line_complete: bool = True
    missing: bool = False


@dataclass(frozen=True)
class LogBaseline:
    files: tuple[LogPosition, ...]


def _identity(stat):
    return stat.st_dev, stat.st_ino


def _anchor(stream, offset):
    size = min(offset, _ANCHOR_BYTES)
    stream.seek(offset - size)
    tail = stream.read(size)
    if len(tail) != size:
        raise OSError("Native log changed while reading its boundary")
    return hashlib.sha256(tail).digest(), not tail or tail.endswith(b"\n")


def _position(stream, name):
    stat = os.fstat(stream.fileno())
    digest, complete = _anchor(stream, stat.st_size)
    current = os.fstat(stream.fileno())
    if (_identity(current), current.st_size, current.st_mtime_ns) != (
            _identity(stat), stat.st_size, stat.st_mtime_ns):
        raise OSError("Native log changed while capturing its boundary")
    return LogPosition(name, _identity(stat), stat.st_size, digest, complete)


def capture_auth_log(client_dir: Path) -> LogBaseline:
    """Capture offsets before starting/reconfiguring the authentication core."""
    positions = []
    for name in _NAMES:
        try:
            with (Path(client_dir) / "logs" / name).open("rb") as stream:
                positions.append(_position(stream, name))
        except FileNotFoundError:
            positions.append(LogPosition(name, None, 0, b"", missing=True))
        except OSError:
            # An unreadable old file must never become a zero-offset baseline.
            positions.append(LogPosition(name, None, 0, b"", missing=False))
    return LogBaseline(tuple(positions))


@dataclass
class _Cursor:
    position: LogPosition
    pending: bytes = field(default=b"", repr=False)
    skip_partial: bool = False
    event: tuple[float, bool] | None = None


class AuthLogObserver:
    def __init__(self, client_dir: Path, baseline: LogBaseline, started_at: float,
                 *, pid: int | None = None, thread_owner=None,
                 session_created_at: float | None = None):
        if (not isinstance(baseline, LogBaseline) or
                tuple(item.name for item in baseline.files) != _NAMES or
                not math.isfinite(started_at)):
            raise ValueError("Invalid authentication log baseline")
        if pid is not None and (type(pid) is not int or pid <= 0):
            raise ValueError("Invalid authentication core PID")
        if session_created_at is not None and not math.isfinite(session_created_at):
            raise ValueError("Invalid authentication session creation time")
        self._directory = Path(client_dir) / "logs"
        self._started_at = math.floor(max(started_at, session_created_at)
                                      if session_created_at is not None else started_at)
        self._pid = pid
        self._thread_owner = thread_owner or _thread_owner_pid
        self._cursors = [_Cursor(item, skip_partial=not item.line_complete)
                         for item in baseline.files]
        self.event_time: float | None = None

    def _event(self, line, now):
        # The native logger uses an ASCII header even in a GB18030 file.
        # Removing CR is necessary because the message group's .* is greedy.
        match = _HEADER.fullmatch(line.rstrip(b"\r"))
        if match is None or self._pid is None:
            return None
        message = match[4]
        if message == _SUCCESS:
            succeeded = True
        elif message == _LOGOFF or _FAILURE.fullmatch(message) or _DISCONNECT.fullmatch(message):
            succeeded = False
        else:
            return None
        try:
            when = datetime.strptime(match[1].decode("ascii"), "%Y-%m-%d %H:%M:%S").timestamp()
        except (ValueError, OverflowError, OSError):
            return None
        if when < self._started_at or when > now + 5:
            return None
        # P is an OS thread ID; T is milliseconds from a CRT clock origin,
        # not a thread ID. DLL/CRT initialization delays make a narrow T-to-
        # process-start tolerance unsuitable as an authentication requirement.
        thread_id = int(match[3])
        if not 0 < thread_id <= 0xFFFFFFFF:
            return None
        try:
            owner = self._thread_owner(thread_id)
        except (OSError, ValueError, TypeError, AttributeError):
            owner = None
        owned = type(owner) is int and owner == self._pid
        if succeeded and not owned:
            return None
        if not succeeded and type(owner) is int and owner > 0 and not owned:
            # A known different process cannot change this core's evidence.
            return None
        # An exact new negative whose thread has exited or cannot be queried
        # revokes success conservatively. It never asserts bad credentials.
        return when, succeeded

    @staticmethod
    def _rebase(cursor, stream):
        cursor.position = _position(stream, cursor.position.name)
        cursor.pending = b""
        cursor.skip_partial = not cursor.position.line_complete
        cursor.event = None

    def _read(self, cursor, now):
        """Return False on lost continuity; never consume a replacement's past."""
        previous = cursor.position
        try:
            with (self._directory / previous.name).open("rb") as stream:
                stat = os.fstat(stream.fileno())
                if previous.identity is None:
                    if not previous.missing:
                        self._rebase(cursor, stream)
                        return False
                    previous = LogPosition(previous.name, _identity(stat), 0,
                                           hashlib.sha256(b"").digest())
                    cursor.position = previous
                if (_identity(stat) != previous.identity or stat.st_size < previous.offset or
                        _anchor(stream, previous.offset)[0] != previous.anchor or
                        stat.st_size - previous.offset > _MAX_READ):
                    self._rebase(cursor, stream)
                    return False
                stream.seek(previous.offset)
                incoming = stream.read(stat.st_size - previous.offset)
                if len(incoming) != stat.st_size - previous.offset:
                    self._rebase(cursor, stream)
                    return False
                new_offset = previous.offset + len(incoming)
                digest, complete = _anchor(stream, new_offset)
                current = os.fstat(stream.fileno())
                if _identity(current) != previous.identity or current.st_size < new_offset:
                    self._rebase(cursor, stream)
                    return False
                if current.st_size > stat.st_size:
                    # A disconnect may be in the just-appended region. Retry
                    # the old boundary next poll instead of accepting a prefix.
                    return False
                if current.st_mtime_ns != stat.st_mtime_ns:
                    self._rebase(cursor, stream)
                    return False
                cursor.position = LogPosition(previous.name, previous.identity,
                                              new_offset, digest, complete)
                lines = (cursor.pending + incoming).split(b"\n")
                cursor.pending = lines.pop()
                if cursor.skip_partial and lines:
                    lines.pop(0)
                    cursor.skip_partial = False
                if len(cursor.pending) > _MAX_READ:
                    cursor.pending = b""
                    cursor.skip_partial = True
                    cursor.event = None
                    return False
                for line in lines:
                    event = self._event(line, now)
                    if event is not None and (cursor.event is None or event[0] >= cursor.event[0]):
                        cursor.event = event
                return True
        except FileNotFoundError:
            if previous.identity is None and previous.missing:
                return True
        except OSError:
            pass
        cursor.position = LogPosition(previous.name, None, 0, b"", missing=False)
        cursor.pending = b""
        cursor.event = None
        return False

    def poll(self) -> bool | None:
        """Return the latest incremental notification, without exposing its text.

        Equal-second events from different files cannot be ordered, so a
        negative notification wins that tie. Sequence within one file is known.
        """
        now = time.time()
        continuous = True
        for cursor in self._cursors:
            continuous = self._read(cursor, now) and continuous
        if not continuous:
            for cursor in self._cursors:
                cursor.event = None
            self.event_time = None
            return None
        events = [cursor.event for cursor in self._cursors if cursor.event is not None]
        if not events:
            self.event_time = None
            return None
        self.event_time = max(event[0] for event in events)
        return all(value for when, value in events if when == self.event_time)

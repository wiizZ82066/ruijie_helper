"""Current-user Windows DPAPI storage; plaintext is used only in memory.

The optional protector argument exists for offline tests. Production callers
should use WindowsDPAPI, which does not enable CRYPTPROTECT_LOCAL_MACHINE.
No command, log, client configuration, or account enumeration is involved.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import threading
from uuid import uuid4


class CredentialStoreError(RuntimeError):
    """A deliberately non-sensitive message safe for the application to show."""


class CredentialUnlockError(CredentialStoreError):
    """Existing data must be retained until the user explicitly clears it."""


@dataclass(frozen=True)
class Credentials:
    # Neither identifier nor password should appear in repr/exception output.
    username: str = field(repr=False)
    password: str = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.username, str) or not self.username.strip():
            raise ValueError("请输入账号。")
        if not isinstance(self.password, str) or not self.password:
            raise ValueError("请输入密码。")
        if len(self.username) > 4096 or len(self.password) > 65536:
            raise ValueError("账号或密码长度超出支持范围。")


class WindowsDPAPI:
    """CryptProtectData/CryptUnprotectData, bound to the current Windows user."""

    _ENTROPY = b"CampusLogin credentials v1"
    _UI_FORBIDDEN = 1

    def encrypt(self, data: bytes) -> bytes:
        return self._transform(data, decrypt=False)

    def decrypt(self, data: bytes) -> bytes:
        return self._transform(data, decrypt=True)

    def _transform(self, data: bytes, *, decrypt: bool) -> bytes:
        if os.name != "nt":
            raise CredentialStoreError("账号加密仅支持 Windows 当前用户。")
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

        crypt = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        crypt.CryptProtectData.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.POINTER(Blob),
                                           ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        crypt.CryptProtectData.restype = wintypes.BOOL
        crypt.CryptUnprotectData.argtypes = [ctypes.POINTER(Blob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(Blob),
                                             ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        crypt.CryptUnprotectData.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        incoming = ctypes.create_string_buffer(data)
        entropy = ctypes.create_string_buffer(self._ENTROPY)
        source = Blob(len(data), ctypes.cast(incoming, ctypes.POINTER(ctypes.c_ubyte)))
        extra = Blob(len(self._ENTROPY), ctypes.cast(entropy, ctypes.POINTER(ctypes.c_ubyte)))
        output = Blob()
        try:
            function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
            ok = function(ctypes.byref(source), None, ctypes.byref(extra), None, None,
                          self._UI_FORBIDDEN, ctypes.byref(output))
            if not ok or not output.pbData or not output.cbData:
                raise CredentialStoreError("Windows 无法解密账号信息。" if decrypt else "Windows 无法加密账号信息。")
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            if output.pbData:
                if decrypt:
                    ctypes.memset(output.pbData, 0, output.cbData)
                kernel.LocalFree(output.pbData)
            ctypes.memset(incoming, 0, ctypes.sizeof(incoming))


class CredentialStore:
    """Optional remembered credentials, with an explicit failure-recovery gate.

    load() returns Credentials or None. save(..., remember=False) retains the
    values only in this instance and removes an existing *readable* saved entry.
    A load/decryption failure locks further saves; clear() is the explicit user
    action that discards the unreadable entry and permits saving again.
    """

    _HEADER = b"CampusLogin-DPAPI-v1\n"
    _MAX_FILE_BYTES = 1024 * 1024
    _locks = {}
    _locks_guard = threading.Lock()

    def __init__(self, data_dir=None, protector=None):
        base = Path(os.environ.get("APPDATA", str(Path.home()))) / "CampusLogin"
        self.path = (Path(data_dir) if data_dir is not None else base).resolve() / "credentials.dpapi"
        self.protector = protector if protector is not None else WindowsDPAPI()
        self._memory = None
        self._memory_only = False
        self._locked = False
        with self._locks_guard:
            self._lock = self._locks.setdefault(str(self.path).casefold(), threading.RLock())

    @property
    def locked(self) -> bool:
        return self._locked

    @property
    def remembered(self) -> bool:
        return self.path.is_file()

    def _read_file(self):
        try:
            if self.path.stat().st_size > self._MAX_FILE_BYTES:
                raise ValueError("oversized")
            content = self.path.read_bytes()
            if len(content) > self._MAX_FILE_BYTES:
                raise ValueError("oversized")
            return content
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            self._locked = True
            raise CredentialUnlockError("无法读取已保存的账号信息；请明确删除后重新保存。") from None

    def _decode(self, content):
        try:
            if not content.startswith(self._HEADER) or len(content) <= len(self._HEADER):
                raise ValueError("unsupported")
            plaintext = self.protector.decrypt(content[len(self._HEADER):])
            data = json.loads(plaintext.decode("utf-8"))
            if not isinstance(data, dict) or data.get("version") != 1:
                raise ValueError("unsupported")
            return Credentials(data["username"], data["password"])
        except Exception:
            self._locked = True
            # Never include the provider exception or JSON parser's plaintext.
            raise CredentialUnlockError("无法解密已保存的账号信息；请使用原 Windows 账户，或明确删除后重新保存。") from None

    def _check_unlocked(self):
        if self._locked:
            raise CredentialUnlockError("已保存的账号信息尚未解锁，未覆盖；请先明确删除。")

    def load(self) -> Credentials | None:
        with self._lock:
            self._check_unlocked()
            if self._memory_only:
                return self._memory
            content = self._read_file()
            self._memory = self._decode(content) if content is not None else None
            return self._memory

    def _unchanged(self, expected):
        if self._read_file() != expected:
            raise CredentialStoreError("保存的账号信息已被其他操作更改，请重新读取后再保存。")

    def _atomic_write(self, content, previous):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp-" + uuid4().hex)
        try:
            with temporary.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            self._unchanged(previous)
            os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def save(self, credentials: Credentials, *, remember: bool) -> None:
        if not isinstance(credentials, Credentials) or type(remember) is not bool:
            raise TypeError("凭据或记住选项的类型无效。")
        with self._lock:
            self._check_unlocked()
            previous = self._read_file()
            if previous is not None:
                self._decode(previous)  # Validate every existing entry before replacing or removing it.
            try:
                if remember:
                    plaintext = json.dumps({"version": 1, "username": credentials.username,
                                            "password": credentials.password}, ensure_ascii=False).encode("utf-8")
                    encrypted = self.protector.encrypt(plaintext)
                    if not isinstance(encrypted, bytes) or not encrypted:
                        raise ValueError("invalid encrypted output")
                    self._atomic_write(self._HEADER + encrypted, previous)
                elif previous is not None:
                    self._unchanged(previous)
                    self.path.unlink()
            except CredentialStoreError:
                raise
            except Exception:
                raise CredentialStoreError("保存账号信息失败，未完成更新。") from None
            self._memory = credentials
            self._memory_only = not remember

    def clear(self) -> None:
        """Explicitly forget saved and in-memory credentials, including locked data."""
        with self._lock:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                raise CredentialStoreError("删除已保存的账号信息失败。") from None
            self._memory = None
            self._memory_only = False
            self._locked = False

"""Prepare the reviewed native client's encoded profile before authentication.

Our optional credential vault uses DPAPI. The native client additionally retains
its own machine-derived DES-CBC password representation and reversibly encoded
INI files. This compatibility format is not a replacement for a secure vault.
No plaintext password is written to a file, command argument, or log. The
original client uses the account identifier as a user directory name and may
include it in its own status/log files; this module cannot hide those records.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import re
import struct
import time

from utils.credential_store import Credentials
from utils import core_patch

_MAX_PROFILE = 2 * 1024 * 1024


class CredentialPreparationError(RuntimeError):
    """Non-sensitive message safe for the GUI."""


def decode_profile(encoded: bytes) -> bytes:
    """CSuConfigFile / 0x432498: prediction flags, literal bytes, bit inversion."""
    if not encoded or len(encoded) > _MAX_PROFILE:
        raise CredentialPreparationError("原客户端配置为空或大小异常，未修改。")
    data = bytes(255 - b for b in encoded)
    dictionary = bytearray(b" " * 32768)
    result = bytearray()
    older = previous = offset = 0
    while offset < len(data):
        flags = data[offset]
        offset += 1
        for bit in range(8):
            index = (older << 7) ^ previous
            if flags & (1 << bit):
                value = dictionary[index]
            else:
                if offset == len(data):
                    return bytes(result)
                value = data[offset]
                offset += 1
                dictionary[index] = value
            result.append(value)
            if len(result) > _MAX_PROFILE:
                raise CredentialPreparationError("原客户端配置解码后过大，未修改。")
            older, previous = previous, value
    return bytes(result)


def encode_profile(plain: bytes) -> bytes:
    # All-literal blocks are valid in the native decoder; no dictionary matches
    # are required. This also gives a simple independently verified encoder.
    if not plain or len(plain) > _MAX_PROFILE:
        raise CredentialPreparationError("待写入的原客户端配置大小异常。")
    packed = b"".join(b"\0" + plain[i:i + 8] for i in range(0, len(plain), 8))
    return bytes(255 - b for b in packed)


def _text(blob: bytes) -> str:
    try:
        text = decode_profile(blob).decode("mbcs" if os.name == "nt" else "cp936")
    except UnicodeError:
        raise CredentialPreparationError("原客户端配置字符编码不受支持，未修改。") from None
    if "\0" in text or not re.search(r"(?m)^\[PUBLIC\]\s*$", text):
        raise CredentialPreparationError("原客户端配置结构不受支持，未修改。")
    return text


def _get(text: str, section: str, key: str, default="") -> str:
    active = ""
    found = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            active = line[1:-1].casefold()
        elif active == section.casefold() and "=" in line and not line.startswith((";", "#")):
            name, value = line.split("=", 1)
            if name.strip().casefold() == key.casefold():
                found.append(value.strip())
    if len(found) > 1:
        raise CredentialPreparationError("原客户端配置存在重复关键字段，未修改。")
    return found[0] if found else default


def _set(text: str, section: str, key: str, value: str) -> str:
    if any(c in value for c in "\r\n\0"):
        raise CredentialPreparationError("账号包含客户端不支持的控制字符。")
    lines = text.splitlines()
    active = False
    start = end = None
    matches = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if active:
                end = index
                break
            active = stripped[1:-1].casefold() == section.casefold()
            if active:
                start = index
        elif active and "=" in stripped and stripped.split("=", 1)[0].strip().casefold() == key.casefold():
            matches.append(index)
    if len(matches) > 1:
        raise CredentialPreparationError("原客户端配置存在重复关键字段，未修改。")
    value_line = f"{key}={value}"
    if matches:
        lines[matches[0]] = value_line
    elif start is not None:
        lines.insert(end if end is not None else len(lines), value_line)
    else:
        lines.extend([f"[{section}]", value_line])
    return "\r\n".join(lines) + "\r\n"


def _native_bytes(value: str) -> bytes:
    try:
        return value.encode("mbcs" if os.name == "nt" else "cp936", errors="strict")
    except UnicodeError:
        raise CredentialPreparationError("账号或密码包含此版本客户端无法表示的字符。") from None


def _user_path(client_dir: Path, username: str) -> Path:
    raw = _native_bytes(username)
    escaped = bytearray()
    for byte in raw:
        escaped.extend(f"#{byte:02x}".encode() if byte in b'"#*/:<>?\\' else bytes([byte]))
    name = escaped.decode("mbcs" if os.name == "nt" else "cp936")
    if not name or name in (".", "..") or name.endswith((".", " ")) or len(name) > 160:
        raise CredentialPreparationError("账号不能安全映射到原客户端用户配置。")
    stem = name.split(".", 1)[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        raise CredentialPreparationError("账号不能安全映射到原客户端用户配置。")
    parent = client_dir / "users" / name
    path = parent / "userinfo.dat"
    if (not path.resolve().is_relative_to(client_dir.resolve())
            or not path.resolve().is_relative_to((client_dir / "users").resolve())
            or parent.is_symlink() or path.is_symlink()
            or getattr(parent, "is_junction", lambda: False)()):
        raise CredentialPreparationError("原客户端用户配置路径异常，未修改。")
    return path


def encrypt_native_password(password: str, material: bytes) -> str:
    """0x4ba5eb: DES key=MD5[:8], CBC IV=MD5[8:], zero padding, uppercase hex."""
    if len(material) != 16:
        raise CredentialPreparationError("原客户端密码编码参数无效。")
    from Crypto.Cipher import DES
    plain = _native_bytes(password)
    if not plain or len(plain) > 128 or b"\0" in plain:
        raise CredentialPreparationError("密码为空、过长或含有客户端不支持的字符。")
    padded = plain + b"\0" * (-len(plain) % 8)
    return DES.new(material[:8], DES.MODE_CBC, iv=material[8:]).encrypt(padded).hex().upper()


def _verify_import_core(client_dir: Path):
    """Accept only the reviewed original or its exact compatible patch."""
    raw = (client_dir / "8021x.exe").read_bytes()
    original = bytearray(raw)
    for item in core_patch.PATCHES:
        if original[item.offset:item.offset + len(item.replacement)] == item.replacement:
            original[item.offset:item.offset + len(item.replacement)] = item.expected[:len(item.replacement)]
    patched, _ = core_patch.patch_bytes(bytes(original))
    if raw not in (bytes(original), patched):
        raise CredentialPreparationError("此客户端版本暂不支持账号导入。")


def _read_import_profile(path: Path) -> bytes:
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise CredentialPreparationError("原客户端配置路径异常，未导入。")
    with path.open("rb") as stream:
        raw = stream.read(_MAX_PROFILE + 1)
    if not raw or len(raw) > _MAX_PROFILE:
        raise CredentialPreparationError("原客户端配置为空或大小异常，未导入。")
    return raw


def _decrypt_saved_password(cipher: str, material: bytes) -> str:
    """Decode the reviewed native format in memory; never return raw bytes/errors."""
    try:
        if len(material) != 16 or not re.fullmatch(r"(?:[0-9a-fA-F]{16}){1,16}", cipher):
            raise ValueError()
        from Crypto.Cipher import DES
        plain = DES.new(material[:8], DES.MODE_CBC, iv=material[8:]).decrypt(bytes.fromhex(cipher))
        value, separator, padding = plain.partition(b"\0")
        if not value or (separator and (len(padding) > 6 or any(padding))):
            raise ValueError()
        password = value.decode("mbcs" if os.name == "nt" else "cp936", errors="strict")
        if any(ord(c) < 32 or ord(c) == 127 for c in password) or _native_bytes(password) != value:
            raise ValueError()
        if encrypt_native_password(password, material).casefold() != cipher.casefold():
            raise ValueError()
        return password
    except Exception:
        raise CredentialPreparationError("无法读取锐捷保存的密码，请在本机原客户端重新保存，或手动输入。") from None


def read_saved_credentials(client_dir: Path, *, material_provider=None) -> Credentials:
    """Read only the selected native account. No enumeration, login or file writes.

    DES has no authenticity tag: structural checks detect malformed data, but
    only a later successful authentication verifies that the password is valid.
    """
    try:
        client_dir = Path(client_dir).resolve()
        _verify_import_core(client_dir)
        users = client_dir / "users"
        if users.is_symlink() or getattr(users, "is_junction", lambda: False)():
            raise CredentialPreparationError("原客户端配置路径异常，未导入。")
        global_path = client_dir / "SuConfig.dat"
        global_raw = _read_import_profile(global_path)
        username = _get(_text(global_raw), "PUBLIC", "Name")
        if (not username or len(_native_bytes(username)) > 128 or
                any(ord(c) < 32 or c in "[];=" for c in username)):
            raise CredentialPreparationError("锐捷未保存可导入的当前账号，请先在原客户端保存账号。")
        user_path = _user_path(client_dir, username)
        user_raw = _read_import_profile(user_path)
        profile = _text(user_raw)
        cipher = _get(profile, "PUBLIC", "Password")
        if not cipher or _get(profile, "PUBLIC", "SaveCheck", "1") != "1":
            raise CredentialPreparationError("锐捷未保存当前账号的密码，请先在原客户端记住密码。")
        material = (material_provider or _machine_material)()
        password = _decrypt_saved_password(cipher, material)
        if (_read_import_profile(global_path) != global_raw or
                _read_import_profile(user_path) != user_raw):
            raise CredentialPreparationError("锐捷账号配置正在变化，请稍后重新导入。")
        return Credentials(username, password)
    except CredentialPreparationError:
        raise
    except Exception:
        # Filesystem errors can contain an account-named path. Never expose it.
        raise CredentialPreparationError("无法读取锐捷保存的账号，请检查客户端目录及版本，或手动输入。") from None


def _machine_material() -> bytes:
    """Reproduce 0x467094/0x467590/0x4ba25e; read-only IDENTIFY requests.

    Do not substitute modern storage-query serial numbers: their representation
    and fallback behavior differ from the actual client.
    """
    if os.name != "nt":
        raise CredentialPreparationError("认证凭据准备仅支持 Windows。")
    from ctypes import wintypes as w
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    api.CreateFileW.restype = w.HANDLE
    api.CloseHandle.argtypes = [w.HANDLE]
    api.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, ctypes.c_void_p, w.DWORD,
                                   ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
    api.DeviceIoControl.restype = w.BOOL
    api.GetSystemDirectoryW.argtypes = [w.LPWSTR, w.UINT]
    api.GetSystemDirectoryW.restype = w.UINT

    def query(path, access, code, incoming, out_size):
        handle = api.CreateFileW(path, access, 3, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            return None
        try:
            src = ctypes.create_string_buffer(incoming) if incoming else None
            dst = ctypes.create_string_buffer(out_size)
            count = w.DWORD()
            ok = api.DeviceIoControl(handle, code, src, len(incoming), dst, out_size, ctypes.byref(count), None)
            return bytes(dst) if ok else None
        finally:
            api.CloseHandle(handle)

    system = ctypes.create_unicode_buffer(260)
    disk = 0
    if api.GetSystemDirectoryW(system, 260):
        # VOLUME_DISK_EXTENTS: first DISK_EXTENT's disk number is at byte 8.
        result = query("\\\\.\\" + system.value[:2], 0x80000000, 0x560000, b"", 4096)
        if result and len(result) >= 12:
            disk = struct.unpack_from("<I", result, 8)[0]

    def serial_once():
        if disk > 3:
            return b""
        incoming = bytearray(32)
        struct.pack_into("<I", incoming, 0, 512)
        incoming[10] = 0xEC  # ATA IDENTIFY; never a disk write command.
        result = query(f"\\\\.\\PhysicalDrive{disk}", 0xC0000000, 0x7C088, bytes(incoming), 528)
        if not result:
            incoming = bytearray(60)
            struct.pack_into("<I", incoming, 0, 28)
            incoming[4:12] = b"SCSIDISK"
            struct.pack_into("<I", incoming, 12, 10000)
            struct.pack_into("<I", incoming, 16, 0x1B0501)
            struct.pack_into("<I", incoming, 24, 32)
            struct.pack_into("<I", incoming, 28, 512)
            incoming[38] = 0xEC
            result = query(f"\\\\.\\Scsi{disk}", 0xC0000000, 0x4D008, bytes(incoming), 556)
            if result:
                result = result[28:]
        if not result or len(result) < 56:
            return b""
        serial = bytearray()
        for i in range(36, 56, 2):
            serial.extend((result[i + 1], result[i]))
        return bytes(serial).replace(b" ", b"").split(b"\0", 1)[0]

    first = serial_once()
    second = serial_once()
    # Native retries once when two successive identity reads agree, and rejects
    # unstable or failed reads in favor of its deterministic fallback.
    if not first or first != second or first != serial_once():
        first = b"AB45A862"
    return hashlib.md5(first).digest()


def _encoded_text(text: str) -> bytes:
    return encode_profile(_native_bytes(text))


def _build_profiles(client_dir: Path, credentials: Credentials, material: bytes, *, adapter_name=None):
    username = credentials.username
    if username != username.strip() or not username or len(_native_bytes(username)) > 128 or any(ord(c) < 32 for c in username):
        raise CredentialPreparationError("账号为空、过长或包含客户端不支持的空白字符。")
    if any(c in username for c in "[];="):
        raise CredentialPreparationError("账号含有此版本配置格式不支持的字符。")
    global_path = client_dir / "SuConfig.dat"
    if (global_path.is_symlink() or (client_dir / "users").is_symlink()
            or getattr(client_dir / "users", "is_junction", lambda: False)()):
        raise CredentialPreparationError("原客户端配置路径异常，未修改。")
    original_global = global_path.read_bytes()
    global_text = _text(original_global)
    target = _user_path(client_dir, username)
    old_name = _get(global_text, "PUBLIC", "Name")
    template = target if target.is_file() else _user_path(client_dir, old_name) if old_name else None
    if template is None or not template.is_file():
        raise CredentialPreparationError("缺少可复用的原客户端用户配置，请先完成一次网卡和认证方式配置。")
    user_text = _text(template.read_bytes())
    if adapter_name is not None:
        if (not isinstance(adapter_name, str) or not adapter_name or len(adapter_name) > 256 or
                any(ord(c) < 32 or c in '[];=' for c in adapter_name)):
            raise CredentialPreparationError('所选有线网卡名称无效。')
        user_text = _set(user_text, 'PUBLIC', 'Adapter', adapter_name)
        user_text = _set(user_text, 'PUBLIC', 'AuthModeMediaType', 'Wire')
        user_text = _set(user_text, 'PUBLIC', 'AuthMode', 'EAPMD5')
    cipher = encrypt_native_password(credentials.password, material)
    for key, value in {"Password": cipher, "UserPassword": cipher, "SaveCheck": "1", "RunConnect": "1"}.items():
        user_text = _set(user_text, "PUBLIC", key, value)
    count_text = _get(global_text, "USERS", "Number", "0")
    if not count_text.isdecimal() or not 0 <= int(count_text) <= 1000:
        raise CredentialPreparationError("原客户端用户列表结构异常，未修改。")
    count = int(count_text)
    names = [_get(global_text, "USERS", f"username{i}") for i in range(count)]
    if username not in names:
        global_text = _set(global_text, "USERS", f"username{count}", username)
        global_text = _set(global_text, "USERS", "Number", str(count + 1))
    for section, key, value in [("PUBLIC", "Name", username), ("NETDETECT", "LastAuthUsername", username),
                                 ("PUBLIC", "SaveCheck", "1"), ("PUBLIC", "RunConnect", "1"),
                                 ("PUBLIC", "ModifySave", "1"),
                                 ("DOMAIN", "SupportSoftrunAuth", "1")]:
        global_text = _set(global_text, section, key, value)
    return [(target, _encoded_text(user_text)), (global_path, _encoded_text(global_text))]


def prepare_credentials(client_dir: Path, credentials: Credentials, log=lambda _: None, *, data_dir=None, operations=None, material_provider=None, adapter_name=None) -> dict:
    """Stop only the verified installation, atomically prepare, restore service.

    Return the result baseline and timestamp captured before the service can
    authenticate using the new profile. No authentication success is implied.
    Test seams never run real processes or networking.
    """
    from utils.core_install import CoreInstaller, InstallOperations
    from utils.auth_runtime import CoreSession, _running_core, result_snapshot, start_core
    from utils.auth_log import capture_auth_log

    client_dir = Path(client_dir).resolve()
    data_dir = Path(data_dir) if data_dir is not None else Path(os.environ.get("APPDATA", str(Path.home()))) / "CampusLogin"
    installer = CoreInstaller(client_dir, data_dir=data_dir, operations=operations or InstallOperations())
    ops = installer.operations
    attempted = []
    service = None
    journal = None
    try:
        if not isinstance(credentials, Credentials):
            raise CredentialPreparationError("账号输入格式无效。")
        material = (material_provider or _machine_material)()
        # Parse and encode in memory before touching a process or a live file.
        proposed = _build_profiles(client_dir, credentials, material, adapter_name=adapter_name)
        with installer._exclusive():
            _, patched, _ = installer._material()
            if core_patch.digest(installer.target.read_bytes()) != core_patch.digest(patched):
                raise CredentialPreparationError("认证核心不是本工具校验过的兼容版本，未写入账号。")
            if ops.other_core_paths(installer.target):
                raise CredentialPreparationError("另一安装目录的认证核心正在运行，未写入账号。")
            service = ops.service_snapshot()
            installer._verify_service(service)
            prior = installer._journal()
            if prior and prior.get("phase") not in ("complete", "rolled_back"):
                raise CredentialPreparationError("存在未完成的服务恢复记录，请先完成核心恢复。")
            journal = {"version": 1, "target": str(installer.target), "operation": "credentials",
                       "phase": "prepared", "service_before": service}
            installer._save_journal(journal)
            try:
                installer._stop(service, journal, log)
                ops.stop_exact_core(installer.target)
                if _running_core(installer.target) is not None:
                    raise CredentialPreparationError("认证核心尚未退出，未写入账号。")
                # The core may flush settings while shutting down. Rebuild from
                # its final files rather than replacing unrelated final changes.
                proposed = _build_profiles(client_dir, credentials, material, adapter_name=adapter_name)
                for path, content in proposed:
                    old = path.read_bytes() if path.exists() else None
                    path.parent.mkdir(parents=True, exist_ok=True)
                    attempted.append((path, old, content))
                    installer._atomic_write(path, content)
                    if path.read_bytes() != content:
                        raise CredentialPreparationError("写入的认证配置校验失败。")
                log_before = capture_auth_log(client_dir)
                before, started = result_snapshot(client_dir), time.time()
                journal["phase"] = "profile_prepared"
                installer._save_journal(journal)
                # The native service can launch a ShowHide/ShowNormal mode
                # which bypasses the user's RunConnect setting. Start the
                # ordinary software-start path while that service is stopped.
                session = start_core(client_dir, log)
                if not isinstance(session, CoreSession) or session.created_at < started:
                    raise CredentialPreparationError("未能确认使用新账号配置启动的认证核心。")
                installer._restore_service(service)
                if _running_core(installer.target) != session:
                    raise CredentialPreparationError("恢复锐捷服务后认证核心发生变化，未确认本次账号登录。")
                journal["phase"] = "complete"
                installer._save_journal(journal)
                installer._emit(log, "账号已通过原客户端兼容格式交给认证核心，正在等待新的认证结果。")
                return {"before": before, "started": started, "log_before": log_before}
            except Exception:
                rollback_failed = False
                # A partially restarted service must be stopped before restoring
                # a profile, using the same verified service boundaries.
                try:
                    current = ops.service_snapshot()
                    installer._verify_service(current)
                    installer._stop(current, journal, log)
                    ops.stop_exact_core(installer.target)
                    for path, old, written in reversed(attempted):
                        current_bytes = path.read_bytes() if path.exists() else None
                        if current_bytes == old:
                            continue
                        if current_bytes != written:
                            rollback_failed = True
                            continue
                        if old is None:
                            path.unlink(missing_ok=True)
                        else:
                            installer._atomic_write(path, old)
                except Exception:
                    rollback_failed = True
                try:
                    installer._restore_service(service)
                except Exception:
                    rollback_failed = True
                journal["phase"] = "recovery_required" if rollback_failed else "rolled_back"
                installer._save_journal(journal)
                if rollback_failed:
                    raise CredentialPreparationError("账号准备未完成，部分配置或锐捷服务尚未恢复，请使用恢复功能后重试。") from None
                raise CredentialPreparationError("账号准备未完成，原配置和锐捷服务状态已恢复。") from None
    except CredentialPreparationError:
        raise
    except Exception:
        # Paths below users contain an account identifier. Never surface raw
        # OS errors, crypto errors, source text, or chained exceptions to the UI.
        raise CredentialPreparationError("无法准备原客户端的账号配置；请确认管理员权限与客户端安装完整。") from None

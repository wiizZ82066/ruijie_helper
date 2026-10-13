"""Find an existing Ruijie installation without launching or changing anything.

Only known registry locations and a few paths beside this program are checked.
No disk walk, account file, password, or client configuration is read.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys

try:
    import winreg
except ImportError:  # Keep the discovery helpers and offline tests portable.
    winreg = None


def _path(value) -> Path | None:
    if not isinstance(value, (str, os.PathLike)):
        return None
    text = os.fspath(value).strip()
    if not text:
        return None
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1].strip()
    if not text:
        return None
    text = os.path.expandvars(os.path.expanduser(text))
    if text.startswith("\\??\\"):
        text = text[4:]
    try:
        return Path(text).resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def is_client_dir(path) -> bool:
    """Whether this directory contains the authentication core and its service.

    Existence is discovery, not version approval. CoreInstaller performs the
    executable hash and service-registration checks before any installation.
    """
    directory = _path(path)
    if directory is None:
        return False
    try:
        return (directory.is_dir() and (directory / "8021x.exe").is_file()
                and (directory / "suservice.exe").is_file())
    except (OSError, ValueError):
        return False


def _command_directory(value) -> Path | None:
    """Parse a registry executable command; never execute it.

    Quoted paths, unquoted paths with spaces, service arguments, environment
    variables, and DisplayIcon's trailing resource index are supported.
    """
    if not isinstance(value, str):
        return None
    value = os.path.expandvars(value.strip())
    match = re.match(r'^(?:"([^"\r\n]+\.exe)"|([^"\r\n]+?\.exe))(?=\s|,[-+]?\d+\s*$|$)', value,
                     re.IGNORECASE)
    if not match:
        return None
    executable = _path(match.group(1) or match.group(2))
    return executable.parent if executable else None


def _registry_value(root, key: str, name: str, view: int = 0):
    try:
        with winreg.OpenKey(root, key, 0, winreg.KEY_READ | view) as handle:
            value, _ = winreg.QueryValueEx(handle, name)
            return value if isinstance(value, str) else None
    except OSError:
        return None


def _uninstall_candidates(root, view):
    location = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    try:
        with winreg.OpenKey(root, location, 0, winreg.KEY_READ | view) as handle:
            # Bound registry enumeration even if a damaged key reports nonsense.
            count = min(winreg.QueryInfoKey(handle)[0], 4096)
            for index in range(count):
                try:
                    name = winreg.EnumKey(handle, index)
                except OSError:
                    continue
                key = location + "\\" + name
                display = _registry_value(root, key, "DisplayName", view) or ""
                product = (name + " " + display).casefold()
                if "ruijie" not in product and "锐捷" not in product:
                    continue
                yield _path(_registry_value(root, key, "InstallLocation", view))
                for field in ("DisplayIcon", "UninstallString"):
                    yield _command_directory(_registry_value(root, key, field, view))
    except OSError:
        return


def _registry_candidates():
    if winreg is None:
        return
    # SYSTEM is not WOW64-redirected. The running service's configured location
    # takes precedence over stale uninstall entries after an installation moves.
    service = _registry_value(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Services\RJSuService", "ImagePath")
    yield _command_directory(service)
    views = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for view in views:
            for executable in ("RuijieSupplicant.exe", "8021x.exe"):
                key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + executable
                yield _command_directory(_registry_value(root, key, "", view))
                yield _path(_registry_value(root, key, "Path", view))
            yield from _uninstall_candidates(root, view)


def _nearby_candidates():
    base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]
    yield base
    for name in ("Ruijie Supplicant", "RuijieSupplicant"):
        yield base / name
        yield base.parent / name


def discover_client_dir(saved_path=None) -> str | None:
    """Return the first valid absolute installation directory, or None.

    Priority: an explicit saved selection, the registered Ruijie service,
    application/uninstall records (both registry views), then nearby folders.
    Invalid or unavailable candidates are skipped. No directory is created.
    """
    selected = _path(saved_path)
    if is_client_dir(selected):
        return str(selected)
    seen = set()
    for source in (_registry_candidates, _nearby_candidates):
        for candidate in source():
            directory = _path(candidate)
            if directory is None:
                continue
            key = str(directory).casefold()
            if key in seen:
                continue
            seen.add(key)
            if is_client_dir(directory):
                return str(directory)
    return None

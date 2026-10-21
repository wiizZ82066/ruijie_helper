"""Pinned desktop runtime and Windows peer authentication for the Flet UI.

Flet 0.86.5's desktop protocol is unencrypted local IPC. Before it can read or
write any UI state, a peer must be the exact Flutter child launched here. This
does not protect against an administrator/debugger controlling either process.
No HTTP transport, user runtime cache, or runtime download is used at launch.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import importlib
import ipaddress
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

import psutil

FLET_VERSION = "0.86.5"
ARCHIVE_URL = "https://github.com/flet-dev/flet/releases/download/v0.86.5/flet-windows.zip"
ARCHIVE_SHA256 = "ded43763d47debd4474c6580ecbafdd745e7eb916d71d96e617fe655edfb37ac"
# Canonical JSON of the complete official archive's file map; see prepare_runtime.
MANIFEST_SHA256 = "b24ec5cf5be66d4ca84e2c44789bd5c0717b95206bd6947a57c87a3a8e1635b3"


class DesktopRuntimeError(RuntimeError):
    """A required desktop runtime or peer identity could not be verified."""


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _is_redirect(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def runtime_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "flet_runtime"
    return Path(__file__).resolve().parents[1] / "build" / "flet-runtime"


def validate_runtime(directory: Path | None = None) -> Path:
    """Validate all shipped files against a source-pinned manifest, then return EXE."""
    root = directory or runtime_directory()
    try:
        if _is_redirect(root) or not root.is_dir():
            raise ValueError("runtime directory")
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        if hashlib.sha256(_canonical(manifest)).hexdigest() != MANIFEST_SHA256:
            raise ValueError("manifest digest")
        if manifest["version"] != FLET_VERSION or manifest["archive_sha256"] != ARCHIVE_SHA256:
            raise ValueError("runtime version")
        expected = manifest["files"]
        actual = set()
        for item in root.rglob("*"):
            if _is_redirect(item):
                raise ValueError("redirected runtime path")
            if item.is_file() and item != root / "manifest.json":
                rel = item.relative_to(root).as_posix()
                actual.add(rel)
                if expected.get(rel) != _sha256(item):
                    raise ValueError("runtime file digest")
        if actual != set(expected) or "flet/flet.exe" not in actual:
            raise ValueError("runtime file inventory")
        return (root / "flet" / "flet.exe").resolve(strict=True)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise DesktopRuntimeError("Desktop runtime verification failed; rebuild with build_flet.ps1.") from exc


def _endpoint(address) -> tuple[str, int]:
    if not address or len(address) < 2:
        raise ValueError("Missing TCP endpoint")
    host = ipaddress.ip_address(address[0].split("%", 1)[0])
    if getattr(host, "ipv4_mapped", None) is not None:
        host = host.ipv4_mapped
    if not host.is_loopback:
        raise ValueError("Non-loopback TCP endpoint")
    return str(host), int(address[1])


@dataclass(frozen=True)
class _Child:
    pid: int
    created_at: float
    parent_pid: int
    executable: Path


class _PeerGuard:
    """Authenticate before Flet's handler can replace its existing connection."""

    def __init__(self, executable: Path):
        self.executable = executable.resolve(strict=True)
        self.child: _Child | None = None
        self.registered = asyncio.Event()
        self.failed = False
        self.process = None
        self.pid_file: Path | None = None
        self._launching = False

    def _register(self, pid: int) -> None:
        process = psutil.Process(pid)
        executable = Path(process.exe()).resolve(strict=True)
        if process.ppid() != os.getpid() or executable != self.executable:
            raise DesktopRuntimeError("Unexpected desktop child identity.")
        self.child = _Child(pid, process.create_time(), os.getpid(), executable)
        self.registered.set()

    async def launch(self, page_url, assets_dir, hidden):
        if self._launching:
            raise DesktopRuntimeError("A desktop view has already been launched.")
        self._launching = True
        # The URL contains only the local IPC port. Credentials never go through
        # command lines, environment variables, this PID file, or an HTTP server.
        if not re.fullmatch(r"tcp://localhost:[0-9]{1,5}", page_url):
            raise DesktopRuntimeError("Only the local desktop transport is supported.")
        descriptor, pid_file = tempfile.mkstemp(prefix="campus-flet-", suffix=".pid")
        os.close(descriptor)
        self.pid_file = Path(pid_file)
        args = [str(self.executable), page_url, pid_file]
        if assets_dir:
            args.append(str(Path(assets_dir).resolve(strict=True)))
        child_env = {k: v for k, v in os.environ.items() if not k.upper().startswith("FLET_")}
        if hidden:
            child_env["FLET_HIDE_WINDOW_ON_START"] = "true"
        try:
            self.process = await asyncio.create_subprocess_exec(
                *args, env=child_env, cwd=str(self.executable.parent),
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            self._register(self.process.pid)
            return self.process, pid_file
        except BaseException:
            self.failed = True
            self.registered.set()
            if self.process is not None and self.process.returncode is None:
                self.process.terminate()
                await self.process.wait()
            self.cleanup(pid_file)
            raise

    def _owns_connection(self, writer) -> bool:
        """Match the OS-owned reverse TCP tuple, not any value sent by the peer."""
        child = self.child
        if child is None or self.failed:
            return False
        try:
            peer = _endpoint(writer.get_extra_info("peername"))
            local = _endpoint(writer.get_extra_info("sockname"))
            matches = []
            for conn in psutil.net_connections(kind="tcp"):
                if not conn.laddr or not conn.raddr:
                    continue
                try:
                    reverse = _endpoint(conn.laddr), _endpoint(conn.raddr)
                except ValueError:
                    continue
                if reverse == (peer, local):
                    matches.append(conn)
            if len(matches) != 1 or matches[0].pid != child.pid or matches[0].status != psutil.CONN_ESTABLISHED:
                return False
            process = psutil.Process(child.pid)
            return (
                process.is_running()
                and process.create_time() == child.created_at
                and process.ppid() == child.parent_pid == os.getpid()
                and Path(process.exe()).resolve(strict=True) == child.executable == self.executable
            )
        except (psutil.Error, OSError, ValueError, TypeError, AttributeError):
            return False

    async def handle(self, original, server, reader, writer):
        try:
            # Flutter can connect before create_subprocess_exec returns its PID.
            await asyncio.wait_for(self.registered.wait(), timeout=2.0)
            allowed = await asyncio.to_thread(self._owns_connection, writer)
        except Exception:
            # A failed OS identity query is a denial, including unexpected
            # provider errors. Never pass an unverified connection to Flet.
            allowed = False
        if not allowed:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
            return
        await original(server, reader, writer)

    def cleanup(self, pid_file=None) -> None:
        # Never use Flet's writable PID-file contents to kill a process. The
        # normal launch awaits the subprocess; abnormal exit may need to stop it.
        if self.child is not None and self.process is not None and self.process.returncode is None:
            try:
                process = psutil.Process(self.child.pid)
                if (process.create_time() == self.child.created_at
                        and process.ppid() == self.child.parent_pid == os.getpid()
                        and Path(process.exe()).resolve(strict=True) == self.executable):
                    process.terminate()
            except (psutil.Error, OSError):
                pass
        if self.pid_file is not None:
            try:
                self.pid_file.unlink(missing_ok=True)
            except OSError:
                pass


def _silence_protocol_logs() -> None:
    names = {"flet", "flet_transport", "flet_object_patch", "flet_controls", "flet_desktop"}
    names.update(name for name in logging.Logger.manager.loggerDict if name.startswith("flet"))
    for name in names:
        logger = logging.getLogger(name)
        logger.setLevel(logging.CRITICAL + 1)
        logger.disabled = True
        logger.propagate = False


def _check_versions() -> None:
    import flet.version
    import flet_desktop.version
    if flet.version.flet_version != FLET_VERSION or flet_desktop.version.version != FLET_VERSION:
        raise DesktopRuntimeError("Install the exact dependencies from requirements-flet.txt.")


@contextmanager
def _replace_attribute(target, name, value):
    previous = getattr(target, name)
    setattr(target, name, value)
    try:
        yield
    finally:
        setattr(target, name, previous)


def run_desktop(main, *, assets_dir=None, hidden=False) -> None:
    """Run one pinned native view with peer verification and no web fallback."""
    if sys.platform != "win32":
        raise DesktopRuntimeError("This desktop launcher requires Windows.")
    import flet as ft
    import flet_desktop
    from flet.messaging.flet_socket_server import FletSocketServer
    app_module = importlib.import_module("flet.app")
    _check_versions()
    executable = validate_runtime()
    guard = _PeerGuard(executable)
    original = FletSocketServer.handle_connection

    async def checked_connection(server, reader, writer):
        await guard.handle(original, server, reader, writer)

    # These switches could force an HTTP/browser or embedding path. Ignore all
    # inherited Flet configuration for this deliberately desktop-only program.
    inherited = {k: v for k, v in os.environ.items() if k.upper().startswith("FLET_")}
    for key in inherited:
        os.environ.pop(key, None)
    _silence_protocol_logs()
    try:
        with _replace_attribute(FletSocketServer, "handle_connection", checked_connection), \
                _replace_attribute(flet_desktop, "open_flet_view_async", guard.launch), \
                _replace_attribute(flet_desktop, "close_flet_view", guard.cleanup), \
                _replace_attribute(app_module, "ensure_flet_desktop_package_installed", _check_versions):
            ft.run(main, view=ft.AppView.FLET_APP_HIDDEN if hidden else ft.AppView.FLET_APP,
                   assets_dir=assets_dir, port=0)
    finally:
        guard.cleanup()
        for key in list(os.environ):
            if key.upper().startswith("FLET_"):
                os.environ.pop(key, None)
        os.environ.update(inherited)


def prepare_runtime(project_directory: Path) -> Path:
    """Build-time only: download the official pinned archive and extract it safely."""
    import shutil
    import urllib.request
    import zipfile
    from uuid import uuid4
    project_directory = project_directory.resolve(strict=True)
    destination = project_directory / "build" / "flet-runtime"
    # A verified runtime is immutable input to a build. Reuse it, including
    # while a source preview is running, instead of deleting loaded DLLs.
    try:
        validate_runtime(destination)
        return destination
    except DesktopRuntimeError:
        pass
    downloads = project_directory / "build" / "flet-downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / f"flet-windows-{FLET_VERSION}.zip"
    if not archive.is_file() or _sha256(archive) != ARCHIVE_SHA256:
        partial = archive.with_suffix(".download")
        with urllib.request.urlopen(ARCHIVE_URL, timeout=60) as source, partial.open("wb") as output:
            shutil.copyfileobj(source, output)
        if _sha256(partial) != ARCHIVE_SHA256:
            partial.unlink(missing_ok=True)
            raise DesktopRuntimeError("Official Flet archive checksum mismatch.")
        partial.replace(archive)
    # Reconstruct from the verified archive in a new directory. Never trust a
    # user cache or silently retain extra DLLs from a previous extraction.
    # Python 3.14's mkdtemp(mode=0700) gives Windows directories a restricted
    # DACL. Renaming that directory into the runtime retains that ACL and can
    # make it unreadable to a restricted launcher/build runner. Public runtime
    # files should inherit the workspace ACL instead, as ordinary mkdir does.
    staging = downloads / ("flet-runtime-" + uuid4().hex)
    staging.mkdir()
    try:
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                relative = PurePosixPath(member.filename)
                if relative.is_absolute() or ".." in relative.parts or "\\" in member.filename or ":" in member.filename:
                    raise DesktopRuntimeError("Invalid desktop archive path.")
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise DesktopRuntimeError("Desktop archive contains a symbolic link.")
            bundle.extractall(staging)
        manifest = {"version": FLET_VERSION, "archive_sha256": ARCHIVE_SHA256,
                    "files": {p.relative_to(staging).as_posix(): _sha256(p)
                              for p in sorted(staging.rglob("*")) if p.is_file()}}
        if hashlib.sha256(_canonical(manifest)).hexdigest() != MANIFEST_SHA256:
            raise DesktopRuntimeError("Desktop archive file inventory does not match the source pin.")
        (staging / "manifest.json").write_bytes(_canonical(manifest))
        if destination.exists():
            if _is_redirect(destination) or destination.resolve().parent != (project_directory / "build").resolve():
                raise DesktopRuntimeError("Invalid build runtime directory.")
            for process in psutil.process_iter(["exe"]):
                try:
                    running_exe = process.info["exe"]
                    if running_exe and Path(running_exe).resolve().is_relative_to(destination.resolve()):
                        raise DesktopRuntimeError("Close desktop previews before replacing an invalid runtime.")
                except (psutil.Error, OSError):
                    continue
            shutil.rmtree(destination)
        staging.rename(destination)
        validate_runtime(destination)
        return destination
    finally:
        if staging.exists():
            shutil.rmtree(staging)

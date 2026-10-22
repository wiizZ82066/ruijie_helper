"""Synthetic desktop identities only; never starts an actual UI or network server."""
import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from fixture_support import fixture_directory
from utils import flet_runtime as runtime


class RuntimeManifestTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, "flet-runtime")
        self.exe = self.root / "flet" / "flet.exe"
        self.exe.parent.mkdir()
        self.exe.write_bytes(b"synthetic executable, never run")
        (self.exe.parent / "support.dll").write_bytes(b"synthetic DLL")
        self.manifest = {"version": runtime.FLET_VERSION, "archive_sha256": runtime.ARCHIVE_SHA256,
                         "files": {p.relative_to(self.root).as_posix(): runtime._sha256(p)
                                   for p in self.root.rglob("*") if p.is_file()}}
        (self.root / "manifest.json").write_bytes(runtime._canonical(self.manifest))
        pin = hashlib.sha256(runtime._canonical(self.manifest)).hexdigest()
        self.patch = patch.object(runtime, "MANIFEST_SHA256", pin)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_full_validated_inventory_returns_exact_executable(self):
        self.assertEqual(runtime.validate_runtime(self.root), self.exe.resolve())

    def test_changed_executable_and_rewritten_manifest_do_not_self_attest(self):
        self.exe.write_bytes(b"changed")
        self.manifest["files"]["flet/flet.exe"] = runtime._sha256(self.exe)
        (self.root / "manifest.json").write_bytes(runtime._canonical(self.manifest))
        with self.assertRaises(runtime.DesktopRuntimeError):
            runtime.validate_runtime(self.root)

    def test_missing_support_file_fails(self):
        (self.exe.parent / "support.dll").unlink()
        with self.assertRaises(runtime.DesktopRuntimeError):
            runtime.validate_runtime(self.root)

    def test_unexpected_dll_or_nested_manifest_fails(self):
        for name in ("untrusted.dll", "manifest.json"):
            with self.subTest(name=name):
                item = self.exe.parent / name
                item.write_bytes(b"extra")
                with self.assertRaises(runtime.DesktopRuntimeError):
                    runtime.validate_runtime(self.root)
                item.unlink()

    def test_redirected_file_fails_even_when_hash_matches(self):
        original = runtime._is_redirect
        with patch.object(runtime, "_is_redirect", side_effect=lambda p: p == self.exe or original(p)):
            with self.assertRaises(runtime.DesktopRuntimeError):
                runtime.validate_runtime(self.root)

    def test_prepare_reuses_fully_verified_runtime_without_download_or_reextract(self):
        project = fixture_directory(self, "flet-runtime-project")
        destination = project / "build" / "flet-runtime"
        shutil.copytree(self.root, destination)
        with patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected network")), \
             patch("zipfile.ZipFile", side_effect=AssertionError("Unexpected extraction")):
            self.assertEqual(runtime.prepare_runtime(project), destination)
        self.assertEqual(runtime.validate_runtime(destination), destination / "flet" / "flet.exe")


class PeerGuardTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.exe = fixture_directory(self, "flet-runtime-peer") / "flet.exe"
        self.exe.write_bytes(b"synthetic")
        self.guard = runtime._PeerGuard(self.exe)
        self.guard.child = runtime._Child(12001, 1234.5, os.getpid(), self.exe.resolve())
        self.guard.registered.set()
        self.writer = Mock()
        self.writer.wait_closed = AsyncMock()
        self.writer.get_extra_info.side_effect = lambda name: {
            "peername": ("127.0.0.1", 52001), "sockname": ("127.0.0.1", 52002)}[name]
        self.connection = SimpleNamespace(laddr=("127.0.0.1", 52001),
            raddr=("127.0.0.1", 52002), pid=12001, status=runtime.psutil.CONN_ESTABLISHED)
        self.process = Mock()
        self.process.create_time.return_value = 1234.5
        self.process.ppid.return_value = os.getpid()
        self.process.exe.return_value = str(self.exe)
        self.process.is_running.return_value = True
        self.connections = patch.object(runtime.psutil, "net_connections", return_value=[self.connection]).start()
        self.processes = patch.object(runtime.psutil, "Process", return_value=self.process).start()
        self.addCleanup(patch.stopall)

    async def test_exact_child_can_reach_original_handler(self):
        original = AsyncMock()
        await self.guard.handle(original, "server", "reader", self.writer)
        original.assert_awaited_once_with("server", "reader", self.writer)
        self.writer.close.assert_not_called()

    async def test_foreign_peer_never_replaces_existing_flet_client(self):
        self.connection.pid = 99999
        original = AsyncMock()
        await self.guard.handle(original, "server", "reader", self.writer)
        original.assert_not_called()
        self.writer.close.assert_called_once()

    def test_wrong_tuple_duplicate_unknown_owner_and_non_established_are_rejected(self):
        cases = [[], [self.connection, self.connection],
                 [SimpleNamespace(laddr=self.connection.laddr, raddr=self.connection.raddr, pid=None, status="ESTABLISHED")],
                 [SimpleNamespace(laddr=self.connection.laddr, raddr=self.connection.raddr, pid=12001, status="CLOSE_WAIT")],
                 [SimpleNamespace(laddr=self.connection.raddr, raddr=self.connection.laddr, pid=12001, status="ESTABLISHED")]]
        for connections in cases:
            with self.subTest(connections=connections):
                self.connections.return_value = connections
                self.assertFalse(self.guard._owns_connection(self.writer))

    def test_pid_reuse_parent_change_and_executable_change_are_rejected(self):
        for method, value in [("create_time", 1235.0), ("ppid", os.getpid() + 1),
                              ("exe", str(self.exe.parent / "different.exe")), ("is_running", False)]:
            with self.subTest(method=method):
                target = getattr(self.process, method)
                previous = target.return_value
                target.return_value = value
                self.assertFalse(self.guard._owns_connection(self.writer))
                target.return_value = previous

    def test_ipv6_loopback_works_but_external_address_is_rejected(self):
        self.writer.get_extra_info.side_effect = lambda name: {
            "peername": ("::1", 52001, 0, 0), "sockname": ("::1", 52002, 0, 0)}[name]
        self.connection.laddr, self.connection.raddr = ("::1", 52001), ("::1", 52002)
        self.assertTrue(self.guard._owns_connection(self.writer))
        self.writer.get_extra_info.side_effect = lambda name: ("192.0.2.1", 52001)
        self.assertFalse(self.guard._owns_connection(self.writer))

    def test_access_denied_fails_closed(self):
        self.connections.side_effect = runtime.psutil.AccessDenied()
        self.assertFalse(self.guard._owns_connection(self.writer))

    async def test_peer_waits_for_launch_registration_without_reading_protocol(self):
        self.guard.registered.clear()
        original = AsyncMock()
        pending = asyncio.create_task(self.guard.handle(original, "server", "reader", self.writer))
        await asyncio.sleep(0)
        original.assert_not_called()
        self.guard.registered.set()
        await pending
        original.assert_awaited_once()

    async def test_failed_launch_never_accepts_peer(self):
        self.guard.failed = True
        original = AsyncMock()
        await self.guard.handle(original, "server", "reader", self.writer)
        original.assert_not_called()

    async def test_unexpected_identity_provider_error_closes_peer(self):
        original = AsyncMock()
        with patch.object(self.guard, "_owns_connection", side_effect=RuntimeError("synthetic provider failure")):
            await self.guard.handle(original, "server", "reader", self.writer)
        original.assert_not_called()
        self.writer.close.assert_called_once()

    async def test_strict_launcher_ignores_inherited_runtime_web_and_cwd(self):
        process = SimpleNamespace(pid=12001, returncode=None)
        creator = AsyncMock(return_value=process)
        with patch.object(runtime.asyncio, "create_subprocess_exec", creator), \
             patch.dict(os.environ, {"FLET_VIEW_PATH": "untrusted", "FLET_FORCE_WEB_SERVER": "true"}):
            result, pid_file = await self.guard.launch("tcp://localhost:52002", None, False)
        self.assertIs(result, process)
        self.assertEqual(creator.call_args.args[0], str(self.exe.resolve()))
        self.assertEqual(creator.call_args.kwargs["cwd"], str(self.exe.parent.resolve()))
        self.assertFalse(any(k.startswith("FLET_") for k in creator.call_args.kwargs["env"]))
        Path(pid_file).unlink()

    async def test_web_url_is_never_launched(self):
        with patch.object(runtime.asyncio, "create_subprocess_exec", AsyncMock()) as creator:
            with self.assertRaises(runtime.DesktopRuntimeError):
                await self.guard.launch("http://localhost:8000", None, False)
            creator.assert_not_called()

    def test_cleanup_never_uses_writable_pid_file_to_choose_a_process(self):
        pid_file = self.exe.parent / "untrusted.pid"
        pid_file.write_text("99999")
        self.guard.pid_file = pid_file
        self.guard.process = SimpleNamespace(returncode=None)
        self.guard.cleanup(str(pid_file))
        self.processes.assert_called_once_with(12001)
        self.process.terminate.assert_called_once()
        self.assertFalse(pid_file.exists())


class LoggingTests(unittest.TestCase):
    def test_native_crash_is_not_a_successful_desktop_exit(self):
        exe = fixture_directory(self, 'exit-code') / 'flet.exe'
        exe.write_bytes(b'synthetic')
        events = Mock()
        guard = runtime._PeerGuard(exe, event_sink=events)
        for code in (0xc0000005, -1073741819, 1, None):
            guard.process = SimpleNamespace(returncode=code)
            with self.subTest(code=code), self.assertRaises(runtime.DesktopRuntimeError):
                guard.verify_exit()
            events.assert_called_with('desktop_exit', exit_code=code)
        guard.process.returncode = 0
        guard.verify_exit()

    def test_diagnostic_failure_does_not_change_normal_exit(self):
        exe = fixture_directory(self, 'exit-journal') / 'flet.exe'
        exe.write_bytes(b'synthetic')
        guard = runtime._PeerGuard(exe, event_sink=Mock(side_effect=OSError('disk unavailable')))
        guard.process = SimpleNamespace(returncode=0)
        guard.verify_exit()

    def test_protocol_and_control_logs_stay_disabled_even_under_root_debug(self):
        runtime._silence_protocol_logs()
        for name in ("flet", "flet_transport", "flet_object_patch", "flet_controls"):
            logger = logging.getLogger(name)
            self.assertTrue(logger.disabled)
            self.assertFalse(logger.propagate)
            self.assertFalse(logger.isEnabledFor(logging.DEBUG))


if __name__ == "__main__":
    unittest.main()

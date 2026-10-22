"""UI-independent service regressions; native, credential and network APIs are mocked."""
import base64
import builtins
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fixture_support import fixture_directory
from utils import auth_service, auth_startup
from utils.auth_runtime import CoreSession
from utils.credential_store import Credentials, CredentialUnlockError


GUID = "11111111-1111-4111-8111-111111111111"  # Synthetic, never a host adapter.
KEY = 'synthetic-hotspot"$123'
ACCOUNT = "synthetic-campus-account"
PASSWORD = 'synthetic-login"$123'


class AuthServiceTests(unittest.TestCase):
    def test_runtime_diagnostics_keep_exit_code_but_no_exception_text(self):
        self.service.record_runtime_event('runtime_failed', error=ValueError('secret-account secret-password'))
        self.service.record_runtime_event('desktop_exit', exit_code=-1073741819)
        self.service.record_runtime_event('unknown-event-secret')
        lines = self.service.journal.path.read_text(encoding='utf-8').splitlines()
        rows = [json.loads(line) for line in lines]
        self.assertEqual(rows[-2]['error_type'], 'ValueError')
        self.assertEqual(rows[-1]['outcome'], '0xC0000005')
        self.assertNotIn('secret', '\n'.join(lines))

    def mocked(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def setUp(self):
        self.root = fixture_directory(self, "auth-service")
        for target in ("subprocess.run", "subprocess.Popen", "psutil.process_iter"):
            self.mocked(target, side_effect=AssertionError("Real OS operations are forbidden"))
        self.mocked("ctypes.WinDLL", side_effect=AssertionError("Real native calls are forbidden"), create=True)
        # Python's Windows version probe can itself invoke a shell. ASCII
        # fixtures use the portable UTF-8 validation branch without that probe.
        self.mocked("utils.hotspot.platform.system", return_value="OfflineTestOS")
        self.store_type = self.mocked("utils.auth_service.CredentialStore", autospec=True)
        self.store = self.store_type.return_value
        self.store.load.return_value = None
        self.service = auth_service.CampusService(self.root / "user data", self.root / "source frontend.py")
        self.values = dict(auth_service.DEFAULT_SETTINGS, client_dir=str(self.root / "mock client"),
                           ethernet_guid=GUID, ssid="Synthetic hotspot", hotspot_key=KEY,
                           connection_mode="wired", wired_backend="native")
        self.credentials = Credentials(ACCOUNT, PASSWORD)
        self.logs = []
        self.cancel = threading.Event()
        self.client_valid = self.mocked("utils.auth_service.is_client_dir", return_value=True)
        self.discovery = self.mocked("utils.auth_service.discover_client_dir", return_value=None)
        self.installer_type = self.mocked("utils.auth_service.CoreInstaller", autospec=True)
        self.installer = self.installer_type.return_value
        self.installer.status.return_value = {"state": "patched", "recovery_needed": False}
        self.installer.restore.return_value = {"restored": True}
        self.prepare = self.mocked("utils.auth_service.prepare_credentials",
                                  return_value={"before": "new-account-baseline", "started": 200.0})
        self.session = CoreSession(123, 200.25)
        self.start = self.mocked("utils.auth_service.start_core", return_value=self.session)
        self.snapshot = self.mocked("utils.auth_service.result_snapshot", return_value="old-baseline")
        self.wait_auth = self.mocked("utils.auth_service.wait_authentication", return_value=True)
        self.hotspot_start = self.mocked("utils.auth_service.HotspotManager.start_hotspot_detailed",
                                        return_value={"ok": True, "ap_on": True})
        self.hotspot_stop = self.mocked("utils.auth_service.HotspotManager.stop_hotspot", return_value=(True, ""))
        self.hotspot_status = self.mocked("utils.auth_service.HotspotManager.get_hotspot_status", return_value="未启动")
        self.diagnostics = self.mocked("utils.auth_service.collect_network_diagnostics", return_value={"findings": []})
        self.startup = self.mocked("utils.auth_service.configure_startup", side_effect=lambda enabled, **_: {"enabled": enabled})
        self.mocked('utils.auth_service.WindowsOperations.list_adapters', return_value=[
            dict(guid=GUID, if_type=6, hardware_interface=True, status='Up', interface_description='Synthetic Ethernet')])
        self.monitor = self.mocked('utils.auth_service.NativeSessionMonitor', autospec=True).return_value
        self.monitor.verify.return_value = dict(connection_kind='wired', backend='native',
            authenticated=True, ready=True, active=True, retryable=False, message='已连接校园网 · 兼容认证')

    def tearDown(self):
        for secret in (ACCOUNT, PASSWORD, KEY):
            self.assertNotIn(secret, repr(self.logs))

    def connect(self, **overrides):
        return self.service.connect(dict(self.values, **overrides), self.credentials, True, self.cancel, self.logs.append)

    def test_module_import_never_imports_a_gui_framework_or_entrypoint(self):
        original = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name.startswith("PySide6") or name == "campus_authenticator":
                raise AssertionError("GUI import is forbidden")
            return original(name, *args, **kwargs)
        spec = importlib.util.spec_from_file_location("offline_auth_service_import", auth_service.__file__)
        with patch("builtins.__import__", side_effect=guarded):
            spec.loader.exec_module(importlib.util.module_from_spec(spec))

    def test_import_saves_dpapi_and_disables_legacy_without_touching_network(self):
        self.service.save_settings(dict(self.values, legacy_saved_login=True))
        reader = self.mocked("utils.auth_service.read_saved_credentials", return_value=self.credentials)
        result = self.service.import_credentials(self.values)
        self.assertIs(result, self.credentials)
        reader.assert_called_once_with(Path(self.values["client_dir"]).resolve())
        self.store.save.assert_called_once_with(self.credentials, remember=True)
        self.assertFalse(self.service.load_settings()["legacy_saved_login"])
        self.assertNotIn(ACCOUNT, self.service.settings_path.read_text(encoding="utf-8"))
        self.prepare.assert_not_called()
        self.installer.install.assert_not_called()
        self.start.assert_not_called()
        self.hotspot_start.assert_not_called()

    def test_import_preserves_locked_vault_and_does_not_read_native_profile(self):
        self.store.load.side_effect = CredentialUnlockError("无法解锁")
        reader = self.mocked("utils.auth_service.read_saved_credentials")
        with self.assertRaises(CredentialUnlockError):
            self.service.import_credentials(self.values)
        reader.assert_not_called()
        self.store.save.assert_not_called()

    def test_failed_native_import_does_not_replace_existing_credentials(self):
        self.mocked("utils.auth_service.read_saved_credentials", side_effect=ValueError("未保存密码"))
        with self.assertRaisesRegex(ValueError, "未保存密码"):
            self.service.import_credentials(self.values)
        self.store.save.assert_not_called()
        self.assertFalse(self.service.settings_path.exists())

    def test_defaults_and_load_whitelist_never_include_account_fields(self):
        self.assertEqual(self.service.load_settings(), auth_service.DEFAULT_SETTINGS)
        self.assertFalse(self.service.data_dir.exists())
        self.service.data_dir.mkdir()
        self.service.settings_path.write_text(json.dumps(dict(self.values, username=ACCOUNT, password=PASSWORD,
                                                              arbitrary="discard")), encoding="utf-8")
        loaded = self.service.load_settings()
        self.assertEqual(set(loaded), set(auth_service.DEFAULT_SETTINGS))
        self.assertEqual(loaded["hotspot_key"], KEY)
        self.assertNotIn(ACCOUNT, json.dumps(loaded))

    def test_save_is_atomic_and_whitelisted_and_partial_updates_preserve_values(self):
        saved = self.service.save_settings(dict(self.values, username=ACCOUNT, password=PASSWORD))
        self.assertEqual(json.loads(self.service.settings_path.read_text(encoding="utf-8")), saved)
        self.assertEqual(set(saved), set(auth_service.DEFAULT_SETTINGS))
        updated = self.service.save_settings({"auto_login": False})
        self.assertEqual(updated["ssid"], self.values["ssid"])
        self.assertFalse(updated["auto_login"])
        self.assertEqual(list(self.service.data_dir.iterdir()), [self.service.settings_path])

    def test_invalid_settings_do_not_replace_previous_file(self):
        self.service.save_settings(self.values)
        previous = self.service.settings_path.read_bytes()
        for changes in ({"hotspot_key": "short"}, {"band": "unsupported"}, {"auto_login": "false"},
                        {"ethernet_guid": None, "auto_hotspot": True}):
            with self.subTest(fields=list(changes)), self.assertRaises(ValueError):
                self.service.save_settings(dict(self.values, **changes))
            self.assertEqual(self.service.settings_path.read_bytes(), previous)

    def test_credentials_load_and_clear_preserve_locked_data_until_explicit_clear(self):
        self.store.load.return_value = self.credentials
        self.assertEqual(self.service.load_credentials(), self.credentials)
        self.store.load.side_effect = CredentialUnlockError("Synthetic locked record")
        with self.assertRaises(CredentialUnlockError):
            self.service.load_credentials()
        self.store.clear.assert_not_called()
        self.service.clear_credentials()
        self.store.clear.assert_called_once()
        self.assertEqual(self.service._login_secrets, set())

    def test_only_hardware_ethernet_is_returned_and_discovery_uses_explicit_path(self):
        physical = {"guid": GUID, "if_type": 6, "hardware_interface": True}
        with patch.object(auth_service.WindowsOperations, "list_adapters", return_value=[physical,
                {"if_type": 6, "hardware_interface": False}, {"if_type": 71, "hardware_interface": True},
                {"if_type": 53, "hardware_interface": False}]):
            self.assertEqual(self.service.list_adapters(), [physical])
        self.service.discover_client(self.values["client_dir"])
        self.discovery.assert_called_once_with(self.values["client_dir"])

    def test_patched_core_prepares_credentials_and_waits_for_exact_new_session(self):
        order = Mock()
        for name, method in (("save_credentials", self.store.save), ("prepare", self.prepare),
                             ("start", self.start), ("wait", self.wait_auth)):
            order.attach_mock(method, name)
        result = self.connect()
        self.assertEqual([entry[0] for entry in order.mock_calls], ["save_credentials", "prepare", "start", "wait"])
        self.installer.install.assert_not_called()
        self.store.save.assert_called_once_with(self.credentials, remember=True)
        self.assertEqual(self.prepare.call_args.kwargs["data_dir"], self.service.data_dir)
        self.assertEqual(self.wait_auth.call_args.args[1:4], ("new-account-baseline", 200.0, self.cancel))
        self.assertIs(self.wait_auth.call_args.kwargs["session"], self.session)
        self.assertIsNone(self.wait_auth.call_args.kwargs["ethernet_adapter_guid"])
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["ready"])
        self.hotspot_start.assert_not_called()

    def test_original_or_interrupted_install_is_completed_before_preparation(self):
        for current in ({"state": "original"}, {"state": "patched", "recovery_needed": True}):
            with self.subTest(state=current):
                self.installer.status.return_value = current
                order = Mock()
                order.attach_mock(self.installer.install, "install")
                order.attach_mock(self.prepare, "prepare")
                self.connect()
                self.assertEqual([entry[0] for entry in order.mock_calls], ["install", "prepare"])

    def test_unknown_core_and_unavailable_preparation_cannot_start_any_session(self):
        with patch.object(auth_service, "prepare_credentials", None), self.assertRaises(RuntimeError):
            self.connect()
        self.store.save.assert_not_called()
        self.installer_type.assert_not_called()
        self.installer.status.return_value = {"state": "unknown"}
        with self.assertRaises(RuntimeError):
            self.connect()
        self.installer.install.assert_not_called()
        self.prepare.assert_not_called()
        self.start.assert_not_called()

    def test_missing_credentials_never_fall_back_to_previous_native_account(self):
        with self.assertRaises(ValueError):
            self.service.connect(self.values, None, False, self.cancel, self.logs.append)
        self.store.save.assert_not_called()
        self.start.assert_not_called()

    def test_malformed_preparation_or_older_session_cannot_validate_old_success(self):
        for prepared in ({}, {"before": "x", "started": True}, {"before": "x", "started": float("nan")}):
            with self.subTest(prepared_fields=list(prepared)):
                self.prepare.return_value = prepared
                with self.assertRaises(RuntimeError):
                    self.connect()
        self.start.assert_not_called()
        self.prepare.return_value = {"before": "new", "started": 201.0}
        with self.assertRaises(RuntimeError):
            self.connect()
        self.wait_auth.assert_not_called()

    def test_legacy_saved_login_prepares_credentials_and_waits_for_new_session(self):
        reader = self.mocked("utils.auth_service.read_saved_credentials", return_value=self.credentials)
        result = self.service.connect(dict(self.values, legacy_saved_login=True), None, False, self.cancel, self.logs.append)
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["ready"])
        reader.assert_called_once()
        self.assertEqual(self.prepare.call_args.args[1], self.credentials)
        self.store.save.assert_not_called()
        self.start.assert_called_once()
        self.assertEqual(self.wait_auth.call_args.args[1:3], ("new-account-baseline", 200.0))
        self.assertIsNone(self.wait_auth.call_args.kwargs["ethernet_adapter_guid"])

    def test_legacy_auto_hotspot_requires_fresh_authentication(self):
        self.mocked("utils.auth_service.read_saved_credentials", return_value=self.credentials)
        self.service.connect(dict(self.values, legacy_saved_login=True, auto_hotspot=True),
                             None, False, self.cancel, self.logs.append)
        self.assertIsNone(self.wait_auth.call_args.kwargs["ethernet_adapter_guid"])
        self.assertIs(self.wait_auth.call_args.kwargs["session"], self.session)
        self.hotspot_start.assert_called_once()

    def test_missing_native_password_fails_before_any_authentication_changes(self):
        self.mocked("utils.auth_service.read_saved_credentials", side_effect=RuntimeError("锐捷未保存密码"))
        with self.assertRaisesRegex(RuntimeError, "未保存密码"):
            self.service.connect(dict(self.values, legacy_saved_login=True), None, False, self.cancel, self.logs.append)
        self.prepare.assert_not_called()
        self.installer.install.assert_not_called()
        self.start.assert_not_called()
        self.assertFalse(self.service.settings_path.exists())

    def test_automatic_connect_skips_without_physical_ethernet_before_reading_credentials(self):
        reader = self.mocked("utils.auth_service.read_saved_credentials", return_value=self.credentials)
        selected = dict(guid=GUID, if_type=6, hardware_interface=True, status="Up")
        for rows in [[], [dict(selected, status="Down")], [dict(selected, hardware_interface=False)],
                     [dict(selected, if_type=71)], [dict(selected, guid="another-interface")]]:
            with self.subTest(rows=rows), patch.object(self.service, "list_adapters", return_value=rows):
                result = self.service.connect(dict(self.values, legacy_saved_login=True), None, False,
                    self.cancel, self.logs.append, require_ethernet=True)
                self.assertTrue(result["skipped"])
                self.assertFalse(result["authenticated"])
        reader.assert_not_called()
        self.store.save.assert_not_called()
        self.installer.install.assert_not_called()
        self.start.assert_not_called()
        self.assertFalse(self.service.settings_path.exists())

    def test_automatic_connect_uses_unique_up_ethernet_and_then_authenticates(self):
        selected = dict(guid=GUID, if_type=6, hardware_interface=True, status="Up")
        with patch.object(self.service, "list_adapters", return_value=[selected]):
            result = self.service.connect(dict(self.values, ethernet_guid=None), self.credentials, True,
                self.cancel, self.logs.append, require_ethernet=True)
        self.assertTrue(result["authenticated"])
        self.assertEqual(self.service.load_settings()["ethernet_guid"], GUID)

    def test_automatic_connect_does_not_guess_between_two_ethernet_connections(self):
        rows = [dict(guid=guid, if_type=6, hardware_interface=True, status="Up")
                for guid in (GUID, "22222222-2222-4222-8222-222222222222")]
        with patch.object(self.service, "list_adapters", return_value=rows):
            result = self.service.connect(dict(self.values, ethernet_guid=None), self.credentials, True,
                self.cancel, self.logs.append, require_ethernet=True)
        self.assertTrue(result["skipped"])
        self.start.assert_not_called()

    def test_adapter_probe_failure_or_cancellation_cannot_start_authentication(self):
        with patch.object(self.service, "list_adapters", side_effect=RuntimeError("网卡读取失败")):
            with self.assertRaisesRegex(RuntimeError, "网卡读取失败"):
                self.service.connect(self.values, self.credentials, True, self.cancel,
                                     self.logs.append, require_ethernet=True)
        def adapters():
            self.cancel.set()
            return [dict(guid=GUID, if_type=6, hardware_interface=True, status="Up")]
        with patch.object(self.service, "list_adapters", side_effect=adapters):
            result = self.service.connect(self.values, self.credentials, True, self.cancel,
                                          self.logs.append, require_ethernet=True)
        self.assertFalse(result["authenticated"])
        self.store.save.assert_not_called()
        self.start.assert_not_called()

    def test_failed_authentication_keeps_core_and_never_opens_hotspot(self):
        self.wait_auth.return_value = False
        result = self.connect(auto_hotspot=True)
        self.assertFalse(result["authenticated"])
        self.assertFalse(result["ready"])
        self.start.assert_called_once()
        self.hotspot_start.assert_not_called()

    def test_cancellation_before_work_or_after_verification_never_opens_hotspot(self):
        self.cancel.set()
        self.assertFalse(self.connect(auto_hotspot=True)["authenticated"])
        self.store.save.assert_not_called()
        self.start.assert_not_called()
        self.cancel.clear()
        def verified_then_cancel(*_, **__):
            self.cancel.set()
            return True
        self.wait_auth.side_effect = verified_then_cancel
        self.assertFalse(self.connect(auto_hotspot=True)["ready"])
        self.hotspot_start.assert_not_called()

    def test_partial_hotspot_failure_retains_actual_radio_state_and_redacts_errors(self):
        self.hotspot_start.return_value = {"ok": False, "ap_on": True, "error": json.dumps({"key": KEY})}
        result = self.connect(auto_hotspot=True)
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["hotspot"])
        self.assertFalse(result["ready"])
        self.assertIn("[redacted]", "".join(self.logs))
        self.assertNotIn(json.dumps(KEY)[1:-1], "".join(self.logs))

    def test_cancel_while_auto_hotspot_waits_for_status_lock_never_starts_radio(self):
        entered, release, waiting = threading.Event(), threading.Event(), threading.Event()

        class ObservedLock:
            """Expose real lock contention without timing-based assertions."""
            def __init__(self):
                self.lock = threading.RLock()

            def __enter__(self):
                if not self.lock.acquire(blocking=False):
                    waiting.set()
                    self.lock.acquire()
                return self

            def __exit__(self, *_):
                self.lock.release()

        self.service._hotspot_lock = ObservedLock()

        def status(_):
            entered.set()
            if not release.wait(3):
                raise RuntimeError("Synthetic test release missing")
            return "未启动"

        self.hotspot_status.side_effect = status
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending_status = pool.submit(self.service.hotspot_status, GUID)
            try:
                self.assertTrue(entered.wait(1))
                pending_connect = pool.submit(self.connect, auto_hotspot=True)
                self.assertTrue(waiting.wait(1))
                self.assertFalse(pending_connect.done())
                self.cancel.set()
            finally:
                release.set()
            self.assertEqual(pending_status.result(timeout=1), "未启动")
            result = pending_connect.result(timeout=1)
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["cancelled"])
        self.assertFalse(result["ready"])
        self.assertNotIn("hotspot", result)
        self.hotspot_start.assert_not_called()
        # Cancellation belongs to automatic post-login work; a later explicit
        # manual request still operates through the usual serialized path.
        self.assertTrue(self.service.toggle_hotspot(True, self.values, self.logs.append)["ready"])
        self.hotspot_start.assert_called_once()

    def test_sensitive_upstream_exception_is_redacted_before_frontend_receives_it(self):
        self.prepare.side_effect = RuntimeError(ACCOUNT + " " + json.dumps(PASSWORD))
        with self.assertRaises(RuntimeError) as caught:
            self.connect()
        self.assertIn("[redacted]", str(caught.exception))
        self.assertNotIn(ACCOUNT, str(caught.exception))
        self.assertNotIn(json.dumps(PASSWORD)[1:-1], str(caught.exception))
        self.start.assert_not_called()

    def test_stop_ignores_unfinished_settings_and_missing_source(self):
        result = self.service.toggle_hotspot(False, {"hotspot_key": "", "ethernet_guid": None}, self.logs.append)
        self.assertFalse(result["hotspot"])
        self.hotspot_stop.assert_called_once_with(None)
        self.assertFalse(self.service.settings_path.exists())

    def test_startup_enabling_requires_completed_install_and_targets_instance_entry(self):
        for current in ({"state": "original"}, {"state": "patched", "recovery_needed": True}):
            with self.subTest(current=current), self.assertRaises(RuntimeError):
                self.installer.status.return_value = current
                self.service.set_startup(True, self.values, self.logs.append)
        self.startup.assert_not_called()
        self.installer.status.return_value = {"state": "patched"}
        self.assertTrue(self.service.set_startup(True, self.values, self.logs.append)["enabled"])
        self.startup.assert_called_once_with(True, entry_script=self.service.entry_script)
        self.service.set_startup(False, {}, self.logs.append)
        self.startup.assert_called_with(False, entry_script=self.service.entry_script)

    def test_startup_read_uses_stable_user_task_even_after_moving_program(self):
        with patch("utils.auth_service.subprocess.run") as run:
            for content, code, expected in [('{"enabled":true}', 0, True), ('{"enabled":false}', 0, False),
                                            ('{"enabled":null}', 0, None), ('{"enabled":false}', 1, None),
                                            ('{"enabled":"false"}', 0, None), ('invalid', 0, None)]:
                run.return_value = SimpleNamespace(returncode=code, stdout=content)
                self.assertIs(self.service.read_startup_state(), expected)
            payload = json.loads(run.call_args.kwargs["input"])
            self.assertEqual(payload["arguments"], subprocess.list2cmdline([str(self.service.entry_script), "--connect", "--minimized"]))
            script = base64.b64decode(run.call_args.args[0][-1]).decode("utf-16le")
            self.assertNotIn("$action.Arguments -ine [string]$data.arguments", script)
            self.assertIn("CampusLogin-", script)
            self.assertNotIn("IndexOf", script)

    def test_startup_helper_keeps_default_entry_and_supports_custom_or_frozen_entry(self):
        with patch.object(sys, "frozen", False, create=True), patch("utils.auth_startup.subprocess.run") as run:
            run.return_value = SimpleNamespace(returncode=0, stdout='{"enabled":true}')
            auth_startup.set_startup(True)
            default_payload = json.loads(run.call_args.kwargs["input"])
            self.assertIn("campus_authenticator.py", default_payload["arguments"])
            auth_startup.set_startup(True, entry_script=self.service.entry_script)
            self.assertEqual(json.loads(run.call_args.kwargs["input"]),
                             dict(default_payload, arguments=self.service._startup_identity()["arguments"]))
            with patch.object(sys, "frozen", True, create=True):
                auth_startup.set_startup(True, entry_script=self.service.entry_script)
                payload = json.loads(run.call_args.kwargs["input"])
                self.assertEqual(payload["arguments"], "--connect --minimized")
                self.assertEqual(payload["executable"], sys.executable)
                self.assertEqual(self.service._startup_identity()["arguments"], payload["arguments"])

    def test_startup_disable_requires_confirmed_system_result(self):
        with patch('utils.auth_startup.subprocess.run') as run:
            run.return_value=SimpleNamespace(returncode=0,stdout='{"enabled":true}')
            with self.assertRaisesRegex(RuntimeError,'未确认'):
                auth_startup.set_startup(False)
            run.return_value=SimpleNamespace(returncode=0,stdout='{"enabled":false}')
            self.assertFalse(auth_startup.set_startup(False)['enabled'])
            script=base64.b64decode(run.call_args.args[0][-1]).decode('utf-16le')
            self.assertIn('$folder.DeleteTask($name, 0)',script)
            self.assertIn('Startup removal not confirmed',script)

    def test_uninstall_preserves_task_owned_by_another_copy(self):
        with patch('utils.auth_startup.subprocess.run') as run:
            run.return_value = SimpleNamespace(returncode=0, stdout='{"enabled":true,"preserved":true}')
            self.assertTrue(auth_startup.set_startup(False, remove_only_matching=True)['preserved'])
            payload = json.loads(run.call_args.kwargs['input'])
            self.assertTrue(payload['remove_only_matching'])
            with self.assertRaises(RuntimeError):
                auth_startup.set_startup(False)

    def test_restore_disables_future_automation_even_with_invalid_hotspot_draft(self):
        result = self.service.restore(dict(self.values, auto_login=True, auto_hotspot=True, hotspot_key=""), self.logs.append)
        self.installer.restore.assert_called_once()
        self.startup.assert_called_once_with(False, entry_script=self.service.entry_script)
        saved = self.service.load_settings()
        self.assertFalse(saved["auto_login"])
        self.assertFalse(saved["auto_hotspot"])
        self.assertTrue(result["startup_disabled"])
        self.assertTrue(result["settings_saved"])

    def test_restore_reports_task_failure_but_still_disables_saved_automation(self):
        self.startup.side_effect = RuntimeError(KEY)
        result = self.service.restore(self.values, self.logs.append)
        self.assertFalse(result["startup_disabled"])
        self.assertTrue(result["settings_saved"])
        self.assertFalse(self.service.load_settings()["auto_login"])
        self.assertIn("[redacted]", "".join(self.logs))

    def test_hotspot_operations_serialize_but_unrelated_connection_reads_are_not_blocked(self):
        entered, release, toggle_called = threading.Event(), threading.Event(), threading.Event()
        order = []
        def status(_):
            order.append("read-enter")
            entered.set()
            if not release.wait(3):
                raise RuntimeError("Synthetic test release missing")
            order.append("read-exit")
            return "未启动"
        def stop(_):
            order.append("stop")
            return True, ""
        def toggle():
            toggle_called.set()
            return self.service.toggle_hotspot(False, self.values, self.logs.append)
        self.hotspot_status.side_effect = status
        self.hotspot_stop.side_effect = stop
        with ThreadPoolExecutor(max_workers=3) as pool:
            pending_status = pool.submit(self.service.hotspot_status, GUID)
            try:
                self.assertTrue(entered.wait(1))
                self.assertTrue(pool.submit(self.connect).result(timeout=1)["authenticated"])
                pending_stop = pool.submit(toggle)
                self.assertTrue(toggle_called.wait(1))
                self.hotspot_stop.assert_not_called()
            finally:
                release.set()
            self.assertEqual(pending_status.result(timeout=1), "未启动")
            self.assertFalse(pending_stop.result(timeout=1)["hotspot"])
        self.assertEqual(order, ["read-enter", "read-exit", "stop"])


if __name__ == "__main__":
    unittest.main()

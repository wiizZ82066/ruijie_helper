"""Offline Qt workflow tests: every native/core/network boundary is mocked."""
import json
import os
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from fixture_support import fixture_directory

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QEventLoop, QThread, QTimer, Qt
    from PySide6.QtWidgets import QApplication, QLineEdit, QLabel
    from campus_authenticator import (AuthWindow, HotspotManager, WindowsOperations,
                                     read_startup_state, run_packaged_self_test)
    from utils.credential_store import Credentials, CredentialUnlockError
except ImportError:
    AuthWindow = None

# Deliberately synthetic adapter identity; never copied from a host.
GUID = "11111111-1111-4111-8111-111111111111"
SECRET = 'Offline-Sensitive"$Key123'


@unittest.skipIf(AuthWindow is None, "PySide6 is not installed")
class AuthenticatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def mocked(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def setUp(self):
        self.root = fixture_directory(self, "authenticator")
        self.client_dir = self.root / "mock-client"
        self.data_dir = self.root / "mock-user-data"
        self.mocked("campus_authenticator.DATA_DIR", new=self.data_dir)
        self.mocked("campus_authenticator.SETTINGS", new=self.data_dir / "settings.json")
        # Guard native boundaries before constructing any widget.
        self.mocked("subprocess.Popen", side_effect=AssertionError("Real process creation is forbidden in offline tests"))
        self.mocked("subprocess.run", side_effect=AssertionError("Real commands are forbidden in offline tests"))
        self.discover = self.mocked("campus_authenticator.discover_client_dir", return_value=str(self.client_dir))
        self.valid_client = self.mocked("campus_authenticator.is_client_dir", return_value=True)
        self.store_type = self.mocked("campus_authenticator.CredentialStore", autospec=True)
        self.store = self.store_type.return_value
        self.store.load.return_value = None
        self.prepare = self.mocked("campus_authenticator.prepare_credentials", return_value={"before": "prepared-baseline", "started": 12345.0})
        loaded = {"ssid": "Existing", "hotspot_key": "KeptKey123"} if self._testMethodName == "test_existing_settings_override_new_defaults" else {}
        with patch.object(AuthWindow, "_load_settings", staticmethod(lambda _: loaded)):
            self.window = AuthWindow(self_test=True)
        self.initial_defaults = (self.window.ssid.text(), self.window.key.text())
        self.window.client.setText(str(self.client_dir))
        self.window.legacy_login.setChecked(True)  # Existing workflow tests exercise the explicit compatibility option.
        self.window.key.setText(SECRET)
        self.value = {
            "client_dir": str(self.client_dir), "auto_login": True,
            "auto_hotspot": False, "ethernet_guid": GUID,
            "ssid": "Offline Campus", "hotspot_key": SECRET, "band": "2.4GHz",
        }
        self.save = self.mocked("campus_authenticator.AuthWindow.save", return_value=self.value)
        self.installer_type = self.mocked("campus_authenticator.CoreInstaller", autospec=True)
        self.installer = self.installer_type.return_value
        self.installer.status.return_value = {"state": "patched", "recovery_needed": False}
        self.start = self.mocked("campus_authenticator.start_core", return_value=True)
        self.snapshot = self.mocked("campus_authenticator.result_snapshot", return_value="before")
        self.wait_auth = self.mocked("campus_authenticator.wait_authentication", return_value=True)
        self.hotspot_start = self.mocked("campus_authenticator.HotspotManager.start_hotspot_detailed",
                                       return_value={"ok": True, "ap_on": True, "sharing_ready": True})
        self.hotspot_stop = self.mocked("campus_authenticator.HotspotManager.stop_hotspot", return_value=(True, ""))
        self.hotspot_status = self.mocked("campus_authenticator.HotspotManager.get_hotspot_status", return_value="未启动")
        self.startup = self.mocked("campus_authenticator.set_startup", side_effect=lambda enabled: {"enabled": enabled})
        self.kill_move = self.mocked("utils.supplicant.SupplicantManager.kill_and_move")
        self.quarantine = self.mocked("utils.campus_connection.CampusConnectionManager._quarantine_component")
        self.adapter_changes = self.mocked("utils.campus_connection.WindowsOperations.set_adapter_enabled")

    def tearDown(self):
        self.assertIsNone(self.window._thread)
        self.kill_move.assert_not_called()
        self.quarantine.assert_not_called()
        self.adapter_changes.assert_not_called()
        self.assertNotIn(SECRET, self.window.log.toPlainText())
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()

    def wait_job(self):
        loop, poll, watchdog = QEventLoop(), QTimer(), QTimer()
        poll.setInterval(10)
        poll.timeout.connect(lambda: loop.quit() if self.window._thread is None else None)
        watchdog.setSingleShot(True)
        watchdog.timeout.connect(loop.quit)
        poll.start()
        watchdog.start(3000)
        loop.exec()
        poll.stop()
        watchdog.stop()
        self.assertIsNone(self.window._thread, "Mock job did not finish")

    def test_callbacks_are_on_main_thread_and_failure_allows_reuse(self):
        def fail(log):
            raise RuntimeError("offline failure")
        self.window.run_job(fail)
        self.wait_job()
        self.assertIn("offline failure", self.window.log.toPlainText())
        calls = []
        self.window.run_job(lambda log: QThread.currentThread() != self.app.thread(),
                            lambda was_worker: calls.append((was_worker, QThread.currentThread() == self.app.thread())))
        self.wait_job()
        self.assertEqual(calls, [(True, True)])
        self.assertTrue(self.window.controls.isEnabled())

    def test_overview_reads_overlap_and_results_apply_on_main_thread(self):
        barrier = threading.Barrier(3)
        readers, callbacks = [], []
        adapters = [{"guid": GUID, "name": "Synthetic Ethernet", "status": "Up",
                     "if_type": 6, "hardware_interface": True}]

        def read(value):
            readers.append((threading.get_ident(), QThread.currentThread() == self.app.thread()))
            # A sequential implementation breaks the barrier and fails this test.
            barrier.wait(timeout=1.5)
            return value

        def record_callback(original):
            def apply(value):
                callbacks.append(QThread.currentThread() == self.app.thread())
                original(value)
            return apply

        self.hotspot_status.side_effect = lambda _: read("已启动")
        with patch.object(WindowsOperations, "list_adapters", side_effect=lambda: read(adapters)), \
             patch("campus_authenticator.read_startup_state", side_effect=lambda: read(True)), \
             patch.object(self.window, "_apply_adapters", side_effect=record_callback(self.window._apply_adapters)), \
             patch.object(self.window, "_set_startup_state", side_effect=record_callback(self.window._set_startup_state)), \
             patch.object(self.window, "_apply_hotspot_status", side_effect=record_callback(self.window._apply_hotspot_status)):
            self.window.refresh_overview()
            self.wait_job()
        self.assertEqual(len({identity for identity, _ in readers}), 3)
        self.assertEqual([on_main for _, on_main in readers], [False, False, False])
        self.assertEqual(callbacks, [True, True, True])
        self.assertEqual(self.window.ethernet.currentData(), GUID)
        self.assertIs(self.window._startup_known, True)
        self.assertIs(self.window._hotspot_state, True)

    def test_read_only_job_keeps_inputs_available_and_restores_actions(self):
        self.window.legacy_login.setChecked(False)
        release = threading.Event()
        self.window.run_job(lambda _: release.wait(timeout=2), read_only=True)
        try:
            for widget in (self.window.controls, self.window.username, self.window.login_password,
                           self.window.login_password_toggle, self.window.key, self.window.password_toggle):
                self.assertTrue(widget.isEnabled())
            for widget in (self.window.connect_button, self.window.hotspot_button,
                           self.window.settings_controls, self.window.save_button):
                self.assertFalse(widget.isEnabled())
        finally:
            release.set()
            self.wait_job()
        for widget in (self.window.controls, self.window.username, self.window.connect_button,
                       self.window.hotspot_button, self.window.settings_controls, self.window.save_button):
            self.assertTrue(widget.isEnabled())

    def test_mutating_job_disables_inputs_and_actions_until_idle(self):
        self.window.legacy_login.setChecked(False)
        release = threading.Event()
        self.window.run_job(lambda _: release.wait(timeout=2))
        widgets = (self.window.controls, self.window.username, self.window.login_password,
                   self.window.key, self.window.connect_button, self.window.hotspot_button,
                   self.window.settings_controls, self.window.save_button)
        try:
            for widget in widgets:
                self.assertFalse(widget.isEnabled())
        finally:
            release.set()
            self.wait_job()
        for widget in widgets:
            self.assertTrue(widget.isEnabled())

    def test_only_physical_ethernet_is_offered(self):
        adapters = [
            {"guid": GUID, "name": "Ethernet", "status": "Up", "if_type": 6, "hardware_interface": True},
            {"guid": "wifi", "name": "Wi-Fi", "status": "Up", "if_type": 71, "hardware_interface": True},
            {"guid": "virtual", "name": "Virtual", "status": "Up", "if_type": 6, "hardware_interface": False},
            {"guid": "tun", "name": "Mihomo", "status": "Up", "if_type": 53, "hardware_interface": False},
        ]
        with patch.object(WindowsOperations, "list_adapters", return_value=adapters):
            self.window.refresh_adapters()
            self.wait_job()
        self.assertEqual(self.window.ethernet.count(), 1)
        self.assertEqual(self.window.ethernet.currentData(), GUID)

    def test_patched_core_starts_directly_without_install(self):
        self.window.connect_network()
        self.wait_job()
        self.installer.install.assert_not_called()
        self.installer.restore.assert_not_called()
        self.start.assert_called_once()
        self.wait_auth.assert_not_called()

    def test_original_core_installs_before_start(self):
        self.installer.status.return_value = {"state": "original"}
        order = Mock()
        order.attach_mock(self.installer.install, "install")
        order.attach_mock(self.start, "start")
        self.window.connect_network()
        self.wait_job()
        self.assertEqual([call[0] for call in order.mock_calls], ["install", "start"])

    def test_interrupted_install_is_recovered_before_start(self):
        self.installer.status.return_value = {"state": "patched", "recovery_needed": True}
        self.window.connect_network()
        self.wait_job()
        self.installer.install.assert_called_once()
        self.start.assert_called_once()

    def test_unknown_core_never_starts(self):
        self.installer.status.return_value = {"state": "unknown"}
        self.window.connect_network()
        self.wait_job()
        self.installer.install.assert_not_called()
        self.start.assert_not_called()

    def test_hotspot_waits_for_authentication_and_uses_selected_source(self):
        self.value["auto_hotspot"] = True
        order = Mock()
        order.attach_mock(self.start, "start")
        order.attach_mock(self.wait_auth, "wait")
        order.attach_mock(self.hotspot_start, "hotspot")
        self.window.connect_network()
        self.wait_job()
        self.assertEqual([call[0] for call in order.mock_calls], ["start", "wait", "hotspot"])
        self.assertEqual(self.wait_auth.call_args.kwargs["ethernet_adapter_guid"], GUID)
        self.hotspot_start.assert_called_once_with("Offline Campus", SECRET, "2.4GHz", GUID)

    def test_no_success_result_keeps_core_and_does_not_start_hotspot(self):
        self.value["auto_hotspot"] = True
        self.wait_auth.return_value = False
        self.window.connect_network()
        self.wait_job()
        self.start.assert_called_once()
        self.hotspot_start.assert_not_called()
        self.assertIn("保持运行", self.window.log.toPlainText())

    def test_hotspot_backend_error_is_redacted_before_logging(self):
        self.value["auto_hotspot"] = True
        self.hotspot_start.return_value = {"ok": False, "ap_on": False, "error": "Rejected password: " + SECRET}
        self.window.connect_network()
        self.wait_job()
        self.assertIn("[redacted]", self.window.log.toPlainText())

    def test_default_name_and_password_and_show_hide_are_synchronized(self):
        self.assertEqual(self.initial_defaults, ("ovo", "12345678"))
        self.window.password_toggle.click()
        self.assertEqual(self.window.key.echoMode(), QLineEdit.EchoMode.Normal)
        self.assertEqual(self.window.settings_key.echoMode(), QLineEdit.EchoMode.Normal)
        self.window.settings_password_toggle.click()
        self.assertEqual(self.window.key.echoMode(), QLineEdit.EchoMode.Password)
        self.window.settings_ssid.setText("Changed name")
        self.assertEqual(self.window.ssid.text(), "Changed name")

    def test_existing_settings_override_new_defaults(self):
        self.assertEqual(self.initial_defaults, ("Existing", "KeptKey123"))

    def test_advanced_controls_are_in_settings_and_save_keeps_dialog_open(self):
        self.window.open_settings()
        self.assertTrue(self.window.settings_dialog.isVisible())
        self.assertEqual([self.window.settings_tabs.tabText(i) for i in range(3)], ["常规", "热点", "维护"])
        self.assertTrue(self.window.settings_dialog.isAncestorOf(self.window.client))
        self.assertTrue(self.window.settings_dialog.isAncestorOf(self.window.log))
        self.window.save_button.click()
        self.assertTrue(self.window.settings_dialog.isVisible())
        self.hotspot_start.assert_not_called()
        self.hotspot_stop.assert_not_called()
        self.start.assert_not_called()
        self.startup.assert_not_called()

    def test_unknown_startup_state_is_not_reported_as_disabled(self):
        self.window._set_startup_state(None)
        self.assertEqual(self.window.startup_checkbox.checkState(), Qt.CheckState.PartiallyChecked)
        self.assertIn("未知", self.window.startup_status.text())
        self.window._set_startup_state(True)
        self.assertTrue(self.window.startup_checkbox.isChecked())
        self.startup.assert_not_called()

    def test_hotspot_partial_success_still_allows_turning_radio_off(self):
        self.hotspot_start.return_value = {"ok": False, "ap_on": True, "sharing_ready": False,
                                           "error": "offline sharing error"}
        self.window.toggle_hotspot(True)
        self.wait_job()
        self.assertEqual(self.window.hotspot_button.text(), "关闭热点")
        self.assertIn("共享未就绪", self.window.status.text())
        self.window.hotspot_button.click()
        self.wait_job()
        self.hotspot_stop.assert_called_once_with(self.window.ethernet.currentData())
        self.assertEqual(self.window.hotspot_button.text(), "开启热点")

    def test_stop_remains_available_with_unfinished_hotspot_settings(self):
        self.window.key.clear()
        self.window.auto_hotspot.setChecked(True)
        self.save.side_effect = ValueError("invalid draft")
        self.window.toggle_hotspot(False)
        self.wait_job()
        self.save.assert_not_called()
        self.hotspot_stop.assert_called_once()

    def test_unknown_hotspot_button_only_checks_state(self):
        self.window.hotspot_button.click()
        self.wait_job()
        self.hotspot_status.assert_called_once()
        self.hotspot_start.assert_not_called()
        self.hotspot_stop.assert_not_called()
        self.assertEqual(self.window.hotspot_button.text(), "开启热点")

    def test_missing_directory_does_not_start_installation(self):
        self.valid_client.return_value = False
        self.discover.return_value = None
        self.window.client.clear()
        self.window.connect_network()
        self.assertIsNone(self.window._thread)
        self.installer.install.assert_not_called()
        self.start.assert_not_called()

    def test_invalid_saved_directory_uses_discovered_location(self):
        self.valid_client.return_value = False
        self.window.client.setText("old moved location")
        self.window.connect_network()
        self.wait_job()
        self.discover.assert_called_once_with("old moved location")
        self.assertEqual(self.window.client.text(), self.discover.return_value)

    def test_diagnostics_stays_out_of_main_status(self):
        before = self.window.status.text()
        with patch("utils.network_diagnostics.collect_network_diagnostics", return_value={"diagnostic": "offline details"}):
            self.window.diagnose()
            self.wait_job()
        self.assertEqual(self.window.status.text(), before)
        self.assertIn("offline details", self.window.log.toPlainText())

    def test_startup_reader_returns_unknown_on_failed_or_ambiguous_query(self):
        with patch("campus_authenticator.subprocess.run") as command:
            for payload, expected in [('{"enabled":true}', True), ('{"enabled":false}', False),
                                      ('{"enabled":null}', None), ('not-json', None)]:
                command.return_value = SimpleNamespace(returncode=0, stdout=payload)
                self.assertIs(read_startup_state(), expected)
            command.return_value = SimpleNamespace(returncode=1, stdout='{"enabled":false}')
            self.assertIsNone(read_startup_state())

    def test_packaged_self_test_checks_synthetic_codec_and_des_golden_vector(self):
        run_packaged_self_test()
        self.prepare.assert_not_called()
        self.store.load.assert_not_called()
        self.start.assert_not_called()
        with patch("utils.auth_credentials.encrypt_native_password", return_value="wrong"):
            with self.assertRaisesRegex(RuntimeError, "DES-CBC"):
                run_packaged_self_test()

    def enter_account(self):
        self.window.legacy_login.setChecked(False)
        self.window.username.setText("offline-campus-account")
        self.window.login_password.setText("offline-login-password")

    def test_account_credentials_use_store_and_preparation_before_core_start(self):
        self.enter_account()
        self.window.remember_credentials.setChecked(True)
        self.installer.status.return_value = {"state": "original"}
        order = Mock()
        for name, method in (("install", self.installer.install), ("prepare", self.prepare),
                             ("start", self.start), ("wait", self.wait_auth)):
            order.attach_mock(method, name)
        self.window.connect_network()
        self.wait_job()
        self.assertEqual([call[0] for call in order.mock_calls], ["install", "prepare", "start", "wait"])
        credentials = Credentials("offline-campus-account", "offline-login-password")
        self.store.save.assert_called_once_with(credentials, remember=True)
        self.assertEqual(self.prepare.call_args.args[1], credentials)
        self.assertEqual(self.prepare.call_args.kwargs["data_dir"], self.data_dir)
        self.assertEqual(self.wait_auth.call_args.args[1:3], ("prepared-baseline", 12345.0))
        self.assertIsNone(self.wait_auth.call_args.kwargs["ethernet_adapter_guid"])
        self.assertEqual(self.window.status.text(), "已连接校园网")
        self.assertNotIn(credentials.username, self.window.log.toPlainText())
        self.assertNotIn(credentials.password, self.window.log.toPlainText())

    def test_account_and_login_password_never_enter_settings_values(self):
        self.enter_account()
        value = self.window.values()
        self.assertNotIn("username", value)
        self.assertNotIn("password", value)
        self.assertNotIn(self.window.username.text(), json.dumps(value))
        self.assertNotIn(self.window.login_password.text(), json.dumps(value))

    def test_account_login_waits_for_new_authentication_even_without_hotspot(self):
        self.enter_account()
        self.wait_auth.return_value = False
        self.window.connect_network()
        self.wait_job()
        self.wait_auth.assert_called_once()
        self.assertNotEqual(self.window.status.text(), "已连接校园网")
        self.store.save.assert_called_once_with(Credentials("offline-campus-account", "offline-login-password"), remember=False)

    def test_unavailable_preparation_never_installs_or_starts_core(self):
        self.enter_account()
        with patch("campus_authenticator.prepare_credentials", None):
            self.window.connect_network()
        self.installer.install.assert_not_called()
        self.start.assert_not_called()
        self.store.save.assert_not_called()

    def test_failed_preparation_does_not_claim_success_or_start_core(self):
        self.enter_account()
        self.prepare.side_effect = RuntimeError("offline preparation failure")
        self.window.connect_network()
        self.wait_job()
        self.start.assert_not_called()
        self.wait_auth.assert_not_called()

    def test_missing_unremembered_account_does_not_auto_open_native_client(self):
        self.window.legacy_login.setChecked(False)
        self.assertFalse(self.window.request_auto_connection(True))
        self.window.idle()
        self.app.processEvents()
        self.start.assert_not_called()
        self.assertIn("请输入", self.window.status.text())

    def test_self_test_does_not_read_real_saved_accounts(self):
        self.store.load.assert_not_called()

    def test_decryption_failure_preserves_record_until_explicit_clear(self):
        self.window.legacy_login.setChecked(False)
        self.store.load.side_effect = CredentialUnlockError("synthetic decrypt failure")
        self.window._load_saved_credentials()
        self.assertFalse(self.window.request_auto_connection(True))
        self.store.clear.assert_not_called()
        self.store.save.assert_not_called()
        self.window.clear_credentials()
        self.store.clear.assert_called_once()
        self.assertFalse(self.window._credential_load_error)
        self.assertFalse(self.window.remember_credentials.isChecked())
        self.assertEqual(self.window.remember_credentials.text(), "在本程序记住账号密码")
        self.assertIn("本程序", self.window.settings_message.text())

    def test_loaded_accounts_fill_inputs_and_sensitive_errors_are_redacted(self):
        self.window.legacy_login.setChecked(False)
        self.store.load.return_value = Credentials("offline-user", 'fake-secret"123')
        self.window._load_saved_credentials()
        self.assertTrue(self.window.remember_credentials.isChecked())
        self.assertTrue(self.window.request_auto_connection(True))
        self.window._pending_connect = False
        self.window.append_log('offline-user fake-secret"123')
        self.window.append_log(json.dumps({"error": 'fake-secret"123'}))
        self.assertNotIn("offline-user", self.window.log.toPlainText())
        self.assertNotIn('fake-secret"123', self.window.log.toPlainText())
        self.assertNotIn('fake-secret\\"123', self.window.log.toPlainText())
        self.window.login_password_toggle.click()
        self.assertEqual(self.window.login_password.echoMode(), QLineEdit.EchoMode.Normal)

    def test_restore_disables_startup_and_next_launch_autologin(self):
        self.window.auto_login.setChecked(True)
        self.window.auto_hotspot.setChecked(True)
        self.window.restore()
        self.wait_job()
        self.installer.restore.assert_called_once()
        self.startup.assert_called_once_with(False)
        self.assertFalse(self.window.auto_login.isChecked())
        self.assertFalse(self.window.auto_hotspot.isChecked())
        self.save.assert_called_once()

    def test_incomplete_install_cannot_enable_startup(self):
        for current in ({"state": "original"}, {"state": "patched", "recovery_needed": True}):
            with self.subTest(current=current):
                self.installer.status.return_value = current
                self.window.startup(True)
                self.wait_job()
        self.startup.assert_not_called()


if __name__ == "__main__":
    unittest.main()

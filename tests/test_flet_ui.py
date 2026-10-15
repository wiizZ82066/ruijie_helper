"""Real Flet controls, fake page/service, deterministic offline async workflows."""
import asyncio
from contextlib import contextmanager
import json
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import flet as ft
import campus_flet as gui
from utils.credential_store import Credentials


GUID = "11111111-1111-4111-8111-111111111111"
ACCOUNT = "synthetic-campus-user"
PASSWORD = 'synthetic-password-"value"'


class FakePage:
    def __init__(self):
        self.controls = []
        self.updates = 0
        self.window = SimpleNamespace(destroy=AsyncMock(), to_front=AsyncMock())
        self.show_dialog = Mock()
        self.pop_dialog = Mock()

    def add(self, *controls):
        self.controls.extend(controls)

    def update(self):
        self.updates += 1


class GatedRead:
    def __init__(self, value=None, error=None):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.value, self.error = value, error

    def __call__(self, *args):
        self.entered.set()
        try:
            if not self.release.wait(timeout=3):
                raise AssertionError("Offline gate was not released")
            if self.error is not None:
                raise self.error
            return self.value
        finally:
            self.finished.set()


class FletUITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.patchers = []
        for target in ("subprocess.run", "subprocess.Popen", "ctypes.WinDLL", "psutil.Process",
                       "psutil.process_iter"):
            patcher = patch(target, side_effect=AssertionError("Real OS access forbidden"), create=True)
            patcher.start()
            self.patchers.append(patcher)
        self.page = FakePage()
        self.service = Mock(spec=gui.PreviewService)
        self.service.load_settings.return_value = {"auto_login": False, "auto_hotspot": False,
            "ssid": "Synthetic hotspot", "hotspot_key": "synthetic123", "band": "2.4GHz"}
        self.service.load_credentials.return_value = None
        self.service.list_adapters.return_value = [{"guid": GUID, "name": "Synthetic Ethernet",
            "status": "Up", "if_type": 6, "hardware_interface": True}]
        self.service.read_startup_state.return_value = False
        self.service.hotspot_status.return_value = "未启动"
        self.service.connect.return_value = {"message": "已连接校园网", "authenticated": True}
        self.service.save_settings.side_effect = lambda values: dict(values)
        self.service.set_startup.side_effect = lambda enabled, values, log: {"enabled": enabled}
        self.ui = gui.CampusUI(self.page, self.service, preview=True)
        self.ui.build()
        self.gates = []
        self.pending = []

    async def asyncTearDown(self):
        self.ui.jobs.close()
        for gate in self.gates:
            gate.release.set()
        tasks = list(self.ui.tasks) + self.pending
        if tasks:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 4)
        for patcher in reversed(self.patchers):
            patcher.stop()

    def gate(self, *args, **kwargs):
        gate = GatedRead(*args, **kwargs)
        self.gates.append(gate)
        return gate

    def task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.pending.append(task)
        return task

    async def until(self, predicate):
        for _ in range(1000):
            if predicate():
                return
            await asyncio.sleep(.001)
        self.fail("Offline event was not observed")

    def type_credentials(self):
        self.ui.username.value, self.ui.password.value = ACCOUNT, PASSWORD
        self.ui.changed("username")
        self.ui.changed("password")

    def assert_inputs_enabled(self):
        for control in (self.ui.username, self.ui.password, self.ui.connect_button,
                        self.ui.client, self.ui.ssid, self.ui.key, self.ui.save_button):
            self.assertIsNot(control.disabled, True)

    def assert_statuses_match(self, expected=None):
        self.assertEqual(self.ui.status.value, self.ui.notice.value)
        if expected is not None:
            self.assertEqual(self.ui.status.value, expected)

    @contextmanager
    def matching_status_updates(self):
        """Each rendered frame must agree, including busy and error frames."""
        samples = []
        original = self.page.update

        def update():
            samples.append((self.ui.status.value, self.ui.notice.value))
            original()

        with patch.object(self.page, "update", side_effect=update):
            yield samples
        self.assertTrue(samples)
        for status, notice in samples:
            self.assertEqual(status, notice)
        self.assert_statuses_match()

    def test_real_controls_build_with_the_installed_flet_api(self):
        self.assertIsInstance(self.ui.username, ft.TextField)
        self.assertIsInstance(self.ui.connect_button, ft.Button)
        self.assertTrue(self.ui.password.password)
        self.assertTrue(self.ui.password.can_reveal_password)
        self.assertEqual(len(self.page.controls), 1)
        self.assert_inputs_enabled()

    def test_initial_status_and_footer_show_the_same_nonempty_message(self):
        self.assert_statuses_match()
        self.assertTrue(self.ui.status.value.strip())

    async def test_resize_reflows_existing_controls_without_losing_typed_values(self):
        self.type_credentials()
        fields = self.ui.username, self.ui.password, self.ui.ssid, self.ui.key
        self.ui.ssid.value, self.ui.key.value = "Synthetic edited hotspot", "edited-key-123"
        home = self.ui.body.content
        responsive = [control for control in home.controls if isinstance(control, ft.ResponsiveRow)]
        self.assertEqual(len(responsive), 1)
        self.assertEqual(len(responsive[0].controls), 2)
        for width, compact in ((600, True), (1100, False), (480, True)):
            await self.ui.resized(SimpleNamespace(width=width))
            self.assertIs(self.ui.body.content, home)
            self.assertEqual((self.ui.username, self.ui.password, self.ui.ssid, self.ui.key), fields)
            self.assertEqual((self.ui.username.value, self.ui.password.value), (ACCOUNT, PASSWORD))
            self.assertEqual((self.ui.ssid.value, self.ui.key.value), ("Synthetic edited hotspot", "edited-key-123"))
            self.assertIs(self.ui.sidebar.visible, not compact)
            self.assertIs(self.ui.compact_bar.visible, compact)
        await self.ui.show_settings()
        settings = self.ui.body.content
        await self.ui.resized(SimpleNamespace(width=1100))
        self.assertIs(self.ui.body.content, settings)
        self.assertEqual((self.ui.username, self.ui.password, self.ui.ssid, self.ui.key), fields)

    async def test_slow_hotspot_and_startup_reads_do_not_block_login(self):
        hotspot, startup = self.gate("未启动"), self.gate(False)
        self.service.hotspot_status.side_effect = hotspot
        self.service.read_startup_state.side_effect = startup
        self.task(self.ui.refresh_hotspot())
        await self.ui.show_settings()
        await self.until(lambda: hotspot.entered.is_set() and startup.entered.is_set())
        self.assert_inputs_enabled()
        self.type_credentials()
        await asyncio.wait_for(self.ui.connect(), .5)
        self.service.connect.assert_called_once()
        self.assertFalse(hotspot.finished.is_set())
        self.assertFalse(startup.finished.is_set())
        self.assertEqual(self.ui.status.value, "已连接校园网")

    async def test_bootstrap_ready_does_not_wait_for_optional_hotspot_read(self):
        hotspot = self.gate("未启动")
        self.service.hotspot_status.side_effect = hotspot
        await asyncio.wait_for(self.ui.bootstrap(), .5)
        await self.until(hotspot.entered.is_set)
        self.assertTrue(self.ui.ready.is_set())
        self.assertFalse(hotspot.finished.is_set())
        self.assertEqual(self.ui.ethernet.value, GUID)
        self.assert_inputs_enabled()

    async def test_auto_connect_runs_once_without_waiting_for_optional_reads(self):
        hotspot, startup = self.gate("未启动"), self.gate(False)
        self.service.hotspot_status.side_effect = hotspot
        self.service.read_startup_state.side_effect = startup
        self.service.load_settings.return_value["auto_login"] = True
        self.service.load_credentials.return_value = Credentials(ACCOUNT, PASSWORD)
        await self.ui.show_settings()
        await self.until(startup.entered.is_set)
        await asyncio.wait_for(self.ui.bootstrap(auto_connect=True), .5)
        self.service.connect.assert_called_once()
        self.assertTrue(self.ui.ready.is_set())
        self.assertFalse(startup.finished.is_set())
        self.assertFalse(hotspot.finished.is_set())

    def test_adapter_and_settings_arrival_order_preserves_valid_selection_and_user_edit(self):
        other = "22222222-2222-4222-8222-222222222222"
        rows = self.service.list_adapters.return_value + [{"guid": other, "name": "Synthetic second Ethernet",
            "status": "Up", "if_type": 6, "hardware_interface": True}]
        self.ui._apply_adapters(rows)
        self.assertIsNone(self.ui.ethernet.value)
        self.ui._apply_settings({"ethernet_guid": other})
        self.assertEqual(self.ui.ethernet.value, other)
        self.assertEqual(self.ui.network_label.value, "Synthetic second Ethernet")
        self.ui.ethernet.value = GUID
        self.ui.dirty.add("ethernet_guid")
        self.ui._apply_settings({"ethernet_guid": other})
        self.assertEqual(self.ui.ethernet.value, GUID)
        self.assertEqual(self.ui.network_label.value, "Synthetic Ethernet")

    async def test_missing_manually_selected_ethernet_never_switches_to_another_up_adapter(self):
        other = "22222222-2222-4222-8222-222222222222"
        remaining = {"guid": other, "name": "Synthetic alternative Ethernet", "status": "Up",
                     "if_type": 6, "hardware_interface": True}
        self.ui._apply_adapters(self.service.list_adapters.return_value + [remaining])
        self.ui.ethernet.value = GUID
        self.ui.changed("ethernet_guid")
        self.ui._apply_adapters([remaining])
        self.assertIsNone(self.ui.ethernet.value)
        self.assertIsNone(self.ui.values()["ethernet_guid"])
        self.assertNotEqual(self.ui.network_label.value, remaining["name"])

    async def test_connect_waits_for_saved_preferences_before_capturing_values_only(self):
        saved = dict(self.service.load_settings.return_value, ssid="Synthetic saved hotspot",
                     hotspot_key="synthetic-saved-key", band="5GHz", client_dir="synthetic-client-directory",
                     ethernet_guid=GUID)
        preferences, hotspot, startup = self.gate(saved), self.gate("未启动"), self.gate(False)
        self.service.load_settings.side_effect = preferences
        self.service.hotspot_status.side_effect = hotspot
        self.service.read_startup_state.side_effect = startup
        bootstrap = self.task(self.ui.bootstrap())
        await self.until(preferences.entered.is_set)
        self.task(self.ui.refresh_hotspot())
        await self.ui.show_settings()
        await self.until(lambda: hotspot.entered.is_set() and startup.entered.is_set())
        self.type_credentials()
        connect = self.task(self.ui.connect())
        for _ in range(5):
            await asyncio.sleep(0)
        self.service.connect.assert_not_called()
        self.assertFalse(self.ui.jobs.mutation_busy)
        preferences.release.set()
        await asyncio.wait_for(connect, 1)
        await bootstrap
        self.service.connect.assert_called_once()
        received = self.service.connect.call_args.args[0]
        for key in ("ssid", "hotspot_key", "band", "client_dir", "ethernet_guid"):
            self.assertEqual(received[key], saved[key])
        self.assertFalse(hotspot.finished.is_set())
        self.assertFalse(startup.finished.is_set())

    async def test_action_admission_also_waits_for_initial_preferences(self):
        preferences = self.gate(self.service.load_settings.return_value)
        self.service.load_settings.side_effect = preferences
        bootstrap = self.task(self.ui.bootstrap())
        await self.until(preferences.entered.is_set)
        worker = Mock(return_value={"message": "设置已更新"})
        action = self.task(self.ui.action(worker, "正在处理"))
        for _ in range(5):
            await asyncio.sleep(0)
        worker.assert_not_called()
        self.assertFalse(self.ui.jobs.mutation_busy)
        preferences.release.set()
        await asyncio.wait_for(action, 1)
        await bootstrap
        worker.assert_called_once()

    async def test_old_hotspot_value_cannot_overwrite_completed_action(self):
        old = self.gate("未启动")
        calls = 0
        def status(_):
            nonlocal calls
            calls += 1
            return old() if calls == 1 else "已启动"
        self.service.hotspot_status.side_effect = status
        pending = self.task(self.ui.refresh_hotspot())
        await self.until(old.entered.is_set)
        await self.ui.action(lambda log: {"message": "新的操作已完成", "hotspot": True}, "正在操作")
        await self.until(lambda: calls >= 2)
        old.release.set()
        await pending
        self.assertIs(self.ui.hotspot_state, True)
        self.assertEqual(self.ui.status.value, "新的操作已完成")
        self.assert_statuses_match()

    async def test_old_startup_value_cannot_overwrite_startup_change(self):
        old = self.gate(False)
        self.service.read_startup_state.side_effect = old
        await self.ui.show_settings()
        await self.until(old.entered.is_set)
        self.ui.startup.value = True
        await self.ui.change_startup(None)
        self.assertIs(self.ui.startup_state, True)
        old.release.set()
        await self.until(old.finished.is_set)
        await asyncio.gather(*list(self.ui.tasks))
        self.assertIs(self.ui.startup_state, True)
        self.assertIs(self.ui.startup.value, True)
        self.assert_statuses_match("自启动设置已更新")

    async def test_old_read_error_cannot_overwrite_new_action_message(self):
        old = self.gate(error=RuntimeError("synthetic stale read error"))
        apply = Mock()
        pending = self.task(self.ui.read("discovery", old, apply, error_message="过期错误提示"))
        await self.until(old.entered.is_set)
        self.type_credentials()
        await self.ui.connect()
        expected = self.ui.notice.value
        old.release.set()
        await pending
        self.assertEqual(self.ui.notice.value, expected)
        self.assertNotIn("过期", self.ui.notice.value)
        self.assert_statuses_match(expected)
        apply.assert_not_called()

    async def test_check_hotspot_button_cannot_publish_old_notice_after_login(self):
        old = self.gate("未启动")
        calls = 0
        def status(_):
            nonlocal calls
            calls += 1
            return old() if calls == 1 else "未启动"
        self.service.hotspot_status.side_effect = status
        pending = self.task(self.ui.toggle_hotspot())
        await self.until(old.entered.is_set)
        self.type_credentials()
        await self.ui.connect()
        expected = self.ui.notice.value
        old.release.set()
        await pending
        self.assertEqual(self.ui.notice.value, expected)
        self.assertEqual(self.ui.status.value, "已连接校园网")
        self.assert_statuses_match(expected)

    async def test_late_credentials_never_replace_user_input_or_remember_choice(self):
        old = self.gate(Credentials("synthetic-saved-user", "synthetic-saved-password"))
        self.service.load_credentials.side_effect = old
        pending = self.task(self.ui.read("credentials", self.ui._credentials, self.ui._apply_credentials))
        await self.until(old.entered.is_set)
        self.type_credentials()
        self.ui.remember.value = False
        self.ui.changed("remember")
        old.release.set()
        await pending
        self.assertEqual((self.ui.username.value, self.ui.password.value), (ACCOUNT, PASSWORD))
        self.assertIs(self.ui.remember.value, False)

    async def test_late_settings_cannot_switch_typed_credentials_to_legacy_login(self):
        old = self.gate({"legacy_saved_login": True, "auto_login": True})
        pending = self.task(self.ui.read("settings", old, self.ui._apply_settings))
        await self.until(old.entered.is_set)
        self.type_credentials()
        old.release.set()
        await pending
        self.assertIs(self.ui.legacy.value, False)
        self.assert_inputs_enabled()

    async def test_user_switching_login_mode_cancels_pending_auto_login(self):
        credentials = self.gate(Credentials(ACCOUNT, PASSWORD))
        self.service.load_credentials.side_effect = credentials
        self.service.load_settings.return_value["auto_login"] = True
        pending = self.task(self.ui.bootstrap(auto_connect=True))
        await self.until(credentials.entered.is_set)
        self.ui.legacy.value = True
        await self.ui.legacy_changed(None)
        credentials.release.set()
        await pending
        self.service.connect.assert_not_called()

    async def test_concurrent_mutations_execute_service_only_once(self):
        active = self.gate({"message": "已连接校园网"})
        self.service.connect.side_effect = active
        self.type_credentials()
        first = self.task(self.ui.connect())
        await self.until(active.entered.is_set)
        await self.ui.connect()
        await self.ui.save_settings()
        self.service.connect.assert_called_once()
        self.service.save_settings.assert_not_called()
        self.assertTrue(self.ui.jobs.mutation_busy)
        active.release.set()
        await first
        self.assertFalse(self.ui.jobs.mutation_busy)
        self.assert_inputs_enabled()

    async def test_authenticated_backend_result_stops_spinner_and_restores_controls(self):
        active = self.gate({"message": "已连接校园网", "authenticated": True, "ready": True})
        self.service.connect.side_effect = active
        self.type_credentials()
        pending = self.task(self.ui.connect())
        await self.until(active.entered.is_set)
        self.assertTrue(self.ui.progress.visible)
        self.assertTrue(self.ui.connect_button.disabled)
        self.assert_statuses_match("正在连接校园网…")
        active.release.set()
        await pending
        self.assertIs(self.ui.progress.visible, False)
        self.assertFalse(self.ui.jobs.mutation_busy)
        for control in self.ui.action_controls:
            self.assertIsNot(control.disabled, True)
        self.assertEqual(self.ui.status.value, "已连接校园网")
        self.assertEqual(self.ui.notice.value, "已连接校园网")

    async def test_timeout_and_unknown_backend_results_stop_spinner_without_claiming_success(self):
        self.type_credentials()
        for result in ({"message": "等待登录完成", "authenticated": False, "ready": False},
                       {"message": "认证状态暂未确认", "authenticated": None, "ready": False}):
            with self.subTest(authenticated=result["authenticated"]):
                self.service.connect.return_value = result
                await self.ui.connect()
                self.assertIs(self.ui.progress.visible, False)
                self.assertFalse(self.ui.jobs.mutation_busy)
                for control in self.ui.action_controls:
                    self.assertIsNot(control.disabled, True)
                self.assertEqual(self.ui.status.value, result["message"])
                self.assert_statuses_match(result["message"])
                self.assertNotIn("正在连接", self.ui.status.value)
                self.assertNotIn("正在连接", self.ui.notice.value)
                self.assertNotEqual(self.ui.status.value, "已连接校园网")

    async def test_connection_error_updates_both_statuses_without_exposing_credentials(self):
        self.type_credentials()
        self.service.connect.side_effect = RuntimeError(
            json.dumps({"account": ACCOUNT, "password": PASSWORD}))
        with self.matching_status_updates():
            await self.ui.connect()
        self.assertFalse(self.ui.progress.visible)
        self.assertNotIn("正在连接", self.ui.status.value)
        self.assertIn("[redacted]", self.ui.status.value)
        for secret in (ACCOUNT, PASSWORD, json.dumps(PASSWORD)[1:-1]):
            self.assertNotIn(secret, self.ui.status.value)
            self.assertNotIn(secret, "\n".join(self.ui.logs))

    async def test_invalid_credentials_updates_both_statuses_without_calling_backend(self):
        original = self.ui.status.value
        with self.matching_status_updates():
            await self.ui.connect()
        self.service.connect.assert_not_called()
        self.assertNotEqual(self.ui.status.value, original)
        self.assertFalse(self.ui.progress.visible)
        self.assert_inputs_enabled()

    async def test_save_settings_custom_completion_updates_both_statuses(self):
        saved = dict(self.service.load_settings.return_value, ssid="Synthetic edited hotspot")
        active = self.gate(saved)
        self.service.save_settings.side_effect = active
        with self.matching_status_updates():
            pending = self.task(self.ui.save_settings())
            await self.until(active.entered.is_set)
            self.assert_statuses_match("正在保存…")
            active.release.set()
            await pending
        self.assert_statuses_match("设置已保存")
        self.assertEqual(self.ui.settings, saved)

    async def test_startup_custom_completion_updates_both_statuses(self):
        active = self.gate({"enabled": True})
        self.service.set_startup.side_effect = active
        self.ui.startup.value = True
        with self.matching_status_updates():
            pending = self.task(self.ui.change_startup(None))
            await self.until(active.entered.is_set)
            self.assert_statuses_match("正在设置自启动…")
            active.release.set()
            await pending
        self.assert_statuses_match("自启动设置已更新")
        self.assertIs(self.ui.startup_state, True)

    async def test_restore_confirmed_completion_updates_both_statuses(self):
        active = self.gate({"startup_disabled": True})
        self.service.restore.side_effect = active
        await self.ui.confirm_restore()
        self.service.restore.assert_not_called()
        dialog = self.page.show_dialog.call_args.args[0]
        with self.matching_status_updates():
            pending = self.task(dialog.actions[1].on_click(None))
            await self.until(active.entered.is_set)
            self.assert_statuses_match("正在恢复原版…")
            active.release.set()
            await pending
        self.assertIn("已恢复原版", self.ui.status.value)
        self.assertIs(self.ui.startup_state, False)
        self.assertIs(self.ui.auto_login.value, False)
        self.assertIs(self.ui.auto_hotspot.value, False)

    async def test_forget_credentials_custom_completion_updates_both_statuses(self):
        self.type_credentials()
        self.ui.remember.value = True
        self.service.clear_credentials.return_value = None
        await self.ui.confirm_forget()
        self.service.clear_credentials.assert_not_called()
        dialog = self.page.show_dialog.call_args.args[0]
        with self.matching_status_updates():
            await dialog.actions[1].on_click(None)
        self.assert_statuses_match("已清除本程序保存的账号")
        self.assertEqual((self.ui.username.value, self.ui.password.value), ("", ""))
        self.assertIs(self.ui.remember.value, False)

    async def test_read_failure_discovery_and_diagnostics_keep_both_statuses_equal(self):
        self.service.discover_client.return_value = None
        self.service.diagnose.return_value = {"network_changed": False}
        with self.matching_status_updates():
            await self.ui.read("synthetic", Mock(side_effect=RuntimeError("Synthetic error")),
                               Mock(), error_message="读取状态失败，请重试")
            self.assert_statuses_match("读取状态失败，请重试")
            await self.ui.discover()
            self.assert_statuses_match("未找到客户端，请手动选择目录")
            await self.ui.diagnose()
            self.assert_statuses_match("网络检查完成，详情见维护记录")

    async def test_hotspot_unknown_refresh_keeps_both_statuses_equal(self):
        active = self.gate("未启动")
        self.service.hotspot_status.side_effect = active
        with self.matching_status_updates():
            pending = self.task(self.ui.toggle_hotspot())
            await self.until(active.entered.is_set)
            self.assert_statuses_match("正在读取热点状态…")
            active.release.set()
            await pending
        self.assert_statuses_match("热点状态已更新")

    async def test_navigation_and_status_reads_leave_inputs_available(self):
        startup = self.gate(False)
        self.service.read_startup_state.side_effect = startup
        await self.ui.show_settings()
        await self.until(startup.entered.is_set)
        self.assertEqual(self.ui.current_view, "settings")
        self.assert_inputs_enabled()
        await self.ui.show_home()
        self.assertEqual(self.ui.current_view, "home")
        self.assertFalse(startup.finished.is_set())
        self.assert_inputs_enabled()

    async def test_exit_during_mutation_sets_cancel_and_destroys_only_after_completion(self):
        active = self.gate({"message": "已安全结束"})
        self.service.connect.side_effect = active
        events = []
        async def destroy():
            self.assertTrue(active.finished.is_set())
            self.assertFalse(self.ui.jobs.mutation_busy)
            events.append("destroy")
        self.page.window.destroy.side_effect = destroy
        self.type_credentials()
        pending = self.task(self.ui.connect())
        await self.until(active.entered.is_set)
        await self.ui.exit()
        self.assertTrue(self.ui.cancel.is_set())
        self.assertTrue(self.ui.exit_pending)
        self.assert_statuses_match("正在等待当前操作安全完成…")
        self.assertFalse(self.ui.jobs.closed)
        self.page.window.destroy.assert_not_awaited()
        active.release.set()
        await pending
        self.assertTrue(self.ui.jobs.closed)
        self.assertEqual(events, ["destroy"])
        self.page.window.destroy.assert_awaited_once()

    async def test_cancelled_handler_keeps_write_slot_until_real_worker_finishes(self):
        active = self.gate({"message": "已安全结束"})
        self.service.connect.side_effect = active
        self.type_credentials()
        pending = self.task(self.ui.connect())
        await self.until(active.entered.is_set)
        pending.cancel()
        for _ in range(5):
            await asyncio.sleep(0)
        self.assertTrue(self.ui.cancel.is_set())
        self.assertTrue(self.ui.jobs.mutation_busy)
        self.assertFalse(active.finished.is_set())
        await self.ui.connect()
        self.service.connect.assert_called_once()
        await self.ui.exit()
        self.page.window.destroy.assert_not_awaited()
        active.release.set()
        await asyncio.gather(pending, return_exceptions=True)
        self.assertFalse(self.ui.jobs.mutation_busy)
        self.assertTrue(self.ui.jobs.closed)
        self.page.window.destroy.assert_awaited_once()

    async def test_progress_delivery_after_loop_closure_cannot_fail_actual_worker(self):
        finished = threading.Event()
        def connect(values, credentials, remember, cancel, log):
            log("synthetic worker progress")
            finished.set()
            return {"message": "已连接校园网"}
        self.service.connect.side_effect = connect
        self.ui.loop = SimpleNamespace(run_in_executor=asyncio.get_running_loop().run_in_executor,
            call_soon_threadsafe=Mock(side_effect=RuntimeError("Event loop is closed")))
        self.type_credentials()
        await self.ui.connect()
        self.assertTrue(finished.is_set())
        self.assertEqual(self.ui.status.value, "已连接校园网")

    async def test_page_update_failure_never_leaves_a_reserved_write_slot(self):
        worker = Mock(return_value={"message": "should not run"})
        with patch.object(self.page, "update", side_effect=RuntimeError("Synthetic closed page")), \
             patch.object(self.ui, "spawn", side_effect=lambda coroutine: coroutine.close()):
            with self.assertRaises(RuntimeError):
                await self.ui.action(worker, "正在处理")
        worker.assert_not_called()
        self.assertFalse(self.ui.jobs.mutation_busy)
        self.assert_inputs_enabled()
        self.type_credentials()
        await self.ui.connect()
        self.service.connect.assert_called_once()

    async def test_executor_submission_failure_releases_write_slot_for_retry(self):
        worker = Mock()
        real_loop = self.ui.loop
        self.ui.loop = SimpleNamespace(run_in_executor=Mock(side_effect=RuntimeError("Synthetic executor unavailable")),
            call_soon_threadsafe=real_loop.call_soon_threadsafe)
        await self.ui.action(worker, "正在处理")
        worker.assert_not_called()
        self.assertFalse(self.ui.jobs.mutation_busy)
        self.assert_inputs_enabled()
        self.ui.loop = real_loop
        self.type_credentials()
        await self.ui.connect()
        self.service.connect.assert_called_once()

    async def test_pending_exit_is_honored_even_when_final_ui_update_fails(self):
        self.ui.exit_pending = True
        with patch.object(self.page, "update", side_effect=RuntimeError("Synthetic closed page")):
            with self.assertRaises(RuntimeError):
                await self.ui.action(Mock(), "正在处理")
        self.assertFalse(self.ui.jobs.mutation_busy)
        self.assertTrue(self.ui.jobs.closed)
        self.page.window.destroy.assert_awaited_once()

    async def test_close_rejects_late_read_callback_and_error(self):
        old = self.gate("late")
        apply = Mock()
        pending = self.task(self.ui.read("diagnostics", old, apply, error_message="late error"))
        await self.until(old.entered.is_set)
        await self.ui.exit()
        updates = self.page.updates
        old.release.set()
        await pending
        apply.assert_not_called()
        self.assertEqual(self.page.updates, updates)

    async def test_action_errors_and_progress_redact_synthetic_credentials(self):
        self.type_credentials()
        def fail(log):
            log("synthetic progress " + ACCOUNT + " " + PASSWORD)
            raise RuntimeError(json.dumps({"account": ACCOUNT, "password": PASSWORD}))
        await self.ui.action(fail, "正在处理")
        await asyncio.sleep(0)
        visible = "\n".join(self.ui.logs) + self.ui.notice.value + self.ui.status.value
        for secret in (ACCOUNT, PASSWORD, json.dumps(PASSWORD)[1:-1]):
            self.assertNotIn(secret, visible)
        self.assertIn("[redacted]", visible)
        self.assert_statuses_match()


class FletEntrypointTests(unittest.TestCase):
    def test_live_instance_never_launches_second_frontend(self):
        from utils import auth_service, flet_runtime, instance_guard
        guard = Mock()
        guard.acquire.return_value = False
        shell = SimpleNamespace(IsUserAnAdmin=Mock(return_value=True), MessageBoxW=Mock())
        with patch.object(gui.ctypes, "windll", SimpleNamespace(shell32=shell, user32=shell), create=True), \
             patch.object(gui.sys, "argv", ["synthetic-campus.py"]), \
             patch.object(auth_service, "CampusService"), \
             patch.object(instance_guard, "InstanceGuard", return_value=guard), \
             patch.object(flet_runtime, "run_desktop") as run:
            gui.main()
        run.assert_not_called()

    def test_guard_is_released_after_desktop_runtime_has_returned(self):
        from utils import auth_service, flet_runtime, instance_guard
        guard = Mock()
        guard.acquire.return_value = True
        events = []
        def run(*args, **kwargs):
            guard.release.assert_not_called()
            events.append("runtime-returned")
        guard.release.side_effect = lambda: events.append("released")
        shell = SimpleNamespace(IsUserAnAdmin=Mock(return_value=True))
        with patch.object(gui.ctypes, "windll", SimpleNamespace(shell32=shell), create=True), \
             patch.object(gui.sys, "argv", ["synthetic-campus.py"]), \
             patch.object(auth_service, "CampusService"), \
             patch.object(instance_guard, "InstanceGuard", return_value=guard), \
             patch.object(flet_runtime, "run_desktop", side_effect=run):
            gui.main()
        self.assertEqual(events, ["runtime-returned", "released"])


if __name__ == "__main__":
    unittest.main()

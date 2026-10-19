"""Offline UI regressions for changing links; never call native networking."""
import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch
from types import SimpleNamespace

import campus_flet as gui
from test_flet_ui import FakePage


class ConnectionWatchTests(unittest.IsolatedAsyncioTestCase):
    async def recovery(self, *, wake=False, retryable=False, fatal=False, disconnected=False,
                       enabled=True, cold=False):
        service = Mock(spec=gui.PreviewService)
        service.maintain_wireless.return_value = None
        target = ('wired', 'synthetic-a')
        service.connection_target.return_value = target
        ui = gui.CampusUI(FakePage(), service, preview=True)
        ui.resume_watch = SimpleNamespace(reader=None, poll=lambda:False)
        ui.username.value, ui.password.value = 'synthetic-user', 'synthetic-password'
        ui.auto_login.value = enabled
        ui.connection_inputs = None if disconnected else ui._connection_inputs()
        ui.last_attempt_target = ('wireless', '') if cold else target
        state = {'active': not retryable, 'ready': not retryable, 'retryable': retryable,
                 'message': 'synthetic state'}
        service.wired_status.side_effect = lambda: dict(state)
        async def connect(**kwargs):
            ui.last_attempt_target = target
            if fatal:
                state.update(active=False, ready=False, retryable=False)
            ui._apply_wired_status(dict(state))
        ui.connect = AsyncMock(side_effect=connect)
        ticks, now = 0, 0
        async def tick(_):
            nonlocal ticks, now
            ticks += 1
            now += 40 if wake and ticks == 2 else 2
            if ticks > 70: ui.jobs.close()
        with patch.object(gui, 'time', SimpleNamespace(monotonic=lambda: now)), \
             patch.object(gui.asyncio, 'sleep', side_effect=tick):
            await ui.watch_network()
        return ui

    async def test_wake_reconnects_same_adapter_once_after_settling(self):
        ui = await self.recovery(wake=True)
        ui.connect.assert_awaited_once_with(automatic=True)

    async def test_transient_failures_retry_only_three_times(self):
        ui = await self.recovery(retryable=True)
        self.assertEqual(ui.connect.await_count, 3)
        self.assertIn('已暂停', ui.status.value)

    async def test_rejected_credentials_during_recovery_stop_retries(self):
        ui = await self.recovery(retryable=True, fatal=True)
        ui.connect.assert_awaited_once()

    async def test_wake_does_not_reconnect_after_user_disconnect_or_disabled_auto(self):
        for kwargs in ({'disconnected':True}, {'enabled':False}):
            ui = await self.recovery(wake=True, **kwargs)
            ui.connect.assert_not_awaited()

    async def test_cold_boot_link_appears_before_first_watch_sample(self):
        ui = await self.recovery(cold=True)
        ui.connect.assert_awaited_once()

    async def exercise(self, targets, *, edit=False, enabled=True):
        service = Mock(spec=gui.PreviewService)
        service.maintain_wireless.return_value = None
        service.connection_target.side_effect = list(targets)
        ui = gui.CampusUI(FakePage(), service, preview=True)
        ui.connection_mode.value = "auto"
        ui.auto_login.value = enabled
        ui.username.value = "synthetic-user"
        ui.password.value = "synthetic-password"
        ui.connection_inputs = ui._connection_inputs()
        if edit:
            ui.password.value = "unfinished-edit"
        ui.connect = AsyncMock()
        ticks = 0
        async def tick(_):
            nonlocal ticks
            ticks += 1
            if ticks > len(targets):
                ui.jobs.close()
        with patch.object(gui.asyncio, "sleep", side_effect=tick):
            await ui.watch_network()
        return ui, service

    async def test_only_stable_link_changes_connect_and_a_failed_attempt_is_not_retried(self):
        wired, down, wifi = ("wired", "synthetic-a"), ("wireless", ""), ("wireless", "synthetic-w")
        ui, service = await self.exercise([wired, down, wired, down, down, wifi, wifi, wifi, wired, wired, wired, wired])
        self.assertEqual(ui.connect.await_count, 2)
        self.assertTrue(all(call.kwargs == {"automatic": True} for call in ui.connect.await_args_list))

    async def test_draft_password_cannot_be_submitted_by_background_switch(self):
        ui, service = await self.exercise([("wired", "a"), ("wireless", ""), ("wireless", "")], edit=True)
        ui.connect.assert_not_awaited()
        service.connection_target.assert_not_called()

    async def test_disabled_auto_login_never_switches(self):
        ui, service = await self.exercise([("wired", "a"), ("wireless", ""), ("wireless", "")], enabled=False)
        ui.connect.assert_not_awaited()
        service.connection_target.assert_not_called()

    async def test_ambiguous_link_is_not_authenticated(self):
        ui, service = await self.exercise([("wired", "a"), ("ambiguous", ""), ("ambiguous", "")])
        ui.connect.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()

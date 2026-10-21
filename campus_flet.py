"""Desktop Flet interface. Network operations stay in the shared service layer."""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import flet as ft

from utils.credential_store import Credentials, CredentialStoreError
from utils.ui_tasks import TaskCoordinator
from utils.connection_events import ProgressMessage, STAGE_LABELS

INK = "#172B35"
MUTED = "#6D818B"
TEAL = "#087F83"
PALE = "#E8F5F3"
LINE = "#E4EBED"
BG = "#F3F6F7"


def resource_path(name):
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / name


def redact(message, secrets):
    text = str(message)
    for secret in sorted({str(v) for v in secrets if v}, key=len, reverse=True):
        for variant in {secret, json.dumps(secret, ensure_ascii=False)[1:-1],
                        json.dumps(secret, ensure_ascii=True)[1:-1]}:
            text = text.replace(variant, "[redacted]")
    return text


class CampusUI:
    def __init__(self, page, service, *, preview=False, minimized=False):
        self.page, self.service = page, service
        self.preview, self.minimized = preview, minimized
        self.loop = asyncio.get_running_loop()
        self.jobs = TaskCoordinator()
        self.cancel = threading.Event()
        self.settings = {}
        self.adapters = None
        self.dirty = set()
        self.secrets = set()
        self.credential_error = False
        self.hotspot_state = None
        self.startup_state = None
        self.startup_revision = 0
        self.startup_changing = False
        self.startup_waiting = minimized
        self.next_startup_check = 0
        self.auto_requested = False
        self.manual_action = False
        self.exit_pending = False
        self.tray = None
        self.tasks = set()
        self.logs = []
        self.current_view = "home"
        self.compact = False
        self.ready = asyncio.Event()
        self.preferences_task = None
        self.network_watch_started = False
        self.connection_inputs = None
        self.wired_active = False
        self.last_wired_status = None
        self.recovery_attempts = 0
        self.next_recovery = 0
        self.recovery_pending = False
        self.last_attempt_target = None
        from utils.resume_watch import ResumeWatch
        self.resume_watch = ResumeWatch(reader=(lambda: (0, 0)) if preview else None)
        self._make_controls()

    def field(self, name, hint, *, password=False, value=""):
        control = ft.TextField(value=value, hint_text=hint, password=password,
            width=float("inf"),
            can_reveal_password=password, text_size=14, filled=True,
            fill_color="#F7F9FA", border_color=LINE, focused_border_color=TEAL,
            border_radius=12, content_padding=ft.Padding.symmetric(horizontal=16, vertical=15),
            autocorrect=False, enable_suggestions=False,
            on_change=lambda e: self.changed(name))
        return control

    def changed(self, name):
        self.dirty.add(name)
        if name in {"username", "password", "legacy_saved_login"}:
            self.auto_requested = False
        if name in {"username", "password"}:
            self.dirty.add("legacy_saved_login")
        if name == "ethernet_guid":
            self.jobs.invalidate_read("hotspot")
            self.hotspot_state = None
            self._show_hotspot(None)
            self.spawn(self.refresh_hotspot())
        if name in {"connection_mode", "wired_backend"}:
            self._show_connection_options()
            if self.adapters is not None:
                self._apply_adapters(self.adapters)
            self.spawn(self.refresh_compatibility())
            self.update()
        if name == 'client_dir':
            self.jobs.invalidate_read('compatibility')
            self.compatibility_label.value = '保存或重新进入设置后检测'

    def spawn(self, coroutine):
        if self.jobs.closed:
            coroutine.close()
            return
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def update(self):
        if not self.jobs.closed:
            self.page.update()

    def _make_controls(self):
        self.username = self.field("username", "输入校园账号")
        self.password = self.field("password", "输入登录密码", password=True)
        self.password.on_submit = self.connect
        self.remember = ft.Checkbox(label="记住账号密码", value=False,
            active_color=TEAL, on_change=lambda e: self.changed("remember"))
        self.import_button = ft.TextButton("从锐捷导入账号", icon=ft.Icons.DOWNLOAD_ROUNDED,
            tooltip="读取锐捷当前账号，并由 Windows 加密保存", on_click=self.import_credentials)
        self.ssid = self.field("ssid", "热点名称", value="ovo")
        self.key = self.field("hotspot_key", "至少 8 位密码", password=True, value="12345678")
        self.client = self.field("client_dir", "自动查找已安装的锐捷客户端")
        self.auto_login = ft.Switch(label="运行后自动连接", value=True, active_color=TEAL,
            on_change=lambda e: self.changed("auto_login"))
        self.auto_hotspot = ft.Switch(label="连接成功后自动开启热点", value=False, active_color=TEAL,
            on_change=lambda e: self.changed("auto_hotspot"))
        self.legacy = ft.Switch(label="使用原客户端保存的账号", value=False, active_color=TEAL,
            on_change=self.legacy_changed)
        self.startup = ft.Switch(label="开机自启动", value=False,
            active_color=TEAL, on_change=self.change_startup)
        self.startup_label = ft.Text("进入设置后读取状态", size=12, color=MUTED)
        self.ethernet = ft.Dropdown(label="有线网络", options=[], value=None,
            width=float("inf"),
            text_size=13, filled=True, fill_color="#F7F9FA", border_color=LINE,
            border_radius=12, on_select=lambda e: self.changed("ethernet_guid"))
        self.connection_mode = ft.Dropdown(label="连接方式", value="auto", width=float("inf"),
            options=[ft.DropdownOption(key=k, text=t) for k, t in
                     (("auto", "自动 · 有线优先"), ("wired", "仅有线"), ("wireless", "仅无线 JNU"))],
            text_size=13, filled=True, fill_color="#F7F9FA", border_color=LINE,
            border_radius=12, on_select=lambda e: self.changed("connection_mode"))
        self.wired_backend = ft.Dropdown(label="有线认证方式", value="auto",width=float("inf"), menu_width=280,
            options=[ft.DropdownOption(key='auto',text='自动 · 本程序优先'),
                     ft.DropdownOption(key='independent',text='本程序认证'),ft.DropdownOption(key='native',text='兼容认证 · 使用锐捷')],
            filled=True,fill_color='#F7F9FA',border_color=LINE,border_radius=12,
            on_select=lambda e:self.changed('wired_backend'))
        self.wired_service = self.field('wired_service','认证服务',value='internet')
        self.client_options = ft.Column([
            self.label("锐捷客户端目录"), self.client,
            ft.Row([ft.TextButton("自动查找", icon=ft.Icons.SEARCH_ROUNDED, on_click=self.discover),
                    ft.TextButton("选择目录", icon=ft.Icons.FOLDER_OPEN_ROUNDED, on_click=self.browse)], wrap=True),
        ], visible=False, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
        self.compatibility_label = ft.Text('进入设置后检测兼容备选', size=12, color=MUTED)
        self.wired_options = ft.Container(ft.Column([
            self.wired_backend, self.compatibility_label, self.client_options,
        ], spacing=12, horizontal_alignment=ft.CrossAxisAlignment.STRETCH),
            bgcolor='#F7F9FA', padding=16, border_radius=12)
        self.band = ft.Dropdown(label="热点频段", value="2.4GHz",
            width=float("inf"), menu_width=240,
            options=[ft.DropdownOption(key=n, text=n) for n in ["2.4GHz", "5GHz", "自动"]],
            border_color=LINE, border_radius=12, filled=True, fill_color="#F7F9FA",
            on_select=lambda e: self.changed("band"))
        self.status = ft.Text("输入账号，即可连接", size=14, color=MUTED)
        self.hotspot_label = ft.Text("正在读取状态", size=12, color=MUTED)
        self.network_label = ft.Text("自动识别有线网络", size=12, color=MUTED)
        self.connect_button = ft.Button("连接校园网", icon=ft.Icons.ARROW_FORWARD_ROUNDED,
            on_click=self.connect, height=50, width=float("inf"),
            style=ft.ButtonStyle(bgcolor=TEAL, color="white", elevation=0,
                shape=ft.RoundedRectangleBorder(radius=12)))
        self.hotspot_button = ft.Button("查看热点", icon=ft.Icons.WIFI_TETHERING_ROUNDED,
            on_click=self.toggle_hotspot, height=46, width=float("inf"),
            style=ft.ButtonStyle(bgcolor=PALE, color=TEAL, elevation=0,
                shape=ft.RoundedRectangleBorder(radius=12)))
        self.progress = ft.ProgressBar(height=8, border_radius=4, color=TEAL, bgcolor=LINE, value=0, visible=False)
        self.flow_label = ft.Text('准备连接', size=12, color=TEAL, expand=True)
        self.flow_percent = ft.Text('0%', size=12, color=TEAL, weight=ft.FontWeight.W_600)
        self.flow_panel = ft.Container(ft.Column([
            ft.Row([self.flow_label, self.flow_percent]), self.progress,
        ], spacing=9), padding=ft.Padding(14, 12, 14, 12), border_radius=12, bgcolor=PALE, visible=False)
        self.notice = ft.Text(self.status.value, size=12, color=MUTED)
        self.log_view = ft.TextField(multiline=True, read_only=True, min_lines=8,
            max_lines=14, text_size=12, border_color=LINE, border_radius=12)
        self.save_button = ft.Button("保存设置", icon=ft.Icons.CHECK_ROUNDED,
            bgcolor=TEAL, color="white", on_click=self.save_settings)
        self.action_controls = [self.connect_button, self.hotspot_button, self.save_button,
            self.startup, self.auto_login, self.auto_hotspot, self.legacy,
            self.ethernet, self.connection_mode, self.wired_backend, self.wired_service, self.band, self.client, self.username, self.password,
            self.remember, self.import_button, self.ssid, self.key]

    @staticmethod
    def card(controls, *, expand=None):
        return ft.Container(ft.Column(controls, spacing=16, horizontal_alignment=ft.CrossAxisAlignment.STRETCH), bgcolor="white",
            padding=24, border_radius=20, border=ft.Border.all(1, LINE), expand=expand)

    @staticmethod
    def label(text):
        return ft.Text(text, size=12, color=MUTED, weight=ft.FontWeight.W_500)

    def home(self):
        login = self.card([
            ft.Row([ft.Container(ft.Icon(ft.Icons.LAN_ROUNDED, color=TEAL, size=22),
                                bgcolor=PALE, padding=11, border_radius=13),
                    ft.Column([ft.Text("校园网登录", size=18, weight=ft.FontWeight.W_600),
                               self.network_label], spacing=4)], spacing=12),
            ft.Container(height=2),
            ft.Column([self.label("校园账号"), self.username], spacing=7, horizontal_alignment=ft.CrossAxisAlignment.STRETCH),
            ft.Column([self.label("登录密码"), self.password], spacing=7, horizontal_alignment=ft.CrossAxisAlignment.STRETCH),
            ft.Row([self.remember, self.import_button], wrap=True, spacing=8), self.connect_button,
            self.flow_panel,
        ])
        return self.section("校园网", self.status, login)

    def hotspot_view(self):
        hotspot = self.card([
            ft.Row([ft.Container(ft.Icon(ft.Icons.WIFI_ROUNDED, color=TEAL, size=22),
                                bgcolor=PALE, padding=11, border_radius=13),
                    ft.Column([ft.Text("个人热点", size=18, weight=ft.FontWeight.W_600),
                               self.hotspot_label], spacing=4)], spacing=12),
            ft.Container(height=2),
            ft.Column([self.label("热点名称"), self.ssid], spacing=7, horizontal_alignment=ft.CrossAxisAlignment.STRETCH),
            ft.Column([self.label("热点密码"), self.key], spacing=7, horizontal_alignment=ft.CrossAxisAlignment.STRETCH),
            self.band, self.auto_hotspot, self.hotspot_button,
        ])
        return self.section("个人热点", None, hotspot)

    @staticmethod
    def section(title, subtitle, content):
        return ft.Column([
            ft.Text(title, size=28, weight=ft.FontWeight.W_700, color=INK),
            *([subtitle] if subtitle is not None else []), ft.Container(height=6),
            ft.Container(ft.Container(content, width=640), alignment=ft.Alignment.TOP_LEFT),
        ], spacing=10, scroll=ft.ScrollMode.AUTO, expand=True, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)

    def settings_view(self):
        general = self.card([
            ft.Text("常规", size=18, weight=ft.FontWeight.W_600),
            self.connection_mode, self.wired_options,
            ft.Divider(color=LINE), self.auto_login, self.legacy,
            self.startup, self.startup_label,
        ])
        maintenance = self.card([
            ft.Text("维护", size=18, weight=ft.FontWeight.W_600),
            ft.Row([ft.TextButton("检查网络", on_click=self.diagnose),
                    ft.TextButton("清除保存的账号", on_click=self.confirm_forget),
                    ft.TextButton("恢复原版", on_click=self.confirm_restore)], wrap=True),
            ft.ExpansionTile(title=ft.Text("运行记录", size=13, color=MUTED),
                controls=[self.log_view,
                    ft.TextButton('打开本地日志', icon=ft.Icons.FOLDER_OPEN_ROUNDED, on_click=self.open_logs)], expanded_cross_axis_alignment=ft.CrossAxisAlignment.STRETCH,
                tile_padding=0, maintain_state=True, icon_color=TEAL),
        ])
        return ft.Column([
            ft.Row([ft.Text("设置", size=28, weight=ft.FontWeight.W_700),
                    ft.Container(expand=True), self.save_button]),
            ft.Container(height=6),
            general, maintenance,
        ], spacing=16, scroll=ft.ScrollMode.AUTO, expand=True, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)

    def build(self):
        self.page.title = "校园网" if not self.preview else "校园网 · 界面预览"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.theme = ft.Theme(color_scheme_seed=TEAL, font_family="Microsoft YaHei UI", use_material3=True)
        self.page.bgcolor = BG
        self.page.padding = 0
        self.page.window.width, self.page.window.height = 1040, 720
        self.page.window.min_width, self.page.window.min_height = 480, 540
        self.page.window.icon = str(resource_path("icon/app.ico"))
        self.page.on_resize = self.resized
        self.page.window.prevent_close = True
        self.page.window.on_event = self.window_event
        self.page.window.visible = not self.minimized
        self.nav_home = self.nav_button("连接", ft.Icons.GRID_VIEW_ROUNDED, self.show_home, selected=True)
        self.nav_hotspot = self.nav_button("热点", ft.Icons.WIFI_TETHERING_ROUNDED, self.show_hotspot)
        self.nav_settings = self.nav_button("设置", ft.Icons.SETTINGS_OUTLINED, self.show_settings)
        self.sidebar = ft.Container(ft.Column([
            ft.Container(ft.Icon(ft.Icons.LAN_ROUNDED, color="white", size=30),
                         bgcolor=TEAL, padding=15, border_radius=18, width=60),
            ft.Text("校园网", size=22, weight=ft.FontWeight.W_700, color=INK),
            ft.Container(height=26), self.nav_home, self.nav_hotspot, self.nav_settings,
            ft.Container(expand=True),
            ft.Text("CAMPUS", size=11, color="#93A3AA", weight=ft.FontWeight.W_600),
        ], spacing=10, expand=True), width=168, padding=ft.Padding(22, 34, 18, 24),
            bgcolor="#EDF2F3", border=ft.Border(right=ft.BorderSide(1, LINE)))
        self.body = ft.Container(self.home(), expand=True, padding=ft.Padding(28, 30, 28, 12))
        self.compact_bar = ft.Container(ft.Row([
            ft.Icon(ft.Icons.LAN_ROUNDED, color=TEAL, size=24),
            ft.Text("校园网", size=18, weight=ft.FontWeight.W_600, expand=True),
            ft.IconButton(ft.Icons.GRID_VIEW_ROUNDED, tooltip="连接", icon_color=TEAL, on_click=self.show_home),
            ft.IconButton(ft.Icons.WIFI_TETHERING_ROUNDED, tooltip="热点", icon_color=TEAL, on_click=self.show_hotspot),
            ft.IconButton(ft.Icons.SETTINGS_OUTLINED, tooltip="设置", icon_color=TEAL, on_click=self.show_settings),
        ], spacing=8), padding=ft.Padding(20, 10, 12, 6), visible=False)
        self.footer = ft.Container(self.notice, padding=ft.Padding(28, 0, 28, 18), visible=False)
        self.page.add(ft.Row([self.sidebar,
            ft.Column([self.compact_bar, self.body, self.footer], spacing=0,
                expand=True, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
        ], spacing=0, expand=True, vertical_alignment=ft.CrossAxisAlignment.STRETCH))
        width = getattr(self.page, "width", None)
        if isinstance(width, (int, float)):
            self._resize(width)

    def _resize(self, width):
        compact = width < 820
        if compact == self.compact:
            return
        self.compact = compact
        self.sidebar.visible = not compact
        self.compact_bar.visible = compact
        inset = 20 if compact else 28
        self.body.padding = ft.Padding(inset, 16 if compact else 30, inset, 12)
        self.footer.padding = ft.Padding(inset, 0, inset, 18)
        self.update()

    async def resized(self, event):
        self._resize(event.width)

    @staticmethod
    def nav_button(text, icon, handler, selected=False):
        return ft.Button(text, icon=icon, height=44, width=128, on_click=handler,
            style=ft.ButtonStyle(bgcolor="white" if selected else "#EDF2F3",
                color=TEAL if selected else MUTED, elevation=0,
                alignment=ft.Alignment.CENTER_LEFT, padding=12,
                shape=ft.RoundedRectangleBorder(radius=12)))

    def _nav(self, view):
        self.current_view = view
        self.footer.visible = view != 'home'
        self.nav_home.style.bgcolor = "white" if view == "home" else "#EDF2F3"
        self.nav_home.style.color = TEAL if view == "home" else MUTED
        self.nav_settings.style.bgcolor = "white" if view == "settings" else "#EDF2F3"
        self.nav_settings.style.color = TEAL if view == "settings" else MUTED
        self.nav_hotspot.style.bgcolor = "white" if view == "hotspot" else "#EDF2F3"
        self.nav_hotspot.style.color = TEAL if view == "hotspot" else MUTED
        self.body.content = {"home": self.home, "hotspot": self.hotspot_view, "settings": self.settings_view}[view]()
        self.update()

    async def show_home(self, e=None):
        self._nav("home")

    async def show_hotspot(self, e=None):
        self._nav("hotspot")
        self.spawn(self.refresh_hotspot())

    async def show_settings(self, e=None):
        self._nav("settings")
        self.spawn(self.refresh_startup())
        self.spawn(self.refresh_compatibility())

    async def refresh_startup(self):
        # System startup is independent of authentication. Do not discard its
        # result every time a network mutation starts or finishes.
        if self.startup_changing:
            return
        self.startup_revision += 1
        revision = self.startup_revision
        try:
            state = await asyncio.to_thread(self.service.read_startup_state)
        except Exception:
            state = None
        if not self.jobs.closed and revision == self.startup_revision:
            self._show_startup(state)
            self.update()

    async def refresh_compatibility(self):
        if self.connection_mode.value == 'wireless':
            return
        values = self.values()
        def apply(result):
            if values.get('client_dir') == self.client.value and isinstance(result, dict):
                self.compatibility_label.value = result.get('message', '兼容备选暂未确认')
        await self.read('compatibility', lambda: self.service.compatibility_status(values), apply)

    def _show_connection_options(self):
        self.wired_options.visible = self.connection_mode.value != 'wireless'
        self.client_options.visible = self.wired_backend.value == 'native'
        self.compatibility_label.visible = self.wired_backend.value != 'independent'

    async def read(self, key, fn, apply, *, error_message=None):
        ticket = self.jobs.begin_read(key)
        if ticket is None:
            return False
        try:
            value = await asyncio.to_thread(fn)
        except Exception:
            if self.jobs.accept_read(ticket) and error_message:
                self.set_status(error_message)
                self.update()
            return False
        if self.jobs.accept_read(ticket):
            apply(value)
            self.update()
            return True
        return False

    async def bootstrap(self, auto_connect=False):
        # Only local preferences, credentials and the millisecond adapter read
        # participate in auto-login readiness. Slow optional status never does.
        self.preferences_task = asyncio.create_task(
            self.read("settings", self.service.load_settings, self._apply_settings))
        await asyncio.gather(
            self.preferences_task,
            self.read("credentials", self._credentials, self._apply_credentials),
            self.read("adapters", self.service.list_adapters, self._apply_adapters,
                      error_message="暂未读到有线网卡，可在设置中刷新"),
        )
        self.ready.set()
        if self.jobs.closed:
            return
        usable = self.legacy.value or (not self.credential_error and self.username.value and self.password.value)
        requested = auto_connect or bool(self.settings and self.auto_login.value)
        if requested and usable and not self.manual_action and not ({"username", "password", "legacy_saved_login"} & self.dirty):
            self.connection_inputs = self._connection_inputs()
            if not self.startup_waiting or await self.startup_admitted():
                await self.connect(automatic=True)
        else:
            self.spawn(self.refresh_hotspot())
        if not self.preview and not self.network_watch_started:
            self.network_watch_started = True
            self.spawn(self.watch_network())

    async def startup_admitted(self):
        values, inputs = self.values(), self._connection_inputs()
        result = await asyncio.to_thread(self.service.startup_decision, values)
        if (self.jobs.closed or self.jobs.mutation_busy or not self.startup_waiting or
                values != self.values() or inputs != self._connection_inputs()):
            return False
        self.next_startup_check = time.monotonic() + 30
        if isinstance(result, dict) and result.get('connect') is True:
            self.startup_waiting = False
            return True
        if isinstance(result, dict):
            self.set_status(result.get('message', '等待可用校园网'))
            self.update()
        return False

    def _connection_inputs(self):
        return (self.username.value, self.password.value, self.legacy.value,
                self.wired_backend.value, self.connection_mode.value)

    async def watch_network(self):
        """Debounce media changes. Never retry a rejected password on a timer."""
        last, candidate = self.last_attempt_target, None
        samples = 0
        while not self.jobs.closed:
            before_sleep = time.monotonic()
            await asyncio.sleep(2)
            resumed = self.resume_watch.poll() or (
                self.resume_watch.reader is None and time.monotonic() - before_sleep > 15)
            if self.jobs.closed:
                break
            if resumed and self.connection_inputs is not None and self.auto_login.value:
                self.recovery_pending = True
                self.recovery_attempts = 0
                self.next_recovery = time.monotonic() + 5
            if not self.jobs.mutation_busy:
                await self.read('wired-status',self.service.wired_status,self._apply_wired_status)
                await self.read("wireless-keepalive", self.service.maintain_wireless,
                                lambda _: None, error_message="JNU 在线状态未确认，请重新连接")
            if (self.jobs.mutation_busy or not self.auto_login.value or
                    self.connection_inputs != self._connection_inputs()):
                last = candidate = None
                samples = 0
                continue
            if self.startup_waiting:
                if time.monotonic() >= self.next_startup_check and await self.startup_admitted():
                    await self.connect(automatic=True)
                continue
            state = self.last_wired_status or {}
            if state.get('retryable'):
                self.recovery_pending = True
                if self.recovery_attempts >= 3:
                    self.set_status('自动重连已暂停，请检查网络后手动连接')
                    self.update()
            elif state.get('ready') and not self.recovery_pending:
                self.recovery_attempts = 0
            ticket = self.jobs.begin_read("connection-target")
            if ticket is None:
                continue
            values = self.values()
            try:
                target = await asyncio.to_thread(self.service.connection_target, values)
            except Exception:
                continue
            if not self.jobs.accept_read(ticket) or values != self.values():
                continue
            if last is None:
                last = target
            samples = samples + 1 if target == candidate else 1
            candidate = target
            recovering = (self.recovery_pending and self.recovery_attempts < 3 and
                          time.monotonic() >= self.next_recovery)
            if (target == last and not recovering) or samples < 2:
                continue
            last = target
            if target[0] not in ("wired", "wireless"):
                continue
            if recovering:
                self.recovery_attempts += 1
                self.recovery_pending = False
            await self.connect(automatic=True)
            self.next_recovery = time.monotonic() + (5, 15, 30)[min(self.recovery_attempts, 2)]
            # Connection itself can change the WLAN association; seed the
            # next observation rather than authenticate the same link twice.
            last, candidate = self.last_attempt_target, None
            samples = 0

    def _credentials(self):
        try:
            return self.service.load_credentials(), False
        except CredentialStoreError:
            return None, True

    def _apply_credentials(self, result):
        credentials, failed = result
        self.credential_error = failed
        if failed:
            self.set_status("保存的账号无法解锁，可在设置中清除后重新输入")
        if credentials and not ({"username", "password", "remember"} & self.dirty):
            self.username.value, self.password.value = credentials.username, credentials.password
            self.remember.value = True
            self.secrets.update((credentials.username, credentials.password))

    def _apply_settings(self, values):
        self.settings = dict(values)
        for name, control in self.setting_fields().items():
            if name in {"ethernet_guid", "wired_service"}:
                continue
            if name not in self.dirty and name in values:
                control.value = values[name]
        if self.adapters is not None:
            self._apply_adapters(self.adapters)
        self._apply_legacy()
        self._show_connection_options()

    def _apply_adapters(self, rows):
        self.adapters = rows
        selected = self.ethernet.value or self.settings.get("ethernet_guid")
        physical = [r for r in rows if r.get("if_type") == 6 and r.get("hardware_interface") is True]
        self.ethernet.options = [ft.DropdownOption(key=r["guid"], text=r["name"] +
            (" · 已连接" if r.get("status") == "Up" else " · 未连接")) for r in physical]
        up = [r for r in physical if r.get("status") == "Up"]
        up.sort(key=lambda r: (r['guid'] != selected, str(r['guid'])))
        self.ethernet.value = up[0]['guid'] if up else None
        self.network_label.value = ("JNU 无线网络" if self.connection_mode.value == 'wireless' else
            "有线网络 · 自动选择" if up else "等待有线连接" if self.connection_mode.value == 'wired' else "自动连接 JNU 无线")

    async def wait_preferences(self):
        # Preserve saved preferences if a user acts immediately after launch.
        # This waits only for a small local file, never optional system probes.
        if self.preferences_task is not None:
            await asyncio.shield(self.preferences_task)

    def setting_fields(self):
        return {"client_dir": self.client, "auto_login": self.auto_login,
            "auto_hotspot": self.auto_hotspot, "ethernet_guid": self.ethernet,
            "ssid": self.ssid, "hotspot_key": self.key, "band": self.band,
            "legacy_saved_login": self.legacy, "connection_mode": self.connection_mode,
            'wired_backend':self.wired_backend,'wired_service':self.wired_service}

    def _apply_wired_status(self,result):
        if not isinstance(result,dict) or result==self.last_wired_status:
            return
        self.last_wired_status=dict(result)
        self.wired_active=bool(result.get('active'))
        ready=result.get('ready',True)
        if not self.jobs.mutation_busy and not ready:
            self.flow_panel.visible=False
        self.connect_button.content=('断开校园网' if ready else '重新连接') if self.wired_active else '连接校园网'
        self.connect_button.icon=ft.Icons.LINK_OFF_ROUNDED if self.wired_active else ft.Icons.ARROW_FORWARD_ROUNDED
        self.set_status(result.get('message','尚未连接校园网'))

    def values(self):
        values = {key: control.value for key, control in self.setting_fields().items()}
        values.update(wired_service="internet")
        return values

    def _apply_legacy(self):
        for c in [self.username, self.password, self.remember]:
            c.disabled = bool(self.legacy.value) or self.jobs.mutation_busy

    async def legacy_changed(self, e):
        self.changed("legacy_saved_login")
        self._apply_legacy()
        self.update()

    def _show_startup(self, state):
        if type(state) is not bool and self.startup_state is not None:
            self.startup_label.value = '暂未读到系统状态 · 保留上次确认结果'
            return
        self.startup_state = state if type(state) is bool else None
        self.startup.value = state is True
        self.startup_label.value = ("已开启 · 登录后约 30 秒启动" if state is True else
                                    "已关闭" if state is False else "状态暂未确认，可点击设置")

    def _show_hotspot(self, state):
        self.hotspot_state = state if type(state) is bool else None
        self.hotspot_label.value = "已开启" if state is True else "已关闭" if state is False else "暂未确认"
        self.hotspot_label.color = TEAL if state is True else MUTED
        self.hotspot_button.content = "关闭热点" if state is True else "开启热点" if state is False else "查看热点"

    async def refresh_hotspot(self):
        guid = self.ethernet.value
        def apply(state):
            if self.ethernet.value == guid:
                self._show_hotspot(True if state == "已启动" else False if state == "未启动" else None)
        return await self.read("hotspot", lambda: self.service.hotspot_status(guid), apply)

    def _redact_status(self, message):
        self.secrets.update(v for v in [self.username.value, self.password.value, self.key.value,
            self.settings.get("hotspot_key")] if v)
        return redact(message, self.secrets)

    def set_status(self, message, *, record=False):
        """Render both visible status locations from one sanitized message."""
        text = self.append_log(message) if record else self._redact_status(message)
        self.status.value = self.notice.value = text

    def append_log(self, message):
        text = self._redact_status(message)
        self.logs = (self.logs + [text])[-200:]
        self.log_view.value = "\n".join(self.logs)
        return text

    def _busy(self, busy):
        if busy:
            self.progress.visible = True
            self.flow_panel.visible = True
            self.progress.value = 0
            self.progress.color = TEAL
            self.flow_label.value = '准备连接'
            self.flow_percent.value = '0%'
        else:
            self.progress.visible=self.flow_panel.visible
            if self.progress.value != 1:
                self.flow_label.value = '操作未完成'
                self.progress.color = '#B86E2C'
        for control in self.action_controls:
            control.disabled = busy
        self._apply_legacy()

    async def action(self, fn, message, apply=None):
        await self.wait_preferences()
        ticket = self.jobs.begin_mutation()
        if ticket is None:
            return
        self.manual_action = True
        self.cancel.clear()
        self.set_status(message)
        def progress(message):
            def deliver():
                if self.jobs.accept_mutation(ticket):
                    if isinstance(message, ProgressMessage):
                        # Only verified completion reaches 100%. Repairs may
                        # revisit an earlier stage without reversing the bar.
                        portion={'network':.08,'prepare':.22,'authenticate':.45,'address':.65,'verify':.85,'complete':1}.get(message.stage,0)
                        self.progress.value = max(self.progress.value or 0, portion)
                        self.flow_percent.value = f'{self.progress.value:.0%}'
                        self.flow_label.value = STAGE_LABELS.get(message.stage,'正在连接')
                        self.set_status(message, record=True)
                    else:
                        self.append_log(message)
                    self.update()
            try:
                self.loop.call_soon_threadsafe(deliver)
            except RuntimeError:
                # A transport teardown must not interrupt native cleanup.
                pass
        try:
            self._busy(True)
            self.update()
            worker = self.loop.run_in_executor(None, fn, progress)
            while True:
                try:
                    result = await asyncio.shield(worker)
                    break
                except asyncio.CancelledError:
                    # Cancelling an await cannot stop its native thread. Keep
                    # the mutation slot until that thread has really returned.
                    self.cancel.set()
                    self.exit_pending = True
                    if worker.done():
                        result = worker.result()
                        break
            if self.jobs.accept_mutation(ticket):
                if apply:
                    apply(result)
                    self.flow_panel.visible = False
                elif isinstance(result, dict):
                    if result.get('connection_kind')=='wired':
                        self._apply_wired_status(result)
                    elif result.get('connection_kind')=='wireless':
                        self.wired_active=False
                        self.last_wired_status=None
                        self.connect_button.content='连接校园网'
                        self.connect_button.icon=ft.Icons.ARROW_FORWARD_ROUNDED
                    if "hotspot" in result:
                        self._show_hotspot(result["hotspot"])
                    self.set_status(result.get("message", "已完成"), record=True)
                    if result.get('ready'):
                        self.progress.value=1
                        self.flow_percent.value='100%'
                        self.flow_label.value='已连接'
                    elif 'connection_kind' not in result:
                        self.flow_panel.visible=False
                    elif not result.get('active') and not result.get('authenticated'):
                        self.flow_panel.visible=False
        except Exception as error:
            if self.jobs.accept_mutation(ticket):
                self.set_status("操作未完成：" + str(error), record=True)
        finally:
            if self.jobs.finish_mutation(ticket):
                self._busy(False)
                try:
                    self.update()
                finally:
                    if self.exit_pending:
                        await self.exit()
                    else:
                        self.spawn(self.refresh_hotspot())
                        if self.current_view == 'settings' and self.startup_state is None:
                            self.spawn(self.refresh_startup())

    async def connect(self, e=None, *, automatic=False):
        await self.wait_preferences()
        if self.jobs.mutation_busy:
            return
        if (self.wired_active and (self.last_wired_status or {}).get('ready',True) and not automatic and
                (self.connection_inputs is None or self.connection_inputs == self._connection_inputs())):
            self.connection_inputs=None
            self.recovery_pending=False
            await self.action(lambda log:self.service.disconnect(),'正在断开校园网…')
            return
        try:
            credentials = None if self.legacy.value else Credentials(
                (self.username.value or "").strip(), self.password.value or "")
        except ValueError as error:
            self.set_status(error)
            self.update()
            return
        values, remember = self.values(), bool(self.remember.value)
        if not automatic:
            self.startup_waiting = False
            self.recovery_attempts = 0
            self.recovery_pending = False
        self.connection_inputs = self._connection_inputs()
        if credentials:
            self.secrets.update((credentials.username, credentials.password))
        def perform(log):
            self.service.record_ui_event(
                f'自动连接 / 重连，当前重试次数 {self.recovery_attempts}' if automatic else '用户请求连接')
            target = self.service.connection_target(values)
            if isinstance(target, tuple):
                self.last_attempt_target = target
            selected_values = dict(values, ethernet_guid=target[1]) if isinstance(target, tuple) and target[0] == 'wired' else values
            return self.service.connect(selected_values, credentials, remember, self.cancel, log,
                                        require_ethernet=automatic)
        await self.action(perform, "正在检查网络连接…" if automatic else "正在连接校园网…")
        await self.read('wired-status', self.service.wired_status, self._apply_wired_status)

    async def open_logs(self, e=None):
        try:
            await asyncio.to_thread(self.service.open_logs)
        except Exception:
            self.set_status('无法打开日志目录，请检查本机文件权限', record=True)
            self.update()

    async def import_credentials(self, e=None):
        await self.wait_preferences()
        values = self.values()
        def done(credentials):
            self.secrets.update((credentials.username, credentials.password))
            self.username.value, self.password.value = credentials.username, credentials.password
            self.password.password = True
            self.remember.value = True
            self.legacy.value = False
            self.credential_error = False
            self.dirty.update({"username", "password", "remember", "legacy_saved_login"})
            self.set_status("账号已导入并加密保存，可连接校园网")
        await self.action(lambda log: self.service.import_credentials(values), "正在导入锐捷账号…", done)

    async def toggle_hotspot(self, e=None):
        await self.wait_preferences()
        await self.read('adapters', self.service.list_adapters, self._apply_adapters)
        if self.hotspot_state is None:
            self.set_status("正在读取热点状态…")
            self.update()
            accepted = await self.refresh_hotspot()
            if accepted:
                self.set_status("热点状态已更新" if self.hotspot_state is not None else "暂时无法确认热点状态，请稍后重试")
                self.update()
            return
        enabled, values = not self.hotspot_state, self.values()
        await self.action(lambda log: self.service.toggle_hotspot(enabled, values, log),
                          "正在开启热点…" if enabled else "正在关闭热点…")

    async def save_settings(self, e=None):
        await self.wait_preferences()
        values = self.values()
        def done(result):
            self.settings = dict(result)
            self.set_status("设置已保存")
        await self.action(lambda log: self.service.save_settings(values), "正在保存…", done)

    async def change_startup(self, e):
        requested=getattr(e,'data',None)
        enabled = requested if type(requested) is bool else (
            requested.lower()=='true' if isinstance(requested,str) and requested.lower() in ('true','false') else bool(self.startup.value))
        await self.wait_preferences()
        if self.jobs.mutation_busy:
            self._show_startup(self.startup_state)
            self.update()
            return
        self.startup_revision += 1
        self.startup_changing = True
        values = self.values()
        done_ok=False
        def done(result):
            nonlocal done_ok
            done_ok=True
            self._show_startup(result.get("enabled"))
            self.set_status("自启动设置已更新")
        try:
            await self.action(lambda log: self.service.set_startup(enabled, values, log), "正在设置自启动…", done)
        finally:
            self.startup_changing = False
        if not done_ok:
            await self.refresh_startup()

    async def discover(self, e=None):
        revision = self.client.value
        def apply(path):
            if path and self.client.value == revision:
                self.client.value = str(path)
                self.dirty.add("client_dir")
            self.set_status("已找到客户端" if path else "未找到客户端，请手动选择目录")
        await self.read("discovery", lambda: self.service.discover_client(), apply)

    async def browse(self, e=None):
        if self.jobs.mutation_busy:
            return
        picker = ft.FilePicker()
        value = await picker.get_directory_path(dialog_title="选择锐捷客户端目录", initial_directory=self.client.value or None)
        if value and not self.jobs.closed:
            self.client.value = value
            self.changed("client_dir")
            self.update()

    async def refresh_adapters_click(self, e=None):
        await self.read("adapters", self.service.list_adapters, self._apply_adapters)

    async def diagnose(self, e=None):
        guid = self.ethernet.value
        def done(result):
            self.append_log(json.dumps(result, ensure_ascii=False, indent=2))
            self.set_status("网络检查完成，详情见维护记录")
        await self.read("diagnostics", lambda: self.service.diagnose(guid), done,
                        error_message="网络检查未完成，请稍后重试")

    async def confirm_forget(self, e=None):
        async def confirm(event):
            self.page.pop_dialog()
            def done(result):
                self.username.value = self.password.value = ""
                self.remember.value = False
                self.credential_error = False
                self.dirty.update({"username", "password", "remember"})
                self.set_status("已清除本程序保存的账号")
            await self.action(lambda log: self.service.clear_credentials(), "正在清除保存的账号…", done)
        self.confirm("清除保存的账号？", "仅清除本程序保存的账号。下次连接时需要重新输入。", confirm)

    async def confirm_restore(self, e=None):
        await self.wait_preferences()
        values = self.values()
        async def confirm(event):
            self.page.pop_dialog()
            def done(result):
                self.auto_login.value = self.auto_hotspot.value = False
                self._show_startup(False if result.get("startup_disabled") else None)
                self.set_status("已恢复原版认证核心")
            await self.action(lambda log: self.service.restore(values, log), "正在恢复原版…", done)
        self.confirm("恢复原版认证核心？", "将恢复备份的原版文件并尝试关闭自动启动。原版的网络限制也会恢复。", confirm)

    def confirm(self, title, text, handler):
        async def dismiss(e):
            self.page.pop_dialog()
        self.page.show_dialog(ft.AlertDialog(title=ft.Text(title), content=ft.Text(text),
            actions=[ft.TextButton("取消", on_click=dismiss), ft.TextButton("确认", on_click=handler)]))

    async def setup_tray(self):
        if self.preview:
            return
        def start():
            import pystray
            from PIL import Image
            def show(icon, item):
                asyncio.run_coroutine_threadsafe(self.reveal(), self.loop)
            def quit_app(icon, item):
                asyncio.run_coroutine_threadsafe(self.exit(), self.loop)
            tray = pystray.Icon("CampusLogin", Image.open(resource_path("icon/app.ico")), "校园网",
                pystray.Menu(pystray.MenuItem("打开", show, default=True), pystray.MenuItem("退出", quit_app)))
            tray.run_detached()
            return tray
        try:
            tray = await asyncio.to_thread(start)
            if self.jobs.closed:
                tray.stop()
            else:
                self.tray = tray
        except Exception:
            self.page.window.visible = True
            self.update()

    async def reveal(self):
        if not self.jobs.closed:
            self.page.window.visible = True
            self.page.window.minimized = False
            self.update()
            await self.page.window.to_front()

    async def window_event(self, e):
        if e.type == ft.WindowEventType.CLOSE:
            if self.tray:
                self.page.window.visible = False
                self.update()
            else:
                await self.exit()

    async def exit(self):
        if self.jobs.mutation_busy:
            self.exit_pending = True
            self.cancel.set()
            self.set_status("正在等待当前操作安全完成…")
            self.update()
            return
        self.jobs.close()
        try:
            await asyncio.to_thread(self.service.close)
        except Exception:
            pass
        if self.tray:
            self.tray.stop()
            self.tray = None
        await self.page.window.destroy()


class PreviewService:
    def open_logs(self):
        pass

    def record_ui_event(self, message):
        pass
    """Deterministic UI preview; cannot access credentials or change networking."""
    def __init__(self):
        self.connected = False
        self.hotspot = False
    def load_settings(self):
        return {"auto_login": False, "auto_hotspot": False, "ssid": "ovo", "hotspot_key": "12345678", "band": "2.4GHz"}
    def load_credentials(self):
        return None
    def import_credentials(self, values):
        return Credentials("demo-account", "DemoPassword9")
    def list_adapters(self):
        return [{"guid": "11111111-1111-4111-8111-111111111111", "name": "以太网",
                 "status": "Up", "if_type": 6, "hardware_interface": True}]
    def connection_target(self, values):
        return ("wired", "11111111-1111-4111-8111-111111111111")
    def maintain_wireless(self):
        return None
    def wired_status(self):
        return None
    def disconnect(self):
        self.connected=False
        return {'connection_kind':'wired','authenticated':False,'ready':False,'active':False,'message':'已断开校园网'}
    def close(self):
        self.connected=False
    def hotspot_status(self, guid):
        time.sleep(1.5)
        return "已启动" if self.hotspot else "未启动"
    def read_startup_state(self):
        time.sleep(1.5)
        return False
    def compatibility_status(self, values):
        return {'supported': False, 'message': '未检测到可用的兼容备选'}
    def startup_decision(self, values):
        return {'connect': True, 'reason': 'preview', 'message': '预览'}
    def connect(self, values, credentials, remember, cancel, log, *, require_ethernet=False):
        self.connected = True
        return {"message": "已连接校园网", "authenticated": True}
    def toggle_hotspot(self, enabled, values, log):
        self.hotspot = enabled
        return {"message": "热点已开启" if enabled else "热点已关闭", "hotspot": enabled}
    def save_settings(self, values, require_hotspot=False):
        return dict(values)
    def discover_client(self, saved_path=None):
        return None
    def clear_credentials(self):
        return None
    def set_startup(self, enabled, values, log):
        return {"enabled": enabled}
    def diagnose(self, guid):
        return {"preview": True, "network_changed": False}
    def restore(self, values, log):
        return {"startup_disabled": True}


def runtime_self_test():
    """Synthetic crypto checks; no real credential files or network access."""
    from utils.auth_credentials import decode_profile, encode_profile, encrypt_native_password, _decrypt_saved_password
    from utils.credential_store import WindowsDPAPI
    profile = b"[PUBLIC]\r\nName=SELF_TEST\r\n"
    if decode_profile(encode_profile(profile)) != profile:
        raise RuntimeError("Profile codec self-test failed")
    material = bytes.fromhex("0123456789abcdef1234567890abcdef")
    if encrypt_native_password("Now is the time for all ", material) != "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6":
        raise RuntimeError("DES-CBC self-test failed")
    if _decrypt_saved_password("E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6", material) != "Now is the time for all ":
        raise RuntimeError("Native import self-test failed")
    protector = WindowsDPAPI()
    if protector.decrypt(protector.encrypt(profile)) != profile:
        raise RuntimeError("DPAPI self-test failed")
    from datetime import datetime
    import tempfile
    from uuid import uuid4
    from utils.auth_log import AuthLogObserver, capture_auth_log
    # Exercise the bundled native-log detector with exact synthetic records.
    # No installed client, stored account or network state is consulted.
    test_dir = Path(tempfile.gettempdir()) / ("CampusLogin-selftest-" + uuid4().hex)
    log_dir = test_dir / "logs"
    log_dir.mkdir(parents=True)
    log_path = log_dir / "ui.log"
    pid = 54871  # Synthetic identity; no process is opened.
    tid = 54872
    def record(when, event):
        stamp = datetime.fromtimestamp(when).strftime("%Y-%m-%d %H:%M:%S")
        return f"[{stamp}][T:123][P:{tid}][info]:{event}\r\n".encode("ascii")
    success = "CSupplicantDlg::OnNotifyAuthResult AUTH_SUCCESS"
    stopped = "CSupplicantDlg::OnNotifyAuthResult AUTH_ALREADY_LOGOFF"
    now = time.time()
    try:
        log_path.write_bytes(record(now - 120, success))
        baseline = capture_auth_log(test_dir)
        observer = AuthLogObserver(test_dir, baseline, now - 3, pid=pid,
            thread_owner=lambda value: pid if value == tid else None)
        if observer.poll() is not None:
            raise RuntimeError("Historical auth-log self-test failed")
        with log_path.open("ab") as stream:
            stream.write(record(now, success))
        if observer.poll() is not True:
            raise RuntimeError("Fresh auth-log self-test failed")
        with log_path.open("ab") as stream:
            stream.write(record(now + 1, stopped))
        if observer.poll() is not False:
            raise RuntimeError("Auth-log logoff self-test failed")
    finally:
        log_path.unlink(missing_ok=True)
        log_dir.rmdir()
        test_dir.rmdir()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--connect", action="store_true")
    parser.add_argument("--minimized", action="store_true")
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--test-report", type=Path)
    args = parser.parse_args()
    preview = args.preview or args.self_test
    if not preview and not ctypes.windll.shell32.IsUserAnAdmin():
        arguments = sys.argv[1:] if getattr(sys, "frozen", False) else [str(Path(__file__).resolve()), *sys.argv[1:]]
        code = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
            subprocess.list2cmdline(arguments), str(Path(sys.executable).parent), 1)
        return 0 if code > 32 else 1
    from utils.flet_runtime import run_desktop
    from utils.auth_service import CampusService
    data_dir = Path(os.environ.get("APPDATA", str(Path.home()))) / "CampusLogin"
    service = PreviewService() if preview else CampusService(data_dir=data_dir, entry_script=Path(__file__).resolve())
    result = {"self_test": bool(args.self_test), "ok": False}
    created = time.perf_counter()
    async def app(page):
        ui = CampusUI(page, service, preview=preview, minimized=args.minimized)
        ui.build()
        result["controls_ready_seconds"] = round(time.perf_counter() - created, 4)
        if args.self_test:
            import psutil
            result["process_to_controls_seconds"] = round(time.time() - psutil.Process().create_time(), 4)
        ui.spawn(ui.bootstrap(args.connect))
        ui.spawn(ui.setup_tray())
        if args.self_test:
            await ui.ready.wait()
            # The status reader deliberately sleeps 1.5s. Login must be usable
            # and finish while that independent query is still pending.
            ui.username.value, ui.password.value = "preview-user", "preview-password"
            interactive = not ui.connect_button.disabled
            began = time.perf_counter()
            await ui.connect()
            duration = time.perf_counter() - began
            ui._nav("settings")
            ui._nav("home")
            synchronized = ui.status.value == ui.notice.value == "已连接校园网"
            await ui.import_credentials()
            imported = (ui.username.value == "demo-account" and ui.password.value == "DemoPassword9"
                        and ui.password.password and ui.remember.value and not ui.legacy.value
                        and ui.status.value == ui.notice.value)
            result.update(ok=bool(interactive and service.connected and duration < 1.0 and synchronized and imported),
                          native_import_ui_ok=bool(imported),
                          login_available_during_status_read=interactive,
                          status_synchronized=synchronized,
                          synthetic_connect_seconds=round(duration, 4))
            await asyncio.sleep(0.3)
            await ui.exit()
    guard = None
    try:
        if args.self_test:
            runtime_self_test()
            result["crypto_ok"] = True
            result["auth_log_ok"] = True
        if not preview:
            from utils.instance_guard import InstanceGuard
            guard = InstanceGuard(data_dir)
            if not guard.acquire():
                if not args.minimized:
                    ctypes.windll.user32.MessageBoxW(None, "程序已运行，请从系统托盘打开。", "校园网", 0x40)
                return 0
        run_desktop(app, assets_dir=str(resource_path("icon")), hidden=args.minimized)
    except Exception:
        if args.self_test:
            result["ok"] = False
            result["error"] = "Runtime or desktop initialization failed"
        else:
            ctypes.windll.user32.MessageBoxW(None,
                "程序未能启动。请完整解压发布包，保留 _internal 文件夹，并确认另一版本已经退出。",
                "校园网", 0x10)
        return 1
    finally:
        if guard:
            guard.release()
        if args.self_test and args.test_report:
            args.test_report.parent.mkdir(parents=True, exist_ok=True)
            args.test_report.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0 if not args.self_test or result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

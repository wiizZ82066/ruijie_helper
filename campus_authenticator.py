"""A compact desktop interface for campus authentication and mobile hotspot."""
import argparse
import base64
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QObject, QThread, QTimer, Signal, Slot, Qt, QLockFile
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QFormLayout, QLabel, QLineEdit, QComboBox, QPushButton,
                             QCheckBox, QPlainTextEdit, QFileDialog, QMessageBox,
                             QSystemTrayIcon, QMenu, QDialog, QTabWidget, QFrame)
from utils.core_install import CoreInstaller
from utils.auth_runtime import start_core, result_snapshot, wait_authentication
from utils.auth_startup import set_startup
from utils.campus_connection import WindowsOperations
from utils.client_discovery import discover_client_dir, is_client_dir
from utils.credential_store import Credentials, CredentialStore, CredentialStoreError
from utils.hotspot import HotspotManager

try:
    from utils.auth_credentials import prepare_credentials
except ImportError:
    prepare_credentials = None  # Unavailable transport must fail before starting the client.

DATA_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "CampusLogin"
SETTINGS = DATA_DIR / "settings.json"

STYLE = """
QMainWindow, QDialog { background: #F4F7FB; }
QWidget { color: #17334D; font-family: 'Microsoft YaHei UI', 'Segoe UI'; font-size: 13px; }
QLabel { background: transparent; }
QLabel#title { font-size: 28px; font-weight: 700; }
QLabel#section { font-size: 17px; font-weight: 600; }
QLabel#muted { color: #76889A; font-size: 12px; }
QLabel#status { font-size: 14px; color: #5D7388; }
QLabel#badge { color: #15738D; background: #EAF5F9; border-radius: 11px; padding: 4px 10px; font-size: 11px; }
QFrame#card { background: white; border: 1px solid #E7EDF4; border-radius: 19px; }
QLineEdit, QComboBox { background: #F7F9FC; border: 1px solid #E3EAF2; border-radius: 9px; padding: 9px 11px; min-height: 18px; }
QLineEdit:focus, QComboBox:focus { border: 1px solid #258AA6; background: white; }
QLineEdit:disabled, QComboBox:disabled { color: #8A9AA9; }
QComboBox::drop-down { border: none; width: 24px; }
QPushButton { background: white; border: 1px solid #DCE6EF; border-radius: 10px; padding: 9px 15px; font-weight: 500; }
QPushButton:hover { background: #EDF5FA; border-color: #BBD5E5; }
QPushButton:pressed { background: #E0EDF5; }
QPushButton:disabled { color: #91A2B1; background: #EDF1F5; border-color: #E7EDF3; }
QPushButton#primary { background: #147F9C; color: white; border: none; font-size: 16px; font-weight: 600; padding: 13px; }
QPushButton#primary:hover { background: #0E708D; }
QPushButton#primary:disabled { background: #A6C3CF; }
QPushButton#soft { background: #EAF5F9; border: none; color: #136D86; }
QPushButton#quiet { background: transparent; border: none; color: #59778E; }
QPushButton#quiet:hover { background: #E7EEF6; }
QCheckBox { spacing: 9px; padding: 5px 0; }
QTabWidget::pane { border: 1px solid #E3EAF2; background: white; border-radius: 12px; }
QTabBar::tab { background: transparent; padding: 10px 19px; color: #708397; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #147F9C; border-bottom: 2px solid #147F9C; }
QPlainTextEdit { background: #F7F9FC; border: 1px solid #E3EAF2; border-radius: 9px; padding: 8px; font-size: 12px; }
"""


def read_startup_state():
    """Read this user's actual task state; None means it could not be verified."""
    script = r'''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$scheduler=New-Object -ComObject Schedule.Service
$scheduler.Connect()
try { $task=$scheduler.GetFolder('\').GetTask('CampusLogin-' + $sid) }
catch {
 if ($_.Exception.GetBaseException().HResult -eq -2147024894) {
  @{enabled=$false} | ConvertTo-Json -Compress; exit
 }
 throw
}
if ($task.Definition.Actions.Count -ne 1) { @{enabled=$null} | ConvertTo-Json -Compress; exit }
$action=$task.Definition.Actions.Item(1)
if ([string]$action.Path -ine [string]$data.executable) { @{enabled=$null} | ConvertTo-Json -Compress; exit }
if ($data.script -and ([string]$action.Arguments).IndexOf([string]$data.script,[StringComparison]::OrdinalIgnoreCase) -lt 0) {
 @{enabled=$null} | ConvertTo-Json -Compress; exit
}
@{enabled=[bool]$task.Enabled} | ConvertTo-Json -Compress
'''
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand",
             base64.b64encode(script.encode("utf-16le")).decode("ascii")],
            input=json.dumps({"executable": sys.executable,
                              "script": None if getattr(sys, "frozen", False) else str(Path(__file__).resolve())}),
            capture_output=True, encoding="utf-8", errors="replace", timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            return None
        data = json.loads(result.stdout)
        value = data.get("enabled") if isinstance(data, dict) else None
        return value if type(value) is bool else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def run_packaged_self_test():
    """Exercise bundled native crypto and profile coding with synthetic data only."""
    from utils.auth_credentials import decode_profile, encode_profile, encrypt_native_password
    profile = b"[PUBLIC]\r\nName=SELF_TEST\r\n"
    if decode_profile(encode_profile(profile)) != profile:
        raise RuntimeError("Profile codec self-test failed")
    if encode_profile(b"[PUBLIC]\r\n") != bytes.fromhex("FFA4AFAABDB3B6BCA2FFF2F5"):
        raise RuntimeError("Profile encoder golden self-test failed")
    material = bytes.fromhex("0123456789abcdef1234567890abcdef")
    # Fixed DES-CBC known-answer vector; this loads Crypto._raw_des/_raw_cbc.
    if encrypt_native_password("Now is the time for all ", material) != "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6":
        raise RuntimeError("DES-CBC golden self-test failed")


class Job(QObject):
    progress = Signal(str)
    done = Signal(object)
    error = Signal(str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    @Slot()
    def run(self):
        try:
            self.done.emit(self.fn(self.progress.emit))
        except Exception as exc:
            self.error.emit(str(exc))


class AuthWindow(QMainWindow):
    def __init__(self, *, self_test=False, auto_connect=False, minimized=False):
        super().__init__()
        self._thread = self._job = self._callback = None
        self._cancel = threading.Event()
        self._self_test = self_test
        self._settings = self._load_settings(self_test)
        self._startup_known = None
        self._hotspot_state = None
        self._hotspot_action = False
        self._credential_load_error = False
        self._login_secrets = set()
        self.credential_store = CredentialStore(DATA_DIR)
        self.setWindowTitle("校园网")
        self.resize(620, 680)
        self.setMinimumSize(560, 650)
        self.setStyleSheet(STYLE)

        saved_client = self._settings.get("client_dir", "")
        client_dir = saved_client if self_test else (discover_client_dir(saved_client) or saved_client)
        self.client = QLineEdit(str(client_dir or ""))
        self.client.setPlaceholderText("自动查找客户端，或手动选择目录")
        self.auto_login = QCheckBox("运行后自动连接")
        self.auto_login.setChecked(bool(self._settings.get("auto_login", True)))
        self.auto_hotspot = QCheckBox("连接成功后自动开启热点")
        self.auto_hotspot.setChecked(bool(self._settings.get("auto_hotspot", False)))
        self.username = QLineEdit()
        self.username.setPlaceholderText("校园账号")
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("登录密码")
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.remember_credentials = QCheckBox("在本程序记住账号密码")
        self.legacy_login = QCheckBox("使用原客户端中保存的账号")
        self.legacy_login.setChecked(bool(self._settings.get("legacy_saved_login", False)))
        self.legacy_login.toggled.connect(self._apply_legacy_login)
        self.ethernet = QComboBox()
        self.ssid = QLineEdit(str(self._settings.get("ssid", "ovo")))
        self.key = QLineEdit(str(self._settings.get("hotspot_key", "12345678")))
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.band = QComboBox()
        self.band.addItems(["2.4GHz", "5GHz", "自动"])
        self.band.setCurrentText(str(self._settings.get("band", "2.4GHz")))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(1000)

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(30, 26, 30, 26)
        layout.setSpacing(20)
        header = QHBoxLayout()
        title = QLabel("校园网")
        title.setObjectName("title")
        header.addWidget(title)
        header.addStretch()
        self.settings_button = QPushButton("设置")
        self.settings_button.setObjectName("quiet")
        self.settings_button.clicked.connect(self.open_settings)
        header.addWidget(self.settings_button)
        layout.addLayout(header)

        self.controls = QWidget()
        body = QVBoxLayout(self.controls)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(18)
        connection, connection_layout = self._card()
        heading = QLabel("校园网络")
        heading.setObjectName("section")
        connection_layout.addWidget(heading)
        self.status = QLabel("准备就绪")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        connection_layout.addWidget(self.status)
        login_form = QFormLayout()
        login_form.setVerticalSpacing(10)
        login_form.setHorizontalSpacing(16)
        login_form.addRow("账号", self.username)
        password_row = QHBoxLayout()
        password_row.addWidget(self.login_password, 1)
        self.login_password_toggle = QPushButton("显示")
        self.login_password_toggle.setObjectName("quiet")
        self.login_password_toggle.setCheckable(True)
        self.login_password_toggle.toggled.connect(self.set_login_password_visible)
        password_row.addWidget(self.login_password_toggle)
        login_form.addRow("密码", password_row)
        connection_layout.addLayout(login_form)
        connection_layout.addWidget(self.remember_credentials)
        self.connect_button = QPushButton("连接校园网")
        self.connect_button.setObjectName("primary")
        self.connect_button.clicked.connect(self.connect_network)
        connection_layout.addWidget(self.connect_button)
        body.addWidget(connection)

        hotspot, hotspot_layout = self._card()
        heading_row = QHBoxLayout()
        heading = QLabel("个人热点")
        heading.setObjectName("section")
        heading_row.addWidget(heading)
        heading_row.addStretch()
        self.hotspot_status = QLabel("待检查")
        self.hotspot_status.setObjectName("badge")
        heading_row.addWidget(self.hotspot_status)
        hotspot_layout.addLayout(heading_row)
        hotspot_layout.addSpacing(3)
        form = QFormLayout()
        form.setVerticalSpacing(12)
        form.setHorizontalSpacing(16)
        form.addRow("名称", self.ssid)
        password_row = QHBoxLayout()
        password_row.addWidget(self.key, 1)
        self.password_toggle = QPushButton("显示")
        self.password_toggle.setObjectName("quiet")
        self.password_toggle.setCheckable(True)
        self.password_toggle.toggled.connect(self.set_password_visible)
        password_row.addWidget(self.password_toggle)
        form.addRow("密码", password_row)
        hotspot_layout.addLayout(form)
        self.hotspot_button = QPushButton("检查热点")
        self.hotspot_button.setObjectName("soft")
        self.hotspot_button.clicked.connect(self._toggle_hotspot_clicked)
        hotspot_layout.addWidget(self.hotspot_button)
        body.addWidget(hotspot)
        layout.addWidget(self.controls)
        layout.addStretch(1)
        self._build_settings()
        self._apply_legacy_login(self.legacy_login.isChecked())
        if not self_test:
            self._load_saved_credentials()

        icon = QIcon(str(Path(getattr(sys, "_MEIPASS", Path(__file__).parent)) / "icon" / "app.ico"))
        self.setWindowIcon(icon)
        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip("校园网")
        menu = QMenu()
        for label, action in [("打开", self.showNormal), ("退出", self.exit_app)]:
            item = QAction(label, self)
            item.triggered.connect(action)
            menu.addAction(item)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self.showNormal() if reason == QSystemTrayIcon.ActivationReason.DoubleClick else None)
        if not self_test:
            self.tray.show()
            self.request_auto_connection(auto_connect or (bool(self._settings) and self.auto_login.isChecked()))
            QTimer.singleShot(0, self.refresh_overview)
            if minimized and self._pending_connect and QSystemTrayIcon.isSystemTrayAvailable():
                QTimer.singleShot(100, self.hide)

    @staticmethod
    def _load_settings(self_test):
        if not self_test:
            try:
                value = json.loads(SETTINGS.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    return value
            except (OSError, ValueError):
                pass
        return {}

    @staticmethod
    def _card():
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(23, 20, 23, 20)
        layout.setSpacing(10)
        return card, layout

    def _build_settings(self):
        self.settings_dialog = QDialog(self)
        self.settings_dialog.setWindowTitle("设置")
        self.settings_dialog.resize(620, 550)
        outer = QVBoxLayout(self.settings_dialog)
        outer.setContentsMargins(22, 22, 22, 20)
        outer.setSpacing(16)
        title = QLabel("设置")
        title.setObjectName("section")
        outer.addWidget(title)
        self.settings_controls = QWidget()
        controls_layout = QVBoxLayout(self.settings_controls)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        self.settings_tabs = QTabWidget()
        controls_layout.addWidget(self.settings_tabs)
        outer.addWidget(self.settings_controls, 1)

        general = QWidget()
        general_layout = QVBoxLayout(general)
        general_layout.setContentsMargins(20, 22, 20, 20)
        general_layout.setSpacing(12)
        general_layout.addWidget(QLabel("客户端目录"))
        general_layout.addWidget(self.client)
        path_buttons = QHBoxLayout()
        locate = QPushButton("自动查找")
        locate.clicked.connect(self.discover_client)
        browse = QPushButton("选择目录")
        browse.clicked.connect(self.browse)
        path_buttons.addWidget(locate)
        path_buttons.addWidget(browse)
        path_buttons.addStretch()
        general_layout.addLayout(path_buttons)
        general_layout.addSpacing(14)
        general_layout.addWidget(self.auto_login)
        general_layout.addWidget(self.legacy_login)
        self.startup_checkbox = QCheckBox("登录 Windows 后自动启动")
        self.startup_checkbox.clicked.connect(self.startup)
        general_layout.addWidget(self.startup_checkbox)
        self.startup_status = QLabel()
        self.startup_status.setObjectName("muted")
        general_layout.addWidget(self.startup_status)
        self._set_startup_state(None)
        general_layout.addStretch()
        self.settings_tabs.addTab(general, "常规")

        hotspot = QWidget()
        hotspot_layout = QVBoxLayout(hotspot)
        hotspot_layout.setContentsMargins(20, 22, 20, 20)
        form = QFormLayout()
        form.setVerticalSpacing(13)
        self.settings_ssid = QLineEdit(self.ssid.text())
        self.settings_key = QLineEdit(self.key.text())
        self.settings_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssid.textChanged.connect(self.settings_ssid.setText)
        self.settings_ssid.textChanged.connect(self.ssid.setText)
        self.key.textChanged.connect(self.settings_key.setText)
        self.settings_key.textChanged.connect(self.key.setText)
        form.addRow("名称", self.settings_ssid)
        row = QHBoxLayout()
        row.addWidget(self.settings_key, 1)
        self.settings_password_toggle = QPushButton("显示")
        self.settings_password_toggle.setObjectName("quiet")
        self.settings_password_toggle.setCheckable(True)
        self.settings_password_toggle.toggled.connect(self.set_password_visible)
        row.addWidget(self.settings_password_toggle)
        form.addRow("密码", row)
        form.addRow("频段", self.band)
        source = QHBoxLayout()
        source.addWidget(self.ethernet, 1)
        refresh = QPushButton("刷新")
        refresh.clicked.connect(self.refresh_adapters)
        source.addWidget(refresh)
        form.addRow("有线网络", source)
        hotspot_layout.addLayout(form)
        hotspot_layout.addSpacing(15)
        hotspot_layout.addWidget(self.auto_hotspot)
        hint = QLabel("热点开启时，修改名称和密码将在下次开启后生效。")
        hint.setWordWrap(True)
        hint.setObjectName("muted")
        hotspot_layout.addWidget(hint)
        hotspot_layout.addStretch()
        self.settings_tabs.addTab(hotspot, "热点")

        maintenance = QWidget()
        maintenance_layout = QVBoxLayout(maintenance)
        maintenance_layout.setContentsMargins(16, 20, 16, 16)
        row = QHBoxLayout()
        diagnose = QPushButton("检查网络")
        diagnose.clicked.connect(self.diagnose)
        restore = QPushButton("恢复原版")
        restore.clicked.connect(self.restore)
        forget = QPushButton("清除本程序保存的账号")
        forget.clicked.connect(self.clear_credentials)
        row.addWidget(diagnose)
        row.addWidget(restore)
        row.addWidget(forget)
        row.addStretch()
        maintenance_layout.addLayout(row)
        maintenance_layout.addWidget(self.log, 1)
        self.settings_tabs.addTab(maintenance, "维护")

        footer = QHBoxLayout()
        self.settings_message = QLabel("")
        self.settings_message.setObjectName("muted")
        self.settings_message.setWordWrap(True)
        footer.addWidget(self.settings_message, 1)
        self.save_button = QPushButton("保存设置")
        self.save_button.setObjectName("soft")
        self.save_button.clicked.connect(self.save_click)
        footer.addWidget(self.save_button)
        close = QPushButton("完成")
        close.clicked.connect(self.settings_dialog.hide)
        footer.addWidget(close)
        outer.addLayout(footer)

    def open_settings(self):
        self.settings_dialog.show()
        self.settings_dialog.raise_()
        self.settings_dialog.activateWindow()
        if not self._self_test and self._thread is None:
            self.run_job(lambda log: read_startup_state(), self._set_startup_state)

    def set_password_visible(self, visible):
        mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        for field in (self.key, self.settings_key):
            field.setEchoMode(mode)
        for button in (self.password_toggle, self.settings_password_toggle):
            button.blockSignals(True)
            button.setChecked(visible)
            button.setText("隐藏" if visible else "显示")
            button.blockSignals(False)

    def set_login_password_visible(self, visible):
        self.login_password.setEchoMode(QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)
        self.login_password_toggle.setText("隐藏" if visible else "显示")

    def _apply_legacy_login(self, enabled):
        for control in (self.username, self.login_password, self.remember_credentials):
            control.setEnabled(not enabled)
        if hasattr(self, "login_password_toggle"):
            self.login_password_toggle.setEnabled(not enabled)

    def _load_saved_credentials(self):
        try:
            credentials = self.credential_store.load()
            if credentials is not None:
                self.username.setText(credentials.username)
                self.login_password.setText(credentials.password)
                self.remember_credentials.setChecked(True)
                self._login_secrets.update((credentials.username, credentials.password))
        except CredentialStoreError:
            self._credential_load_error = True
            self.remember_credentials.setChecked(False)
            self.status.setText("本程序保存的账号无法解锁")
            self.settings_message.setText("请在维护中清除本程序保存的账号，再重新输入")
            self.append_log("本程序保存的账号无法解锁，原记录已保留；可在维护中明确清除后重新保存。")

    def request_auto_connection(self, requested):
        usable = self.legacy_login.isChecked() or (
            not self._credential_load_error and bool(self.username.text().strip()) and bool(self.login_password.text()))
        self._pending_connect = bool(requested and usable)
        if requested and not usable:
            self.status.setText("请先解锁已保存的账号" if self._credential_load_error else "请输入校园账号和密码")
        return self._pending_connect

    def clear_credentials(self):
        try:
            self.credential_store.clear()
        except CredentialStoreError:
            self.failed("清除本程序保存的账号失败，请稍后重试。")
            return
        self.username.clear()
        self.login_password.clear()
        self.remember_credentials.setChecked(False)
        self._credential_load_error = False
        self._login_secrets.clear()
        self._pending_connect = False
        self.settings_message.setText("已清除本程序保存的账号")
        self.status.setText("请输入校园账号和密码")
        self.append_log("已清除本程序保存的账号；原客户端的账号记录保持不变。")

    def _set_startup_state(self, enabled):
        self._startup_known = enabled if type(enabled) is bool else None
        self.startup_checkbox.blockSignals(True)
        self.startup_checkbox.setTristate(self._startup_known is None)
        self.startup_checkbox.setCheckState(Qt.CheckState.PartiallyChecked if self._startup_known is None else
                                           Qt.CheckState.Checked if enabled else Qt.CheckState.Unchecked)
        self.startup_checkbox.blockSignals(False)
        self.startup_status.setText("状态未知，点击复选框可设置" if self._startup_known is None else
                                    "已开启 · 登录后约 30 秒启动" if enabled else "已关闭")

    def _set_hotspot_state(self, enabled):
        self._hotspot_state = enabled if type(enabled) is bool else None
        self.hotspot_status.setText("已开启" if enabled is True else "已关闭" if enabled is False else "待检查")
        self.hotspot_button.setText("关闭热点" if enabled is True else "开启热点" if enabled is False else "检查热点")

    def _apply_hotspot_status(self, status):
        self._set_hotspot_state(True if status == "已启动" else False if status == "未启动" else None)
        if self._hotspot_state is None:
            self.append_log("热点状态暂时无法确认：" + str(status))

    def _toggle_hotspot_clicked(self):
        if self._hotspot_state is None:
            guid = self.ethernet.currentData()
            self.run_job(lambda log: HotspotManager.get_hotspot_status(guid), self._apply_hotspot_status)
        else:
            self.toggle_hotspot(not self._hotspot_state)

    def browse(self):
        value = QFileDialog.getExistingDirectory(self, "选择客户端目录", self.client.text())
        if value:
            self.client.setText(value)

    def discover_client(self):
        value = discover_client_dir()
        if value:
            self.client.setText(value)
            self.settings_message.setText("已找到客户端")
        else:
            self.settings_message.setText("未找到客户端，请手动选择目录")

    def _require_client(self):
        value = self.client.text().strip()
        directory = str(Path(value).resolve()) if is_client_dir(value) else discover_client_dir(value)
        if not directory:
            raise ValueError("未找到客户端，请在设置中选择客户端目录。")
        self.client.setText(directory)
        return Path(directory)

    def values(self):
        return {"client_dir": self.client.text().strip(), "auto_login": self.auto_login.isChecked(),
                "auto_hotspot": self.auto_hotspot.isChecked(), "ethernet_guid": self.ethernet.currentData(),
                "ssid": self.ssid.text(), "hotspot_key": self.key.text(), "band": self.band.currentText(),
                "legacy_saved_login": self.legacy_login.isChecked()}

    def save(self, validate_hotspot=False):
        value = self.values()
        HotspotManager._validate_credentials(value["ssid"], value["hotspot_key"])
        if (validate_hotspot or value["auto_hotspot"]) and not value["ethernet_guid"]:
            raise ValueError("请在设置中选择热点使用的有线网络。")
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        temporary = SETTINGS.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(SETTINGS)
        self._settings = value
        return value

    def save_click(self):
        try:
            self.save()
            self.settings_message.setText("已保存")
            self.append_log("设置已保存。")
        except Exception as exc:
            self.failed(str(exc))

    @Slot(str)
    def append_log(self, message):
        text = str(message)
        secrets = {self.key.text(), str(self._settings.get("hotspot_key", "")), self.username.text(),
                   self.login_password.text(), *self._login_secrets}
        for secret in sorted(secrets, key=len, reverse=True):
            if secret:
                for representation in {secret, json.dumps(secret, ensure_ascii=False)[1:-1],
                                       json.dumps(secret, ensure_ascii=True)[1:-1]}:
                    text = text.replace(representation, "[redacted]")
        self.log.appendPlainText(text)

    def run_job(self, fn, callback=None, *, read_only=False):
        if self._thread is not None:
            return
        # Read-only startup checks need not prevent typing or revealing a
        # password. Actions stay serialized until the snapshot is applied.
        self.controls.setEnabled(read_only)
        self.connect_button.setEnabled(False)
        self.hotspot_button.setEnabled(False)
        self.settings_controls.setEnabled(False)
        self.save_button.setEnabled(False)
        self._cancel.clear()
        self._callback = callback
        self._thread = QThread(self)
        self._job = Job(fn)
        self._job.moveToThread(self._thread)
        self._thread.started.connect(self._job.run)
        self._job.progress.connect(self.append_log)
        self._job.done.connect(self.completed, Qt.ConnectionType.QueuedConnection)
        self._job.error.connect(self.failed, Qt.ConnectionType.QueuedConnection)
        self._job.done.connect(self._thread.quit)
        self._job.error.connect(self._thread.quit)
        self._job.done.connect(self._job.deleteLater)
        self._job.error.connect(self._job.deleteLater)
        self._thread.finished.connect(self.idle)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    @Slot(object)
    def completed(self, result):
        if self._callback:
            self._callback(result)

    @Slot(str)
    def failed(self, message):
        self.status.setText("操作未完成，请在设置中查看详情")
        self.settings_message.setText("操作未完成，详情见维护")
        self.append_log(message)
        self._set_startup_state(self._startup_known)
        if self._hotspot_action:
            self._set_hotspot_state(None)
        self.showNormal()

    @Slot()
    def idle(self):
        self._thread = self._job = self._callback = None
        self._hotspot_action = False
        self.controls.setEnabled(True)
        self.connect_button.setEnabled(True)
        self.hotspot_button.setEnabled(True)
        self.settings_controls.setEnabled(True)
        self.save_button.setEnabled(True)
        if getattr(self, "_pending_connect", False):
            self._pending_connect = False
            QTimer.singleShot(0, self.connect_network)

    def _apply_adapters(self, items):
        selected = self.ethernet.currentData() or self._settings.get("ethernet_guid")
        self.ethernet.clear()
        for item in items:
            if item.get("if_type") == 6 and item.get("hardware_interface"):
                label = "已连接" if item.get("status") == "Up" else "未连接"
                self.ethernet.addItem(f"{item['name']} · {label}", item["guid"])
        index = self.ethernet.findData(selected)
        if index < 0:
            up = [item for item in items if item.get("if_type") == 6 and item.get("hardware_interface") and item.get("status") == "Up"]
            index = self.ethernet.findData(up[0]["guid"]) if len(up) == 1 else -1
        self.ethernet.setCurrentIndex(index)

    def refresh_adapters(self, checked=False):
        self.run_job(lambda log: WindowsOperations().list_adapters(), self._apply_adapters)

    def refresh_overview(self):
        guid = self._settings.get("ethernet_guid")
        def job(log):
            # Independent reads used to spawn three PowerShell processes in
            # sequence and held the whole form disabled until the last one.
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="overview") as pool:
                adapters = pool.submit(WindowsOperations().list_adapters)
                startup = pool.submit(read_startup_state)
                hotspot = pool.submit(HotspotManager.get_hotspot_status, guid)
                return adapters.result(), startup.result(), hotspot.result()
        def done(result):
            self._apply_adapters(result[0])
            self._set_startup_state(result[1])
            self._apply_hotspot_status(result[2])
        self.run_job(job, done, read_only=True)

    def connect_network(self):
        try:
            credentials = None
            if not self.legacy_login.isChecked():
                credentials = Credentials(self.username.text().strip(), self.login_password.text())
                if prepare_credentials is None:
                    raise RuntimeError("此版本尚未支持账号登录，请更新后再试。")
                self._login_secrets.update((credentials.username, credentials.password))
            client_dir = self._require_client()
            value = self.save()
            if credentials is not None:
                self.credential_store.save(credentials, remember=self.remember_credentials.isChecked())
        except Exception as exc:
            self.failed(str(exc))
            return
        self.status.setText("正在连接…")
        self._hotspot_action = bool(value["auto_hotspot"])
        def job(log):
            before, began = result_snapshot(client_dir), time.time()
            installer = CoreInstaller(client_dir, data_dir=DATA_DIR)
            current = installer.status()
            state = current["state"]
            if state in ("original", "patched") and (state == "original" or current.get("recovery_needed")):
                log("正在备份和校验核心，并完成锐捷服务状态恢复。")
                installer.install(log=log)
            elif state != "patched":
                raise RuntimeError("认证核心缺失或版本未核验，已停止。请先恢复原版 8021x.exe。")
            if credentials is not None:
                # Preparation samples and starts the new core before restoring
                # the service. start_core below reuses that session; never accept
                # the previous account's success from an older result.
                prepared = prepare_credentials(client_dir, credentials, log=log, data_dir=DATA_DIR)
                if (not isinstance(prepared, dict) or "before" not in prepared or
                        type(prepared.get("started")) not in (int, float)):
                    raise RuntimeError("账号登录准备未完成，未继续连接。")
                before, began = prepared["before"], prepared["started"]
            session = start_core(client_dir, log)
            if credentials is None and not value["auto_hotspot"]:
                return {"message": "请在登录窗口完成连接"}
            log("等待认证结果…")
            if not wait_authentication(client_dir, before, began, self._cancel, session=session,
                                       ethernet_adapter_guid=None if credentials is not None else value["ethernet_guid"]):
                log("认证核心保持运行；未取得认证成功结果，暂未自动开启热点。")
                return {"message": "等待登录完成"}
            if not value["auto_hotspot"]:
                return {"message": "已连接校园网"}
            result = self._start_hotspot(value, log)
            result["message"] = "已连接校园网" if result.pop("ready") else (
                "已连接，热点共享未就绪" if result["hotspot"] else "已连接，热点未能开启")
            return result
        self.run_job(job, self.show_result)

    def show_result(self, value):
        if isinstance(value, dict):
            if "hotspot" in value:
                self._set_hotspot_state(value["hotspot"])
            message = str(value.get("message", "已完成"))
        else:
            message = str(value)
        self.status.setText(message)
        self.append_log(message)

    def toggle_hotspot(self, enabled):
        try:
            # Stopping an active radio must remain possible even when the user
            # has an unfinished name/password edit or its source disappeared.
            value = self.save(validate_hotspot=True) if enabled else self.values()
        except Exception as exc:
            self.failed(str(exc))
            return
        self._hotspot_action = True
        self.status.setText("正在开启热点…" if enabled else "正在关闭热点…")
        def job(log):
            if enabled:
                return self._start_hotspot(value, log)
            ok, error = HotspotManager.stop_hotspot(value["ethernet_guid"])
            if not ok:
                raise RuntimeError(error)
            return {"message": "热点已关闭", "hotspot": False}
        self.run_job(job, self.show_result)

    @staticmethod
    def _start_hotspot(value, log):
        result = HotspotManager.start_hotspot_detailed(
            value["ssid"], value["hotspot_key"], value["band"], value["ethernet_guid"])
        ready = result.get("ok") is True
        # The radio can be on even if Windows sharing failed. Keep its actual
        # state so the one-button control can still turn it off.
        on = result.get("ap_on")
        on = on if type(on) is bool else None
        if not ready:
            log("热点开启未完成：" + str(result.get("error") or result.get("error_code") or "无法确认共享状态"))
        return {"ready": ready, "hotspot": on,
                "message": "热点已开启" if ready else "热点已开启，共享未就绪" if on else "热点未能开启"}

    def diagnose(self):
        guid = self.ethernet.currentData()
        def job(log):
            from utils.network_diagnostics import collect_network_diagnostics
            return collect_network_diagnostics(guid)
        def done(result):
            self.append_log(json.dumps(result, ensure_ascii=False, indent=2))
            self.settings_message.setText("检查完成，详情见下方记录")
        self.run_job(job, done)

    def restore(self):
        try:
            client_dir = self._require_client()
        except Exception as exc:
            self.failed(str(exc))
            return
        def job(log):
            result = CoreInstaller(client_dir, data_dir=DATA_DIR).restore(log=log)
            try:
                set_startup(False)
                result = dict(result, startup_disabled=True)
            except Exception as exc:
                log("原版核心已恢复，但关闭自启动失败：" + str(exc))
                result = dict(result, startup_disabled=False)
            return result
        def done(result):
            self.auto_login.setChecked(False)
            self.auto_hotspot.setChecked(False)
            self._set_startup_state(False if result.get("startup_disabled") else None)
            try:
                self.save()
            except Exception as exc:
                self.append_log("保存恢复后的设置失败：" + str(exc))
            self.show_result("已恢复原版")
        self.run_job(job, done)

    def startup(self, enabled):
        enabled = bool(enabled)
        try:
            client_dir = self._require_client() if enabled else None
            if enabled:
                self.save()
        except Exception as exc:
            self.failed(str(exc))
            return
        def job(log):
            if enabled:
                current = CoreInstaller(client_dir, data_dir=DATA_DIR).status()
                if current["state"] != "patched" or current.get("recovery_needed"):
                    raise RuntimeError("请先成功连接一次，再开启登录自启动。")
            return set_startup(enabled)
        def done(result):
            self._set_startup_state(result.get("enabled"))
            self.settings_message.setText("自启动设置已更新")
        self.run_job(job, done)

    def closeEvent(self, event):
        if self._self_test:
            event.accept()
        elif self._thread is not None or QSystemTrayIcon.isSystemTrayAvailable():
            self.hide()
            event.ignore()
        else:
            event.accept()
            QApplication.instance().quit()

    def exit_app(self):
        if self._thread is not None:
            self._cancel.set()
            self.showNormal()
            self.append_log("等待当前操作安全完成后可退出。")
        else:
            QApplication.instance().quit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--connect", action="store_true")
    parser.add_argument("--minimized", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        try:
            run_packaged_self_test()
        except Exception:
            return 1
    if not args.self_test and not ctypes.windll.shell32.IsUserAnAdmin():
        parameters = sys.argv[1:] if getattr(sys, "frozen", False) else [str(Path(__file__).resolve()), *sys.argv[1:]]
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, subprocess.list2cmdline(parameters), str(Path(sys.executable).parent), 1)
        return 0 if result > 32 else 1
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setQuitOnLastWindowClosed(False)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock = QLockFile(str(DATA_DIR / "authenticator.lock"))
    lock.setStaleLockTime(0)
    if not args.self_test and not lock.tryLock(100):
        QMessageBox.information(None, "校园网", "程序已运行，请从系统托盘打开。")
        return 0
    window = AuthWindow(self_test=args.self_test, auto_connect=args.connect, minimized=args.minimized)
    window.show()
    if args.self_test:
        QTimer.singleShot(200, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

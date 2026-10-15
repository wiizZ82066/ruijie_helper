"""GUI-independent application operations, called by a frontend's worker threads.

Methods are synchronous: the frontend owns dispatch, cancellation and rendering.
Hotspot state/ownership reads and changes share one instance lock. Unrelated
read-only operations do not acquire the core-operation lock or hotspot lock.
"""
from __future__ import annotations

import base64
from functools import wraps
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from uuid import UUID, uuid4

from utils.auth_runtime import CoreSession, result_snapshot, start_core, wait_authentication
from utils.auth_log import capture_auth_log
from utils.auth_startup import set_startup as configure_startup
from utils.campus_connection import WindowsOperations
from utils.client_discovery import discover_client_dir, is_client_dir
from utils.core_install import CoreInstaller
from utils.credential_store import Credentials, CredentialStore, CredentialStoreError
from utils.hotspot import HotspotManager
from utils.network_diagnostics import collect_network_diagnostics

try:
    from utils.auth_credentials import prepare_credentials
except ImportError:
    prepare_credentials = None


DEFAULT_SETTINGS = {
    "client_dir": "", "auto_login": True, "auto_hotspot": False,
    "ethernet_guid": None, "ssid": "ovo", "hotspot_key": "12345678",
    "band": "2.4GHz", "legacy_saved_login": False,
}

_STARTUP_QUERY = r'''$ErrorActionPreference='Stop'
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
if ([string]$action.Path -ine [string]$data.executable -or
    [string]$action.Arguments -ine [string]$data.arguments) {
 @{enabled=$null} | ConvertTo-Json -Compress; exit
}
@{enabled=[bool]$task.Enabled} | ConvertTo-Json -Compress
'''


def _safe_errors(method):
    @wraps(method)
    def run(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except CredentialStoreError:
            raise  # This API deliberately provides non-sensitive typed errors.
        except Exception as error:
            kind = ValueError if isinstance(error, ValueError) else RuntimeError
            raise kind(self._redact(str(error))) from None
    return run


class CampusService:
    def __init__(self, data_dir=None, entry_script=None):
        self.data_dir = (Path(data_dir).resolve() if data_dir is not None else
                         Path(os.environ.get("APPDATA", str(Path.home()))) / "CampusLogin")
        self.settings_path = self.data_dir / "settings.json"
        self.entry_script = (Path(entry_script).resolve() if entry_script is not None else
                             Path(__file__).resolve().parents[1] / "campus_authenticator.py")
        self.credential_store = CredentialStore(self.data_dir)
        self._operation_lock = threading.RLock()
        self._hotspot_lock = threading.RLock()
        self._settings_lock = threading.RLock()
        self._secrets_lock = threading.RLock()
        self._login_secrets = set()
        self._hotspot_keys = set()

    def _remember(self, values=None, credentials=None):
        with self._secrets_lock:
            if isinstance(values, dict) and isinstance(values.get("hotspot_key"), str):
                self._hotspot_keys.add(values["hotspot_key"])
            if isinstance(credentials, Credentials):
                self._login_secrets.update((credentials.username, credentials.password))

    def _redact(self, message):
        text = str(message)
        with self._secrets_lock:
            secrets = self._login_secrets | self._hotspot_keys
        for secret in sorted(secrets, key=len, reverse=True):
            if secret:
                for value in (secret, json.dumps(secret, ensure_ascii=False)[1:-1],
                              json.dumps(secret, ensure_ascii=True)[1:-1]):
                    text = text.replace(value, "[redacted]")
        return text

    def _logger(self, log):
        return lambda message: (log or (lambda _: None))(self._redact(message))

    @staticmethod
    def _settings(values, *, strict=False, base=None):
        if not isinstance(values, dict):
            raise ValueError("设置格式无效。")
        result = dict(DEFAULT_SETTINGS if base is None else base)
        for name, default in DEFAULT_SETTINGS.items():
            if name not in values:
                continue
            value = values[name]
            valid = type(value) is bool if type(default) is bool else isinstance(value, str)
            if name == "ethernet_guid":
                try:
                    value = str(UUID(str(value).strip().strip("{}"))).upper() if value else None
                    valid = True
                except (ValueError, TypeError, AttributeError):
                    valid = False
            elif name == "band":
                valid = value in ("2.4GHz", "5GHz", "自动")
            if not valid:
                if strict:
                    raise ValueError("设置字段格式无效：" + name)
                continue
            result[name] = value.strip() if name == "client_dir" else value
        return result

    def load_settings(self) -> dict:
        with self._settings_lock:
            try:
                values = json.loads(self.settings_path.read_text(encoding="utf-8"))
                result = self._settings(values)
            except (OSError, ValueError, TypeError):
                result = dict(DEFAULT_SETTINGS)
        self._remember(result)
        return result

    def _write_settings(self, values):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.settings_path.with_name(self.settings_path.name + ".tmp-" + uuid4().hex)
        try:
            temporary.write_text(json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(self.settings_path)
        finally:
            temporary.unlink(missing_ok=True)

    @_safe_errors
    def save_settings(self, values, require_hotspot=False) -> dict:
        self._remember(values)
        with self._settings_lock:
            result = self._settings(values, strict=True, base=self.load_settings())
            HotspotManager._validate_credentials(result["ssid"], result["hotspot_key"])
            if (require_hotspot or result["auto_hotspot"]) and not result["ethernet_guid"]:
                raise ValueError("请在设置中选择热点使用的有线网络。")
            self._write_settings(result)
        return result

    def load_credentials(self) -> Credentials | None:
        result = self.credential_store.load()
        self._remember(credentials=result)
        return result

    def clear_credentials(self):
        with self._operation_lock:
            self.credential_store.clear()
            with self._secrets_lock:
                self._login_secrets.clear()

    def discover_client(self, saved_path=None):
        return discover_client_dir(saved_path)

    def list_adapters(self):
        return [item for item in WindowsOperations().list_adapters()
                if item.get("if_type") == 6 and item.get("hardware_interface") is True]

    def _require_client(self, values):
        saved = values.get("client_dir", "")
        directory = str(Path(saved).resolve()) if saved and is_client_dir(saved) else self.discover_client(saved)
        if not directory:
            raise ValueError("未找到客户端，请在设置中选择客户端目录。")
        return Path(directory).resolve()

    def _startup_identity(self):
        arguments = ("--connect --minimized" if getattr(sys, "frozen", False) else
                     subprocess.list2cmdline([str(self.entry_script), "--connect", "--minimized"]))
        return {"executable": sys.executable, "arguments": arguments}

    def read_startup_state(self) -> bool | None:
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand",
                 base64.b64encode(_STARTUP_QUERY.encode("utf-16le")).decode("ascii")],
                input=json.dumps(self._startup_identity()), capture_output=True, encoding="utf-8", errors="replace",
                timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode:
                return None
            data = json.loads(result.stdout)
            value = data.get("enabled") if isinstance(data, dict) else None
            return value if type(value) is bool else None
        except (OSError, ValueError, subprocess.SubprocessError):
            return None

    @_safe_errors
    def set_startup(self, enabled, values, log) -> dict:
        self._remember(values)
        if type(enabled) is not bool:
            raise ValueError("自启动选项格式无效。")
        with self._operation_lock:
            if enabled:
                client_dir = self._require_client(values)
                current = CoreInstaller(client_dir, data_dir=self.data_dir).status()
                if current.get("state") != "patched" or current.get("recovery_needed"):
                    raise RuntimeError("请先成功连接一次，再开启登录自启动。")
                self.save_settings(dict(values, client_dir=str(client_dir)))
            return configure_startup(enabled, entry_script=self.entry_script)

    @staticmethod
    def _cancelled():
        return {"message": "已取消等待，认证核心保持当前状态", "authenticated": False, "ready": False}

    @_safe_errors
    def connect(self, values, credentials, remember, cancel, log) -> dict:
        self._remember(values, credentials)
        emit = self._logger(log)
        cancel = cancel if cancel is not None else threading.Event()
        with self._operation_lock:
            if cancel.is_set():
                return self._cancelled()
            if values.get("legacy_saved_login", False):
                credentials = None
            elif not isinstance(credentials, Credentials):
                raise ValueError("请输入校园账号和密码。")
            if credentials is not None and prepare_credentials is None:
                raise RuntimeError("此版本尚未支持账号登录，请更新后再试。")
            client_dir = self._require_client(values)
            value = self.save_settings(dict(values, client_dir=str(client_dir)))
            if credentials is not None:
                self.credential_store.save(credentials, remember=remember)
            log_before = capture_auth_log(client_dir)
            before, began = result_snapshot(client_dir), time.time()
            installer = CoreInstaller(client_dir, data_dir=self.data_dir)
            current = installer.status()
            state = current.get("state")
            if state in ("original", "patched") and (state == "original" or current.get("recovery_needed")):
                emit("正在备份和校验核心，并完成锐捷服务状态恢复。")
                installer.install(log=emit)
            elif state != "patched":
                raise RuntimeError("认证核心缺失或版本未核验，已停止。请先恢复原版 8021x.exe。")
            if cancel.is_set():
                return self._cancelled()
            if credentials is not None:
                # This operation starts the new core before restoring the native
                # service. Its baseline must replace every older account result.
                prepared = prepare_credentials(client_dir, credentials, log=emit, data_dir=self.data_dir)
                if (not isinstance(prepared, dict) or "before" not in prepared or
                        type(prepared.get("started")) not in (int, float) or
                        not math.isfinite(prepared["started"])):
                    raise RuntimeError("账号登录准备未完成，未继续连接。")
                before, began = prepared["before"], prepared["started"]
                log_before = prepared.get("log_before")
            if cancel.is_set():
                return self._cancelled()
            session = start_core(client_dir, emit)
            if not isinstance(session, CoreSession) or (credentials is not None and session.created_at < began):
                raise RuntimeError("未能确认本次账号配置对应的认证会话。")
            if credentials is None and not value["auto_hotspot"]:
                return {"message": "请在登录窗口完成连接", "authenticated": False, "ready": False}
            emit("等待认证结果…")
            if not wait_authentication(client_dir, before, began, cancel, session=session,
                                       ethernet_adapter_guid=None if credentials is not None else value["ethernet_guid"],
                                       log_before=log_before):
                emit("认证核心保持运行；未取得认证成功结果，暂未自动开启热点。")
                return {"message": "认证结果暂未确认，请在设置中查看运行记录", "authenticated": False, "ready": False}
            if cancel.is_set():
                return self._cancelled()
            if not value["auto_hotspot"]:
                return {"message": "已连接校园网", "authenticated": True, "ready": True}
            result = self._start_hotspot(value, emit, cancel=cancel)
            result["authenticated"] = True
            if result.get("cancelled"):
                return result
            result["message"] = "已连接校园网" if result["ready"] else (
                "已连接，热点共享未就绪" if result["hotspot"] else "已连接，热点未能开启")
            return result

    def _start_hotspot(self, values, emit, *, cancel=None):
        with self._hotspot_lock:
            # A status query may hold this lock while the frontend asks to
            # exit. Recheck only after acquiring it, before changing Wi-Fi.
            if cancel is not None and cancel.is_set():
                return {"ready": False, "cancelled": True,
                        "message": "已连接校园网，已取消自动开启热点"}
            result = HotspotManager.start_hotspot_detailed(
                values["ssid"], values["hotspot_key"], values["band"], values["ethernet_guid"])
        ready, on = result.get("ok") is True, result.get("ap_on")
        on = on if type(on) is bool else None
        if not ready:
            emit("热点开启未完成：" + str(result.get("error") or result.get("error_code") or "无法确认共享状态"))
        return {"ready": ready, "hotspot": on,
                "message": "热点已开启" if ready else "热点已开启，共享未就绪" if on else "热点未能开启"}

    @_safe_errors
    def toggle_hotspot(self, enabled, values, log) -> dict:
        self._remember(values)
        emit = self._logger(log)
        if type(enabled) is not bool:
            raise ValueError("热点开关格式无效。")
        with self._operation_lock:
            if enabled:
                return self._start_hotspot(self.save_settings(values, require_hotspot=True), emit)
            # Always permit stopping with an unfinished form or missing source.
            with self._hotspot_lock:
                ok, error = HotspotManager.stop_hotspot(values.get("ethernet_guid"))
            if not ok:
                raise RuntimeError(error or "热点关闭未完成。")
            return {"message": "热点已关闭", "hotspot": False, "ready": True}

    @_safe_errors
    def hotspot_status(self, guid) -> str:
        with self._hotspot_lock:
            return HotspotManager.get_hotspot_status(guid)

    @_safe_errors
    def diagnose(self, guid) -> dict:
        with self._hotspot_lock:
            return collect_network_diagnostics(guid)

    @_safe_errors
    def restore(self, values, log) -> dict:
        self._remember(values)
        emit = self._logger(log)
        with self._operation_lock:
            client_dir = self._require_client(values)
            result = dict(CoreInstaller(client_dir, data_dir=self.data_dir).restore(log=emit))
            try:
                configure_startup(False, entry_script=self.entry_script)
                result["startup_disabled"] = True
            except Exception as error:
                emit("原版核心已恢复，但关闭自启动失败：" + str(error))
                result["startup_disabled"] = False
            with self._settings_lock:
                restored = self._settings(values, base=self.load_settings())
                restored.update(auto_login=False, auto_hotspot=False, client_dir=str(client_dir))
                try:
                    # Disabling future automation must not depend on whether a
                    # draft hotspot password currently passes start validation.
                    self._write_settings(restored)
                    result["settings_saved"] = True
                except OSError as error:
                    emit("保存恢复后的设置失败：" + str(error))
                    result["settings_saved"] = False
            result.update(settings=restored, message="已恢复原版")
            return result

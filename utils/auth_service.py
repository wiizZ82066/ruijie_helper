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
from utils.connection_events import LocalJournal, ProgressMessage
from utils.wired_native_session import NativeSessionMonitor
from utils.wired_network import NetworkUnavailable

try:
    from utils.auth_credentials import prepare_credentials, read_saved_credentials
except ImportError:
    prepare_credentials = None
    read_saved_credentials = None


DEFAULT_SETTINGS = {
    "client_dir": "", "auto_login": True, "auto_hotspot": False,
    "ethernet_guid": None, "ssid": "ovo", "hotspot_key": "12345678",
    "band": "2.4GHz", "legacy_saved_login": False,
    "connection_mode": "auto",
    "wired_backend": "auto", "wired_service": "internet",
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
# The task name belongs to this user. A moved executable must not make an
# existing startup task impossible to display or disable from the new copy.
@{enabled=[bool]$task.Enabled} | ConvertTo-Json -Compress
'''


def _safe_errors(method):
    @wraps(method)
    def run(self, *args, **kwargs):
        began=time.monotonic()
        connection=method.__name__=='connect'
        if connection:
            self._trace.session=uuid4().hex[:12]
            self.journal.write('connection_start','开始连接',session=self._trace.session)
        try:
            result=method(self, *args, **kwargs)
            if connection:
                state=result if isinstance(result,dict) else {}
                self.journal.write('connection_result',state.get('message','连接操作结束'),
                    session=self._trace.session, duration_ms=round((time.monotonic()-began)*1000),
                    ready=state.get('ready'),authenticated=state.get('authenticated'),
                    cancelled=state.get('cancelled'),outcome='ready' if state.get('ready') else 'not_ready')
            return result
        except CredentialStoreError as error:
            self.journal.write('credential_error','无法读取或保存账号',
                session=getattr(self._trace,'session',''),operation=method.__name__,error_type=type(error).__name__)
            raise  # This API deliberately provides non-sensitive typed errors.
        except Exception as error:
            if connection and self._wired_session is None and self._native_session is None and self._last_wired_status is None:
                self._last_wired_status = dict(connection_kind='wired', active=False,
                    ready=False, authenticated=False, retryable=isinstance(error, NetworkUnavailable),
                    message=self._redact(str(error)))
            self.journal.write('operation_error', self._redact(str(error)),
                session=getattr(self._trace,'session',''), operation=method.__name__,
                duration_ms=round((time.monotonic()-began)*1000),error_type=type(error).__name__)
            kind = ValueError if isinstance(error, ValueError) else RuntimeError
            raise kind(self._redact(str(error))) from None
        finally:
            if connection:
                self._trace.session=''
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
        self._wireless_session = None
        self._wireless_next_keepalive = 0.0
        self._wired_session = None
        self._native_session = None
        self._last_wired_status = None
        self._journal_wired_status = None
        self._trace = threading.local()
        self.journal = LocalJournal(self.data_dir / 'logs', self._redact)

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
        began=time.monotonic()
        session=getattr(self._trace,'session','') or uuid4().hex[:12]
        current_stage=''
        stage_started=began
        sequence=0
        lock=threading.Lock()
        def emit(message):
            nonlocal current_stage,stage_started,sequence
            text = self._redact(message)
            stage = getattr(message, 'stage', '')
            with lock:
                now=time.monotonic()
                if stage and stage!=current_stage:
                    if current_stage:
                        self.journal.write('stage_finished','阶段结束',session=session,stage=current_stage,
                            duration_ms=round((now-stage_started)*1000))
                    current_stage,stage_started=stage,now
                sequence+=1
                fields=dict(getattr(message,'fields',{}))
                fields.update(stage=stage or current_stage,session=session,sequence=sequence,
                              elapsed_ms=round((now-began)*1000))
                self.journal.write(getattr(message,'event','progress'), text, **fields)
            (log or (lambda _: None))(ProgressMessage(stage, text) if stage else text)
        return emit

    def open_logs(self):
        self.journal.directory.mkdir(parents=True, exist_ok=True)
        os.startfile(str(self.journal.directory))

    def record_ui_event(self, message):
        self.journal.write('ui', message)

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
            elif name == "connection_mode":
                valid = value in ("wired", "wireless", "auto")
            elif name == "wired_backend":
                valid = value in ("auto", "independent", "native")
            elif name == "wired_service":
                valid = isinstance(value,str) and value.isascii() and 1<=len(value)<=32 and all(ord(c)>=32 for c in value)
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
            if (require_hotspot or (result["auto_hotspot"] and result["connection_mode"] == "wired")) and not result["ethernet_guid"]:
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

    @_safe_errors
    def import_credentials(self, values) -> Credentials:
        with self._operation_lock:
            # Retain the existing vault when it cannot be unlocked.
            self.load_credentials()
            if read_saved_credentials is None:
                raise RuntimeError("此版本暂不支持账号导入，请更新后再试。")
            client_dir = self._require_client(values)
            credentials = read_saved_credentials(client_dir)
            self._remember(credentials=credentials)
            self.credential_store.save(credentials, remember=True)
            try:
                with self._settings_lock:
                    current = self.load_settings()
                    current.update(client_dir=str(client_dir), legacy_saved_login=False)
                    self._write_settings(current)
            except Exception:
                raise RuntimeError("账号已加密保存，但登录方式设置未保存，请重试导入。") from None
            return credentials

    def discover_client(self, saved_path=None):
        return discover_client_dir(saved_path)

    def compatibility_status(self, values):
        """Read-only capability check; never install, start or read credentials."""
        try:
            directory = self._require_client(values)
            state = CoreInstaller(directory, data_dir=self.data_dir).status()
            supported = state.get('state') in ('original', 'patched') and not state.get('recovery_needed')
            return {'supported': supported, 'message': '兼容备选可用' if supported else '客户端版本不受支持或需要恢复'}
        except Exception:
            return {'supported': False, 'message': '未检测到可用的兼容备选'}

    def startup_decision(self, values):
        from utils.startup_network import decision
        try:
            result = decision(values, self.connection_target(values))
        except Exception:
            result = {'connect': False, 'reason': 'network_not_ready', 'message': '等待网络就绪'}
        self.journal.write('startup_network_check', result['message'], reason=result['reason'])
        return result

    def list_adapters(self):
        return [item for item in WindowsOperations().list_adapters()
                if item.get("if_type") == 6 and item.get("hardware_interface") is True
                and not any(token in str(item.get("interface_description", "")).upper()
                            for token in ("RNDIS", "REMOTE NDIS", "APPLE MOBILE DEVICE"))]

    def connection_target(self, values):
        """Read only; no global online state and no HTTP or credential access."""
        mode = values.get("connection_mode", "wired")
        if mode not in ("wired", "wireless", "auto"):
            raise ValueError("连接方式无效。")
        if mode != "wireless":
            up = [r for r in self.list_adapters() if r.get("status") == "Up" and
                  r.get("if_type") == 6 and r.get("hardware_interface") is True]
            selected = values.get("ethernet_guid")
            if up:
                # Keep an available previous interface, otherwise choose a
                # stable physical interface. Never pin a removed USB adapter.
                up.sort(key=lambda r: (r.get('guid') != selected, str(r.get('guid', ''))))
                return ("wired", up[0]["guid"])
            if selected:
                up = [r for r in up if r.get("guid") == selected]
            if len(up) > 1:
                return ("ambiguous", "")
            if up:
                return ("wired", up[0]["guid"])
            if mode == "wired":
                return ("unplugged", "")
        from utils.wireless_network import current_jnu
        guids = current_jnu()
        return ("wireless", ",".join(sorted(guids)))

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
            began=time.monotonic()
            self.journal.write('startup_request','设置开机自启动',enabled=enabled)
            if enabled and values.get("connection_mode", "wired") == "wired" and values.get("wired_backend", "independent") == "native":
                client_dir = self._require_client(values)
                current = CoreInstaller(client_dir, data_dir=self.data_dir).status()
                if current.get("state") != "patched" or current.get("recovery_needed"):
                    raise RuntimeError("请先成功连接一次，再开启登录自启动。")
                self.save_settings(dict(values, client_dir=str(client_dir)))
            elif enabled:
                self.save_settings(values)
            result=configure_startup(enabled, entry_script=self.entry_script)
            self.journal.write('startup_result','系统自启动任务已核验',enabled=result.get('enabled'),
                duration_ms=round((time.monotonic()-began)*1000))
            return result

    @staticmethod
    def _cancelled():
        return {"message": "已取消等待，认证核心保持当前状态", "authenticated": False, "ready": False}

    @_safe_errors
    def connect(self, values, credentials, remember, cancel, log, *, require_ethernet=False) -> dict:
        self._remember(values, credentials)
        emit = self._logger(log)
        cancel = cancel if cancel is not None else threading.Event()
        with self._operation_lock:
            if cancel.is_set():
                return self._cancelled()
            emit(ProgressMessage('network', '正在检查网络连接…'))
            mode = values.get("connection_mode", "wired")
            if mode not in ("wired", "wireless", "auto"):
                raise ValueError("连接方式无效。")
            if mode != 'wired':
                target, guid = self.connection_target(values)
                if target == "ambiguous":
                    raise ValueError("检测到多张有线网卡，请先在设置中选择。")
                if target == "wireless":
                    return self._connect_wireless(values, credentials, remember, cancel, emit)
                values = dict(values, ethernet_guid=guid)
                require_ethernet = True
            if require_ethernet:
                rows = self.list_adapters()
                connected = [row for row in rows if row.get("if_type") == 6 and
                             row.get("hardware_interface") is True and row.get("status") == "Up"]
                selected = values.get("ethernet_guid")
                if selected:
                    connected = [row for row in connected if row.get("guid") == selected]
                if len(connected) != 1:
                    return {"message": "未检测到可用的有线连接，已跳过自动认证" if not connected else
                            "检测到多张有线网卡，请选择后手动连接", "authenticated": False,
                            "ready": False, "skipped": True}
                values = dict(values, ethernet_guid=connected[0]["guid"])
                if cancel.is_set():
                    return self._cancelled()
            self._wireless_session = None
            backend = values.get('wired_backend', 'independent')
            if backend not in ('auto', 'independent', 'native'):
                raise ValueError('有线认证方式无效。')
            if backend in ('auto', 'independent'):
                try:
                    return self._connect_independent(values, credentials, remember, cancel, emit)
                except RuntimeError:
                    failed = self._last_wired_status or {}
                    if (backend != 'auto' or cancel.is_set() or not failed.get('fallback_allowed') or
                            self.connection_target(values)[0] != 'wired' or
                            not self.compatibility_status(values).get('supported')):
                        raise
                    emit(ProgressMessage('prepare', '本程序认证暂不可用，正在切换兼容认证…'))
            return self._connect_native(values, credentials, remember, cancel, emit)

    def _connect_native(self, values, credentials, remember, cancel, emit):
        self._close_wired()
        adapter = self._wired_adapter(values)
        values = dict(values, ethernet_guid=adapter['guid'])
        native_saved = bool(values.get("legacy_saved_login", False))
        client_dir = self._require_client(values)
        if native_saved:
            if read_saved_credentials is None:
                raise RuntimeError("此版本暂不支持读取锐捷保存的账号，请更新后再试。")
            credentials = read_saved_credentials(client_dir)
            self._remember(credentials=credentials)
        elif not isinstance(credentials, Credentials):
            raise ValueError("请输入校园账号和密码。")
        if credentials is not None and prepare_credentials is None:
            raise RuntimeError("此版本尚未支持账号登录，请更新后再试。")
        value = self.save_settings(dict(values, client_dir=str(client_dir)))
        if not native_saved:
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
            adapter_name = adapter.get('interface_description')
            prepared = prepare_credentials(client_dir, credentials, log=emit, data_dir=self.data_dir,
                                           adapter_name=adapter_name)
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
        monitor = NativeSessionMonitor(client_dir, session, value['ethernet_guid'], emit)
        self._native_session = monitor
        try:
            emit(ProgressMessage('authenticate', '等待兼容认证结果…'))
            accepted = wait_authentication(client_dir, before, began, cancel, session=session,
                ethernet_adapter_guid=None if credentials is not None else value['ethernet_guid'], log_before=log_before)
            if not accepted or cancel.is_set():
                self._close_wired()
                # A native timeout can include rejected credentials. Do not
                # automatically resubmit an unclassified authentication failure.
                result = dict(connection_kind='wired', backend='native', active=False,
                    ready=False, authenticated=False, retryable=False,
                    message='已取消连接' if cancel.is_set() else '兼容认证未通过，请检查账号、网卡和运行记录')
                self._last_wired_status = result
                return result
            emit(ProgressMessage('verify', '正在验证兼容认证的有线出口…'))
            verified = monitor.verify(cancel)
            if not verified.get('ready'):
                self._close_wired()
                verified['active'] = False
                self._last_wired_status = verified
                return verified
        except BaseException:
            self._close_wired()
            raise
        emit(ProgressMessage('complete', verified['message']))
        if not value["auto_hotspot"]:
            return verified
        result = self._start_hotspot(value, emit, cancel=cancel)
        result["authenticated"] = True
        if result.get("cancelled"):
            return result
        result["message"] = "已连接校园网" if result["ready"] else (
            "已连接，热点共享未就绪" if result["hotspot"] else "已连接，热点未能开启")
        return result

    def _close_wired(self):
        if self._wired_session is not None:
            self._wired_session.close()
            self._wired_session = None
        if self._native_session is not None:
            self._native_session.close()
            self._native_session = None
        self._last_wired_status = None

    def _connect_independent(self, values, credentials, remember, cancel, emit):
        from utils.wired_auth import WiredClient
        adapter = self._wired_adapter(values)
        if values.get('legacy_saved_login'):
            if read_saved_credentials is None:
                raise RuntimeError('暂不支持导入原客户端账号，请手动输入。')
            credentials=read_saved_credentials(self._require_client(values))
            self._remember(credentials=credentials)
        if not isinstance(credentials,Credentials):
            raise ValueError('请输入校园账号和密码。')
        value=self.save_settings(dict(values,ethernet_guid=adapter['guid']))
        if not values.get('legacy_saved_login'):
            self.credential_store.save(credentials,remember=remember)
        self._close_wired()
        client=WiredClient(adapter['guid'],value['wired_service'])
        self._wired_session=client
        try:
            result=client.connect(credentials,cancel,emit)
        except BaseException:
            status=client.snapshot()
            try:
                client.close()
            finally:
                self._wired_session=None
                self._last_wired_status=status
            raise
        if result.get('ready') and value['auto_hotspot']:
            hotspot=self._start_hotspot(value,emit,cancel=cancel)
            result.update(hotspot=hotspot.get('hotspot'))
            if not hotspot.get('ready'):
                result['message']='已连接校园网，热点共享未就绪'
        return result

    def _wired_adapter(self, values):
        rows = [r for r in self.list_adapters() if r.get('status') == 'Up']
        if not rows:
            raise NetworkUnavailable('有线网卡暂时不可用，等待网络恢复…')
        selected = str(values.get('ethernet_guid', '')).casefold()
        rows.sort(key=lambda row: (str(row['guid']).casefold() != selected, str(row['guid'])))
        return rows[0]

    def wired_status(self):
        client=self._wired_session or self._native_session
        result=client.snapshot() if client is not None else self._last_wired_status
        if isinstance(result,dict) and result!=self._journal_wired_status:
            self._journal_wired_status=dict(result)
            self.journal.write('wired_status', result.get('message',''),
                ready=result.get('ready'), authenticated=result.get('authenticated'),
                retryable=result.get('retryable'))
        return result

    @_safe_errors
    def disconnect(self):
        with self._operation_lock:
            self._close_wired()
            self.journal.write('disconnect', '用户已断开校园网')
            return {'connection_kind':'wired','authenticated':False,'ready':False,
                    'active':False,'message':'已断开校园网'}

    def close(self):
        with self._operation_lock:
            self._close_wired()
            self._wireless_session=None

    def _connect_wireless(self, values, credentials, remember, cancel, emit):
        self._close_wired()
        from utils.wireless_network import ensure_jnu, current_jnu
        from utils.interface_http import InterfaceHTTP
        from utils.jnu_portal import PortalClient
        emit(ProgressMessage('network',"正在检查并连接 JNU 无线网络…"))
        binding = ensure_jnu(cancel)
        emit(ProgressMessage('address','已连接 JNU，正在确认网络地址…'))
        if cancel.is_set():
            return self._cancelled()
        native_saved = bool(values.get("legacy_saved_login", False))
        if native_saved:
            if read_saved_credentials is None:
                raise RuntimeError("此版本暂不支持读取锐捷保存的账号。")
            credentials = read_saved_credentials(self._require_client(values))
            self._remember(credentials=credentials)
        elif not isinstance(credentials, Credentials):
            raise ValueError("请输入校园账号和密码。")
        # Reading the old profile is optional. No native core install/start,
        # profile writes, process patching, or session attachment happens here.
        self.save_settings(values)
        if not native_saved:
            self.credential_store.save(credentials, remember=remember)
        http = InterfaceHTTP(binding.index, binding.address, binding.dns, cancel)
        client = PortalClient(http, cancel, lambda: binding.guid.upper() in
                              {g.upper() for g in current_jnu()})
        self._wireless_session = None
        result = client.connect(credentials, emit)
        if client.keepalive_seconds > 0 and client.session_index:
            self._wireless_session = client
            self._wireless_next_keepalive = time.monotonic() + client.keepalive_seconds
        if values.get("auto_hotspot"):
            emit("无线连接已完成；自动热点仅在有线连接成功后开启。")
        return result

    @_safe_errors
    def maintain_wireless(self):
        """Only the server-requested heartbeat; never retry credentials here."""
        with self._operation_lock:
            client = self._wireless_session
            if client is None or time.monotonic() < self._wireless_next_keepalive:
                return None
            try:
                if not client.keepalive():
                    raise RuntimeError("JNU 在线状态未确认，请重新连接。")
            except Exception:
                self._wireless_session = None
                raise
            self._wireless_next_keepalive = time.monotonic() + client.keepalive_seconds
            return None

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

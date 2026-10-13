"""One-shot orchestration around the installed Ruijie client.

This module never implements, stores, or retrieves campus credentials. The
official client's saved automatic login is responsible for authentication.
Windows changes happen only in explicit manager methods, never at import time.
"""

from __future__ import annotations

import base64
import configparser
from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Callable, Optional
from uuid import UUID, uuid4


DEFAULT_CLIENT = ""
DEFAULT_ETHERNET_GUID = ""
CREATE_NO_WINDOW = 0x08000000


def _guid(value: str) -> str:
    return str(UUID(str(value).strip().strip("{}"))).upper()


def _same_path(first: str | Path, second: str | Path) -> bool:
    return str(Path(first).resolve()).replace("\\", "/").casefold() == str(
        Path(second).resolve()
    ).replace("\\", "/").casefold()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class CampusConnectionConfig:
    client_path: str = DEFAULT_CLIENT
    ethernet_guid: str = DEFAULT_ETHERNET_GUID
    disable_adapter_guids: list[str] = field(default_factory=list)
    checker_path: Optional[str] = None
    auto_hotspot: bool = True
    auth_timeout: float = 120

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CampusConnectionConfig":
        allowed = cls.__dataclass_fields__
        return cls(**{key: value for key, value in data.items() if key in allowed})

    def validate(self) -> None:
        if not self.client_path:
            from utils.client_discovery import discover_client_dir
            directory = discover_client_dir()
            if directory:
                self.client_path = str(Path(directory) / "RuijieSupplicant.exe")
        client = Path(self.client_path)
        if not client.is_absolute() or not client.is_file():
            raise ValueError("请选择已安装的锐捷客户端完整路径")
        if client.name.casefold() != "ruijiesupplicant.exe":
            raise ValueError("客户端必须为 RuijieSupplicant.exe")
        if not self.ethernet_guid:
            raise ValueError("请选择用于认证的实体有线网卡")
        self.ethernet_guid = _guid(self.ethernet_guid)
        self.disable_adapter_guids = list(dict.fromkeys(
            _guid(value) for value in self.disable_adapter_guids
        ))
        if self.ethernet_guid in self.disable_adapter_guids:
            raise ValueError("不能临时禁用用于认证的以太网网卡")
        if not isinstance(self.auth_timeout, (int, float)) or not 0 < self.auth_timeout <= 3600:
            raise ValueError("认证等待时间必须在 0 至 3600 秒之间")
        if self.checker_path:
            component = Path(self.checker_path)
            if not component.is_absolute() or component.name.casefold() != "8021x.exe":
                raise ValueError("认证组件必须是完整路径的 8021x.exe")


@dataclass
class ConnectionResult:
    success: bool
    message: str
    authenticated: bool = False
    hotspot_started: bool = False
    warnings: list[str] = field(default_factory=list)


class WindowsOperations:
    """Small injectable boundary: tests never invoke Windows or the client."""

    @staticmethod
    def _powershell(script: str) -> str:
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
             "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
            capture_output=True, encoding="utf-8", errors="replace", timeout=30,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Windows 网络操作失败")
        return result.stdout.strip()

    def list_adapters(self) -> list[dict]:
        try:
            from utils.native_adapters import list_adapters
            return list_adapters()
        except (OSError, ValueError, AttributeError, ImportError):
            # Keep the established query for unsupported native APIs/layouts.
            return self._list_adapters_powershell()

    def _list_adapters_powershell(self) -> list[dict]:
        raw = self._powershell("""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$items = @(Get-NetAdapter -IncludeHidden | ForEach-Object {
  [pscustomobject]@{guid=$_.InterfaceGuid.ToString(); name=$_.Name;
    enabled=([int]$_.AdminStatus -eq 1); status=$_.Status.ToString();
    interface_description=$_.InterfaceDescription; if_type=[int]$_.InterfaceType;
    hardware_interface=[bool]$_.HardwareInterface}
})
ConvertTo-Json -InputObject $items -Compress
""")
        items = json.loads(raw or "[]")
        if isinstance(items, dict):
            items = [items]
        for item in items:
            item["guid"] = _guid(item["guid"])
        return items

    def set_adapter_enabled(self, guid: str, enabled: bool) -> None:
        identifier = _guid(guid)  # UUID validation makes the script literal safe.
        operation = "Enable-NetAdapter" if enabled else "Disable-NetAdapter"
        self._powershell(f"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$nic = @(Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -eq [guid]'{identifier}' }})
if ($nic.Count -ne 1) {{ throw '无法唯一定位需要操作的网卡' }}
$nic[0] | {operation} -Confirm:$false -ErrorAction Stop
""")

    @staticmethod
    def start_client(path: Path) -> None:
        subprocess.Popen([str(path)], cwd=str(path.parent), shell=False,
                         creationflags=CREATE_NO_WINDOW)

    @staticmethod
    def stop_exact_executable(path: Path) -> int:
        import psutil

        matches = []
        for process in psutil.process_iter(["exe"]):
            matched = False
            try:
                executable = process.info.get("exe")
                if executable and _same_path(executable, path):
                    matched = True
                    process.terminate()
                    matches.append(process)
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied as error:
                # Never infer identity from the name when a path is unavailable.
                if matched:
                    raise RuntimeError("无法结束选定路径的认证组件") from error
        _, pending = psutil.wait_procs(matches, timeout=5)
        for process in pending:
            process.kill()
        _, pending = psutil.wait_procs(pending, timeout=5)
        if pending:
            raise RuntimeError("选定路径的认证组件未退出，未移动文件")
        return len(matches)

    @staticmethod
    def start_hotspot(ethernet_guid: str) -> tuple[bool, str]:
        from utils.hotspot import HotspotManager

        return HotspotManager.start_hotspot(ethernet_adapter_guid=ethernet_guid)


class CampusConnectionManager:
    def __init__(self, config: CampusConnectionConfig,
                 log: Optional[Callable[[str], None]] = None,
                 *, data_dir: Optional[Path | str] = None,
                 operations: Optional[WindowsOperations] = None):
        self.config = config
        self.log = log or (lambda message: None)
        base = Path(os.environ.get("APPDATA", str(Path.home())))
        self.data_dir = Path(data_dir) if data_dir is not None else base / "ruijie_helper"
        self.journal_path = self.data_dir / "connection_recovery.json"
        self.operations = operations or WindowsOperations()
        self._lock = threading.Lock()

    def _emit(self, message: str) -> None:
        self.log(message)

    def _read_journal(self) -> dict:
        if not self.journal_path.exists():
            return {"version": 1, "adapters": [], "checker": None}
        with self.journal_path.open(encoding="utf-8") as stream:
            journal = json.load(stream)
        if not isinstance(journal, dict) or journal.get("version") != 1:
            raise RuntimeError("恢复记录格式错误；请保留记录并检查后重试")
        return journal

    def _save_journal(self, journal: dict) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.journal_path.with_suffix(".json.tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(journal, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.journal_path)

    def list_adapters(self) -> list[dict]:
        return self.operations.list_adapters()

    def recovery_status(self) -> dict:
        return self._read_journal()

    def recover_adapters(self) -> list[str]:
        """Restore only adapters this manager recorded as originally enabled."""
        journal = self._read_journal()
        errors = []
        remaining = []
        for entry in journal.get("adapters", []):
            if not entry.get("was_enabled"):
                continue
            try:
                self.operations.set_adapter_enabled(_guid(entry["guid"]), True)
                self._emit(f"已恢复网卡：{entry.get('name', entry['guid'])}")
            except Exception as error:
                remaining.append(entry)
                errors.append(f"网卡恢复失败：{entry.get('name', entry.get('guid'))}（{error}）")
        if journal.get("adapters"):
            journal["adapters"] = remaining
            self._save_journal(journal)
        return errors

    def _component_path(self) -> Path:
        return Path(self.config.checker_path) if self.config.checker_path else (
            Path(self.config.client_path).parent / "8021x.exe"
        )

    def _import_legacy_record(self) -> None:
        journal = self._read_journal()
        if journal.get("checker"):
            return
        legacy_path = self.data_dir / "config.json"
        if not legacy_path.exists():
            return
        with legacy_path.open(encoding="utf-8") as stream:
            legacy = json.load(stream)
        record = legacy.get("move_record") if isinstance(legacy, dict) else None
        if not isinstance(record, dict) or record.get("action") != "kill_and_move":
            return
        original, moved = record.get("original_path"), record.get("moved_to")
        if not original or not moved or not _same_path(original, self._component_path()):
            return
        source, destination = Path(original), Path(moved)
        if not source.is_absolute() or not destination.is_absolute():
            raise RuntimeError("已有组件移动记录不是完整路径")
        if not destination.is_file():
            if not source.exists():
                raise RuntimeError("已有移动记录的原文件和备份均不存在，无法恢复认证组件")
            return
        journal["checker"] = {
            "original_path": str(source), "moved_to": str(destination),
            "sha256": _sha256(destination), "state": "quarantined", "legacy": True,
        }
        self._save_journal(journal)
        self._emit("已接管已有认证组件移动记录，登录前将按校验值恢复")

    @staticmethod
    def _move_no_overwrite(source: Path, destination: Path, expected_hash: str) -> None:
        """Exclusive destination creation; either copy remains recoverable on crash."""
        if _same_path(source, destination):
            raise RuntimeError("原文件和备份路径不能相同")
        if _sha256(source) != expected_hash:
            raise RuntimeError("文件校验值发生变化，已停止移动")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as incoming, destination.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        if _sha256(destination) != expected_hash or _sha256(source) != expected_hash:
            raise RuntimeError("移动文件校验失败，保留原文件和副本供恢复")
        shutil.copystat(source, destination)
        source.unlink()

    def restore_checker(self) -> dict:
        """Restore a recorded exact file, checking hashes and never overwriting."""
        self._import_legacy_record()
        journal = self._read_journal()
        record = journal.get("checker")
        if not record:
            return {"restored": False, "message": "没有需要恢复的认证组件"}
        source, moved = Path(record["original_path"]), Path(record["moved_to"])
        expected = record["sha256"]
        if source.name.casefold() != "8021x.exe" or not source.is_absolute() or not moved.is_absolute():
            raise RuntimeError("恢复记录中的认证组件路径无效")
        if source.exists():
            if _sha256(source) != expected:
                raise RuntimeError("认证组件原路径已有不同文件，已停止恢复以免覆盖")
            if moved.exists() and _sha256(moved) != expected:
                raise RuntimeError("认证组件备份校验失败，保留两个文件供检查")
            # A crash can leave both verified copies. Keep the backup; do not delete it.
        elif moved.is_file():
            self._move_no_overwrite(moved, source, expected)
        else:
            raise RuntimeError("认证组件及其备份均缺失，无法恢复")
        record["state"] = "restored"
        self._save_journal(journal)
        self._emit("认证组件已恢复到原安装目录")
        return {"restored": True, "path": str(source)}

    @staticmethod
    def _snapshot(path: Path) -> Optional[tuple[int, int, str]]:
        try:
            stat = path.stat()
            return stat.st_mtime_ns, stat.st_size, _sha256(path)
        except FileNotFoundError:
            return None

    @staticmethod
    def _fresh_result(path: Path, before: Optional[tuple], started_at: float) -> Optional[bool]:
        try:
            snapshot = CampusConnectionManager._snapshot(path)
            if snapshot is None or snapshot == before or path.stat().st_mtime < started_at - 1:
                return None
            if before is not None and snapshot[2] == before[2]:
                return None  # Merely touching an old Succeed file is not a new login.
            raw = path.read_bytes()
            text = None
            if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                encodings = ("utf-16",)
            elif b"\x00" in raw[:80]:
                encodings = ("utf-16-le",)
            else:
                encodings = ("utf-8-sig", "gb18030")
            for encoding in encodings:
                try:
                    text = raw.decode(encoding)
                    break
                except UnicodeError:
                    pass
            if text is None:
                return None
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(text)
            when = datetime.strptime(parser.get("Supplicant", "Time"), "%Y-%m-%d %H:%M:%S")
            if when < datetime.fromtimestamp(started_at).replace(microsecond=0):
                return None
            # Reject implausibly future records as well as stale successes.
            if when.timestamp() > time.time() + 5:
                return None
            result = parser.get("Supplicant", "Result").strip().casefold()
            if result == "succeed":
                return True
            if result in {"fail", "failed", "failure", "error"}:
                return False
        except (OSError, ValueError, configparser.Error):
            pass  # The official client may currently be writing the file.
        return None

    def _disable_selected(self, cancel: threading.Event) -> None:
        deadline = time.monotonic() + min(45, self.config.auth_timeout)
        announced = False
        while True:
            if cancel.is_set():
                raise RuntimeError("连接已取消")
            adapters = {_guid(item["guid"]): item for item in self.list_adapters()}
            ethernet = adapters.get(self.config.ethernet_guid)
            if ethernet:
                if ethernet.get("if_type") != 6 or not ethernet.get("hardware_interface"):
                    raise RuntimeError("认证来源必须为硬件以太网网卡")
                if not ethernet["enabled"]:
                    raise RuntimeError("选定的以太网网卡已禁用，请先手动启用")
                if str(ethernet.get("status", "")).casefold() == "up":
                    break
            if time.monotonic() >= deadline:
                raise RuntimeError("等待以太网就绪超时，请检查网线和网卡连接")
            if not announced:
                self._emit("正在等待选定以太网网卡和有线链路就绪")
                announced = True
            cancel.wait(min(1, max(0, deadline - time.monotonic())))
        for identifier in self.config.disable_adapter_guids:
            if identifier not in adapters:
                raise RuntimeError(f"未找到已选网卡：{identifier}")
        for identifier in self.config.disable_adapter_guids:
            item = adapters[identifier]
            if not item["enabled"]:
                continue
            journal = self._read_journal()
            journal.setdefault("adapters", []).append({
                "guid": identifier, "name": item["name"], "was_enabled": True,
            })
            self._save_journal(journal)  # Record the inverse before changing Windows.
            self.operations.set_adapter_enabled(identifier, False)
            self._emit(f"已临时禁用网卡：{item['name']}")

    def _quarantine_component(self, warnings: list[str]) -> None:
        component = self._component_path()
        if not component.is_file():
            record = self._read_journal().get("checker")
            if record and _same_path(record["original_path"], component):
                moved = Path(record["moved_to"])
                if moved.is_file() and _sha256(moved) == record["sha256"]:
                    self._emit("认证组件已经移出且备份校验通过，复用已有隔离状态")
                    return
            message = "未找到指定路径的 8021x.exe；已跳过组件隔离，继续热点步骤"
            warnings.append(message)
            self._emit(message)
            return
        digest = _sha256(component)
        destination = self.data_dir / "quarantine" / str(uuid4()) / "8021x.exe"
        journal = self._read_journal()
        journal["checker"] = {"original_path": str(component), "moved_to": str(destination),
                              "sha256": digest, "state": "planned"}
        self._save_journal(journal)
        self.operations.stop_exact_executable(component)
        self._move_no_overwrite(component, destination, digest)
        journal["checker"]["state"] = "quarantined"
        self._save_journal(journal)
        self._emit("已结束指定安装路径的认证组件并移入可恢复备份")
        warnings.append("8021x.exe 包含认证功能；当前方法的长期心跳和重新认证仍需验证")

    def connect(self, cancel_event: Optional[threading.Event] = None) -> ConnectionResult:
        if not self._lock.acquire(blocking=False):
            return ConnectionResult(False, "已有连接操作正在执行")
        try:
            return self._connect(cancel_event)
        finally:
            self._lock.release()

    def _connect(self, cancel_event: Optional[threading.Event]) -> ConnectionResult:
        authenticated = False
        warnings: list[str] = []
        failure: Optional[str] = None
        cancel = cancel_event or threading.Event()
        try:
            self.config.validate()
            errors = self.recover_adapters()
            if errors:
                raise RuntimeError("；".join(errors))
            self.restore_checker()
            if cancel.is_set():
                raise RuntimeError("连接已取消")
            self._disable_selected(cancel)
            client = Path(self.config.client_path)
            status_path = client.parent / "SupplicantResult.ini"
            before = self._snapshot(status_path)
            started_at = time.time()
            self.operations.start_client(client)
            self._emit("已启动官方客户端，等待本次自动认证结果（不会读取或保存账号密码）")
            deadline = time.monotonic() + self.config.auth_timeout
            while time.monotonic() < deadline:
                if cancel.is_set():
                    raise RuntimeError("连接已取消")
                result = self._fresh_result(status_path, before, started_at)
                if result is True:
                    authenticated = True
                    break
                if result is False:
                    raise RuntimeError("官方客户端报告本次认证失败，请查看客户端提示")
                cancel.wait(min(0.5, max(0, deadline - time.monotonic())))
            if not authenticated:
                raise RuntimeError("等待本次认证超时；请在官方客户端保存自动认证设置后重试")
            self._emit("已确认本次新写入的认证成功结果")
            self._quarantine_component(warnings)
        except Exception as error:
            failure = str(error)
        finally:
            try:
                errors = self.recover_adapters()
                if errors:
                    warnings.extend(errors)
                    failure = failure or "认证网卡以外的临时网卡状态未能全部恢复"
            except Exception as error:
                failure = failure or f"读取或保存网卡恢复记录失败：{error}"
        if failure:
            self._emit(failure)
            return ConnectionResult(False, failure, authenticated, warnings=warnings)
        if cancel.is_set():
            return ConnectionResult(False, "连接已取消", authenticated, warnings=warnings)
        if self.config.auto_hotspot:
            self._emit("正在使用选定以太网连接开启移动热点")
            try:
                ok, message = self.operations.start_hotspot(self.config.ethernet_guid)
            except Exception as error:
                ok, message = False, str(error)
            if not ok:
                return ConnectionResult(False, f"认证成功，但热点启动失败：{message}",
                                        True, False, warnings)
            return ConnectionResult(True, "校园网认证成功，移动热点已开启", True, True, warnings)
        return ConnectionResult(True, "校园网认证成功", True, False, warnings)

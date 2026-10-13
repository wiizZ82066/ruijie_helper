"""Explicit, version-locked installation and rollback of the local client core.

Importing this module changes nothing. Call install/restore only from an explicit
administrator action. Every privileged boundary is injectable for offline tests.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from typing import Callable, Optional
from uuid import uuid4

from utils import core_patch


SERVICE_NAME = "RJSuService"
CREATE_NO_WINDOW = 0x08000000


def _same_path(first, second) -> bool:
    return str(Path(first).resolve()).casefold() == str(Path(second).resolve()).casefold()


def _service_path_matches(command: str, expected: Path) -> bool:
    # The installed service has only its executable path, with optional quotes.
    # Refuse extra arguments or an ambiguous unquoted command line.
    return _same_path(command.strip().strip('"'), expected)


class ServiceStopRejected(RuntimeError):
    """SCM explicitly refused STOP; only this error permits the narrow fallback."""


class InstallOperations:
    @staticmethod
    def _sc(*arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(["sc.exe", *arguments], capture_output=True, text=True,
                              errors="replace", timeout=30, creationflags=CREATE_NO_WINDOW)

    def service_snapshot(self) -> dict:
        import ctypes
        from ctypes import wintypes
        import winreg

        class Status(ctypes.Structure):
            _fields_ = [(field, wintypes.DWORD) for field in (
                "type", "state", "accepted", "exit_code", "service_exit_code",
                "checkpoint", "wait_hint", "pid", "flags",
            )]
        api = ctypes.WinDLL("advapi32", use_last_error=True)
        api.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        api.OpenSCManagerW.restype = wintypes.HANDLE
        api.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        api.OpenServiceW.restype = wintypes.HANDLE
        api.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        api.QueryServiceStatusEx.restype = wintypes.BOOL
        api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
        api.CloseServiceHandle.restype = wintypes.BOOL
        manager = api.OpenSCManagerW(None, None, 1)
        if not manager:
            raise ctypes.WinError(ctypes.get_last_error())
        service = None
        try:
            service = api.OpenServiceW(manager, SERVICE_NAME, 4)
            if not service:
                raise ctypes.WinError(ctypes.get_last_error())
            state, needed = Status(), wintypes.DWORD()
            if not api.QueryServiceStatusEx(service, 0, ctypes.byref(state), ctypes.sizeof(state),
                                           ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                "SYSTEM\\CurrentControlSet\\Services\\" + SERVICE_NAME) as key:
                start = winreg.QueryValueEx(key, "Start")[0]
                image = winreg.QueryValueEx(key, "ImagePath")[0]
                try:
                    delayed = bool(winreg.QueryValueEx(key, "DelayedAutoStart")[0])
                except FileNotFoundError:
                    delayed = False
            states = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING",
                      5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}
            return {"name": SERVICE_NAME, "state": states.get(state.state, "UNKNOWN"),
                    "pid": int(state.pid), "start_type": start,
                    "delayed_auto_start": delayed, "image_path": image}
        finally:
            if service:
                api.CloseServiceHandle(service)
            api.CloseServiceHandle(manager)

    def _wait_service(self, desired: str, timeout: float = 25) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.service_snapshot()["state"] == desired:
                return
            time.sleep(0.25)
        raise RuntimeError(f"等待锐捷服务状态 {desired} 超时")

    def stop_service(self) -> None:
        result = self._sc("stop", SERVICE_NAME)
        if result.returncode in (1052, 1061):
            raise ServiceStopRejected("锐捷服务拒绝常规停止")
        if result.returncode not in (0, 1062):
            raise RuntimeError(f"停止锐捷服务失败（{result.returncode}）")
        self._wait_service("STOPPED")

    def start_service(self) -> None:
        result = self._sc("start", SERVICE_NAME)
        if result.returncode not in (0, 1056):
            raise RuntimeError(f"恢复启动锐捷服务失败（{result.returncode}）")
        self._wait_service("RUNNING")

    def set_service_start_type(self, start_type: int, delayed: bool = False) -> None:
        modes = {2: "delayed-auto" if delayed else "auto", 3: "demand", 4: "disabled"}
        if start_type not in modes:
            raise RuntimeError("不支持的锐捷服务启动类型，已停止操作")
        result = self._sc("config", SERVICE_NAME, "start=", modes[start_type])
        if result.returncode:
            raise RuntimeError(f"恢复或调整锐捷服务启动类型失败（{result.returncode}）")

    @staticmethod
    def other_core_paths(target: Path) -> list[str]:
        import psutil
        found = []
        for process in psutil.process_iter(["name", "exe"]):
            if (process.info.get("name") or "").casefold() != "8021x.exe":
                continue
            executable = process.info.get("exe")
            if not executable:
                raise RuntimeError("无法核对正在运行的 8021x.exe 路径，请以管理员身份操作")
            if not _same_path(executable, target):
                found.append(executable)
        return sorted(set(found))

    @staticmethod
    def stop_exact_core(target: Path) -> None:
        from utils.campus_connection import WindowsOperations
        WindowsOperations.stop_exact_executable(target)

    @staticmethod
    def process_executable(pid: int) -> str:
        import psutil
        return psutil.Process(pid).exe()

    def terminate_service_pid(self, pid: int, expected_path: Path) -> None:
        import psutil
        current = self.service_snapshot()
        if current["pid"] != pid or not _service_path_matches(current["image_path"], expected_path):
            raise RuntimeError("锐捷服务进程身份发生变化，已取消终止")
        process = psutil.Process(pid)
        if not _same_path(process.exe(), expected_path):
            raise RuntimeError("锐捷服务 PID 的程序路径不匹配，已取消终止")
        process.terminate()
        process.wait(timeout=20)
        self._wait_service("STOPPED")


class CoreInstaller:
    _locks: dict[str, threading.Lock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, client_dir, data_dir=None, operations=None):
        self.client_dir = Path(client_dir).resolve()
        self.target = self.client_dir / "8021x.exe"
        self.service_executable = self.client_dir / "suservice.exe"
        base = Path(os.environ.get("APPDATA", str(Path.home()))) / "ruijie_helper"
        self.data_dir = Path(data_dir).resolve() if data_dir else base / "core-install"
        self.backup_path = self.data_dir / ("8021x.original." + core_patch.ORIGINAL_SHA256 + ".exe")
        self.journal_path = self.data_dir / "core_install_journal.json"
        self.operations = operations or InstallOperations()
        key = str(self.target).casefold()
        with self._locks_guard:
            self._lock = self._locks.setdefault(key, threading.Lock())

    def _journal(self) -> Optional[dict]:
        if not self.journal_path.exists():
            return None
        data = json.loads(self.journal_path.read_text(encoding="utf-8"))
        if data.get("version") != 1 or not _same_path(data.get("target", ""), self.target):
            raise RuntimeError("安装恢复记录与当前目标不匹配")
        return data

    def _save_journal(self, data: dict) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._atomic_write(self.journal_path, json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        temporary = path.with_name(path.name + ".tmp-" + uuid4().hex)
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if core_patch.digest(temporary.read_bytes()) != core_patch.digest(data):
                raise RuntimeError("临时文件校验失败")
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    @contextlib.contextmanager
    def _exclusive(self):
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("另一个核心安装或还原操作正在进行")
        lock_file = None
        try:
            import msvcrt
            self.data_dir.mkdir(parents=True, exist_ok=True)
            lock_file = (self.data_dir / "core_install.lock").open("a+b")
            if lock_file.tell() == 0:
                lock_file.write(b"0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            if lock_file:
                lock_file.close()
            self._lock.release()

    def _material(self) -> tuple[bytes, bytes, dict]:
        if self.backup_path.is_file():
            original = self.backup_path.read_bytes()
        elif self.target.is_file():
            original = self.target.read_bytes()
        else:
            raise RuntimeError("原认证核心及受校验的备份均不存在")
        patched, manifest = core_patch.patch_bytes(original)
        return original, patched, manifest

    def status(self) -> dict:
        result = {"state": "missing", "target": str(self.target),
                  "backup_path": str(self.backup_path), "journal_path": str(self.journal_path)}
        if not self.target.exists():
            return result
        try:
            actual = core_patch.digest(self.target.read_bytes())
            result["sha256"] = actual
            if actual == core_patch.ORIGINAL_SHA256:
                result["state"] = "original"
            else:
                _, patched, _ = self._material()
                result["state"] = "patched" if actual == core_patch.digest(patched) else "unknown"
            journal = self._journal()
            if journal:
                result["phase"] = journal.get("phase")
                result["recovery_needed"] = journal.get("phase") not in ("complete", "rolled_back")
        except Exception as error:
            result["state"] = "unknown"
            result["error"] = str(error)
        return result

    @staticmethod
    def _emit(log: Optional[Callable], message: str) -> None:
        if log:
            try:
                log(message)
            except Exception:
                pass  # Logging must never interrupt rollback or service recovery.

    def _ensure_backup(self, original: bytes) -> None:
        if self.backup_path.exists():
            if self.backup_path.read_bytes() != original:
                raise RuntimeError("已有原始备份校验不匹配，已拒绝覆盖")
        else:
            self._atomic_write(self.backup_path, original)
        if core_patch.digest(self.backup_path.read_bytes()) != core_patch.ORIGINAL_SHA256:
            raise RuntimeError("原始核心备份校验失败")

    def _verify_service(self, snapshot: dict) -> None:
        if snapshot.get("name") != SERVICE_NAME or not _service_path_matches(
            snapshot.get("image_path", ""), self.service_executable
        ):
            raise RuntimeError("锐捷服务注册路径与选定安装目录不一致，已拒绝操作")
        if snapshot.get("state") not in ("RUNNING", "STOPPED"):
            raise RuntimeError("锐捷服务正在切换状态，请稍后重试")
        if snapshot.get("start_type") not in (2, 3, 4):
            raise RuntimeError("锐捷服务启动类型不受支持")

    def _stop(self, original_service: dict, journal: dict, log) -> None:
        if original_service["state"] != "RUNNING":
            return
        try:
            self.operations.stop_service()
        except ServiceStopRejected:
            self._emit(log, "服务拒绝常规停止，正在核对本安装目录的服务进程")
            journal["phase"] = "fallback_planned"
            self._save_journal(journal)
            self.operations.set_service_start_type(4, False)
            journal["phase"] = "service_temporarily_disabled"
            self._save_journal(journal)
            current = self.operations.service_snapshot()
            if current["state"] == "STOPPED":
                return
            self._verify_service(current)
            pid = current.get("pid", 0)
            if not pid or not _same_path(self.operations.process_executable(pid), self.service_executable):
                raise RuntimeError("服务 PID 路径核验失败，已拒绝终止进程")
            journal["verified_service_pid"] = pid
            self._save_journal(journal)
            self.operations.terminate_service_pid(pid, self.service_executable)
        if self.operations.service_snapshot()["state"] != "STOPPED":
            raise RuntimeError("锐捷服务尚未停止，未修改认证核心")

    def _restore_service(self, original: dict) -> None:
        current = self.operations.service_snapshot()
        if not _service_path_matches(current.get("image_path", ""), self.service_executable):
            raise RuntimeError("服务注册路径已变化，无法安全恢复")
        must_start = original["state"] == "RUNNING" and current["state"] != "RUNNING"
        if must_start and original["start_type"] == 4:
            # A service can be running while its next-start setting is disabled.
            self.operations.set_service_start_type(3, False)
            try:
                self.operations.start_service()
            finally:
                self.operations.set_service_start_type(4, original.get("delayed_auto_start", False))
        else:
            self.operations.set_service_start_type(original["start_type"], original.get("delayed_auto_start", False))
            if must_start:
                self.operations.start_service()

    def _change(self, action: str, log=None) -> dict:
        with self._exclusive():
            original, patched, manifest = self._material()
            before = self.target.read_bytes()  # Missing targets require explicit manual recovery.
            before_hash = core_patch.digest(before)
            wanted = patched if action == "install" else original
            after_hash = core_patch.digest(wanted)
            accepted = {core_patch.ORIGINAL_SHA256, core_patch.digest(patched)}
            if before_hash not in accepted:
                raise RuntimeError("当前核心不是已确认的原版或本工具兼容版本，已拒绝覆盖")
            prior = self._journal()
            if before_hash == after_hash and not (prior and prior.get("phase") not in ("complete", "rolled_back")):
                return {"success": True, "state": "patched" if action == "install" else "original",
                        "message": "认证核心已处于目标状态", "backup_path": str(self.backup_path)}
            others = self.operations.other_core_paths(self.target)
            if others:
                raise RuntimeError("发现其他目录的 8021x.exe 正在运行，请先手动退出该副本：" + "；".join(others))
            service = self.operations.service_snapshot()
            self._verify_service(service)
            self._ensure_backup(original)
            self._emit(log, "原始认证核心已完整备份并通过 SHA-256 校验")
            # Preserve an interrupted operation's original service settings.
            if prior and prior.get("phase") not in ("complete", "rolled_back"):
                remembered = prior.get("service_before")
                if not isinstance(remembered, dict):
                    raise RuntimeError("上次操作的服务恢复记录缺失")
                self._verify_service(remembered)
                restore_service = remembered
            else:
                restore_service = service
            journal = {"version": 1, "target": str(self.target), "backup_path": str(self.backup_path),
                       "operation": action, "phase": "prepared", "service_before": restore_service,
                       "observed_service": service, "before_sha256": before_hash,
                       "after_sha256": after_hash, "manifest": manifest}
            self._save_journal(journal)
            failure = None
            try:
                self._stop(service, journal, log)
                journal["phase"] = "service_stopped"
                self._save_journal(journal)
                self.operations.stop_exact_core(self.target)
                if core_patch.digest(self.target.read_bytes()) != before_hash:
                    raise RuntimeError("认证核心在操作期间发生变化，已停止替换")
                journal["phase"] = "replacement_planned"
                self._save_journal(journal)
                self._atomic_write(self.target, wanted)
                if core_patch.digest(self.target.read_bytes()) != after_hash:
                    raise RuntimeError("替换后校验失败")
                journal["phase"] = "file_verified"
                self._save_journal(journal)
                self._restore_service(restore_service)
                journal["phase"] = "complete"
                self._save_journal(journal)
            except Exception as error:
                failure = str(error)
                rollback_errors = []
                try:
                    current_hash = core_patch.digest(self.target.read_bytes())
                    if current_hash == after_hash and current_hash != before_hash:
                        live = self.operations.service_snapshot()
                        self._verify_service(live)
                        self._stop(live, journal, log)
                        self.operations.stop_exact_core(self.target)
                        self._atomic_write(self.target, before)
                    elif current_hash != before_hash:
                        raise RuntimeError("核心内容已变为未知版本，未自动覆盖")
                    if core_patch.digest(self.target.read_bytes()) != before_hash:
                        raise RuntimeError("回滚校验失败")
                except Exception as rollback_error:
                    rollback_errors.append("核心回滚失败：" + str(rollback_error))
                try:
                    self._restore_service(restore_service)
                except Exception as service_error:
                    rollback_errors.append("服务恢复失败：" + str(service_error))
                journal["phase"] = "recovery_required" if rollback_errors else "rolled_back"
                journal["error"] = failure
                journal["recovery_errors"] = rollback_errors
                try:
                    self._save_journal(journal)
                except Exception as journal_error:
                    rollback_errors.append("恢复记录保存失败：" + str(journal_error))
                raise RuntimeError("操作未完成：" + failure + ("；" + "；".join(rollback_errors) if rollback_errors else "；原核心与服务状态已恢复")) from error
            state = "patched" if action == "install" else "original"
            message = "兼容核心安装完成，锐捷服务已恢复" if action == "install" else "原版核心已还原，锐捷服务已恢复"
            self._emit(log, message)
            return {"success": True, "state": state, "message": message,
                    "backup_path": str(self.backup_path), "sha256": after_hash}

    def install(self, log=None) -> dict:
        return self._change("install", log)

    def restore(self, log=None) -> dict:
        return self._change("restore", log)

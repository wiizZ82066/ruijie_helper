"""
校园网认证助手 — FastAPI 后端服务
提供 REST API 供 Electron 前端调用，封装所有 Windows 系统操作。
端口: 18921
"""

import sys
import base64
import uvicorn
from io import BytesIO
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# 将项目根目录加入 path，以便导入 utils 模块
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.network_adapter import NetworkAdapterManager
from utils.supplicant import SupplicantManager, SupplicantConfig
from utils.hotspot import HotspotManager

app = FastAPI(title="CampusAuth API", version="3.0")

# 允许 Electron 跨域访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── 数据模型 ────────────────────────────────────────────

class HotspotConfigModel(BaseModel):
    ssid: str
    password: str
    band: str


class TargetFolderModel(BaseModel):
    folder: str


# ─── 根路由 ──────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "3.0"}


# ─── 网卡管理 ────────────────────────────────────────────

@app.get("/api/adapters")
def get_adapters():
    """获取所有网络适配器列表。"""
    adapters = NetworkAdapterManager.get_adapters()
    return [
        {"name": name, "enabled": status == "Enabled"}
        for name, status in adapters
    ]


@app.post("/api/adapter/{name}/enable")
def enable_adapter(name: str):
    """启用指定网卡。"""
    ok = NetworkAdapterManager.set_adapter_state(name, True)
    if not ok:
        raise HTTPException(500, "操作失败，请确认以管理员权限运行")
    return {"success": True}


@app.post("/api/adapter/{name}/disable")
def disable_adapter(name: str):
    """禁用指定网卡。"""
    ok = NetworkAdapterManager.set_adapter_state(name, False)
    if not ok:
        raise HTTPException(500, "操作失败，请确认以管理员权限运行")
    return {"success": True}


# ─── 8021x 进程管理 ──────────────────────────────────────

@app.get("/api/process/status")
def get_process_status():
    """获取 8021x.exe 进程状态。"""
    running = SupplicantManager.is_running()
    path = SupplicantManager.get_exe_path() if running else None
    return {"running": running, "path": path}


@app.post("/api/process/start")
def start_process(exe_path: Optional[str] = None):
    """启动指定路径的 8021x.exe。"""
    if not exe_path:
        raise HTTPException(400, "未指定 exe_path")
    ok = SupplicantManager.start_exe(exe_path)
    if not ok:
        raise HTTPException(500, "启动失败")
    return {"success": True}


@app.post("/api/process/kill-move")
def kill_and_move():
    """结束 8021x.exe 并移动文件。"""
    ok = SupplicantManager.kill_and_move()
    if not ok:
        raise HTTPException(500, "操作失败")
    return {"success": True}


@app.post("/api/process/restore")
def restore_process():
    """还原 8021x.exe 到原始位置。"""
    ok = SupplicantManager.restore()
    if not ok:
        raise HTTPException(500, "还原失败")
    return {"success": True}


@app.get("/api/process/move-record")
def get_move_record():
    """获取移动操作记录。"""
    record = SupplicantConfig.get_move_record()
    has_record = bool(record and record.get("action") == "kill_and_move")
    return {"has_record": has_record}


# ─── 热点管理 ────────────────────────────────────────────

@app.get("/api/hotspot/status")
def hotspot_status():
    """获取热点运行状态。"""
    status = HotspotManager.get_hotspot_status()
    return {"status": status, "running": status == "已启动"}


@app.post("/api/hotspot/start")
def start_hotspot():
    """启动热点（使用已保存的配置）。"""
    ok, msg = HotspotManager.start_hotspot()
    if not ok:
        raise HTTPException(500, msg or "启动失败")
    return {"success": True}


@app.post("/api/hotspot/stop")
def stop_hotspot():
    """停止热点。"""
    ok, msg = HotspotManager.stop_hotspot()
    if not ok:
        raise HTTPException(500, msg or "停止失败")
    return {"success": True}


# ─── 配置管理 ────────────────────────────────────────────

@app.get("/api/config/hotspot")
def get_hotspot_config():
    """获取热点配置。"""
    config = HotspotManager.load_config()
    target = SupplicantConfig.get_target_folder()
    return {
        "ssid": config.get("ssid", ""),
        "password": config.get("password", ""),
        "band": config.get("band", "2.4GHz"),
        "target_folder": target,
    }


@app.put("/api/config/hotspot")
def save_hotspot_config(body: HotspotConfigModel):
    """保存热点配置。如果热点正在运行，自动重启以应用新配置。"""
    if not body.ssid or not body.password:
        raise HTTPException(400, "热点名称和密码不能为空")
    if len(body.password) < 8:
        raise HTTPException(400, "密码长度不能少于8位")

    HotspotManager.save_config({
        "ssid": body.ssid,
        "password": body.password,
        "band": body.band
    })

    # 如果热点正在运行，重启以应用新配置
    was_running = HotspotManager.get_hotspot_status() == "已启动"
    if was_running:
        stop_ok, stop_msg = HotspotManager.stop_hotspot()
        if not stop_ok:
            raise HTTPException(500, f"停止热点失败: {stop_msg}")
        start_ok, start_msg = HotspotManager.start_hotspot(
            ssid=body.ssid, key=body.password, band=body.band
        )
        if not start_ok:
            raise HTTPException(500, f"重启热点失败: {start_msg}")

    return {"success": True, "restarted": was_running}


@app.put("/api/config/target-folder")
def set_target_folder(body: TargetFolderModel):
    """设置目标文件夹。"""
    SupplicantConfig.set_target_folder(body.folder)
    return {"success": True}


# ─── 二维码 ──────────────────────────────────────────────

@app.get("/api/qrcode")
def get_qr_code():
    """获取 WiFi 二维码（base64 PNG）。"""
    config = HotspotManager.load_config()
    ssid = config.get("ssid", "")
    password = config.get("password", "")
    if not ssid or not password:
        raise HTTPException(400, "SSID 或密码未配置")

    try:
        import qrcode
        wifi_string = f"WIFI:T:WPA;S:{ssid};P:{password};;"
        img = qrcode.make(wifi_string)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        b64 = base64.b64encode(buffer.getvalue()).decode()
        return {"base64": f"data:image/png;base64,{b64}"}
    except Exception as e:
        raise HTTPException(500, f"二维码生成失败: {e}")


# ─── 启动 ────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=18921, log_level="warning")

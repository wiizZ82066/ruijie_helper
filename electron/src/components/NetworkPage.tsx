import { useState, useEffect, useCallback } from 'react';
import SwitchButton from './SwitchButton';
import * as api from '../api';
import type { Adapter } from '../types';

export default function NetworkPage() {
  const [adapters, setAdapters] = useState<Adapter[]>([]);
  const [exePath, setExePath] = useState<string | null>(null);
  const [procRunning, setProcRunning] = useState(false);
  const [selectedExe, setSelectedExe] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  const showToast = useCallback((msg: string, type: 'success' | 'error') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  // ── Poll data ──────────────────────────────────────
  useEffect(() => {
    const poll = async () => {
      const [ads, proc] = await Promise.all([
        api.fetchAdapters(),
        api.fetchProcessStatus(),
      ]);
      setAdapters(ads);
      setExePath(proc.path);
      setProcRunning(proc.running);
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, []);

  // ── Handlers ──────────────────────────────────────
  const handleToggleAdapter = async (name: string, enable: boolean) => {
    const ok = await api.toggleAdapter(name, enable);
    if (!ok) {
      showToast('操作失败，请确认以管理员权限运行', 'error');
    }
    // Refresh immediately
    const ads = await api.fetchAdapters();
    setAdapters(ads);
  };

  const handleChooseExe = async () => {
    // In Electron, we'd use dialog.showOpenDialog via IPC.
    // For now, use a simple prompt or file input.
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.exe';
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
        // Electron adds a `path` property; fall back to name in browser mode
        const path = (file as File & { path?: string }).path || file.name;
        setSelectedExe(path);
      }
    };
    input.click();
  };

  const handleStartExe = async () => {
    if (!selectedExe) {
      showToast('请先选择 8021x.exe 路径', 'error');
      return;
    }
    const ok = await api.startProcess(selectedExe);
    if (ok) {
      showToast('启动成功', 'success');
    } else {
      showToast('启动失败', 'error');
    }
  };

  return (
    <div className="page fade-in">
      {/* ── 8021x Launcher ─────────────────────────────── */}
      <div className="card">
        <div className="card-header">8021x 启动器</div>
        <div className="card-body">
          <div className="path-display">
            {exePath || '未运行'}
          </div>
          <div className="btn-row">
            <button className="btn btn-ghost" onClick={handleChooseExe}>
              📂 选择程序
            </button>
            <button className="btn btn-success" onClick={handleStartExe} disabled={!selectedExe}>
              ▶ 启动
            </button>
            {selectedExe && (
              <span className="info-text" style={{ alignSelf: 'center' }}>
                已选择: {selectedExe}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ── Network Adapters ───────────────────────────── */}
      <div className="card">
        <div className="card-header">网络适配器</div>
        <div className="card-body">
          <div className="table-wrap">
            <table className="nic-table">
              <thead>
                <tr>
                  <th className="col-name">网卡名称</th>
                  <th className="col-status">状态</th>
                  <th className="col-control">控制</th>
                </tr>
              </thead>
              <tbody>
                {adapters.length === 0 ? (
                  <tr>
                    <td colSpan={3} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>
                      未检测到网络适配器
                    </td>
                  </tr>
                ) : (
                  adapters.map((adapter) => (
                    <tr key={adapter.name}>
                      <td>{adapter.name}</td>
                      <td className="col-status">
                        {adapter.enabled ? (
                          <span className="dot-green">● 已启用</span>
                        ) : (
                          <span className="dot-muted">○ 已禁用</span>
                        )}
                      </td>
                      <td className="col-control">
                        <SwitchButton
                          checked={adapter.enabled}
                          onChange={(enable) => handleToggleAdapter(adapter.name, enable)}
                        />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <button
            className="btn btn-ghost"
            onClick={async () => {
              const ads = await api.fetchAdapters();
              setAdapters(ads);
            }}
          >
            🔄 刷新列表
          </button>
        </div>
      </div>

      {/* ── Toast ──────────────────────────────────────── */}
      {toast && (
        <div className={`toast toast-${toast.type}`}>{toast.msg}</div>
      )}
    </div>
  );
}

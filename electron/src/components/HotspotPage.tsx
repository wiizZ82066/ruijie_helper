import { useState, useEffect, useCallback, useRef } from 'react';
import SwitchButton from './SwitchButton';
import * as api from '../api';

export default function HotspotPage() {
  // ── State ──────────────────────────────────────────
  const [procStatus, setProcStatus] = useState({ running: false, path: null as string | null });
  const [hasMoveRecord, setHasMoveRecord] = useState(false);
  const [targetFolder, setTargetFolder] = useState('');
  const [ssid, setSsid] = useState('');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [band, setBand] = useState('2.4GHz');
  const [hotspotRunning, setHotspotRunning] = useState(false);
  const [hotspotSwitching, setHotspotSwitching] = useState(false);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);
  const [pwdError, setPwdError] = useState('');

  const animRef = useRef<number>(0);
  const animTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const showToast = useCallback((msg: string, type: 'success' | 'error') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  // ── Load Config ───────────────────────────────────
  const loadConfig = useCallback(async () => {
    const config = await api.fetchHotspotConfig();
    setSsid(config.ssid);
    setPassword(config.password);
    setBand(config.band);
    setTargetFolder(config.target_folder);
  }, []);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  // ── Poll Process Status (1s) ──────────────────────
  useEffect(() => {
    const poll = async () => {
      const [status, record] = await Promise.all([
        api.fetchProcessStatus(),
        api.getMoveRecord(),
      ]);
      setProcStatus(status);
      setHasMoveRecord(record);
    };
    poll();
    const id = setInterval(poll, 1000);
    return () => clearInterval(id);
  }, []);

  // ── Poll Hotspot Status (3s) ──────────────────────
  useEffect(() => {
    const poll = async () => {
      const status = await api.fetchHotspotStatus();
      setHotspotRunning(status.running);
      if (status.running) {
        const qr = await api.fetchQRCode();
        setQrCode(qr);
      } else {
        setQrCode(null);
      }
    };
    poll();
    const id = setInterval(poll, 3000);
    return () => clearInterval(id);
  }, []);

  // ── Spinner Animation ─────────────────────────────
  useEffect(() => {
    if (hotspotSwitching) {
      let frame = 0;
      animTimerRef.current = setInterval(() => {
        frame = (frame + 1) % 4;
        animRef.current = frame;
      }, 300);
    } else {
      if (animTimerRef.current) clearInterval(animTimerRef.current);
    }
    return () => { if (animTimerRef.current) clearInterval(animTimerRef.current); };
  }, [hotspotSwitching]);

  // ── Handlers ──────────────────────────────────────
  const handleToggleHotspot = async (start: boolean) => {
    setHotspotSwitching(true);
    const ok = await api.toggleHotspot(start);
    setHotspotSwitching(false);
    if (!ok) showToast('操作失败，请检查系统热点设置', 'error');
  };

  const handleSaveConfig = async () => {
    if (!ssid.trim() || !password.trim()) {
      showToast('热点名称和密码不能为空', 'error');
      return;
    }
    if (password.length < 8) {
      setPwdError('密码不能少于 8 位');
      return;
    }
    setPwdError('');
    const result = await api.saveHotspotConfig(ssid, password, band);
    if (result.ok) {
      showToast(result.restarted ? '配置已保存并应用' : '配置已保存', 'success');
    } else {
      showToast('保存失败', 'error');
    }
  };

  const handleKillMove = async () => {
    if (await api.killAndMove()) {
      showToast('进程已结束，文件已移动', 'success');
    } else {
      showToast('操作失败', 'error');
    }
  };

  const handleRestore = async () => {
    if (await api.restoreProcess()) {
      showToast('文件已还原', 'success');
    } else {
      showToast('还原失败', 'error');
    }
  };

  const handleSetTarget = async () => {
    if (!targetFolder.trim()) return;
    if (await api.setTargetFolder(targetFolder)) {
      showToast('目标文件夹已设置', 'success');
    }
  };

  const spinnerFrames = ['◐', '◓', '◑', '◒'];

  return (
    <div className="page fade-in">
      {/* ── 8021x Process Monitor ─────────────────────── */}
      <div className="card">
        <div className="card-header">8021x 进程监控</div>
        <div className="card-body">
          <div className={`status-bar${procStatus.running ? ' running' : ' stopped'}`}>
            <span className="dot" />
            {procStatus.running ? '8021x.exe 运行中' : '8021x.exe 未运行'}
          </div>
          <div className="path-display">
            {procStatus.path || '未检测到进程'}
          </div>
          <div className="btn-row">
            <button className="btn btn-danger" onClick={handleKillMove} disabled={!procStatus.running || hasMoveRecord}>
              ⏹ 结束并移动
            </button>
            <button className="btn btn-success" onClick={handleRestore} disabled={!hasMoveRecord}>
              ↩ 还原
            </button>
            <button className="btn btn-ghost" onClick={() => { loadConfig(); }}>
              🔄 刷新
            </button>
          </div>
          <div className="input-with-btn">
            <input
              className="form-input"
              type="text"
              value={targetFolder}
              onChange={(e) => setTargetFolder(e.target.value)}
              placeholder="选择移动目标文件夹..."
            />
            <button className="btn btn-ghost" onClick={handleSetTarget}>📁 设置</button>
          </div>
        </div>
      </div>

      {/* ── Hotspot Configuration ─────────────────────── */}
      <div className="card">
        <div className="card-header">热点配置</div>
        <div className="card-body">
          <div className="form-row">
            <div className="form-group flex-2">
              <label className="form-label">热点名称</label>
              <input
                className="form-input"
                type="text"
                value={ssid}
                onChange={(e) => setSsid(e.target.value)}
                placeholder="热点名称 (SSID)"
              />
            </div>
            <div className="form-group flex-2">
              <label className="form-label">密码</label>
              <div className="pwd-wrapper">
                <input
                  className="form-input"
                  type={showPwd ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); setPwdError(''); }}
                  placeholder="至少 8 位"
                />
                <button className="pwd-toggle" onClick={() => setShowPwd(!showPwd)}>
                  {showPwd ? '🙈' : '👁'}
                </button>
              </div>
              {pwdError && <span className="error-text">{pwdError}</span>}
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label">频段</label>
              <select
                className="form-select"
                value={band}
                onChange={(e) => setBand(e.target.value)}
              >
                <option value="2.4GHz">2.4GHz</option>
                <option value="5GHz">5GHz</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">&nbsp;</label>
              <button className="btn btn-primary btn-full" onClick={handleSaveConfig}>
                💾 保存并应用
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── Hotspot Control ───────────────────────────── */}
      <div className="card">
        <div className="card-header">热点控制</div>
        <div className="card-body">
          <div className="hotspot-control">
            <SwitchButton
              checked={hotspotRunning}
              onChange={handleToggleHotspot}
              disabled={hotspotSwitching}
            />
            <span className={`hotspot-status-label${hotspotRunning ? ' active' : ''}${hotspotSwitching ? ' switching' : ''}`}>
              {hotspotSwitching
                ? `正在切换 ${spinnerFrames[animRef.current]}`
                : hotspotRunning
                  ? '● 已启动'
                  : '○ 未启动'}
            </span>
          </div>
          {qrCode && (
            <div className="qr-wrapper">
              <img className="qr-image" src={qrCode} alt="WiFi QR Code" />
            </div>
          )}
        </div>
      </div>

      {/* ── Toast ──────────────────────────────────────── */}
      {toast && (
        <div className={`toast toast-${toast.type}`}>{toast.msg}</div>
      )}
    </div>
  );
}

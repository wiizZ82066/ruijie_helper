import { useState, useEffect, useCallback } from 'react';
import SwitchButton from './SwitchButton';
import * as api from '../api';

export default function HotspotPage() {
  // ── 基础状态 ────────────────────────────────
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

  // ── 新模式状态 ──────────────────────────────
  const [networkAccess, setNetworkAccess] = useState('nat');
  const [internetAdapter, setInternetAdapter] = useState('automatic');
  const [accessModes, setAccessModes] = useState<{ id: string; name: string }[]>([]);
  const [adapterOptions, setAdapterOptions] = useState<{ name: string; ip: string | null; gateway: string | null; hasInternet?: boolean; speed?: string | null }[]>([]);

  // ── 连接设备状态 ────────────────────────────
  const [connectedDevices, setConnectedDevices] = useState<{ mac: string; ip?: string }[]>([]);
  const [deviceCount, setDeviceCount] = useState(0);

  const showToast = useCallback((msg: string, type: 'success' | 'error') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  // ── 加载初始数据 ──────────────────────────────
  const loadConfig = useCallback(async () => {
    const config = await api.fetchHotspotConfig();
    setSsid(config.ssid);
    setPassword(config.password);
    setBand(config.band);
    setNetworkAccess(config.network_access || 'nat');
    setInternetAdapter(config.internet_adapter || 'automatic');
    setTargetFolder(config.target_folder);

    // 加载模式列表和网卡列表
    const modes = await api.fetchNetworkAccessModes();
    setAccessModes(modes);
    const adapters = await api.fetchInternetAdapters();
    setAdapterOptions(adapters);
  }, []);

  useEffect(() => { loadConfig(); }, [loadConfig]);

  // ── 轮询 8021x 状态 ─────────────────────────
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

  // ── 轮询热点 + 设备状态 ─────────────────────
  useEffect(() => {
    const poll = async () => {
      const status = await api.fetchHotspotStatus();
      setHotspotRunning(status.running);

      if (status.running) {
        // 获取二维码
        const qr = await api.fetchQRCode();
        setQrCode(qr);

        // 获取连接设备
        const devices = await api.fetchConnectedDevices();
        setConnectedDevices(devices.devices);
        setDeviceCount(devices.count);
      } else {
        setQrCode(null);
        setConnectedDevices([]);
        setDeviceCount(0);
      }
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, []);

  // ── 切换热点 ────────────────────────────────
  const handleToggleHotspot = async (start: boolean) => {
    setHotspotSwitching(true);
    const mode = start ? networkAccess : undefined;
    const adapter = start ? internetAdapter : undefined;
    const result = await api.toggleHotspot(start, mode, adapter);
    setHotspotSwitching(false);
    if (!result.ok) {
      showToast(result.message || '操作失败', 'error');
    }
  };

  // ── 保存配置 ────────────────────────────────
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
    const result = await api.saveHotspotConfig(ssid, password, band, networkAccess, internetAdapter);
    if (result.ok) {
      showToast(result.restarted ? '配置已保存并应用' : '配置已保存', 'success');
    } else {
      showToast('保存失败', 'error');
    }
  };

  // ── 8021x 操作 ──────────────────────────────
  const handleKillMove = async () => {
    if (await api.killAndMove()) showToast('进程已结束，文件已移动', 'success');
    else showToast('操作失败', 'error');
  };

  const handleRestore = async () => {
    if (await api.restoreProcess()) showToast('文件已还原', 'success');
    else showToast('还原失败', 'error');
  };

  const handleSetTarget = async () => {
    if (!targetFolder.trim()) return;
    if (await api.setTargetFolder(targetFolder)) showToast('目标文件夹已设置', 'success');
  };

  // ── 刷新网卡列表 ────────────────────────────
  const refreshAdapters = async () => {
    const adapters = await api.fetchInternetAdapters();
    setAdapterOptions(adapters);
  };

  // ── 网络访问模式描述 ────────────────────────
  const modeDescriptions: Record<string, string> = {
    nat: 'WinNAT 路由器模式，独立子网 (192.168.137.x)，推荐',
    ics: 'Internet 连接共享，传统方式 (HNetCfg)',
    bridge: '桥接模式，与主机同网段',
  };

  return (
    <div className="page fade-in">
      {/* ── 8021x 进程监控 ─────────────────────── */}
      <div className="card">
        <div className="card-header">8021x 进程监控</div>
        <div className="card-body">
          <div className={`status-bar${procStatus.running ? ' running' : ' stopped'}`}>
            <span className="dot" />
            {procStatus.running ? '8021x.exe 运行中' : '8021x.exe 未运行'}
          </div>
          <div className="path-display">{procStatus.path || '未检测到进程'}</div>
          <div className="btn-row">
            <button className="btn btn-danger" onClick={handleKillMove}
              disabled={!procStatus.running || hasMoveRecord}>⏹ 结束并移动</button>
            <button className="btn btn-success" onClick={handleRestore} disabled={!hasMoveRecord}>↩ 还原</button>
            <button className="btn btn-ghost" onClick={loadConfig}>🔄 刷新</button>
          </div>
          <div className="input-with-btn">
            <input className="form-input" type="text" value={targetFolder}
              onChange={(e) => setTargetFolder(e.target.value)} placeholder="移动目标文件夹..." />
            <button className="btn btn-ghost" onClick={handleSetTarget}>📁 设置</button>
          </div>
        </div>
      </div>

      {/* ── 热点配置 ─────────────────────────────── */}
      <div className="card">
        <div className="card-header">热点配置</div>
        <div className="card-body">
          <div className="form-row">
            <div className="form-group flex-2">
              <label className="form-label">热点名称 (SSID)</label>
              <input className="form-input" type="text" value={ssid}
                onChange={(e) => setSsid(e.target.value)} placeholder="热点名称" />
            </div>
            <div className="form-group flex-2">
              <label className="form-label">密码</label>
              <div className="pwd-wrapper">
                <input className="form-input" type={showPwd ? 'text' : 'password'}
                  value={password} onChange={(e) => { setPassword(e.target.value); setPwdError(''); }}
                  placeholder="至少 8 位" />
                <button className="pwd-toggle" onClick={() => setShowPwd(!showPwd)}
                  title={showPwd ? '隐藏密码' : '显示密码'}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                    strokeLinecap="round" strokeLinejoin="round">
                    {showPwd ? (
                      // 眼睛关闭 (不可见)
                      <>
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                        <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                        <line x1="1" y1="1" x2="23" y2="23" />
                        <path d="M14.12 14.12a3 3 0 1 1-4.24-4.24" />
                      </>
                    ) : (
                      // 眼睛打开 (可见)
                      <>
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
                      </>
                    )}
                  </svg>
                </button>
              </div>
              {pwdError && <span className="error-text">{pwdError}</span>}
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label className="form-label">频段</label>
              <select className="form-select" value={band} onChange={(e) => setBand(e.target.value)}>
                <option value="2.4GHz">2.4GHz</option>
                <option value="5GHz">5GHz</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">&nbsp;</label>
              <button className="btn btn-primary btn-full" onClick={handleSaveConfig}>
                💾 保存配置
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── 网络访问模式 + 互联网网卡选择 ──────────── */}
      <div className="card">
        <div className="card-header">网络访问模式</div>
        <div className="card-body">
          <div className="form-row">
            <div className="form-group flex-2">
              <label className="form-label">网络访问方式</label>
              <div className="mode-selector">
                {accessModes.map((mode) => (
                  <label key={mode.id}
                    className={`mode-option${networkAccess === mode.id ? ' selected' : ''}`}
                    onClick={() => setNetworkAccess(mode.id)}>
                    <input type="radio" name="networkAccess" value={mode.id}
                      checked={networkAccess === mode.id} readOnly />
                    <span className="mode-name">{mode.name}</span>
                    <span className="mode-desc">{modeDescriptions[mode.id] || ''}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
          <div className="form-row">
            <div className="form-group flex-2">
              <label className="form-label">
                互联网连接
                <button className="btn btn-xs btn-ghost" onClick={refreshAdapters}
                  style={{ marginLeft: 8, fontSize: 11 }}>🔄 刷新</button>
              </label>
              <div className="adapter-selector">
                <label className={`mode-option${internetAdapter === 'automatic' ? ' selected' : ''}`}
                  onClick={() => setInternetAdapter('automatic')}>
                  <input type="radio" name="internetAdapter" value="automatic"
                    checked={internetAdapter === 'automatic'} readOnly />
                  <span className="mode-name">🔄 自动检测</span>
                  <span className="mode-desc">自动选择当前联网网卡</span>
                </label>
                {adapterOptions.map((ad) => (
                  <label key={ad.name}
                    className={`mode-option${internetAdapter === ad.name ? ' selected' : ''}`}
                    onClick={() => setInternetAdapter(ad.name)}>
                    <input type="radio" name="internetAdapter" value={ad.name}
                      checked={internetAdapter === ad.name} readOnly />
                    <span className="mode-name">{ad.name}</span>
                    <span className="mode-desc">
                      {ad.gateway ? '🌐 已联网' : '🔌 已连接'}
                      {ad.ip ? ` • ${ad.ip}` : ''}
                      {ad.speed ? ` • ${ad.speed}` : ''}
                    </span>
                  </label>
                ))}
                {adapterOptions.length === 0 && (
                  <div className="mode-option disabled">
                    <span className="mode-desc">未检测到联网网卡</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── 热点控制 + 连接设备 ─────────────────────── */}
      <div className="card">
        <div className="card-header">热点控制</div>
        <div className="card-body">
          <div className="hotspot-control-row">
            <div className="hotspot-control-left">
              <SwitchButton checked={hotspotRunning}
                onChange={handleToggleHotspot} disabled={hotspotSwitching} />
              <span className={`hotspot-status-label${hotspotRunning ? ' active' : ''}${hotspotSwitching ? ' switching' : ''}`}>
                {hotspotSwitching
                  ? '⏳ 正在切换...'
                  : hotspotRunning
                    ? '● 已启动'
                    : '○ 未启动'}
              </span>
            </div>
            {/* 热点信息 */}
            {hotspotRunning && (
              <div className="hotspot-info">
                <div className="hotspot-info-item">
                  <span className="info-label">SSID:</span>
                  <span className="info-value">{ssid}</span>
                </div>
                <div className="hotspot-info-item">
                  <span className="info-label">密码:</span>
                  <span className="info-value">{password}</span>
                </div>
                <div className="hotspot-info-item">
                  <span className="info-label">频段:</span>
                  <span className="info-value">{band}</span>
                </div>
                <div className="hotspot-info-item">
                  <span className="info-label">模式:</span>
                  <span className="info-value">
                    {accessModes.find(m => m.id === networkAccess)?.name || networkAccess}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* 连接设备 */}
          {hotspotRunning && (
            <div className="devices-section">
              <div className="devices-header">
                <span className="devices-title">📱 已连接设备</span>
                <span className="devices-count">{deviceCount} 台</span>
              </div>
              {connectedDevices.length > 0 ? (
                <div className="devices-list">
                  {connectedDevices.map((dev, i) => (
                    <div key={i} className="device-item">
                      <span className="device-icon">📱</span>
                      <span className="device-mac">{dev.mac}</span>
                      {dev.ip && <span className="device-ip">{dev.ip}</span>}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="devices-empty">暂无设备连接</div>
              )}
            </div>
          )}

          {/* 二维码 */}
          {qrCode && (
            <div className="qr-wrapper">
              <img className="qr-image" src={qrCode} alt="WiFi QR Code" />
            </div>
          )}
        </div>
      </div>

      {/* ── Toast ────────────────────────────────── */}
      {toast && (
        <div className={`toast toast-${toast.type}`}>{toast.msg}</div>
      )}
    </div>
  );
}

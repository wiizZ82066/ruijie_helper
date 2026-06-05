import type { Adapter, ProcessStatus, HotspotConfig, HotspotStatus, NetworkAccessMode, InternetAdapter, ConnectedDevicesInfo, ApiResponse } from './types';

function getApi() {
  if (typeof window !== 'undefined' && window.api) {
    return window.api;
  }
  return null;
}

async function apiCall<T>(
  method: string,
  endpoint: string,
  body?: Record<string, unknown>
): Promise<{ ok: boolean; data: T | null; error?: string }> {
  const api = getApi();
  if (!api) {
    return { ok: false, data: null, error: 'API not available (Electron IPC bridge missing)' };
  }
  try {
    const res = await api.request(method, endpoint, body) as ApiResponse<T>;
    return { ok: res.ok, data: res.data, error: res.ok ? undefined : String(res.data) };
  } catch (err) {
    return { ok: false, data: null, error: String(err) };
  }
}

// ── Adapters ─────────────────────────────────────────

export async function fetchAdapters(): Promise<Adapter[]> {
  const res = await apiCall<Adapter[]>('GET', '/api/adapters');
  return res.ok && res.data ? res.data : [];
}

export async function toggleAdapter(name: string, enable: boolean): Promise<boolean> {
  const endpoint = enable
    ? `/api/adapter/${encodeURIComponent(name)}/enable`
    : `/api/adapter/${encodeURIComponent(name)}/disable`;
  const res = await apiCall<{ success: boolean }>('POST', endpoint);
  return res.ok;
}

// ── Process ─────────────────────────────────────────

export async function fetchProcessStatus(): Promise<ProcessStatus> {
  const res = await apiCall<ProcessStatus>('GET', '/api/process/status');
  return res.ok && res.data
    ? res.data
    : { running: false, path: null };
}

export async function startProcess(exePath: string): Promise<boolean> {
  const res = await apiCall<{ success: boolean }>('POST', '/api/process/start', { exe_path: exePath });
  return res.ok;
}

export async function killAndMove(): Promise<boolean> {
  const res = await apiCall<{ success: boolean }>('POST', '/api/process/kill-move');
  return res.ok;
}

export async function restoreProcess(): Promise<boolean> {
  const res = await apiCall<{ success: boolean }>('POST', '/api/process/restore');
  return res.ok;
}

export async function getMoveRecord(): Promise<boolean> {
  const res = await apiCall<{ has_record: boolean }>('GET', '/api/process/move-record');
  return res.ok && res.data ? res.data.has_record : false;
}

// ── Hotspot ─────────────────────────────────────────

export async function fetchHotspotStatus(): Promise<HotspotStatus> {
  const res = await apiCall<HotspotStatus>('GET', '/api/hotspot/status');
  return res.ok && res.data
    ? res.data
    : { status: 'Unknown', running: false };
}

export async function toggleHotspot(start: boolean, mode?: string, internetAdapter?: string): Promise<{ ok: boolean; message?: string }> {
  if (start) {
    let endpoint = '/api/hotspot/start';
    const params: string[] = [];
    if (mode) params.push(`mode=${encodeURIComponent(mode)}`);
    if (internetAdapter) params.push(`internet_adapter=${encodeURIComponent(internetAdapter)}`);
    if (params.length > 0) endpoint += '?' + params.join('&');
    const res = await apiCall<{ success: boolean; message: string }>('POST', endpoint);
    return { ok: res.ok, message: res.data?.message };
  } else {
    const res = await apiCall<{ success: boolean }>('POST', '/api/hotspot/stop');
    return { ok: res.ok };
  }
}

// ── Network Access Modes ───────────────────────────

export async function fetchNetworkAccessModes(): Promise<NetworkAccessMode[]> {
  const res = await apiCall<{ modes: NetworkAccessMode[] }>('GET', '/api/hotspot/modes');
  return res.ok && res.data ? res.data.modes : [];
}

export async function fetchInternetAdapters(): Promise<InternetAdapter[]> {
  const res = await apiCall<{ adapters: InternetAdapter[] }>('GET', '/api/network/internet-adapters');
  return res.ok && res.data ? res.data.adapters : [];
}

export async function fetchConnectedDevices(): Promise<ConnectedDevicesInfo> {
  const res = await apiCall<ConnectedDevicesInfo>('GET', '/api/hotspot/connected-devices');
  return res.ok && res.data
    ? res.data
    : { count: 0, devices: [], hotspot_running: false };
}

// ── Config ──────────────────────────────────────────

export async function fetchHotspotConfig(): Promise<HotspotConfig> {
  const res = await apiCall<HotspotConfig>('GET', '/api/config/hotspot');
  return res.ok && res.data
    ? res.data
    : { ssid: '', password: '', band: '2.4GHz', network_access: 'nat', internet_adapter: 'automatic', target_folder: '' };
}

export async function saveHotspotConfig(
  ssid: string,
  password: string,
  band: string,
  networkAccess?: string,
  internetAdapter?: string
): Promise<{ ok: boolean; restarted: boolean }> {
  const res = await apiCall<{ success: boolean; restarted: boolean }>(
    'PUT',
    '/api/config/hotspot',
    { ssid, password, band, network_access: networkAccess, internet_adapter: internetAdapter }
  );
  return { ok: res.ok, restarted: res.ok && res.data ? res.data.restarted : false };
}

export async function setTargetFolder(folder: string): Promise<boolean> {
  const res = await apiCall<{ success: boolean }>('PUT', '/api/config/target-folder', { folder });
  return res.ok;
}

// ── QR Code ─────────────────────────────────────────

export async function fetchQRCode(): Promise<string | null> {
  const res = await apiCall<{ base64: string }>('GET', '/api/qrcode');
  return res.ok && res.data ? res.data.base64 : null;
}

// TypeScript type declarations for CampusAuth

export interface Adapter {
  name: string;
  enabled: boolean;
}

export interface ProcessStatus {
  running: boolean;
  path: string | null;
}

export interface HotspotConfig {
  ssid: string;
  password: string;
  band: string;
  network_access: string;
  internet_adapter: string;
  target_folder: string;
}

export interface HotspotStatus {
  status: string;
  running: boolean;
}

export interface NetworkAccessMode {
  id: string;
  name: string;
  available: boolean;
}

export interface InternetAdapter {
  name: string;
  status: string;
  ip: string | null;
  gateway: string | null;
  speed: string | null;
  hasInternet?: boolean;
}

export interface ConnectedDevice {
  mac: string;
  ip?: string;
  authState: string;
}

export interface ConnectedDevicesInfo {
  count: number;
  devices: ConnectedDevice[];
  hotspot_running: boolean;
}

export interface ApiResponse<T> {
  ok: boolean;
  status: number;
  data: T;
}

declare global {
  interface Window {
    api: {
      request: (method: string, endpoint: string, body?: Record<string, unknown>) => Promise<ApiResponse<unknown>>;
      get: (endpoint: string) => Promise<ApiResponse<unknown>>;
      post: (endpoint: string, body?: Record<string, unknown>) => Promise<ApiResponse<unknown>>;
      put: (endpoint: string, body?: Record<string, unknown>) => Promise<ApiResponse<unknown>>;
    };
  }
}

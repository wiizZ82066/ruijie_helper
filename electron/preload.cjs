const { contextBridge, ipcRenderer } = require('electron');

/**
 * 安全的 API 桥接：通过 IPC 转发 HTTP 请求到 Python 后端。
 * 渲染进程无法直接访问 Node.js API（contextIsolation: true）。
 */
contextBridge.exposeInMainWorld('api', {
  request: (method, endpoint, body) =>
    ipcRenderer.invoke('api-request', { method, endpoint, body }),

  // 便捷方法
  get: (endpoint) => ipcRenderer.invoke('api-request', { method: 'GET', endpoint }),
  post: (endpoint, body) => ipcRenderer.invoke('api-request', { method: 'POST', endpoint, body }),
  put: (endpoint, body) => ipcRenderer.invoke('api-request', { method: 'PUT', endpoint, body }),
});

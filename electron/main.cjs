const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');
const http = require('http');

let mainWindow = null;
let pythonProcess = null;
const API_PORT = 18921;
const API_BASE = `http://127.0.0.1:${API_PORT}`;

// ── 管理员权限检查 ────────────────────────────────────

function isAdmin() {
  try {
    execSync('net session', { stdio: 'ignore', windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

// ── 启动 Python 后端 ────────────────────────────────────

function startPythonBackend() {
  const isDev = !app.isPackaged;
  const pythonExe = 'python';
  let scriptPath;
  let cwd;
  let reqPath;

  if (isDev) {
    cwd = path.join(__dirname, '..');
    scriptPath = path.join(cwd, 'backend', 'server.py');
    reqPath = path.join(cwd, 'requirements.txt');
  } else {
    cwd = process.resourcesPath;
    scriptPath = path.join(cwd, 'backend', 'server.py');
    reqPath = path.join(cwd, 'requirements.txt');
  }

  // 确保 Python 依赖已安装
  const installCmd = `"${pythonExe}" -m pip install -r "${reqPath}" --quiet 2>&1`;
  console.log('[Main] Checking Python dependencies...');
  try {
    const result = require('child_process').execSync(installCmd, {
      cwd,
      windowsHide: true,
      timeout: 60000,
    });
    console.log('[Main] Python dependencies OK');
  } catch (e) {
    console.error('[Main] pip install warning:', e.message);
  }

  console.log(`[Main] Starting Python backend: ${pythonExe} ${scriptPath}`);

  pythonProcess = spawn(pythonExe, [scriptPath], {
    cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });

  pythonProcess.stdout.on('data', (data) => {
    console.log(`[Python] ${data.toString().trim()}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`[Python ERR] ${data.toString().trim()}`);
  });

  pythonProcess.on('close', (code) => {
    console.log(`[Python] Process exited with code ${code}`);
    pythonProcess = null;
  });

  pythonProcess.on('error', (err) => {
    console.error(`[Python] Failed to start: ${err.message}`);
    pythonProcess = null;
  });
}

// ── 等待 API 就绪 ───────────────────────────────────────

function waitForAPI(retries = 30, delay = 500) {
  return new Promise((resolve, reject) => {
    const check = (remaining) => {
      http.get(`${API_BASE}/api/health`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else if (remaining > 0) {
          setTimeout(() => check(remaining - 1), delay);
        } else {
          reject(new Error('API timeout'));
        }
      }).on('error', () => {
        if (remaining > 0) {
          setTimeout(() => check(remaining - 1), delay);
        } else {
          reject(new Error('API not reachable'));
        }
      });
    };
    check(retries);
  });
}

// ── 创建窗口 ────────────────────────────────────────────

function createWindow() {
  const isDev = !app.isPackaged;

  mainWindow = new BrowserWindow({
    width: 1020,
    height: 720,
    minWidth: 860,
    minHeight: 600,
    backgroundColor: '#0d1117',
    title: '校园网认证助手',
    icon: path.join(__dirname, 'app.ico'),
    frame: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  // 去掉菜单栏
  mainWindow.setMenuBarVisibility(false);

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ── IPC 处理器 ──────────────────────────────────────────

ipcMain.handle('api-request', async (event, { method, endpoint, body }) => {
  const url = `${API_BASE}${endpoint}`;
  const options = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };

  if (body && method !== 'GET') {
    options.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(url, options);
    const data = await response.json();
    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: { detail: err.message } };
  }
});

// ── 应用生命周期 ────────────────────────────────────────

app.whenReady().then(async () => {
  // 检查管理员权限，如未提权则重新以管理员身份启动
  if (!isAdmin()) {
    const { exec } = require('child_process');
    exec(
      `powershell -Command "Start-Process -FilePath '${process.execPath}' -Verb RunAs"`,
      { windowsHide: true }
    );
    app.quit();
    return;
  }

  startPythonBackend();

  try {
    await waitForAPI();
    console.log('[Main] Python API is ready');
  } catch (err) {
    console.error('[Main] Failed to connect to Python API:', err.message);
    dialog.showErrorBox('启动失败', '无法连接到后端服务，请检查 Python 环境。');
  }

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (pythonProcess) {
    pythonProcess.kill();
    pythonProcess = null;
  }
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (pythonProcess) {
    pythonProcess.kill();
    pythonProcess = null;
  }
});

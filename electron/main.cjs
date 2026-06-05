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
  let scriptPath;
  let cwd;

  if (isDev) {
    // 开发模式：直接跑 Python
    cwd = path.join(__dirname, '..');
    scriptPath = path.join(cwd, 'backend', 'server.py');
    const pythonExe = 'python';

    console.log(`[Main] 开发模式: ${pythonExe} ${scriptPath}`);

    pythonProcess = spawn(pythonExe, [scriptPath], {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
  } else {
    // 打包模式：使用预编译的 backend.exe（由 Nuitka 构建时编译）
    cwd = process.resourcesPath;
    scriptPath = path.join(cwd, 'backend.exe');

    console.log(`[Main] 启动预编译后端: ${scriptPath}`);

    pythonProcess = spawn(scriptPath, [], {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
  }

  pythonProcess.stdout.on('data', (data) => {
    console.log(`[Python] ${data.toString().trim()}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`[Python ERR] ${data.toString().trim()}`);
  });

  pythonProcess.on('close', (code) => {
    console.log(`[Python] 进程退出, code=${code}`);
    pythonProcess = null;
  });

  pythonProcess.on('error', (err) => {
    console.error(`[Python] 启动失败: ${err.message}`);
    pythonProcess = null;
  });
}

// ── 等待 API 就绪（快速检测）───────────────────────────

function waitForAPI(retries = 30, delay = 200) {
  return new Promise((resolve, reject) => {
    const check = (remaining) => {
      http.get(`${API_BASE}/api/health`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else if (remaining > 0) {
          setTimeout(() => check(remaining - 1), delay);
        } else {
          reject(new Error('API 超时'));
        }
      }).on('error', () => {
        if (remaining > 0) {
          setTimeout(() => check(remaining - 1), delay);
        } else {
          reject(new Error('API 无法连接'));
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
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.setMenuBarVisibility(false);

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  // 等页面加载完成后才显示窗口，减少白屏感
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

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

  // 启动后端（无 pip install，打包后直接启动预编译 exe）
  startPythonBackend();

  try {
    await waitForAPI();
    console.log('[Main] 后端 API 就绪');
  } catch (err) {
    console.error('[Main] 后端连接失败:', err.message);
    dialog.showErrorBox('启动失败', '无法连接到后端服务，请确认以管理员权限运行。');
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

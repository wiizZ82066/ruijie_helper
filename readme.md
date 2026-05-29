# 校园网认证助手

基于 **Electron + React + FastAPI** 的 Windows 网络管理工具，集成网卡控制、802.1x 进程管理、移动热点（WiFi Direct）及 WiFi 二维码分享功能。

## 技术架构

```
┌─────────────────────────────────────────┐
│  Electron (桌面壳)                       │
│  ┌───────────────────────────────────┐  │
│  │  React 18 + TypeScript (前端 UI)   │  │
│  │  暗色工业风主题 · 自定义组件        │  │
│  └──────────┬────────────────────────┘  │
│             │ IPC (window.api)            │
│  ┌──────────▼────────────────────────┐  │
│  │  main.cjs (Node.js 主进程)         │  │
│  │  · 管理员权限检测 & 自动提权        │  │
│  │  · 启动 Python 后端 / 依赖安装     │  │
│  │  · HTTP 请求转发 (127.0.0.1:18921) │  │
│  └──────────┬────────────────────────┘  │
└─────────────┼───────────────────────────┘
              │ HTTP
┌─────────────▼───────────────────────────┐
│  FastAPI 后端 (Python)                   │
│  · /api/adapters    网卡管理             │
│  · /api/process     8021x 进程控制       │
│  · /api/hotspot     热点开关/状态        │
│  · /api/config      配置读写             │
│  · /api/qrcode      WiFi 二维码          │
└─────────────┬───────────────────────────┘
              │ PowerShell / netsh / WinRT
┌─────────────▼───────────────────────────┐
│  Windows 系统 API                        │
└─────────────────────────────────────────┘
```

## 项目结构

```
ruijie_helper/
├── backend/
│   └── server.py              # FastAPI 后端入口
├── utils/
│   ├── hotspot.py             # 热点管理（WinRT API）
│   ├── supplicant.py          # 8021x 进程管理 + 配置
│   └── network_adapter.py     # 网卡管理（netsh）
├── electron/
│   ├── package.json           # Electron 项目配置
│   ├── main.cjs               # Electron 主进程
│   ├── preload.cjs            # IPC 桥接
│   ├── build.bat              # 一键打包脚本
│   └── src/                   # React 前端
│       ├── App.tsx / App.css  # 主应用 + 全局样式
│       ├── api.ts             # API 客户端
│       ├── types.ts           # TypeScript 类型
│       └── components/
│           ├── Sidebar.tsx        # 侧边导航栏
│           ├── SwitchButton.tsx   # 自定义滑动开关
│           ├── HotspotPage.tsx    # 热点管理页
│           └── NetworkPage.tsx    # 网卡控制页
├── icon/
│   ├── app.ico               # 程序图标
│   └── ICON_BASE64.py        # 图标 Base64 源
├── main.py                   # 保留：纯 Python 启动入口
└── requirements.txt
```

## 功能介绍

- **网卡管理**
  - 检测本地所有网络适配器的名称和启停状态。
  - 一键启用/禁用指定网卡，使用滑动开关直观操作。
  - 实时刷新 8021x.exe 进程路径，支持手动选择并启动该程序。

- **8021x 进程控制**
  - 监控 8021x.exe 运行状态（红色运行中 / 绿色未运行）。
  - 结束进程并将可执行文件移动到指定目录；支持还原至原始路径。
  - 仅保留最近一次移动记录，防止误操作。

- **热点管理（WiFi Direct）**
  - 通过 Windows 原生接口（PowerShell 调用 WinRT API）开启/关闭移动热点。
  - 自定义热点名称（SSID）、密码、频段（2.4 GHz / 5 GHz），配置自动持久化。
  - **保存配置后自动重启热点**以应用新参数。
  - **频段切换已修复**：正确设置 Windows API 的 Band 属性。
  - 热点成功开启后自动生成 WiFi 二维码，方便手机扫码连接。
  - 滑动开关控制，切换时显示动画状态反馈。

## 使用方法

### 1. 直接下载运行（推荐）

下载 `Release` 中的 `exe.zip`，解压到任意目录，双击 `校园网认证助手.exe` 即可运行。

> 首次运行会请求管理员权限（程序需要管理网络适配器和热点），请点击「是」。

### 2. 从源码构建

**环境要求：**
- Node.js ≥ 18 + npm
- Python ≥ 3.9 + pip
- Windows 10/11 x64

```bash
# 1. 安装 Python 依赖
pip install -r requirements.txt

# 2. 安装前端依赖
cd electron
npm install

# 3. 一键打包（生成 exe/win-unpacked/）
build.bat
```

### 3. 开发模式

```bash
# 终端 1：启动 Python 后端
python backend/server.py

# 终端 2：启动前端开发服务器
cd electron
npm run dev
```

## 免责声明

- 本程序仅供学习、研究及个人合法使用。
- 严禁将本软件用于任何非法目的（包括但不限于未授权访问网络、干扰他人设备等）。
- 使用者在下载、运行本软件时应遵守当地法律法规，并对自己的行为负责。
- 开发者不对因使用本软件造成的任何直接或间接损失承担责任。

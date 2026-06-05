# 校园网认证助手 V5

基于 **Electron + React + FastAPI** 的 Windows 网络管理工具，集成网卡控制、802.1x 进程管理、移动热点及 WiFi 二维码分享功能。  
本软件仅用以解决`锐捷认证客户端`对有线认证用户的**虚拟机网卡检测**和**多IP限制**。

## V5 重大更新

### 🔥 热点方案重构 —— 参考 MyPublicWiFi
- **三层降级策略**：`hostednetwork + ICS`（主力）→ `TetheringManager`（备选）→ `hostednetwork only`（最终备选）
- **手动配置 ICS**：通过 `HNetCfg.HNetShare` COM 接口强制配置 Internet Connection Sharing，彻底解决手机连接热点后**无网络**的问题
- 不再依赖系统自动共享，连接即有网

### ⚡ 启动速度大幅提升
- **后端预编译**：构建时用 Nuitka 将 Python 后端编译为独立 exe，**无需 Python 环境、无需 pip install**
- **NSIS 安装器**：告别 portable 模式的解压等待，安装即用、秒速启动
- 首次启动时间从 **15s+ 降至 ~3s**

### 📦 打包优化
- 安装包更小、更快
- 支持自定义安装目录
- 自动创建桌面快捷方式

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
│  │  · 启动预编译后端 (backend.exe)     │  │
│  │  · HTTP 请求转发 (127.0.0.1:18921) │  │
│  └──────────┬────────────────────────┘  │
└─────────────┼───────────────────────────┘
              │ HTTP
┌─────────────▼───────────────────────────┐
│  FastAPI 后端 (预编译 backend.exe)       │
│  · /api/adapters    网卡管理             │
│  · /api/process     8021x 进程控制       │
│  · /api/hotspot     热点开关/状态/ICS    │
│  · /api/config      配置读写             │
│  · /api/qrcode      WiFi 二维码          │
└─────────────┬───────────────────────────┘
              │ PowerShell / netsh / WinRT / HNetCfg
┌─────────────▼───────────────────────────┐
│  Windows 系统 API                        │
│  · netsh wlan hostednetwork (MyPublicWiFi)│
│  · HNetCfg.HNetShare COM (ICS 手动配置)  │
│  · Windows.Networking (TetheringManager) │
└─────────────────────────────────────────┘
```

## 项目结构

```
ruijie_helper/
├── backend/
│   └── server.py              # FastAPI 后端入口
├── utils/
│   ├── hotspot.py             # 热点管理（三层降级，参考 MyPublicWiFi）
│   ├── ics_manager.py         # ICS 配置管理（HNetCfg COM）✨ 新增
│   ├── supplicant.py          # 8021x 进程管理 + 配置
│   └── network_adapter.py     # 网卡管理（netsh）
├── electron/
│   ├── package.json           # Electron 项目配置
│   ├── main.cjs               # Electron 主进程（无 pip install）
│   ├── preload.cjs            # IPC 桥接
│   ├── build.bat              # 一键打包脚本（含 Nuitka 编译）
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

- **热点管理（MyPublicWiFi 方案）**
  - **三层降级**：`hostednetwork + ICS`(主力) → `TetheringManager`(备选) → `hostednetwork`(最终)
  - **手动 ICS 配置**：通过 `HNetCfg.HNetShare` COM 接口自动将有线网卡共享给热点，**连接既有网**
  - 自动检测互联网网卡，无需手动选择
  - ICS 状态诊断与一键修复
  - 自定义 SSID、密码、频段，配置自动持久化
  - 热点成功开启后自动生成 WiFi 二维码，方便手机扫码连接

## 默认配置

首次运行时热点配置为：

| 配置项 | 默认值 |
|--------|--------|
| SSID（热点名称） | `test` |
| 密码 | `12345678` |
| 频段 | `2.4GHz` |

> 可在「热点配置」页面中修改，保存后自动生效。

## 使用方法

### 1. 直接下载安装（推荐）

下载 `Release` 中的 [安装包](https://github.com/wiizZ82066/ruijie_helper/releases/tag/V5)，运行 `校园网认证助手_Setup_5.0.0.exe` 即可安装使用。

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

# 3. 一键打包（生成 NSIS 安装器）
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

## 常见问题

1. 连接上电脑热点，手机端显示**无网络**
- V5 已通过 `HNetCfg.HNetShare` COM 接口**自动配置 ICS**，一般无需手动操作。
- 如果仍有问题，可尝试在「热点配置」页面点击修复 ICS，或手动检查：`控制面板` → `网络和共享中心` → `更改适配器设置` → 右键互联网网卡 → `属性` → `共享`。

2. 无法启动认证客户端
- 如果上次使用`结束并移动`且未`还原`，会导致认证客户端无法正常启动，只需要进行一次`还原`，确保`8021x.exe`成功运行即可。

## 免责声明

- 本程序仅供学习、研究及个人合法使用。
- 严禁将本软件用于任何非法目的（包括但不限于未授权访问网络、干扰他人设备等）。
- 使用者在下载、运行本软件时应遵守当地法律法规，并对自己的行为负责。
- 开发者不对因使用本软件造成的任何直接或间接损失承担责任。

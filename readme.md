# 校园网认证助手

推荐入口是 `campus_flet.py`：使用已有锐捷认证核心登录校园网，并管理 Windows 移动热点。程序自动查找客户端安装目录，支持账号密码输入、密码显示切换、当前用户加密保存和登录自启动。

本项目复用原认证核心及驱动，不是独立重写的校园网协议。兼容安装只接受代码中已核验的 RG-SU 6.61 文件；其他版本不会自动套用修改。

## Flet 界面

新增入口 `campus_flet.py` 使用 Flet 桌面界面：窗口较宽时并排显示登录与热点，窄窗口自动纵向排列；客户端目录、自启动和维护功能集中到设置页。热点、自启动状态在后台独立读取，不会阻止输入账号和连接。

```powershell
python -m pip install -r requirements-flet.txt
powershell -NoProfile -ExecutionPolicy Bypass -File build_flet.ps1 -PrepareRuntimeOnly
python campus_flet.py
```

运行 `build_flet.ps1` 可生成 `release/CampusAuthenticatorFlet/CampusAuthenticatorFlet.exe` 和独立 ZIP。完整解压后使用，保留 `_internal` 目录。固定的 Flet 0.86.5 Windows 运行时只在构建时下载并校验；程序启动时不下载依赖。

Flet 与原版共用当前用户的配置、加密账号库和单实例锁，不要同时运行。切换版本后，如需自启动，请在新版本设置页重新启用，使任务指向新程序。这个界面仍使用同一套认证核心和热点逻辑，具体步骤见 [Flet 使用说明](docs/flet-user-guide.txt)。

`python campus_flet.py --preview` 可用模拟数据预览界面；`--self-test --test-report build/flet-smoke.json` 执行模拟界面及依赖检查。两者都不会读取真实账号或改变网络。

## 运行发布包

从 [GitHub Releases 下载最新版](https://github.com/wiizZ82066/ruijie_helper/releases/latest)。

发布包为 `CampusAuthenticatorFlet-win-x64.zip`。请完整解压后运行 `CampusAuthenticatorFlet/CampusAuthenticatorFlet.exe`，并保留同目录的 `_internal` 文件夹。不要只复制 EXE，也不要直接从压缩包内运行。

本地构建产物位于 `release/CampusAuthenticatorFlet/CampusAuthenticatorFlet.exe`，压缩包位于 `release/CampusAuthenticatorFlet-win-x64.zip`。目录版省去每次启动时解压运行库的开销，是默认推荐形式。

1. 保留已安装的锐捷客户端和驱动，启动程序并接受管理员提示。
2. 输入校园账号和密码，点击“连接校园网”。首次连接会校验、备份并安装兼容核心。
3. 如果未发现客户端，在“设置”→“常规”中“自动查找”或“选择目录”。
4. 在“设置”→“网络与热点”选择连接校园网的有线接口。主界面可修改热点名称和密码，并开启或关闭热点。
5. 如需自动连接，在常规设置中启用“运行后自动连接”和“登录 Windows 后自动启动”。

默认热点名称为 `ovo`，默认密码为 `12345678`；已有设置优先。完整步骤和故障处理见 [使用说明](docs/flet-user-guide.txt)。

## 账号与热点边界

“在本程序记住账号密码”将两字段一起交给 Windows 当前用户 DPAPI 加密。校园账号密码不写入本程序的普通设置文件或命令行；不记住时，下次启动需要重新输入，除非明确选择使用原客户端保存账号的兼容方式。

原核心仍需自己的 DES 兼容配置，原生用户目录也保留可辨识的账号。因此清除本程序凭据不会删除原客户端记录，也不代表整个认证链路没有明文账号标识。普通设置文件包含热点密码，备份、配置和诊断记录不应公开。

检测到唯一可用的 Clash/Mihomo TUN 时，热点选择该 TUN 作为共享来源；没有活动 TUN 时使用所选有线网络。验证支持经典 ICS 和本程序明确启动的现代 WinRT 会话，检查来源、私有网卡、地址和路由；已有热点不会因验证失败被自动替换或关闭。

“热点已开启”是本机状态，手机是否获取地址并能访问网页仍需实际检查。不同 Windows 版本、驱动、网络策略和长期运行表现可能不同，不能保证服务器端不识别共享。实现细节见 [架构说明](docs/architecture.md)。

## 从源码运行与构建

需要 Windows x64、支持移动热点的无线网卡、Windows PowerShell，以及 Python 3.10 或更新版本。构建前请用 Git 克隆仓库：构建脚本会检查 Git 跟踪及待发布文件，发现本机路径、常见凭据或不应发布的文件时停止。源码运行和构建使用同一套依赖：

```powershell
python -m pip install -r requirements-flet.txt
powershell -NoProfile -ExecutionPolicy Bypass -File build_flet.ps1 -PrepareRuntimeOnly
python campus_flet.py
```

默认构建目录版和压缩包：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build_flet.ps1
```

旧 Qt 界面仍可从源码运行或构建：

```powershell
python -m pip install -r requirements-oneclick.txt
python campus_authenticator.py
powershell -NoProfile -ExecutionPolicy Bypass -File build_authenticator.ps1
```

离线回归测试不需要真实校园账号，也不应改变网络：

```powershell
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python tools/audit_release.py
```

公开源码与文档不包含原厂客户端二进制、账号配置、真实现场报告或私人分析目录。安装时读取用户已有的受支持客户端，备份和恢复记录留在当前用户的数据目录中。

## 保留的旧入口

`campus_authenticator.py` 保留 Qt 入口，旧发布包可在 [v6.0.0](https://github.com/wiizZ82066/ruijie_helper/releases/tag/v6.0.0) 下载，使用步骤见 [Qt 使用说明](docs/user-guide.txt)。切换到 Flet 后，请退出旧程序，并在新版设置中重新启用自启动。

`main.py` / `ui/` 是更早的 PySide6 界面；`electron/` / `backend/` 是旧 Electron + FastAPI 界面，均不作为当前推荐入口。旧 Electron 仍需要 PATH 中的 Python 和预先安装的后端依赖，不会在每次启动时自动安装依赖。

开发旧 Electron 界面时，在安装依赖后使用 `npm run electron:dev`，由 Electron 启动后端。后端所有 API 都要求当前桌面会话的 Bearer 鉴权；临时令牌由 Electron 随机生成、通过子进程环境传入，并只由主进程代理请求附加。不要将后端作为无鉴权服务单独启动，不要在代码、文档或命令行中放置固定令牌。

@echo off
chcp 65001 >nul
title 校园网认证助手 V5 打包
echo ============================================
echo  校园网认证助手 V5 - 打包脚本
echo ============================================
echo.

cd /d "%~dp0"

echo [1/4] 生成程序图标...
python -c "import base64,io; from PIL import Image; import sys; sys.path.insert(0,'..'); from icon.ICON_BASE64 import ICON_BASE64; data=base64.b64decode(ICON_BASE64); img=Image.open(io.BytesIO(data)); img=img.resize((256,256),Image.LANCZOS); img.save('app.png','PNG'); img.save('app.ico',format='ICO',sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)]); print('Icon generated: app.png + app.ico')"
if errorlevel 1 goto error

echo.
echo [2/4] 构建前端...
call npm run build
if errorlevel 1 goto error

echo.
echo [3/4] 打包 Electron (NSIS 安装器)...
rmdir /s /q "..\exe" 2>nul
call npx electron-builder --win nsis --config.directories.output="..\exe"
if errorlevel 1 goto error

echo.
echo [4/4] 用 rcedit 写入程序图标...
for %%f in ("..\exe\win-unpacked\*.exe") do (
    node node_modules\rcedit\lib\index.js "%%f" --set-icon app.ico
    if !errorlevel! equ 0 (
        echo [OK] 图标已写入: %%~nxf
    ) else (
        echo [WARN] 图标写入失败
    )
)

echo.
echo ============================================
echo  打包完成!
echo  安装包: exe\校园网认证助手_Setup_5.0.0.exe
echo ============================================
goto end

:error
echo.
echo ╔═══════════════════════════════════════════╗
echo ║            打 包 失 败                     ║
echo ╚═══════════════════════════════════════════╝
pause

:end

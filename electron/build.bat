@echo off
chcp 65001 >nul
title 校园网认证助手 V5 打包
echo ============================================
echo  校园网认证助手 V5 - 打包脚本
echo ============================================
echo.

cd /d "%~dp0"

echo [1/5] 安装 Python 编译依赖...
pip install nuitka --quiet
if errorlevel 1 (
    echo [WARN] Nuitka 安装失败，将尝试使用原 Python 脚本
    set COMPILE_BACKEND=0
) else (
    set COMPILE_BACKEND=1
)

echo.
echo [2/5] 编译 Python 后端为独立 exe...
if "%COMPILE_BACKEND%"=="1" (
    cd ..
    python -m nuitka --standalone ^
        --windows-console-mode=disable ^
        --windows-icon-from-ico=icon/app.ico ^
        --include-module=uvicorn ^
        --include-module=fastapi ^
        --include-module=psutil ^
        --include-module=qrcode ^
        --include-package=utils ^
        --windows-uac-admin ^
        --assume-yes-for-downloads ^
        --output-dir=electron ^
        --lto=yes ^
        --nofollow-import-to=unittest ^
        --nofollow-import-to=pytest ^
        --python-flag=-OO ^
        --windows-product-name="校园网认证助手" ^
        --windows-file-description="校园网认证助手后端" ^
        --file-version="5.0.0" ^
        backend/server.py
    if errorlevel 1 (
        echo [WARN] Nuitka 编译失败，将使用原 Python 脚本
        set COMPILE_BACKEND=0
    ) else (
        rem 将编译产物重命名为 backend.exe
        if exist "server.dist\server.exe" (
            move /y "server.dist\server.exe" "backend.exe" >nul
            rmdir /s /q "server.dist" >nul 2>&1
            rmdir /s /q "server.build" >nul 2>&1
            echo [OK] 后端编译成功: backend.exe
        )
    )
    cd electron
) else (
    echo [SKIP] 跳过 Nuitka 编译
)

echo.
echo [3/5] 生成图标...
python -c "import base64,io; from PIL import Image; import sys; sys.path.insert(0,'..'); from icon.ICON_BASE64 import ICON_BASE64; data=base64.b64decode(ICON_BASE64); img=Image.open(io.BytesIO(data)); img=img.resize((256,256),Image.LANCZOS); img.save('app.png','PNG'); img.save('app.ico',format='ICO',sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)]); print('Icon generated: app.png + app.ico')"
if errorlevel 1 goto error

echo.
echo [4/5] 构建前端...
call npm run build
if errorlevel 1 goto error

echo.
echo [5/5] 打包 Electron (NSIS 安装器)...
rmdir /s /q "..\exe" 2>nul
call npx electron-builder --win nsis --config.directories.output="..\exe"
if errorlevel 1 goto error

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

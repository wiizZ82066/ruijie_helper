@echo off
chcp 65001 >nul
echo ============================================
echo  校园网认证助手 - 打包脚本
echo ============================================

cd /d "%~dp0"

echo [1/4] 生成图标...
python -c "import base64,io; from PIL import Image; import sys; sys.path.insert(0,'..'); from icon.ICON_BASE64 import ICON_BASE64; data=base64.b64decode(ICON_BASE64); img=Image.open(io.BytesIO(data)); img=img.resize((256,256),Image.LANCZOS); img.save('app.png','PNG'); img.save('app.ico',format='ICO',sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)]); print('Icon generated: app.png + app.ico')"

echo [2/4] 构建前端...
call npm run build
if errorlevel 1 goto error

echo [3/4] 打包 Electron...
rmdir /s /q "..\exe" 2>nul
call npx electron-builder --win portable --dir --config.directories.output="../exe"
if errorlevel 1 goto error

echo [4/4] 设置程序图标...
python -c "import glob,subprocess; exe=glob.glob(r'..\exe\win-unpacked\*.exe')[0]; subprocess.run([r'%APPDATA%\npm\node_modules\rcedit\bin\rcedit-x64.exe', exe, '--set-icon', 'app.ico'], check=True); print('Icon patched successfully')"

echo.
echo ============================================
echo  打包完成! exe\win-unpacked\
echo ============================================
goto end

:error
echo.
echo 打包失败!
pause

:end

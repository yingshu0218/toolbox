@echo off
setlocal EnableDelayedExpansion

if "%TOOLBOX_PYTHON%"=="" set "TOOLBOX_PYTHON=python"
if "%TOOLBOX_PORT%"=="" set "TOOLBOX_PORT=5001"
set "SCRIPT_DIR=%~dp0"
if "%TOOLBOX_ROOT%"=="" (
  set "ROOT=%SCRIPT_DIR%.."
) else (
  set "ROOT=%TOOLBOX_ROOT%"
)

echo Toolbox starting on http://localhost:%TOOLBOX_PORT%/

REM 延迟3秒后打开浏览器 (给 server 启动时间)
start "" cmd /c "ping -n 4 127.0.0.1 >nul & start http://localhost:%TOOLBOX_PORT%/"

REM 前台运行服务 (Ctrl+C 退出)
"%TOOLBOX_PYTHON%" "%ROOT%\home\server.py"

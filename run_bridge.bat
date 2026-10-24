@echo off
title C++ HTTP Bridge Server (Port 9090)
cd /d "%~dp0"
echo ============================================================
echo   HTTP Bridge Server - Listening on http://localhost:9090
echo ============================================================
echo.
bridge.exe
pause

@echo off
title Secure File Transfer System Launcher
cd /d "%~dp0"
echo ============================================================
echo   Starting Secure File Transfer System (College Demo)
echo ============================================================
echo.
echo [1/3] Launching C++ TCP Server on port 8080...
start "C++ TCP Server (Port 8080)" cmd /k "run_server.bat"
timeout /t 2 /nobreak >nul

echo [2/3] Launching C++ HTTP Bridge on port 9090...
start "C++ HTTP Bridge (Port 9090)" cmd /k "run_bridge.bat"
timeout /t 2 /nobreak >nul

echo [3/3] Opening Frontend in your web browser...
start http://localhost:9090

echo.
echo ============================================================
echo   Both services are now running!
echo   Frontend URL: http://localhost:9090
echo ============================================================
echo.
pause

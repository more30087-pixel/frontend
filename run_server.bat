@echo off
title C++ TCP Server (Port 8080)
cd /d "%~dp0"
echo ============================================================
echo   Secure File Transfer Server - Listening on 127.0.0.1:8080
echo ============================================================
echo.
:loop
server.exe
echo.
echo [Transfer complete. Re-arming server for next connection...]
echo.
goto loop

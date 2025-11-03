@echo off
REM Scorpion Security Platform - Windows Startup Script
title Scorpion Security Platform

echo 🦂 Starting Scorpion Security Platform...
echo.

REM Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js not found. Please install Node.js first.
    pause
    exit /b 1
)

REM Start the web server
echo 🌐 Starting web interface on http://localhost:3001
echo 👤 Default login: admin / admin
echo.

cd /d "%~dp0"
node server/simple-web-server.js

pause
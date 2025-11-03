@echo off
REM Scorpion Security Platform - Windows Installation Script
title Scorpion Installation

echo 🦂 Scorpion Security Platform - Windows Installation
echo ================================================
echo.

REM Check administrator privileges
net session >nul 2>&1
if not %errorlevel%==0 (
    echo ❌ This script requires administrator privileges
    echo    Right-click and "Run as administrator"
    pause
    exit /b 1
)

REM Install dependencies
echo 📦 Installing dependencies...
npm install

REM Build frontend
echo 🔨 Building frontend...
npm run build

REM Create directories
if not exist "reports" mkdir reports
if not exist "results" mkdir results
if not exist "logs" mkdir logs

echo.
echo ✅ Installation completed successfully!
echo 🚀 Run start-windows.bat to launch the platform
echo.
pause
@echo off
REM Scorpion Security Platform - Simple Windows Setup (No Admin Required)
title Scorpion Security Platform Setup

echo 🦂 Scorpion Security Platform - Windows Setup
echo ============================================
echo.

REM Check Node.js version
echo 📋 Checking system requirements...
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js not found
    echo 📥 Please install Node.js from: https://nodejs.org/
    echo    Requires Node.js 16 or higher
    pause
    exit /b 1
) else (
    echo ✅ Node.js found: 
    node --version
)

REM Check npm
npm --version >nul 2>&1
if errorlevel 1 (
    echo ❌ npm not found
    pause
    exit /b 1
) else (
    echo ✅ npm found: 
    npm --version
)

echo.
echo 📦 Installing Node.js dependencies...
npm install
if errorlevel 1 (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo 🔨 Building frontend...
npm run build
if errorlevel 1 (
    echo ❌ Failed to build frontend
    pause
    exit /b 1
)

echo.
echo 📁 Creating directories...
if not exist "reports" mkdir reports
if not exist "results" mkdir results  
if not exist "logs" mkdir logs

echo.
echo ✅ Setup completed successfully!
echo.
echo 🚀 To start Scorpion Security Platform:
echo    1. Double-click start-windows.bat
echo    2. Or run: npm start
echo.
echo 🌐 Web Interface: http://localhost:3001
echo 👤 Default Login: admin / admin
echo.
echo 📖 Documentation: README.md
echo 🔧 Advanced setup: See DOCKER.md for containerization
echo.
pause
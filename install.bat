@echo off
REM Scorpion CLI Installation Script for Windows

echo ========================================
echo 🦂 Scorpion CLI Security Tool - Installation
echo ========================================
echo.

REM Check Node.js installation
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Node.js is not installed!
    echo Please install Node.js 16.0.0 or higher from https://nodejs.org/
    pause
    exit /b 1
)

echo ✅ Node.js detected
node -v
echo.

REM Install dependencies
echo 📦 Installing dependencies...
call npm install
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to install dependencies!
    pause
    exit /b 1
)

echo.
echo 🔗 Creating global symlink...
call npm link
if %ERRORLEVEL% NEQ 0 (
    echo ⚠️  Failed to create global symlink.
    echo.
    echo You can still use the tool locally with:
    echo    scorpion  (Python CLI)
    echo.
    pause
    exit /b 0
)

echo.
echo ✅ Installation complete!
echo.
echo 🚀 Quick Start:
echo    scorpion --help                    # Show help
echo    scorpion scan -t example.com       # Scan a target
echo    scorpion recon -t example.com      # Network reconnaissance
echo.
echo 📖 For full documentation, see README.md
echo.
pause

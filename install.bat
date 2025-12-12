@echo off
REM Scorpion CLI Installation Script for Windows

echo ========================================
echo 🦂 Scorpion CLI Security Tool - Installation
echo ========================================
echo.

REM Check Python installation
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Python is not installed!
    echo Please install Python 3.10 or higher from:
    echo    - Microsoft Store: https://www.microsoft.com/store/productId/9NRWMJP3717K
    echo    - python.org: https://python.org
    echo.
    echo ⚠️  IMPORTANT: Check "Add Python to PATH" during installation!
    pause
    exit /b 1
)

echo ✅ Python detected
python --version
echo.

REM Check Python version
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VERSION=%%v
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set PYTHON_MAJOR=%%a
    set PYTHON_MINOR=%%b
)

if %PYTHON_MAJOR% LSS 3 (
    echo ❌ Python version must be 3.10 or higher!
    echo Current version: %PYTHON_VERSION%
    pause
    exit /b 1
)

if %PYTHON_MAJOR% EQU 3 if %PYTHON_MINOR% LSS 10 (
    echo ❌ Python version must be 3.10 or higher!
    echo Current version: %PYTHON_VERSION%
    pause
    exit /b 1
)

echo.
echo 📦 Creating virtual environment...
if not exist ".venv" (
    python -m venv .venv
    if %ERRORLEVEL% NEQ 0 (
        echo ❌ Failed to create virtual environment!
        pause
        exit /b 1
    )
    echo ✅ Virtual environment created
) else (
    echo ✅ Virtual environment already exists
)

echo.
echo 🔧 Activating virtual environment...
call .venv\Scripts\activate.bat
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to activate virtual environment!
    pause
    exit /b 1
)

echo ✅ Virtual environment activated
echo.

REM Upgrade pip
echo 📦 Upgrading pip...
python -m pip install --upgrade pip

REM Install Scorpion CLI
echo 📦 Installing Scorpion CLI...
python -m pip install -e tools\python_scorpion
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Failed to install Scorpion CLI!
    pause
    exit /b 1
)

echo.
echo ✅ Installation complete!
echo.
echo 🚀 Quick Start:
echo    # Activate virtual environment (if not already active):
echo    .venv\Scripts\activate
echo.
echo    # Show help
echo    scorpion --help
echo.
echo    # Basic scanning
echo    scorpion scan -t example.com --web
echo.
echo    # SSL/TLS analysis
echo    scorpion ssl-analyze -t example.com -p 443
echo.
echo 📖 For full documentation, see:
echo    - README.md
echo    - INSTALL.md (Windows guide)
echo.
echo ⚠️  Remember: To use scorpion after closing this terminal:
echo    .venv\Scripts\activate
echo.
pause

@echo off
setlocal enabledelayedexpansion

REM Scorpion Security Platform - Windows Installer
REM This script provides cross-platform support for Windows systems

REM Simple color codes for Windows
set "RED="
set "GREEN="
set "YELLOW="
set "BLUE="
set "CYAN="
set "NC="

REM Banner
echo.
echo ===============================================================
echo    SCORPION SECURITY PLATFORM - WINDOWS INSTALLER
echo    Global Threat-Hunting Platform
echo    Cross-Platform Vulnerability Assessment Tool
echo ===============================================================
echo.

REM Detect Windows version and architecture
echo Platform detected: Windows
for /f "tokens=4-7 delims=[.] " %%i in ('ver') do (
    set "version=%%i.%%j"
)
echo Version: !version!

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo %GREEN%✅ Running with administrator privileges%NC%
    set "IS_ADMIN=true"
) else (
    echo %YELLOW%⚠️  Not running as administrator (some features may be limited)%NC%
    set "IS_ADMIN=false"
)

REM Check prerequisites
echo.
echo %BLUE%🔍 Checking prerequisites...%NC%

REM Check Node.js
node --version >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%❌ Node.js is not installed%NC%
    echo %YELLOW%Please install Node.js 18+ from https://nodejs.org/%NC%
    echo %YELLOW%Or use the Windows Package Manager:  winget install OpenJS.NodeJS%NC%
    pause
    exit /b 1
)

for /f "tokens=1 delims=v" %%i in ('node --version') do set "node_version=%%i"
echo %GREEN%✅ Node.js !node_version! detected%NC%

REM Check npm
npm --version >nul 2>&1
if %errorLevel% neq 0 (
    echo %RED%❌ npm is not installed%NC%
    pause
    exit /b 1
)

for /f %%i in ('npm --version') do set "npm_version=%%i"
echo %GREEN%✅ npm !npm_version! detected%NC%

REM Check Git
git --version >nul 2>&1
if %errorLevel% neq 0 (
    echo %YELLOW%⚠️  Git not found (optional but recommended)%NC%
    echo %YELLOW%Install with: winget install Git.Git%NC%
) else (
    for /f "tokens=3" %%i in ('git --version') do set "git_version=%%i"
    echo %GREEN%✅ Git !git_version! detected%NC%
)

REM Check Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    python3 --version >nul 2>&1
    if %errorLevel% neq 0 (
        echo %YELLOW%⚠️  Python not found (recommended for advanced exploits)%NC%
        echo %YELLOW%Install with: winget install Python.Python.3%NC%
    ) else (
        for /f "tokens=2" %%i in ('python3 --version') do set "python_version=%%i"
        echo %GREEN%✅ Python !python_version! detected%NC%
    )
) else (
    for /f "tokens=2" %%i in ('python --version') do set "python_version=%%i"
    echo %GREEN%✅ Python !python_version! detected%NC%
)

REM Check PowerShell
powershell -Command "Get-Host" >nul 2>&1
if %errorLevel% neq 0 (
    echo %YELLOW%⚠️  PowerShell not accessible%NC%
) else (
    echo %GREEN%✅ PowerShell detected%NC%
)

REM Check curl
curl --version >nul 2>&1
if %errorLevel% neq 0 (
    echo %YELLOW%⚠️  curl not found (may limit some features)%NC%
) else (
    echo %GREEN%✅ curl detected%NC%
)

REM Check nmap (if installed)
nmap --version >nul 2>&1
if %errorLevel% neq 0 (
    echo %YELLOW%⚠️  nmap not found (recommended for network scanning)%NC%
    echo %YELLOW%Download from: https://nmap.org/download.html%NC%
) else (
    echo %GREEN%✅ nmap detected%NC%
)

REM Install optional Windows tools if administrator
if "%IS_ADMIN%"=="true" (
    echo.
    echo %BLUE%📦 Checking for optional Windows tools...%NC%
    
    REM Check if winget is available
    winget --version >nul 2>&1
    if %errorLevel% == 0 (
        echo %GREEN%✅ Windows Package Manager (winget) available%NC%
        
        REM Offer to install useful tools
        if "%1"=="--install-tools" (
            echo %CYAN%Installing recommended security tools...%NC%
            winget install --id Nmap.Nmap --silent --accept-source-agreements --accept-package-agreements
            winget install --id Wireshark.Wireshark --silent --accept-source-agreements --accept-package-agreements
            winget install --id voidtools.Everything --silent --accept-source-agreements --accept-package-agreements
        )
    ) else (
        echo %YELLOW%⚠️  Windows Package Manager not available%NC%
    )
)

REM Setup Scorpion
echo.
echo %BLUE%🦂 Setting up Scorpion Security Platform...%NC%

REM Install npm dependencies
echo %CYAN%Installing Node.js dependencies...%NC%
npm install
if %errorLevel% neq 0 (
    echo %RED%❌ Failed to install dependencies%NC%
    pause
    exit /b 1
)

REM Run setup script
echo %CYAN%Running platform setup...%NC%
npm run setup
if %errorLevel% neq 0 (
    echo %RED%❌ Setup failed%NC%
    pause
    exit /b 1
)

REM Create batch files for easy access
echo %CYAN%Creating Windows shortcuts...%NC%

REM Create scorpion.bat in the same directory
echo @echo off > scorpion.bat
echo cd /d "%~dp0" >> scorpion.bat
echo node cli/scorpion.js %%* >> scorpion.bat

echo %GREEN%✅ Created scorpion.bat launcher%NC%

REM Create desktop shortcut if requested
if "%1"=="--desktop-shortcut" (
    echo %CYAN%Creating desktop shortcut...%NC%
    powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\Scorpion Security Platform.lnk'); $Shortcut.TargetPath = 'cmd.exe'; $Shortcut.Arguments = '/k cd /d \"%CD%\" && npm run dev:full'; $Shortcut.WorkingDirectory = '%CD%'; $Shortcut.Save()"
    echo %GREEN%✅ Created desktop shortcut%NC%
)

REM Add to PATH if administrator
if "%IS_ADMIN%"=="true" (
    echo %CYAN%Adding to system PATH...%NC%
    setx PATH "%PATH%;%CD%" /M >nul 2>&1
    if %errorLevel% == 0 (
        echo %GREEN%✅ Added to system PATH%NC%
    ) else (
        echo %YELLOW%⚠️  Could not add to system PATH%NC%
    )
)

REM Run compatibility test
echo.
echo %BLUE%🧪 Running cross-platform compatibility test...%NC%
npm run test:platform
if %errorLevel% neq 0 (
    echo %YELLOW%⚠️  Compatibility test had issues, but installation may still work%NC%
)

REM Final success message
echo.
echo %GREEN%
echo ✅ Scorpion Security Platform installed successfully!
echo.
echo 🚀 Quick Start Commands:
echo   npm run cli -- help                    # Show CLI help
echo   npm run cli -- help-advanced           # Show advanced features  
echo   npm run scan -- --target example.com   # Basic vulnerability scan
echo   npm run server                         # Start web interface
echo   npm run dev:full                       # Start development mode
echo.
echo 💡 Windows Shortcuts:
echo   scorpion.bat help                      # Show help
echo   scorpion.bat scan --target example.com # Run scan
echo.
if "%IS_ADMIN%"=="true" (
    echo 📁 Global Command ^(restart CMD to use^):
    echo   scorpion help                       # Show help anywhere
    echo.
)
echo ⚠️  IMPORTANT: Only use on authorized systems!
echo %NC%

REM Keep window open
if "%1" neq "--silent" (
    echo Press any key to continue...
    pause >nul
)

endlocal
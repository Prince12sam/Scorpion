@echo off
setlocal enabledelayedexpansion

REM Scorpion Security Platform - Windows Installer
REM This script provides cross-platform support for Windows systems

echo.
echo ===============================================================
echo    SCORPION SECURITY PLATFORM - WINDOWS INSTALLER
echo    Global Threat-Hunting Platform
echo    Cross-Platform Vulnerability Assessment Tool
echo ===============================================================
echo.

REM Handle help command
if "%1"=="--help" (
    echo Scorpion Security Platform - Windows Installer
    echo.
    echo Usage: install-windows.bat [options]
    echo.
    echo Options:
    echo   --install-tools      Install optional security tools using winget
    echo   --desktop-shortcut   Create desktop shortcut
    echo   --silent             Run without pauses
    echo   --help               Show this help message
    echo.
    pause
    exit /b 0
)

REM Detect Windows version and architecture
echo Platform detected: Windows
for /f "tokens=4-7 delims=[.] " %%i in ('ver') do (
    set "version=%%i.%%j"
)
echo Version: !version!

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges
    set "IS_ADMIN=true"
) else (
    echo Warning: Not running as administrator (some features may be limited)
    set "IS_ADMIN=false"
)

REM Check prerequisites
echo.
echo Checking prerequisites...

REM Check Node.js
node --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Node.js is not installed
    echo Please install Node.js 18+ from https://nodejs.org/
    echo Or use the Windows Package Manager:  winget install OpenJS.NodeJS
    pause
    exit /b 1
)

for /f "tokens=1 delims=v" %%i in ('node --version') do set "node_version=%%i"
echo Node.js !node_version! detected

REM Check npm
npm --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: npm is not installed
    pause
    exit /b 1
)

for /f %%i in ('npm --version') do set "npm_version=%%i"
echo npm !npm_version! detected

REM Check Git
git --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Warning: Git not found (optional but recommended)
    echo Install with: winget install Git.Git
) else (
    for /f "tokens=3" %%i in ('git --version') do set "git_version=%%i"
    echo Git !git_version! detected
)

REM Check Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    python3 --version >nul 2>&1
    if %errorLevel% neq 0 (
        echo Warning: Python not found (recommended for advanced exploits)
        echo Install with: winget install Python.Python.3
    ) else (
        for /f "tokens=2" %%i in ('python3 --version') do set "python_version=%%i"
        echo Python !python_version! detected
    )
) else (
    for /f "tokens=2" %%i in ('python --version') do set "python_version=%%i"
    echo Python !python_version! detected
)

REM Check PowerShell
powershell -Command "Get-Host" >nul 2>&1
if %errorLevel% neq 0 (
    echo Warning: PowerShell not accessible
) else (
    echo PowerShell detected
)

REM Check curl
curl --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Warning: curl not found (may limit some features)
) else (
    echo curl detected
)

REM Check nmap (if installed)
nmap --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Warning: nmap not found (recommended for network scanning)
    echo Download from: https://nmap.org/download.html
) else (
    echo nmap detected
)

REM Install optional Windows tools if administrator
if "%IS_ADMIN%"=="true" (
    echo.
    echo Checking for optional Windows tools...
    
    REM Check if winget is available
    winget --version >nul 2>&1
    if %errorLevel% == 0 (
        echo Windows Package Manager (winget) available
        
        REM Offer to install useful tools
        if "%1"=="--install-tools" (
            echo Installing recommended security tools...
            winget install --id Nmap.Nmap --silent --accept-source-agreements --accept-package-agreements
            winget install --id Wireshark.Wireshark --silent --accept-source-agreements --accept-package-agreements
            winget install --id voidtools.Everything --silent --accept-source-agreements --accept-package-agreements
        )
    ) else (
        echo Warning: Windows Package Manager not available
    )
)

REM Setup Scorpion
echo.
echo Setting up Scorpion Security Platform...

REM Install npm dependencies
echo Installing Node.js dependencies...
npm install
if %errorLevel% neq 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

REM Run setup script
echo Running platform setup...
npm run setup
if %errorLevel% neq 0 (
    echo ERROR: Setup failed
    pause
    exit /b 1
)

REM Create batch files for easy access
echo Creating Windows shortcuts...

REM Create scorpion.bat in the same directory
echo @echo off > scorpion.bat
echo cd /d "%%~dp0" >> scorpion.bat
echo node cli/scorpion.js %%* >> scorpion.bat

echo Created scorpion.bat launcher

REM Create desktop shortcut if requested
if "%1"=="--desktop-shortcut" (
    echo Creating desktop shortcut...
    powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\Scorpion Security Platform.lnk'); $Shortcut.TargetPath = 'cmd.exe'; $Shortcut.Arguments = '/k cd /d \"%CD%\" && npm run dev:full'; $Shortcut.WorkingDirectory = '%CD%'; $Shortcut.Save()"
    echo Created desktop shortcut
)

REM Add to PATH if administrator
if "%IS_ADMIN%"=="true" (
    echo Adding to system PATH...
    setx PATH "%PATH%;%CD%" /M >nul 2>&1
    if %errorLevel% == 0 (
        echo Added to system PATH
    ) else (
        echo Warning: Could not add to system PATH
    )
)

REM Run compatibility test
echo.
echo Running cross-platform compatibility test...
npm run test:platform
if %errorLevel% neq 0 (
    echo Warning: Compatibility test had issues, but installation may still work
)

REM Final success message
echo.
echo ===============================================================
echo  INSTALLATION COMPLETED SUCCESSFULLY!
echo ===============================================================
echo.
echo Quick Start Commands:
echo   npm run cli -- help                    # Show CLI help
echo   npm run cli -- help-advanced           # Show advanced features  
echo   npm run scan -- --target example.com   # Basic vulnerability scan
echo   npm run server                         # Start web interface
echo   npm run dev:full                       # Start development mode
echo.
echo Windows Shortcuts:
echo   scorpion.bat help                      # Show help
echo   scorpion.bat scan --target example.com # Run scan
echo.
if "%IS_ADMIN%"=="true" (
    echo Global Command (restart CMD to use):
    echo   scorpion help                       # Show help anywhere
    echo.
)
echo WARNING: Only use on authorized systems!
echo ===============================================================

REM Keep window open
if "%1" neq "--silent" (
    echo.
    echo Press any key to continue...
    pause >nul
)

endlocal
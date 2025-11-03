@echo off
REM Install Scorpion as Windows Service using PM2

echo 🔧 Installing Scorpion as Windows Service...

REM Check if PM2 is installed
pm2 --version >nul 2>&1
if errorlevel 1 (
    echo 📦 Installing PM2...
    npm install -g pm2
    npm install -g pm2-windows-service
)

REM Stop existing service
pm2 stop scorpion >nul 2>&1
pm2 delete scorpion >nul 2>&1

REM Start Scorpion with PM2
echo 🚀 Starting Scorpion service...
pm2 start server/simple-web-server.js --name scorpion

REM Install PM2 as Windows service
pm2-service-install -n "Scorpion Security Platform"

echo ✅ Service installed successfully!
echo 🔧 Service commands:
echo    pm2 status scorpion     # Check status
echo    pm2 logs scorpion       # View logs
echo    pm2 restart scorpion    # Restart service
echo    pm2 stop scorpion       # Stop service

pause
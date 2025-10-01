@echo off
echo 🦂 Starting Scorpion Security Platform...
echo.

echo Starting API Server...
start "Scorpion API Server" cmd /k "cd /d %~dp0 && npm run server"

echo Waiting for server to start...
timeout /t 3 /nobreak >nul

echo Starting Web Interface...
start "Scorpion Web Interface" cmd /k "cd /d %~dp0 && npm run dev"

echo.
echo 🌐 Platform starting up...
echo.
echo API Server: http://localhost:3001
echo Web Interface: http://localhost:5173
echo.
echo Press any key to close this window...
pause >nul
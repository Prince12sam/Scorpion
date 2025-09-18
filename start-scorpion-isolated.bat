@echo off
title Scorpion Security Platform
echo ==========================================
echo    Scorpion Security Platform Server
echo ==========================================
echo.
echo Starting servers...
echo Frontend: http://localhost:5173
echo Backend API: http://localhost:3001
echo.
echo Press Ctrl+C to stop all servers
echo ==========================================
echo.

cd /d "%~dp0"
npm run dev:full

pause
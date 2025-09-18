@echo off
echo.
echo ========================================
echo   SCORPION SECURITY PLATFORM LAUNCHER
echo ========================================
echo.
echo Starting Scorpion Security Platform...
echo Frontend: http://localhost:5173/
echo Backend:  http://localhost:3001/
echo.
echo Press Ctrl+C to stop both servers
echo.

REM Start the development servers
npm run dev:full

echo.
echo Servers stopped.
pause
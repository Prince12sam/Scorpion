@echo off
echo Starting Scorpion Platform (Fast Mode)...
echo.

echo Backend starting on http://localhost:3001
echo Frontend starting on http://localhost:5173
echo.

start "Frontend" npm run dev
timeout /t 2 /nobreak > nul
start "Backend" node server/quick-server.js

echo.
echo Platform is starting...
echo Open http://localhost:5173 in your browser
echo.
pause
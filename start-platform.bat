@echo off
echo Starting Scorpion Security Platform...
echo.
echo Frontend: http://localhost:5173
echo Backend API: http://localhost:3001
echo.

start /b cmd /c "npm run dev"
timeout /t 3 /nobreak >nul

start /b cmd /c "npm run server"
timeout /t 3 /nobreak >nul

echo.
echo Both servers are starting...
echo Press any key to test the API...
pause >nul

echo.
echo Testing API endpoint...
curl -X POST -H "Content-Type: application/json" -d "{\"target\":\"example.com\"}" http://localhost:3001/api/scanner/scan

echo.
echo Testing completed. Press any key to continue...
pause >nul
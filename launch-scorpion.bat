@echo off
echo Starting Scorpion Security Platform in isolated window...
echo.
echo Servers will run in a separate window to prevent interference.
echo Close the server window to stop the application.
echo.

start "Scorpion Server" cmd /k "cd /d "%~dp0" && start-scorpion-isolated.bat"

echo.
echo Server window opened. You can now run other commands safely.
echo To stop the servers, close the "Scorpion Server" window.
echo.
pause
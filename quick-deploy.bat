@echo off
REM Scorpion Security Platform - Quick Docker Deployment for Windows

echo 🦂 Starting Scorpion Security Platform Docker Deployment...

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

REM Stop existing containers
echo 🛑 Stopping existing containers...
docker-compose down -v >nul 2>&1

REM Build and start the application
echo 🔨 Building Scorpion Security Platform...
docker-compose up --build -d

REM Wait for the application to start
echo ⏳ Waiting for application to start...
timeout /t 10 /nobreak >nul

REM Health check
echo 🔍 Checking application health...
curl -f http://localhost:3001/api/health >nul 2>&1
if %errorlevel%==0 (
    echo ✅ Scorpion Security Platform is running successfully!
    echo 🌐 Web Interface: http://localhost:3001
    echo 👤 Login: admin / admin
    echo 📊 API Docs: http://localhost:3001/api/health
    echo.
    echo 🔧 Useful commands:
    echo   View logs: docker-compose logs -f
    echo   Stop: docker-compose down
    echo   Restart: docker-compose restart
) else (
    echo ❌ Application failed to start properly
    echo 📝 Check logs with: docker-compose logs
    pause
    exit /b 1
)

pause
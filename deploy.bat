@echo off
REM Scorpion Security Platform - Windows Docker Deployment Script

echo 🦂 Scorpion Security Platform - Docker Deployment
echo =================================================

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not running. Please start Docker and try again.
    pause
    exit /b 1
)

REM Check if Docker Compose is available
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose and try again.
    pause
    exit /b 1
)

REM Create necessary directories
echo 📁 Creating directories...
if not exist "results" mkdir results
if not exist "reports" mkdir reports
if not exist "logs" mkdir logs
if not exist "ssl" mkdir ssl

REM Generate self-signed SSL certificates if they don't exist
if not exist "ssl\cert.pem" (
    echo 🔐 Generating self-signed SSL certificates...
    openssl req -newkey rsa:2048 -nodes -keyout ssl\key.pem -x509 -days 365 -out ssl\cert.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
)

REM Build and start services
echo 🚀 Building and starting Scorpion services...
docker-compose down --remove-orphans
docker-compose build --no-cache
docker-compose up -d

REM Wait for services to be ready
echo ⏳ Waiting for services to be ready...
timeout /t 10 /nobreak >nul

REM Check health status
echo 🏥 Checking service health...
docker-compose ps

REM Show access information
echo.
echo ✅ Scorpion Security Platform is now running!
echo =================================================
echo 🌐 Web Interface: https://localhost (HTTP redirects to HTTPS)
echo 🔒 Direct HTTPS: https://localhost:443
echo 📊 API Health: https://localhost/api/health
echo 🔌 WebSocket: wss://localhost/ws
echo.
echo 🔑 Default Credentials:
echo    Username: admin
echo    Password: admin
echo.
echo 📋 Management Commands:
echo    View logs: docker-compose logs -f
echo    Stop: docker-compose down
echo    Restart: docker-compose restart
echo    Update: deploy.bat
echo.
echo ⚠️  Note: Using self-signed certificates. Add security exception in browser.
pause
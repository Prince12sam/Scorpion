# Scorpion Security Platform - Docker Setup for Windows
# Run this script in PowerShell as Administrator

Write-Host "🦂 Scorpion Security Platform - Windows Docker Setup" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "❌ This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check if Docker is installed
$dockerInstalled = Get-Command docker -ErrorAction SilentlyContinue

if (-not $dockerInstalled) {
    Write-Host "⚠️  Docker not found. Please install Docker Desktop first:" -ForegroundColor Yellow
    Write-Host "   https://www.docker.com/products/docker-desktop" -ForegroundColor Cyan
    Write-Host ""
    
    $install = Read-Host "Would you like to install Docker Desktop via Chocolatey? (y/n)"
    if ($install -eq 'y') {
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Host "📦 Installing Chocolatey..." -ForegroundColor Green
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        
        Write-Host "📦 Installing Docker Desktop..." -ForegroundColor Green
        choco install docker-desktop -y
        
        Write-Host "⚠️  Please restart your computer and run this script again" -ForegroundColor Yellow
        exit 0
    } else {
        exit 1
    }
} else {
    Write-Host "✓ Docker already installed" -ForegroundColor Green
}

# Verify Docker is running
$dockerRunning = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Docker is not running. Starting Docker Desktop..." -ForegroundColor Yellow
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    Write-Host "⏳ Waiting for Docker to start (this may take a minute)..." -ForegroundColor Yellow
    
    $timeout = 60
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        Start-Sleep -Seconds 5
        $elapsed += 5
        $dockerRunning = docker info 2>&1
        if ($LASTEXITCODE -eq 0) {
            break
        }
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to start Docker. Please start Docker Desktop manually" -ForegroundColor Red
        exit 1
    }
}

Write-Host "✓ Docker is running" -ForegroundColor Green
Write-Host ""

# Display Docker version
Write-Host "🔍 Docker Version:" -ForegroundColor Cyan
docker --version
docker compose version
Write-Host ""

# Build Scorpion image
Write-Host "🔨 Building Scorpion Security Platform..." -ForegroundColor Green
docker build -t scorpion-security:latest .

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Build successful!" -ForegroundColor Green
Write-Host ""

# Stop and remove existing container if present
$existing = docker ps -a --filter "name=scorpion" --format "{{.Names}}"
if ($existing -eq "scorpion") {
    Write-Host "🛑 Stopping and removing existing container..." -ForegroundColor Yellow
    docker stop scorpion | Out-Null
    docker rm scorpion | Out-Null
}

# Create data directories
$dataPath = "$PSScriptRoot\docker-data"
$directories = @("logs", "reports", "results")
foreach ($dir in $directories) {
    $fullPath = Join-Path $dataPath $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    }
}

# Run Scorpion container
Write-Host "🚀 Starting Scorpion container..." -ForegroundColor Green
docker run -d `
    --name scorpion `
    -p 3001:3001 `
    -v "${dataPath}\logs:/app/logs" `
    -v "${dataPath}\reports:/app/reports" `
    -v "${dataPath}\results:/app/results" `
    --restart unless-stopped `
    scorpion-security:latest

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to start container" -ForegroundColor Red
    exit 1
}

# Wait for container to start
Write-Host "⏳ Waiting for container to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Check if container is running
$running = docker ps --filter "name=scorpion" --format "{{.Names}}"
if ($running -eq "scorpion") {
    Write-Host ""
    Write-Host "✅ Scorpion Security Platform is running!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📍 Access Points:" -ForegroundColor Cyan
    Write-Host "   API Server: http://localhost:3001" -ForegroundColor White
    Write-Host "   Health Check: http://localhost:3001/api/health" -ForegroundColor White
    Write-Host ""
    Write-Host "🔐 Default Credentials:" -ForegroundColor Cyan
    Write-Host "   Username: admin" -ForegroundColor White
    Write-Host "   Password: admin" -ForegroundColor White
    Write-Host ""
    Write-Host "💾 Data Location:" -ForegroundColor Cyan
    Write-Host "   $dataPath" -ForegroundColor White
    Write-Host ""
    Write-Host "📋 Useful Commands:" -ForegroundColor Cyan
    Write-Host "   View logs:     docker logs -f scorpion" -ForegroundColor White
    Write-Host "   Stop:          docker stop scorpion" -ForegroundColor White
    Write-Host "   Start:         docker start scorpion" -ForegroundColor White
    Write-Host "   Restart:       docker restart scorpion" -ForegroundColor White
    Write-Host "   Remove:        docker rm -f scorpion" -ForegroundColor White
    Write-Host "   Shell access:  docker exec -it scorpion /bin/sh" -ForegroundColor White
    Write-Host ""
    
    # Open browser
    $openBrowser = Read-Host "Would you like to open the application in your browser? (y/n)"
    if ($openBrowser -eq 'y') {
        Start-Process "http://localhost:3001"
    }
} else {
    Write-Host "❌ Failed to start container" -ForegroundColor Red
    Write-Host "Logs:" -ForegroundColor Yellow
    docker logs scorpion
    exit 1
}

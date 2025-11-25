# Docker Quick Start Guide for Scorpion Security Platform

## Supported Platforms
- ✅ Linux (Ubuntu, Debian, CentOS, RHEL, Alpine, Arch, Fedora, etc.)
- ✅ macOS (Intel & Apple Silicon M1/M2)
- ✅ Windows (WSL2, Docker Desktop, Windows Containers)
- ✅ ARM64 & AMD64 architectures

## Prerequisites

### Linux
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install docker.io docker-compose

# CentOS/RHEL
sudo yum install docker docker-compose

# Arch Linux
sudo pacman -S docker docker-compose

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### macOS
```bash
# Install Docker Desktop from: https://www.docker.com/products/docker-desktop
# Or use Homebrew:
brew install --cask docker
```

### Windows
```powershell
# Install Docker Desktop from: https://www.docker.com/products/docker-desktop
# Or use Chocolatey:
choco install docker-desktop

# For Windows Containers (optional):
Enable-WindowsOptionalFeature -Online -FeatureName containers -All
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

## Quick Start

### Option 1: Docker Compose (Recommended)
```bash
# Clone repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# Build and start all services
docker-compose up -d

# Access the application
# API: http://localhost:3001
# Web: http://localhost:8080

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Option 2: Docker Build & Run (Linux/macOS)
```bash
# Build image
docker build -t scorpion-security:latest .

# Run container
docker run -d \
  --name scorpion \
  -p 3001:3001 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/results:/app/results \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  scorpion-security:latest

# View logs
docker logs -f scorpion

# Stop container
docker stop scorpion
docker rm scorpion
```

### Option 3: Docker Build & Run (Windows PowerShell)
```powershell
# Build image
docker build -t scorpion-security:latest .

# Run container
docker run -d `
  --name scorpion `
  -p 3001:3001 `
  -v ${PWD}/logs:/app/logs `
  -v ${PWD}/reports:/app/reports `
  -v ${PWD}/results:/app/results `
  --cap-add=NET_ADMIN `
  --cap-add=NET_RAW `
  scorpion-security:latest

# View logs
docker logs -f scorpion
```

### Option 4: Windows Containers (Windows Server)
```powershell
# Build Windows container
docker build -f Dockerfile.windows -t scorpion-security:windows .

# Run Windows container
docker run -d `
  --name scorpion-windows `
  -p 3001:3001 `
  -v C:\ScorpionData\logs:C:\app\logs `
  -v C:\ScorpionData\reports:C:\app\reports `
  scorpion-security:windows
```

## Environment Variables
Create a `.env` file or pass environment variables:

```bash
# Authentication
EASY_LOGIN=true
SCORPION_ADMIN_USER=admin
SCORPION_ADMIN_PASSWORD=your_secure_password

# API Keys (optional)
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here

# Security
JWT_SECRET=your_random_secret_key_here
NODE_ENV=production
```

## Docker Commands Reference

### Build
```bash
# Standard build
docker build -t scorpion-security:latest .

# Build for specific platform
docker build --platform linux/amd64 -t scorpion-security:amd64 .
docker build --platform linux/arm64 -t scorpion-security:arm64 .

# Build Windows container
docker build -f Dockerfile.windows -t scorpion-security:windows .
```

### Run with Environment File
```bash
docker run -d \
  --name scorpion \
  --env-file .env \
  -p 3001:3001 \
  scorpion-security:latest
```

### Volume Management
```bash
# Create named volumes
docker volume create scorpion-logs
docker volume create scorpion-reports
docker volume create scorpion-results

# Run with named volumes
docker run -d \
  --name scorpion \
  -p 3001:3001 \
  -v scorpion-logs:/app/logs \
  -v scorpion-reports:/app/reports \
  -v scorpion-results:/app/results \
  scorpion-security:latest
```

### Container Management
```bash
# Start/Stop
docker start scorpion
docker stop scorpion
docker restart scorpion

# Remove
docker rm scorpion
docker rmi scorpion-security:latest

# Execute commands inside container
docker exec -it scorpion /bin/bash
docker exec -it scorpion node cli/scorpion.js --help

# View logs
docker logs scorpion
docker logs -f --tail 100 scorpion
```

### Health Check
```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' scorpion

# Manual health check
curl http://localhost:3001/api/health
```

## Multi-Architecture Builds

### Using Docker Buildx
```bash
# Create builder
docker buildx create --name scorpion-builder --use

# Build for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t prince12sam/scorpion-security:latest \
  --push .
```

## Distribution-Specific Notes

### Alpine Linux
```bash
# Already using Alpine base image - no changes needed
docker build -t scorpion-security:alpine .
```

### Ubuntu/Debian Base (if preferred)
Create `Dockerfile.ubuntu`:
```dockerfile
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y \
    nmap curl wget openssl git python3 \
    && rm -rf /var/lib/apt/lists/*
# ... rest of Dockerfile
```

### CentOS/RHEL Base
Create `Dockerfile.centos`:
```dockerfile
FROM node:22
RUN yum install -y nmap curl wget openssl git python3 \
    && yum clean all
# ... rest of Dockerfile
```

## Troubleshooting

### Permission Issues (Linux)
```bash
# Fix volume permissions
sudo chown -R 1001:1001 logs reports results

# Or run container as root (not recommended)
docker run --user root ...
```

### Network Issues
```bash
# Use host network mode
docker run --network host ...

# Check if ports are available
netstat -tuln | grep -E '3001|5173'
```

### Windows WSL2 Issues
```powershell
# Restart WSL
wsl --shutdown

# Convert Docker Desktop to WSL2
wsl --set-default-version 2
```

## Production Deployment

### Using Docker Swarm
```bash
docker swarm init
docker stack deploy -c docker-compose.yml scorpion
```

### Using Kubernetes
```bash
# Generate Kubernetes manifests
kompose convert -f docker-compose.yml

# Deploy to Kubernetes
kubectl apply -f scorpion-deployment.yaml
kubectl apply -f scorpion-service.yaml
```

## Security Hardening

### Run with Security Options
```bash
docker run -d \
  --name scorpion \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --read-only \
  --tmpfs /tmp \
  scorpion-security:latest
```

### Use Docker Secrets (Swarm)
```bash
echo "my_secret_password" | docker secret create scorpion_admin_pass -
docker service create \
  --name scorpion \
  --secret scorpion_admin_pass \
  scorpion-security:latest
```

## Support
- GitHub: https://github.com/Prince12sam/Scorpion
- Issues: https://github.com/Prince12sam/Scorpion/issues
- Docker Hub: https://hub.docker.com/r/prince12sam/scorpion-security

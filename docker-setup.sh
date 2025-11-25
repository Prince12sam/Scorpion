#!/bin/bash
# Quick Docker Setup Script for Scorpion Security Platform
# Supports: Ubuntu, Debian, CentOS, RHEL, Fedora, Arch Linux, Alpine

set -e

echo "🦂 Scorpion Security Platform - Docker Setup"
echo "=============================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "❌ Cannot detect OS"
    exit 1
fi

echo "✓ Detected OS: $OS $VERSION"

# Install Docker based on OS
install_docker() {
    case "$OS" in
        ubuntu|debian)
            echo "📦 Installing Docker on Ubuntu/Debian..."
            sudo apt-get update
            sudo apt-get install -y ca-certificates curl gnupg
            sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            sudo chmod a+r /etc/apt/keyrings/docker.gpg
            echo \
              "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
              $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
              sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        
        centos|rhel|fedora)
            echo "📦 Installing Docker on CentOS/RHEL/Fedora..."
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        
        arch|manjaro)
            echo "📦 Installing Docker on Arch Linux..."
            sudo pacman -Sy --noconfirm docker docker-compose
            ;;
        
        alpine)
            echo "📦 Installing Docker on Alpine Linux..."
            sudo apk add --no-cache docker docker-compose
            ;;
        
        *)
            echo "❌ Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker not found. Installing..."
    install_docker
else
    echo "✓ Docker already installed"
fi

# Start and enable Docker
echo "🚀 Starting Docker service..."
sudo systemctl start docker 2>/dev/null || sudo service docker start 2>/dev/null || true
sudo systemctl enable docker 2>/dev/null || true

# Add current user to docker group
if ! groups $USER | grep -q '\bdocker\b'; then
    echo "👤 Adding $USER to docker group..."
    sudo usermod -aG docker $USER
    echo "⚠️  You need to log out and back in for group changes to take effect"
fi

# Verify Docker installation
echo ""
echo "🔍 Verifying Docker installation..."
if docker --version && docker compose version; then
    echo "✓ Docker installed successfully!"
else
    echo "❌ Docker installation verification failed"
    exit 1
fi

# Build and run Scorpion
echo ""
echo "🔨 Building Scorpion Security Platform..."
docker build -t scorpion-security:latest .

echo ""
echo "🚀 Starting Scorpion container..."
docker run -d \
    --name scorpion \
    -p 3001:3001 \
    -v $(pwd)/logs:/app/logs \
    -v $(pwd)/reports:/app/reports \
    -v $(pwd)/results:/app/results \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --restart unless-stopped \
    scorpion-security:latest

# Wait for container to start
echo "⏳ Waiting for container to start..."
sleep 5

# Check if container is running
if docker ps | grep -q scorpion; then
    echo ""
    echo "✅ Scorpion Security Platform is running!"
    echo ""
    echo "📍 Access Points:"
    echo "   API Server: http://localhost:3001"
    echo "   Health Check: http://localhost:3001/api/health"
    echo ""
    echo "🔐 Default Credentials:"
    echo "   Username: admin"
    echo "   Password: admin"
    echo ""
    echo "📋 Useful Commands:"
    echo "   View logs:     docker logs -f scorpion"
    echo "   Stop:          docker stop scorpion"
    echo "   Start:         docker start scorpion"
    echo "   Restart:       docker restart scorpion"
    echo "   Remove:        docker rm -f scorpion"
    echo "   Shell access:  docker exec -it scorpion /bin/sh"
    echo ""
else
    echo "❌ Failed to start container"
    echo "Logs:"
    docker logs scorpion
    exit 1
fi

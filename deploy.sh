#!/bin/bash

# Scorpion Security Platform - Docker Deployment Script

set -e

echo "🦂 Scorpion Security Platform - Docker Deployment"
echo "================================================="

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose >/dev/null 2>&1; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose and try again."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p ./results ./reports ./logs ./ssl

# Generate self-signed SSL certificates if they don't exist
if [ ! -f "./ssl/cert.pem" ] || [ ! -f "./ssl/key.pem" ]; then
    echo "🔐 Generating self-signed SSL certificates..."
    openssl req -newkey rsa:2048 -nodes -keyout ./ssl/key.pem -x509 -days 365 -out ./ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
fi

# Build and start services
echo "🚀 Building and starting Scorpion services..."
docker-compose down --remove-orphans
docker-compose build --no-cache
docker-compose up -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check health status
echo "🏥 Checking service health..."
docker-compose ps

# Show access information
echo ""
echo "✅ Scorpion Security Platform is now running!"
echo "================================================="
echo "🌐 Web Interface: https://localhost (HTTP redirects to HTTPS)"
echo "🔒 Direct HTTPS: https://localhost:443" 
echo "📊 API Health: https://localhost/api/health"
echo "🔌 WebSocket: wss://localhost/ws"
echo ""
echo "🔑 Default Credentials:"
echo "   Username: admin"
echo "   Password: admin"
echo ""
echo "📋 Management Commands:"
echo "   View logs: docker-compose logs -f"
echo "   Stop: docker-compose down"
echo "   Restart: docker-compose restart"
echo "   Update: ./deploy.sh"
echo ""
echo "⚠️  Note: Using self-signed certificates. Add security exception in browser."
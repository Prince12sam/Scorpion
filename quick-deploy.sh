#!/bin/bash

# Scorpion Security Platform - Quick Docker Deployment

echo "🦂 Starting Scorpion Security Platform Docker Deployment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Stop existing containers
echo "🛑 Stopping existing containers..."
docker-compose down -v 2>/dev/null || true

# Build and start the application
echo "🔨 Building Scorpion Security Platform..."
docker-compose up --build -d

# Wait for the application to start
echo "⏳ Waiting for application to start..."
sleep 10

# Health check
echo "🔍 Checking application health..."
if curl -f http://localhost:3001/api/health > /dev/null 2>&1; then
    echo "✅ Scorpion Security Platform is running successfully!"
    echo "🌐 Web Interface: http://localhost:3001"
    echo "👤 Login: admin / admin"
    echo "📊 API Docs: http://localhost:3001/api/health"
    echo ""
    echo "🔧 Useful commands:"
    echo "  View logs: docker-compose logs -f"
    echo "  Stop: docker-compose down"
    echo "  Restart: docker-compose restart"
else
    echo "❌ Application failed to start properly"
    echo "📝 Check logs with: docker-compose logs"
    exit 1
fi
#!/bin/bash

# Scorpion Security Platform - Unix Startup Script
echo "🦂 Starting Scorpion Security Platform..."
echo "========================================"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Please install Node.js first."
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Please run this script from the Scorpion directory"
    exit 1
fi

# Start the web server
echo "🌐 Starting web interface on http://localhost:3001"
echo "👤 Default login: admin / admin"
echo ""

node server/simple-web-server.js
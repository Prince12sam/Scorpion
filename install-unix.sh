#!/bin/bash

# Scorpion Security Platform - Unix Installation Script
echo "🦂 Scorpion Security Platform - Unix Installation"
echo "=============================================="
echo ""

# Check if running as root for system packages
if [ "$EUID" -eq 0 ]; then
    SUDO=""
    echo "✅ Running as root"
else
    SUDO="sudo"
    echo "ℹ️  Will use sudo for system packages"
fi

# Detect package manager and install system dependencies
if command -v apt &> /dev/null; then
    echo "📦 Installing dependencies with apt..."
    $SUDO apt update
    $SUDO apt install -y curl wget git openssl build-essential python3 python3-pip nmap
elif command -v yum &> /dev/null; then
    echo "📦 Installing dependencies with yum..."
    $SUDO yum install -y curl wget git openssl gcc gcc-c++ make python3 python3-pip nmap
elif command -v dnf &> /dev/null; then
    echo "📦 Installing dependencies with dnf..."
    $SUDO dnf install -y curl wget git openssl gcc gcc-c++ make python3 python3-pip nmap
elif command -v pacman &> /dev/null; then
    echo "📦 Installing dependencies with pacman..."
    $SUDO pacman -S --noconfirm curl wget git openssl base-devel python python-pip nmap
elif command -v zypper &> /dev/null; then
    echo "📦 Installing dependencies with zypper..."
    $SUDO zypper install -y curl wget git openssl gcc gcc-c++ make python3 python3-pip nmap
elif command -v brew &> /dev/null; then
    echo "📦 Installing dependencies with Homebrew..."
    brew install curl wget git openssl python3 nmap
else
    echo "⚠️  Unknown package manager. Please install dependencies manually:"
    echo "   - curl, wget, git, openssl, build tools, python3, nmap"
fi

# Install Node.js dependencies
echo "📦 Installing Node.js dependencies..."
npm install

# Build frontend
echo "🔨 Building frontend..."
npm run build

# Create directories
mkdir -p reports results logs

# Set permissions
chmod +x start-unix.sh
chmod +x *.sh

echo ""
echo "✅ Installation completed successfully!"
echo "🚀 Run ./start-unix.sh to launch the platform"
echo ""
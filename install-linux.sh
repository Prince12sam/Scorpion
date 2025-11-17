#!/bin/bash
# Scorpion Security Platform - Universal Linux Installer
# Supports: Ubuntu, Debian, CentOS, Fedora, Arch, Alpine, and other distros

set -e

echo "🦂 Scorpion Security Platform - Linux Installation"
echo "=================================================="

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MGR="apt-get"
    echo "✓ Detected Debian/Ubuntu (apt)"
elif command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
    echo "✓ Detected Fedora/RHEL 8+ (dnf)"
elif command -v yum &> /dev/null; then
    PKG_MGR="yum"
    echo "✓ Detected CentOS/RHEL (yum)"
elif command -v pacman &> /dev/null; then
    PKG_MGR="pacman"
    echo "✓ Detected Arch Linux (pacman)"
elif command -v apk &> /dev/null; then
    PKG_MGR="apk"
    echo "✓ Detected Alpine Linux (apk)"
elif command -v zypper &> /dev/null; then
    PKG_MGR="zypper"
    echo "✓ Detected openSUSE (zypper)"
else
    echo "⚠️  Unknown package manager. Node.js must be installed manually."
    PKG_MGR="none"
fi

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "⚠️  Node.js not found. Installing..."
    
    case $PKG_MGR in
        apt-get)
            sudo apt-get update
            sudo apt-get install -y curl
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
            sudo apt-get install -y nodejs
            ;;
        dnf)
            sudo dnf install -y nodejs npm
            ;;
        yum)
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
            sudo yum install -y nodejs
            ;;
        pacman)
            sudo pacman -Sy --noconfirm nodejs npm
            ;;
        apk)
            sudo apk add --no-cache nodejs npm
            ;;
        zypper)
            sudo zypper install -y nodejs20
            ;;
        *)
            echo "❌ Please install Node.js 18+ manually from https://nodejs.org/"
            exit 1
            ;;
    esac
else
    echo "✓ Node.js found: $(node --version)"
fi

# Check npm
if ! command -v npm &> /dev/null; then
    echo "❌ npm not found. Please install Node.js with npm."
    exit 1
fi
echo "✓ npm found: $(npm --version)"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
npm install

# Setup environment
echo ""
echo "⚙️  Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✓ Created .env from .env.example"
fi

# Make scripts executable
chmod +x install-unix.sh 2>/dev/null || true
chmod +x start-scorpion.sh 2>/dev/null || true
chmod +x cli/scorpion.js 2>/dev/null || true

echo ""
echo "✅ Installation complete!"
echo ""
echo "Quick Start:"
echo "  ./start-scorpion.sh          # Start both API and Web UI"
echo "  npm run server               # Start API only"
echo "  npm run dev                  # Start Web UI only"
echo "  node cli/scorpion.js --help  # CLI help"
echo ""
echo "Default login: admin / admin (EASY_LOGIN=true in .env)"
echo "Web interface: http://localhost:5173"
echo "API server: http://localhost:3001"

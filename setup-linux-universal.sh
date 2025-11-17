#!/bin/bash

# Scorpion Security Platform - Universal Linux Setup
echo "🦂 Scorpion Security Platform - Linux Setup"
echo "==========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ️${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    SUDO=""
    print_warning "Running as root"
else
    SUDO="sudo"
    print_info "Will use sudo for system packages"
fi

# Check Node.js
echo "📋 Checking system requirements..."
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    print_status "Node.js found: $NODE_VERSION"
    
    # Check Node.js version (require 16+)
    NODE_MAJOR=$(echo $NODE_VERSION | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_MAJOR" -lt 16 ]; then
        print_error "Node.js version $NODE_VERSION is too old. Requires Node.js 16+"
        exit 1
    fi
else
    print_error "Node.js not found"
    echo "📥 Please install Node.js:"
    echo "   Ubuntu/Debian: curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs"
    echo "   CentOS/RHEL: curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash - && sudo yum install -y nodejs"
    echo "   Arch: sudo pacman -S nodejs npm"
    echo "   Or visit: https://nodejs.org/"
    exit 1
fi

# Check npm
if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    print_status "npm found: $NPM_VERSION"
else
    print_error "npm not found"
    exit 1
fi

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    print_info "Detected distribution: $PRETTY_NAME"
else
    DISTRO="unknown"
    print_warning "Could not detect Linux distribution"
fi

# Install system dependencies (optional, continues if fails)
echo ""
echo "📦 Installing system dependencies..."

install_with_apt() {
    print_info "Using apt package manager..."
    $SUDO apt update && $SUDO apt install -y curl wget git build-essential python3 python3-pip 2>/dev/null || print_warning "Some packages may have failed to install"
}

install_with_yum() {
    print_info "Using yum package manager..."
    $SUDO yum install -y curl wget git gcc gcc-c++ make python3 python3-pip 2>/dev/null || print_warning "Some packages may have failed to install"
}

install_with_dnf() {
    print_info "Using dnf package manager..."
    $SUDO dnf install -y curl wget git gcc gcc-c++ make python3 python3-pip 2>/dev/null || print_warning "Some packages may have failed to install"
}

install_with_pacman() {
    print_info "Using pacman package manager..."
    $SUDO pacman -S --noconfirm curl wget git base-devel python python-pip 2>/dev/null || print_warning "Some packages may have failed to install"
}

install_with_zypper() {
    print_info "Using zypper package manager..."
    $SUDO zypper install -y curl wget git gcc gcc-c++ make python3 python3-pip 2>/dev/null || print_warning "Some packages may have failed to install"
}

# Try to install system dependencies based on distribution
case $DISTRO in
    ubuntu|debian|mint)
        install_with_apt
        ;;
    centos|rhel|fedora)
        if command -v dnf &> /dev/null; then
            install_with_dnf
        else
            install_with_yum
        fi
        ;;
    arch|manjaro)
        install_with_pacman
        ;;
    opensuse*|suse)
        install_with_zypper
        ;;
    *)
        print_warning "Unknown distribution, skipping system package installation"
        print_info "You may need to manually install: curl, wget, git, build tools, python3"
        ;;
esac

# Install Node.js dependencies
echo ""
echo "📦 Installing Node.js dependencies..."
if npm install; then
    print_status "Dependencies installed successfully"
else
    print_error "Failed to install Node.js dependencies"
    exit 1
fi

# Build frontend
echo ""
echo "🔨 Building frontend..."
if npm run build; then
    print_status "Frontend built successfully"
else
    print_error "Failed to build frontend"
    exit 1
fi

# Create directories
echo ""
echo "📁 Creating directories..."
mkdir -p reports results logs
print_status "Directories created"

# Set permissions
chmod +x *.sh 2>/dev/null || true

# Create systemd service file (optional)
if [ -d "/etc/systemd/system" ] && [ "$EUID" -eq 0 ]; then
    echo ""
    echo "🔧 Creating systemd service..."
    
    cat > /etc/systemd/system/scorpion.service << EOF
[Unit]
Description=Scorpion Security Platform
After=network.target
Wants=network.target

[Service]
Type=simple
User=nobody
Group=nobody
WorkingDirectory=$(pwd)
Environment=NODE_ENV=production
Environment=PORT=3001
ExecStart=$(which node) server/simple-web-server.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_status "Systemd service created"
    print_info "Use: systemctl start scorpion"
    print_info "Auto-start: systemctl enable scorpion"
fi

echo ""
print_status "Setup completed successfully!"
echo ""
echo "🚀 To start Scorpion Security Platform:"
echo "   ./start-unix.sh"
echo "   Or: npm start"
echo ""
echo "🌐 Web Interface: http://localhost:3001"
echo "👤 Default Login: admin / admin"
echo ""
echo "📖 Documentation: README.md"
echo "🔧 Advanced setup: See DOCKER.md for containerization"
echo ""

# Test basic functionality
echo "🧪 Running basic functionality test..."
if node -e "console.log('Node.js working')"; then
    print_status "Basic test passed"
else
    print_warning "Basic test failed"
fi
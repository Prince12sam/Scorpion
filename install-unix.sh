#!/bin/bash

# Scorpion Security Platform - Unix/Linux/macOS Startup Script
# This script provides cross-platform support for Unix-like systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Platform detection
detect_platform() {
    local platform=$(uname -s)
    local arch=$(uname -m)
    
    case $platform in
        "Darwin")
            PLATFORM="macOS"
            PACKAGE_MANAGER="brew"
            ;;
        "Linux")
            PLATFORM="Linux"
            # Detect Linux distribution
            if command -v apt-get &> /dev/null; then
                PACKAGE_MANAGER="apt"
                DISTRO="Debian/Ubuntu"
            elif command -v yum &> /dev/null; then
                PACKAGE_MANAGER="yum"
                DISTRO="RedHat/CentOS"
            elif command -v dnf &> /dev/null; then
                PACKAGE_MANAGER="dnf"
                DISTRO="Fedora"
            elif command -v pacman &> /dev/null; then
                PACKAGE_MANAGER="pacman"
                DISTRO="Arch Linux"
            elif command -v apk &> /dev/null; then
                PACKAGE_MANAGER="apk"
                DISTRO="Alpine Linux"
            else
                PACKAGE_MANAGER="unknown"
                DISTRO="Unknown"
            fi
            ;;
        *)
            PLATFORM="Unknown"
            PACKAGE_MANAGER="unknown"
            ;;
    esac
    
    echo -e "${CYAN}Platform detected: ${YELLOW}$PLATFORM${NC}"
    echo -e "${CYAN}Architecture: ${YELLOW}$arch${NC}"
    if [ "$PLATFORM" = "Linux" ]; then
        echo -e "${CYAN}Distribution: ${YELLOW}$DISTRO${NC}"
        echo -e "${CYAN}Package Manager: ${YELLOW}$PACKAGE_MANAGER${NC}"
    fi
}

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        echo -e "${RED}❌ Node.js is not installed${NC}"
        echo -e "${YELLOW}Please install Node.js 18+ from https://nodejs.org/${NC}"
        exit 1
    fi
    
    local node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$node_version" -lt 18 ]; then
        echo -e "${RED}❌ Node.js version $node_version is too old${NC}"
        echo -e "${YELLOW}Please upgrade to Node.js 18+ from https://nodejs.org/${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Node.js $(node --version) detected${NC}"
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        echo -e "${RED}❌ npm is not installed${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ npm $(npm --version) detected${NC}"
    
    # Check git (optional but recommended)
    if command -v git &> /dev/null; then
        echo -e "${GREEN}✅ Git $(git --version | cut -d' ' -f3) detected${NC}"
    else
        echo -e "${YELLOW}⚠️  Git not found (optional but recommended)${NC}"
    fi
    
    # Check Python (for some exploits)
    if command -v python3 &> /dev/null; then
        echo -e "${GREEN}✅ Python $(python3 --version | cut -d' ' -f2) detected${NC}"
    elif command -v python &> /dev/null; then
        echo -e "${GREEN}✅ Python $(python --version | cut -d' ' -f2) detected${NC}"
    else
        echo -e "${YELLOW}⚠️  Python not found (recommended for advanced exploits)${NC}"
    fi
    
    # Check curl/wget
    if command -v curl &> /dev/null; then
        echo -e "${GREEN}✅ curl detected${NC}"
    elif command -v wget &> /dev/null; then
        echo -e "${GREEN}✅ wget detected${NC}"
    else
        echo -e "${YELLOW}⚠️  Neither curl nor wget found (may limit some features)${NC}"
    fi
    
    # Check netcat
    if command -v nc &> /dev/null; then
        echo -e "${GREEN}✅ netcat detected${NC}"
    else
        echo -e "${YELLOW}⚠️  netcat not found (recommended for reverse shells)${NC}"
    fi
}

# Install system dependencies
install_system_deps() {
    echo -e "${BLUE}📦 Installing system dependencies...${NC}"
    
    case $PACKAGE_MANAGER in
        "apt")
            echo -e "${CYAN}Using apt package manager...${NC}"
            sudo apt update
            sudo apt install -y curl wget netcat-openbsd nmap dnsutils
            ;;
        "yum")
            echo -e "${CYAN}Using yum package manager...${NC}"
            sudo yum update -y
            sudo yum install -y curl wget nc nmap bind-utils
            ;;
        "dnf")
            echo -e "${CYAN}Using dnf package manager...${NC}"
            sudo dnf update -y
            sudo dnf install -y curl wget nc nmap bind-utils
            ;;
        "pacman")
            echo -e "${CYAN}Using pacman package manager...${NC}"
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm curl wget netcat nmap bind-tools
            ;;
        "apk")
            echo -e "${CYAN}Using apk package manager...${NC}"
            sudo apk update
            sudo apk add curl wget netcat-openbsd nmap bind-tools
            ;;
        "brew")
            echo -e "${CYAN}Using Homebrew package manager...${NC}"
            brew update
            brew install curl wget netcat nmap bind
            ;;
        *)
            echo -e "${YELLOW}⚠️  Unknown package manager, skipping system dependencies${NC}"
            ;;
    esac
}

# Setup Scorpion
setup_scorpion() {
    echo -e "${BLUE}🦂 Setting up Scorpion Security Platform...${NC}"
    
    # Install npm dependencies
    echo -e "${CYAN}Installing Node.js dependencies...${NC}"
    npm install
    
    # Run setup script
    echo -e "${CYAN}Running platform setup...${NC}"
    npm run setup
    
    # Create symlinks or aliases
    echo -e "${CYAN}Creating command aliases...${NC}"
    
    # For bash users
    if [ -f "$HOME/.bashrc" ]; then
        if ! grep -q "alias scorpion=" "$HOME/.bashrc"; then
            echo "alias scorpion='node $(pwd)/cli/scorpion.js'" >> "$HOME/.bashrc"
            echo -e "${GREEN}✅ Added scorpion alias to ~/.bashrc${NC}"
        fi
    fi
    
    # For zsh users (macOS default)
    if [ -f "$HOME/.zshrc" ]; then
        if ! grep -q "alias scorpion=" "$HOME/.zshrc"; then
            echo "alias scorpion='node $(pwd)/cli/scorpion.js'" >> "$HOME/.zshrc"
            echo -e "${GREEN}✅ Added scorpion alias to ~/.zshrc${NC}"
        fi
    fi
    
    # Create desktop entry for Linux
    if [ "$PLATFORM" = "Linux" ] && [ -d "$HOME/.local/share/applications" ]; then
        cat > "$HOME/.local/share/applications/scorpion.desktop" << EOF
[Desktop Entry]
Name=Scorpion Security Platform
Comment=Global Threat-Hunting Platform
Exec=gnome-terminal -- bash -c "cd $(pwd) && npm run dev:full; exec bash"
Icon=$(pwd)/public/scorpion-icon.png
Terminal=true
Type=Application
Categories=Development;Security;
EOF
        echo -e "${GREEN}✅ Created desktop entry${NC}"
    fi
}

# Run platform compatibility test
run_compatibility_test() {
    echo -e "${BLUE}🧪 Running cross-platform compatibility test...${NC}"
    npm run test:platform
}

# Main execution
main() {
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  ███████╗ ██████╗ ██████╗ ██████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗  ║"
    echo "║  ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║██╔═══██╗████╗  ██║  ║"
    echo "║  ███████╗██║     ██║   ██║██████╔╝██████╔╝██║██║   ██║██╔██╗ ██║  ║"
    echo "║  ╚════██║██║     ██║   ██║██╔══██╗██╔═══╝ ██║██║   ██║██║╚██╗██║  ║"
    echo "║  ███████║╚██████╗╚██████╔╝██║  ██║██║     ██║╚██████╔╝██║ ╚████║  ║"
    echo "║  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  ║"
    echo "║                                                               ║"
    echo "║            Global Threat-Hunting Platform                    ║"
    echo "║                Unix/Linux/macOS Installer                    ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    detect_platform
    check_prerequisites
    
    if [ "$1" = "--install-deps" ] || [ "$1" = "-i" ]; then
        install_system_deps
    fi
    
    setup_scorpion
    run_compatibility_test
    
    echo -e "${GREEN}"
    echo "✅ Scorpion Security Platform installed successfully!"
    echo ""
    echo "🚀 Quick Start Commands:"
    echo "  npm run cli -- help                    # Show CLI help"
    echo "  npm run cli -- help-advanced           # Show advanced features"
    echo "  npm run scan -- --target example.com   # Basic vulnerability scan"
    echo "  npm run server                         # Start web interface"
    echo "  npm run dev:full                       # Start development mode"
    echo ""
    echo "💡 Command Aliases (restart terminal to use):"
    echo "  scorpion help                          # Show help"
    echo "  scorpion scan --target example.com     # Run scan"
    echo ""
    echo "⚠️  IMPORTANT: Only use on authorized systems!"
    echo -e "${NC}"
}

# Handle command line arguments
case "$1" in
    "--help"|"-h")
        echo "Scorpion Security Platform - Unix/Linux/macOS Installer"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --install-deps, -i    Install system dependencies"
        echo "  --help, -h           Show this help message"
        echo ""
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
#!/bin/bash
# Scorpion CLI Installation Script

echo "🦂 Scorpion CLI Security Tool - Installation"
echo "=============================================="
echo ""

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed!"
    echo "Please install Python 3.10 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo "❌ Python version must be 3.10 or higher!"
    echo "Current version: $PYTHON_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv .venv
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment!"
        exit 1
    fi
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

echo ""
echo "🔧 Activating virtual environment..."

# Activate virtual environment
source .venv/bin/activate

if [ $? -ne 0 ]; then
    echo "❌ Failed to activate virtual environment!"
    exit 1
fi

echo "✅ Virtual environment activated"
echo ""

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install Scorpion CLI
echo "📦 Installing Scorpion CLI..."
pip install -e tools/python_scorpion

if [ $? -ne 0 ]; then
    echo "❌ Failed to install Scorpion CLI!"
    echo ""
    echo "⚠️  If you see 'externally-managed-environment' error:"
    echo "   This means you're trying to install outside a virtual environment."
    echo "   The script already created and activated a venv, but if it failed:"
    echo ""
    echo "   Manual fix:"
    echo "   python3 -m venv .venv"
    echo "   source .venv/bin/activate"
    echo "   pip install -e tools/python_scorpion"
    exit 1
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 Quick Start:"
echo "   # Activate virtual environment (if not already active):"
echo "   source .venv/bin/activate"
echo ""
echo "   # Show help"
echo "   scorpion --help"
echo ""
echo "   # Basic scanning"
echo "   scorpion scan -t example.com --web"
echo ""
echo "   # Advanced scanning (requires root)"
echo "   sudo -E env PATH=\$PATH scorpion scan -t example.com --syn --web"
echo ""
echo "📖 For full documentation, see:"
echo "   - README.md"
echo "   - INSTALL_LINUX.md (Linux-specific guide)"
echo "   - INSTALL_PARROT_OS.md (Parrot OS-specific guide)"
echo ""
echo "⚠️  Remember: To use scorpion after closing this terminal:"
echo "   source .venv/bin/activate"
echo ""

#!/bin/bash
# Scorpion CLI Installation Script

echo "🦂 Scorpion CLI Security Tool - Installation"
echo "=============================================="
echo ""

# Check Node.js installation
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed!"
    echo "Please install Node.js 16.0.0 or higher from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js version must be 16.0.0 or higher!"
    echo "Current version: $(node -v)"
    exit 1
fi

echo "✅ Node.js $(node -v) detected"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies!"
    exit 1
fi

echo ""
echo "🔗 Creating global symlink..."
npm link

if [ $? -ne 0 ]; then
    echo "⚠️  Failed to create global symlink. You may need to run with sudo:"
    echo "   sudo npm link"
    echo ""
    echo "Or use the tool locally with:"
    echo "   node cli/scorpion.js"
    exit 0
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 Quick Start:"
echo "   scorpion --help                    # Show help"
echo "   scorpion scan -t example.com       # Scan a target"
echo "   scorpion recon -t example.com      # Network reconnaissance"
echo ""
echo "📖 For full documentation, see README.md"
echo ""

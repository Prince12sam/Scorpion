#!/bin/bash
# ============================================
# Scorpion CLI - First Time Setup Script
# ============================================
# This script helps you configure Scorpion after cloning

echo "🦂 Welcome to Scorpion CLI Security Tool!"
echo "=========================================="
echo ""

# Check if .env exists
if [ -f ".env" ]; then
    echo "✅ .env file already exists"
else
    echo "📝 Creating .env file from template..."
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✅ Created .env file"
        echo ""
        echo "⚠️  IMPORTANT: Edit .env and add your API keys!"
        echo ""
        echo "Required for AI pentesting:"
        echo "  SCORPION_AI_API_KEY=sk-proj-your-key-here"
        echo ""
        echo "Get your OpenAI API key: https://platform.openai.com/api-keys"
        echo ""
        echo "Edit now? (opens nano)"
        read -p "Press Enter to edit, or Ctrl+C to skip: "
        nano .env
    else
        echo "❌ Error: .env.example not found"
        exit 1
    fi
fi

echo ""
echo "🎯 Quick Test Commands:"
echo "  scorpion --help               # Show all commands"
echo "  scorpion scan -t example.com --web   # Port scan"
echo "  scorpion recon -t example.com        # Reconnaissance"
echo ""
echo "📚 Documentation:"
echo "  README.md            # Overview and quick start"
echo "  API_KEY_SETUP.md     # Detailed API configuration"
echo "  GETTING_STARTED.md   # Step-by-step guide"
echo "  COMMANDS.md          # All available commands"
echo ""
echo "✅ Setup complete! Happy (ethical) hacking! 🦂"

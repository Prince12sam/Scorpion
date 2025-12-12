# ============================================
# Scorpion CLI - First Time Setup Script (Windows)
# ============================================
# This script helps you configure Scorpion after cloning

Write-Host "🦂 Welcome to Scorpion CLI Security Tool!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if .env exists
if (Test-Path ".env") {
    Write-Host "✅ .env file already exists" -ForegroundColor Green
} else {
    Write-Host "📝 Creating .env file from template..." -ForegroundColor Yellow
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "✅ Created .env file" -ForegroundColor Green
        Write-Host ""
        Write-Host "⚠️  IMPORTANT: Edit .env and add your API keys!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Required for AI pentesting:" -ForegroundColor White
        Write-Host "  SCORPION_AI_API_KEY=sk-proj-your-key-here" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Get your OpenAI API key: https://platform.openai.com/api-keys" -ForegroundColor White
        Write-Host ""
        $edit = Read-Host "Edit .env now? (y/n)"
        if ($edit -eq "y" -or $edit -eq "Y") {
            notepad .env
        }
    } else {
        Write-Host "❌ Error: .env.example not found" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "🎯 Quick Test Commands:" -ForegroundColor Cyan
Write-Host "  scorpion --help                      # Show all commands"
Write-Host "  scorpion scan -t example.com --web   # Port scan"
Write-Host "  scorpion recon -t example.com        # Reconnaissance"
Write-Host ""
Write-Host "📚 Documentation:" -ForegroundColor Cyan
Write-Host "  README.md            # Overview and quick start"
Write-Host "  API_KEY_SETUP.md     # Detailed API configuration"
Write-Host "  GETTING_STARTED.md   # Step-by-step guide"
Write-Host "  COMMANDS.md          # All available commands"
Write-Host ""
Write-Host "✅ Setup complete! Happy (ethical) hacking! 🦂" -ForegroundColor Green

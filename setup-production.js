#!/usr/bin/env node

/**
 * Scorpion Security Platform - Production Setup Script
 * Ensures all components are properly configured for GitHub release
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  🦂 SCORPION SECURITY PLATFORM - SETUP & VERIFICATION        ║
║                Professional Security Testing                 ║
╚═══════════════════════════════════════════════════════════════╝
`);

async function setupScorpion() {
  console.log('🔧 Setting up Scorpion Security Platform...\n');

  // Create necessary directories
  const directories = [
    'results',
    'reports', 
    'cli/results',
    'server/logs',
    'data/baselines'
  ];

  directories.forEach(dir => {
    const fullPath = path.join(__dirname, dir);
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true });
      console.log(`✅ Created directory: ${dir}`);
    }
  });

  // Create .env file if it doesn't exist
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) {
    const envContent = `# Scorpion Security Platform Configuration
NODE_ENV=production
PORT=3001
WEB_PORT=5173

# API Keys (Optional - Add your own)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# Security Settings
ENABLE_LOGGING=true
LOG_LEVEL=info
MAX_SCAN_TARGETS=100
RATE_LIMIT_ENABLED=true

# Web Interface
ENABLE_WEB_INTERFACE=true
ENABLE_REAL_TIME_ALERTS=true
`;
    fs.writeFileSync(envPath, envContent);
    console.log('✅ Created .env configuration file');
  }

  // Verify critical files exist
  const criticalFiles = [
    'cli/scorpion.js',
    'server/quick-server.js',
    'src/main.jsx',
    'package.json'
  ];

  let allFilesExist = true;
  criticalFiles.forEach(file => {
    const fullPath = path.join(__dirname, file);
    if (fs.existsSync(fullPath)) {
      console.log(`✅ Verified: ${file}`);
    } else {
      console.log(`❌ Missing: ${file}`);
      allFilesExist = false;
    }
  });

  // Create startup scripts for different platforms
  const startupScripts = {
    'start-scorpion.sh': `#!/bin/bash
# Scorpion Security Platform - Linux/macOS Startup Script
echo "🦂 Starting Scorpion Security Platform..."
npm run dev:full`,
    
    'start-scorpion.bat': `@echo off
REM Scorpion Security Platform - Windows Startup Script
echo 🦂 Starting Scorpion Security Platform...
npm run dev:full`,
    
    'start-scorpion.ps1': `# Scorpion Security Platform - PowerShell Startup Script
Write-Host "🦂 Starting Scorpion Security Platform..." -ForegroundColor Green
npm run dev:full`
  };

  Object.entries(startupScripts).forEach(([filename, content]) => {
    const scriptPath = path.join(__dirname, filename);
    fs.writeFileSync(scriptPath, content);
    console.log(`✅ Created startup script: ${filename}`);
  });

  console.log('\n🎉 Scorpion Security Platform setup completed successfully!\n');
  
  console.log('📖 Quick Start Commands:');
  console.log('  npm start              # Start full platform (web + API)');
  console.log('  npm run server         # Start API server only');
  console.log('  npm run dev            # Start web interface only');
  console.log('  npm run cli --help     # CLI help\n');
  
  console.log('🌐 Platform Access:');
  console.log('  Web Interface: http://localhost:5173');
  console.log('  API Server:    http://localhost:3001');
  console.log('  Health Check:  http://localhost:3001/api/health\n');
  
  if (allFilesExist) {
    console.log('✅ All systems ready - Platform is configured for production use!');
  } else {
    console.log('⚠️  Some files are missing - Please check the installation');
  }
}

setupScorpion().catch(console.error);
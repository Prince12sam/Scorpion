#!/usr/bin/env node

/**
 * Scorpion Cross-Platform System Detector and Installer
 * Automatically detects OS and installs appropriate dependencies
 */

import os from 'os';
import { execSync, spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

class CrossPlatformInstaller {
  constructor() {
    this.platform = os.platform();
    this.arch = os.arch();
    this.release = os.release();
    this.distro = null;
    this.packageManager = null;
    this.isAdmin = false;
    
    console.log('🦂 Scorpion Cross-Platform Installer');
    console.log('=====================================');
    this.detectSystem();
  }

  detectSystem() {
    console.log(`📊 System Information:`);
    console.log(`   Platform: ${this.platform}`);
    console.log(`   Architecture: ${this.arch}`);
    console.log(`   Release: ${this.release}`);
    console.log(`   Node.js: ${process.version}`);
    
    switch (this.platform) {
      case 'win32':
        this.detectWindows();
        break;
      case 'linux':
        this.detectLinux();
        break;
      case 'darwin':
        this.detectMacOS();
        break;
      default:
        console.warn(`⚠️  Unsupported platform: ${this.platform}`);
        console.log('🔄 Attempting generic Unix installation...');
        this.packageManager = 'generic';
    }
  }

  detectWindows() {
    console.log('🪟 Windows System Detected');
    
    // Check Windows version
    try {
      const version = execSync('ver', { encoding: 'utf8' });
      console.log(`   Version: ${version.trim()}`);
      
      // Check if running as administrator
      try {
        execSync('net session >nul 2>&1', { stdio: 'ignore' });
        this.isAdmin = true;
        console.log('   ✅ Running as Administrator');
      } catch {
        console.log('   ⚠️  Not running as Administrator');
      }
      
      // Detect package managers
      this.packageManager = this.detectWindowsPackageManager();
      
    } catch (error) {
      console.warn('   ⚠️  Could not detect Windows version');
    }
  }

  detectWindowsPackageManager() {
    const managers = [
      { name: 'chocolatey', cmd: 'choco --version', friendly: 'Chocolatey' },
      { name: 'winget', cmd: 'winget --version', friendly: 'Windows Package Manager' },
      { name: 'scoop', cmd: 'scoop --version', friendly: 'Scoop' }
    ];

    for (const manager of managers) {
      try {
        execSync(manager.cmd, { stdio: 'ignore' });
        console.log(`   ✅ ${manager.friendly} detected`);
        return manager.name;
      } catch {
        // Manager not found
      }
    }
    
    console.log('   ℹ️  No package manager detected, will use manual installation');
    return 'manual';
  }

  detectLinux() {
    console.log('🐧 Linux System Detected');
    
    // Detect Linux distribution
    this.distro = this.detectLinuxDistro();
    console.log(`   Distribution: ${this.distro}`);
    
    // Detect package manager
    this.packageManager = this.detectLinuxPackageManager();
    console.log(`   Package Manager: ${this.packageManager}`);
    
    // Check if running as root/sudo
    this.isAdmin = process.getuid() === 0;
    console.log(`   Root Access: ${this.isAdmin ? 'Yes' : 'No'}`);
  }

  detectLinuxDistro() {
    const distroFiles = [
      { file: '/etc/os-release', parser: this.parseOSRelease },
      { file: '/etc/lsb-release', parser: this.parseLSBRelease },
      { file: '/etc/redhat-release', parser: this.parseRedhatRelease },
      { file: '/etc/debian_version', parser: () => 'debian' }
    ];

    for (const { file, parser } of distroFiles) {
      if (fs.existsSync(file)) {
        try {
          const content = fs.readFileSync(file, 'utf8');
          return parser.call(this, content) || 'unknown';
        } catch {
          continue;
        }
      }
    }

    // Fallback to uname
    try {
      const uname = execSync('uname -a', { encoding: 'utf8' });
      if (uname.includes('Ubuntu')) return 'ubuntu';
      if (uname.includes('Debian')) return 'debian';
      if (uname.includes('CentOS')) return 'centos';
      if (uname.includes('Red Hat')) return 'rhel';
      if (uname.includes('Fedora')) return 'fedora';
      if (uname.includes('SUSE')) return 'suse';
      if (uname.includes('Arch')) return 'arch';
    } catch {
      // Fallback failed
    }

    return 'unknown';
  }

  parseOSRelease(content) {
    const lines = content.split('\n');
    for (const line of lines) {
      if (line.startsWith('ID=')) {
        return line.split('=')[1].replace(/"/g, '').toLowerCase();
      }
    }
    return null;
  }

  parseLSBRelease(content) {
    const lines = content.split('\n');
    for (const line of lines) {
      if (line.startsWith('DISTRIB_ID=')) {
        return line.split('=')[1].replace(/"/g, '').toLowerCase();
      }
    }
    return null;
  }

  parseRedhatRelease(content) {
    if (content.includes('CentOS')) return 'centos';
    if (content.includes('Red Hat')) return 'rhel';
    if (content.includes('Fedora')) return 'fedora';
    return 'redhat';
  }

  detectLinuxPackageManager() {
    const managers = [
      { name: 'apt', cmd: 'apt --version', distros: ['ubuntu', 'debian', 'mint'] },
      { name: 'yum', cmd: 'yum --version', distros: ['centos', 'rhel', 'fedora'] },
      { name: 'dnf', cmd: 'dnf --version', distros: ['fedora', 'centos'] },
      { name: 'pacman', cmd: 'pacman --version', distros: ['arch', 'manjaro'] },
      { name: 'zypper', cmd: 'zypper --version', distros: ['suse', 'opensuse'] },
      { name: 'apk', cmd: 'apk --version', distros: ['alpine'] },
      { name: 'portage', cmd: 'emerge --version', distros: ['gentoo'] }
    ];

    // First try distro-specific managers
    for (const manager of managers) {
      if (manager.distros.includes(this.distro)) {
        try {
          execSync(manager.cmd, { stdio: 'ignore' });
          return manager.name;
        } catch {
          continue;
        }
      }
    }

    // Fallback to any available manager
    for (const manager of managers) {
      try {
        execSync(manager.cmd, { stdio: 'ignore' });
        return manager.name;
      } catch {
        continue;
      }
    }

    return 'unknown';
  }

  detectMacOS() {
    console.log('🍎 macOS System Detected');
    
    try {
      const version = execSync('sw_vers -productVersion', { encoding: 'utf8' });
      console.log(`   Version: ${version.trim()}`);
      
      // Check for Homebrew
      try {
        execSync('brew --version', { stdio: 'ignore' });
        this.packageManager = 'brew';
        console.log('   ✅ Homebrew detected');
      } catch {
        console.log('   ⚠️  Homebrew not found');
        this.packageManager = 'manual';
      }
      
    } catch (error) {
      console.warn('   ⚠️  Could not detect macOS version');
    }
  }

  async installDependencies() {
    console.log('\n🔧 Installing System Dependencies...');
    
    const dependencies = {
      system: this.getSystemDependencies(),
      security: this.getSecurityTools(),
      optional: this.getOptionalTools()
    };

    for (const [category, deps] of Object.entries(dependencies)) {
      if (deps.length > 0) {
        console.log(`\n📦 Installing ${category} dependencies...`);
        await this.installPackages(deps, category);
      }
    }
  }

  getSystemDependencies() {
    const common = ['curl', 'wget', 'git', 'openssl'];
    
    switch (this.platform) {
      case 'win32':
        return ['git', 'openssl']; // curl/wget often pre-installed
      case 'linux':
        return [...common, 'build-essential', 'python3', 'python3-pip'];
      case 'darwin':
        return [...common, 'python3'];
      default:
        return common;
    }
  }

  getSecurityTools() {
    const tools = ['nmap'];
    
    // Add platform-specific security tools
    if (this.platform === 'linux') {
      tools.push('netcat', 'tcpdump', 'wireshark-common');
    }
    
    return tools;
  }

  getOptionalTools() {
    return ['masscan', 'sqlmap', 'john', 'hashcat'];
  }

  async installPackages(packages, category) {
    for (const pkg of packages) {
      try {
        console.log(`   Installing ${pkg}...`);
        await this.installSinglePackage(pkg);
        console.log(`   ✅ ${pkg} installed successfully`);
      } catch (error) {
        console.warn(`   ⚠️  Failed to install ${pkg}: ${error.message}`);
        if (category === 'system') {
          console.error(`   ❌ Critical dependency ${pkg} failed to install`);
        }
      }
    }
  }

  async installSinglePackage(packageName) {
    const commands = this.getInstallCommand(packageName);
    
    for (const cmd of commands) {
      try {
        execSync(cmd, { stdio: 'inherit' });
        return; // Success
      } catch (error) {
        // Try next command
        continue;
      }
    }
    
    throw new Error(`No install method succeeded for ${packageName}`);
  }

  getInstallCommand(packageName) {
    const commands = [];
    
    switch (this.platform) {
      case 'win32':
        if (this.packageManager === 'chocolatey') {
          commands.push(`choco install ${packageName} -y`);
        }
        if (this.packageManager === 'winget') {
          commands.push(`winget install ${packageName}`);
        }
        if (this.packageManager === 'scoop') {
          commands.push(`scoop install ${packageName}`);
        }
        break;
        
      case 'linux':
        const sudoPrefix = this.isAdmin ? '' : 'sudo ';
        
        switch (this.packageManager) {
          case 'apt':
            commands.push(`${sudoPrefix}apt update && ${sudoPrefix}apt install -y ${packageName}`);
            break;
          case 'yum':
            commands.push(`${sudoPrefix}yum install -y ${packageName}`);
            break;
          case 'dnf':
            commands.push(`${sudoPrefix}dnf install -y ${packageName}`);
            break;
          case 'pacman':
            commands.push(`${sudoPrefix}pacman -S --noconfirm ${packageName}`);
            break;
          case 'zypper':
            commands.push(`${sudoPrefix}zypper install -y ${packageName}`);
            break;
          case 'apk':
            commands.push(`${sudoPrefix}apk add ${packageName}`);
            break;
        }
        break;
        
      case 'darwin':
        if (this.packageManager === 'brew') {
          commands.push(`brew install ${packageName}`);
        }
        break;
    }
    
    return commands;
  }

  createPlatformScripts() {
    console.log('\n📝 Creating Platform-Specific Scripts...');
    
    // Create Windows batch files
    this.createWindowsScripts();
    
    // Create Linux/Unix shell scripts
    this.createUnixScripts();
    
    // Create systemd service files for Linux
    this.createSystemdService();
    
    // Create Windows service scripts
    this.createWindowsService();
  }

  createWindowsScripts() {
    const startScript = `@echo off
REM Scorpion Security Platform - Windows Startup Script
title Scorpion Security Platform

echo 🦂 Starting Scorpion Security Platform...
echo.

REM Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js not found. Please install Node.js first.
    pause
    exit /b 1
)

REM Start the web server
echo 🌐 Starting web interface on http://localhost:3001
echo 👤 Default login: admin / admin
echo.

cd /d "%~dp0"
node server/simple-web-server.js

pause`;

    fs.writeFileSync(path.join(__dirname, 'start-windows.bat'), startScript);

    const installScript = `@echo off
REM Scorpion Security Platform - Windows Installation Script
title Scorpion Installation

echo 🦂 Scorpion Security Platform - Windows Installation
echo ================================================
echo.

REM Check administrator privileges
net session >nul 2>&1
if not %errorlevel%==0 (
    echo ❌ This script requires administrator privileges
    echo    Right-click and "Run as administrator"
    pause
    exit /b 1
)

REM Install dependencies
echo 📦 Installing dependencies...
npm install

REM Build frontend
echo 🔨 Building frontend...
npm run build

REM Create directories
if not exist "reports" mkdir reports
if not exist "results" mkdir results
if not exist "logs" mkdir logs

echo.
echo ✅ Installation completed successfully!
echo 🚀 Run start-windows.bat to launch the platform
echo.
pause`;

    fs.writeFileSync(path.join(__dirname, 'install-windows.bat'), installScript);
  }

  createUnixScripts() {
    const startScript = `#!/bin/bash

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

node server/simple-web-server.js`;

    fs.writeFileSync(path.join(__dirname, 'start-unix.sh'), startScript);
    
    const installScript = `#!/bin/bash

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
echo ""`;

    fs.writeFileSync(path.join(__dirname, 'install-unix.sh'), installScript);
    
    // Make scripts executable
    try {
      execSync('chmod +x start-unix.sh install-unix.sh', { stdio: 'ignore' });
    } catch {
      // Ignore chmod errors on Windows
    }
  }

  createSystemdService() {
    const serviceFile = `[Unit]
Description=Scorpion Security Platform
After=network.target
Wants=network.target

[Service]
Type=simple
User=scorpion
Group=scorpion
WorkingDirectory=${__dirname}
Environment=NODE_ENV=production
Environment=PORT=3001
ExecStart=/usr/bin/node server/simple-web-server.js
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=scorpion

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${__dirname}/logs ${__dirname}/reports ${__dirname}/results

[Install]
WantedBy=multi-user.target`;

    fs.writeFileSync(path.join(__dirname, 'scorpion.service'), serviceFile);
    
    const installServiceScript = `#!/bin/bash

# Install Scorpion as a systemd service

if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

echo "🔧 Installing Scorpion systemd service..."

# Create scorpion user if it doesn't exist
if ! id "scorpion" &>/dev/null; then
    useradd -r -s /bin/false scorpion
    echo "✅ Created scorpion user"
fi

# Set ownership
chown -R scorpion:scorpion ${__dirname}

# Copy service file
cp scorpion.service /etc/systemd/system/
systemctl daemon-reload

echo "✅ Service installed. Use these commands:"
echo "   systemctl start scorpion    # Start service"
echo "   systemctl enable scorpion   # Auto-start on boot"
echo "   systemctl status scorpion   # Check status"
echo "   journalctl -u scorpion -f   # View logs"`;

    fs.writeFileSync(path.join(__dirname, 'install-service-linux.sh'), installServiceScript);
    
    try {
      execSync('chmod +x install-service-linux.sh', { stdio: 'ignore' });
    } catch {
      // Ignore on Windows
    }
  }

  createWindowsService() {
    const serviceScript = `@echo off
REM Install Scorpion as Windows Service using PM2

echo 🔧 Installing Scorpion as Windows Service...

REM Check if PM2 is installed
pm2 --version >nul 2>&1
if errorlevel 1 (
    echo 📦 Installing PM2...
    npm install -g pm2
    npm install -g pm2-windows-service
)

REM Stop existing service
pm2 stop scorpion >nul 2>&1
pm2 delete scorpion >nul 2>&1

REM Start Scorpion with PM2
echo 🚀 Starting Scorpion service...
pm2 start server/simple-web-server.js --name scorpion

REM Install PM2 as Windows service
pm2-service-install -n "Scorpion Security Platform"

echo ✅ Service installed successfully!
echo 🔧 Service commands:
echo    pm2 status scorpion     # Check status
echo    pm2 logs scorpion       # View logs
echo    pm2 restart scorpion    # Restart service
echo    pm2 stop scorpion       # Stop service

pause`;

    fs.writeFileSync(path.join(__dirname, 'install-service-windows.bat'), serviceScript);
  }

  async run() {
    console.log('\n🚀 Starting Cross-Platform Setup...\n');
    
    try {
      // Create platform-specific scripts
      this.createPlatformScripts();
      
      // Install dependencies
      await this.installDependencies();
      
      console.log('\n✅ Cross-Platform Setup Completed!');
      console.log('\n🎯 Quick Start Commands:');
      
      if (this.platform === 'win32') {
        console.log('   Windows: start-windows.bat');
        console.log('   Service: install-service-windows.bat');
      } else {
        console.log('   Unix/Linux: ./start-unix.sh');
        console.log('   Service: sudo ./install-service-linux.sh');
      }
      
      console.log('\n🌐 Web Interface: http://localhost:3001');
      console.log('👤 Default Login: admin / admin');
      
    } catch (error) {
      console.error('❌ Setup failed:', error.message);
      process.exit(1);
    }
  }
}

// Run installer if called directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const installer = new CrossPlatformInstaller();
  installer.run();
}

export { CrossPlatformInstaller };
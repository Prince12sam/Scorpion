# 🦂 Scorpion Security Platform - Cross-Platform Guide

## Universal Installation & Usage Guide

Scorpion Security Platform runs seamlessly on **Windows**, **Linux**, and **macOS** with automatic platform detection and optimization.

---

## 🚀 Quick Start

### Windows
```batch
# Simple setup (no admin required)
setup-windows-simple.bat

# Start the platform
start-windows.bat
# Or: npm start
```

### Linux/Unix
```bash
# Universal Linux installer
chmod +x setup-linux-universal.sh
./setup-linux-universal.sh

# Start the platform
./start-unix.sh
# Or: npm start
```

### macOS
```bash
# Same as Linux
chmod +x setup-linux-universal.sh
./setup-linux-universal.sh
./start-unix.sh
```

---

## 🔧 Platform-Specific Features

### Windows Support
- **Automatic dependency detection** (Chocolatey, Winget, Scoop)
- **Windows Service installation** with PM2
- **PowerShell integration** for advanced operations
- **No admin rights required** for basic functionality
- **Batch file automation** for easy deployment

```batch
# Windows service installation
install-service-windows.bat

# Advanced Windows setup
setup-windows-simple.bat
```

### Linux Support
- **Universal package manager detection**:
  - Ubuntu/Debian: `apt`
  - CentOS/RHEL: `yum`/`dnf`  
  - Arch Linux: `pacman`
  - openSUSE: `zypper`
  - Alpine: `apk`
- **Systemd service integration**
- **Shell script automation**
- **Distribution-specific optimizations**

```bash
# Systemd service (requires root)
sudo ./install-service-linux.sh

# Manual service management
sudo systemctl start scorpion
sudo systemctl enable scorpion
sudo systemctl status scorpion
```

### macOS Support
- **Homebrew integration** for dependencies
- **LaunchDaemon support** for services
- **Native macOS optimizations**

---

## 📦 System Requirements

### Minimum Requirements
- **Node.js 16+** (automatically detected)
- **4GB RAM** (2GB minimum)
- **1GB disk space**
- **Network access** for threat intelligence

### Recommended
- **Node.js 18+** for best performance
- **8GB RAM** for advanced scanning
- **SSD storage** for faster I/O
- **Admin/root access** for service installation

### Dependencies (Auto-installed where possible)
- `curl` - HTTP client
- `wget` - File downloader  
- `git` - Version control
- `openssl` - Cryptography
- `nmap` - Network scanning (optional)
- `python3` - Script support (optional)

---

## 🖥️ Cross-Platform CLI Usage

All CLI commands work identically across platforms:

```bash
# Basic scanning
node cli/scorpion.js scan target.com
scorpion scan target.com --stealth ninja

# Network reconnaissance  
scorpion recon 192.168.1.0/24
scorpion recon target.com --deep

# Password security
scorpion password analyze "mypassword123"
scorpion password generate --length 32

# File integrity monitoring
scorpion fim baseline /important/files
scorpion fim check /important/files

# Threat intelligence
scorpion threat-intel ip 1.2.3.4
scorpion threat-intel domain suspicious.com
```

---

## 🌐 Web Interface Access

The web interface is consistent across all platforms:

- **URL**: http://localhost:3001
- **Login**: admin / admin  
- **Features**: All security modules accessible via web UI
- **API**: RESTful API at `/api/*` endpoints
- **WebSocket**: Real-time updates and monitoring

### Platform-Specific Web Features

#### Windows
- **Internet Explorer/Edge compatibility** mode
- **Windows authentication** integration (enterprise)
- **PowerShell Web Access** for advanced operations

#### Linux
- **Systemd integration** for service status
- **Shell command execution** via web interface
- **Log file integration** with journald

#### macOS
- **Keychain integration** for secure storage
- **Notification Center** integration
- **Touch Bar** shortcuts (MacBook Pro)

---

## 🐳 Docker Support (Universal)

Docker provides the most consistent cross-platform experience:

```bash
# Quick deployment
./quick-deploy.sh    # Linux/macOS
quick-deploy.bat     # Windows

# Manual Docker
docker-compose up --build -d

# Access the platform
http://localhost:3001
```

### Docker Benefits
- **Identical behavior** across all platforms
- **Isolated environment** with all dependencies
- **Easy scaling** and load balancing
- **Production-ready** configuration

---

## 🧪 Testing & Validation

### Cross-Platform Testing
```bash
# Run comprehensive tests
npm run test:cross-platform

# Platform-specific tests
node cross-platform-test.js
```

### Test Categories
- ✅ **System Requirements** - Node.js version, permissions
- ✅ **CLI Commands** - All security modules  
- ✅ **Web Interface** - Server startup, authentication
- ✅ **Security Features** - CSRF, rate limiting, headers
- ✅ **Performance** - Memory usage, response times

### Supported Platforms (Tested)
- ✅ **Windows 10/11** (x64, ARM64)
- ✅ **Ubuntu 18.04+** (x64, ARM64)
- ✅ **Debian 10+** (x64, ARM64)
- ✅ **CentOS 7/8** (x64)
- ✅ **RHEL 7/8** (x64)
- ✅ **Fedora 32+** (x64)
- ✅ **Arch Linux** (x64)
- ✅ **openSUSE** (x64)
- ✅ **Alpine Linux** (x64, ARM64)
- ✅ **macOS 10.15+** (x64, ARM64 M1/M2)

---

## 🔒 Security Considerations

### Platform-Specific Security

#### Windows
- **Windows Defender** exclusions may be needed
- **UAC prompts** for admin operations
- **Windows Firewall** configuration
- **AMSI integration** for script scanning

#### Linux
- **SELinux/AppArmor** compatibility
- **Firewall configuration** (iptables/ufw)
- **User permissions** and sudo access
- **System service security**

#### macOS
- **Gatekeeper** and code signing
- **System Integrity Protection** (SIP)
- **Firewall configuration**
- **Privacy permissions** for network access

---

## 🚀 Production Deployment

### Service Installation

#### Windows (as Service)
```batch
# Install as Windows Service
install-service-windows.bat

# Service management
sc start "Scorpion Security Platform"
sc stop "Scorpion Security Platform"
```

#### Linux (as Systemd Service)
```bash
# Install as systemd service
sudo ./install-service-linux.sh

# Service management  
sudo systemctl start scorpion
sudo systemctl stop scorpion
sudo systemctl restart scorpion
sudo systemctl status scorpion

# View logs
journalctl -u scorpion -f
```

#### macOS (as LaunchDaemon)
```bash
# Install as launch daemon
sudo cp com.scorpion.platform.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.scorpion.platform.plist

# Service management
sudo launchctl start com.scorpion.platform
sudo launchctl stop com.scorpion.platform
```

---

## 🛠️ Troubleshooting

### Common Issues

#### Windows
```batch
# Permission errors
# Solution: Run as Administrator or use setup-windows-simple.bat

# Port already in use
netstat -ano | findstr :3001
taskkill /PID <PID> /F

# Node.js not found
# Install from: https://nodejs.org/
```

#### Linux
```bash
# Permission denied
# Solution: chmod +x *.sh

# Port already in use
sudo netstat -tulpn | grep :3001
sudo kill -9 <PID>

# Missing dependencies
# Run: ./setup-linux-universal.sh
```

#### macOS
```bash
# Permission denied
chmod +x *.sh

# Command not found
# Install Xcode Command Line Tools:
xcode-select --install
```

### Performance Optimization

#### All Platforms
- **Use SSD storage** for faster I/O
- **Increase Node.js memory** limit: `node --max-old-space-size=4096`
- **Enable clustering** in production
- **Use HTTP/2** for better performance

#### Platform-Specific
- **Windows**: Disable Windows Defender real-time scanning for faster file operations
- **Linux**: Use `noatime` mount option for faster file access  
- **macOS**: Disable Spotlight indexing for project directories

---

## 📋 Platform Support Matrix

| Feature | Windows | Linux | macOS | Docker |
|---------|---------|-------|-------|--------|
| Web Interface | ✅ | ✅ | ✅ | ✅ |
| CLI Tools | ✅ | ✅ | ✅ | ✅ |
| Service Installation | ✅ | ✅ | ✅ | ✅ |
| Auto-start | ✅ | ✅ | ✅ | ✅ |
| Package Manager | ✅ | ✅ | ✅ | N/A |
| Security Scanning | ✅ | ✅ | ✅ | ✅ |
| Network Tools | ⚠️¹ | ✅ | ✅ | ✅ |
| File Monitoring | ✅ | ✅ | ✅ | ✅ |
| Threat Intel | ✅ | ✅ | ✅ | ✅ |

¹ Some network tools require admin rights on Windows

---

## 🆘 Support & Documentation

- **Documentation**: [COMPREHENSIVE_TOOL_REVIEW.md](COMPREHENSIVE_TOOL_REVIEW.md)
- **Docker Guide**: [DOCKER.md](DOCKER.md)
- **Security Guide**: [SECURITY_ENHANCEMENTS.md](SECURITY_ENHANCEMENTS.md)
- **Issues**: Submit GitHub issues with platform details
- **Wiki**: Platform-specific guides and tutorials

---

## 🎯 Next Steps

1. **Choose your platform** and run the appropriate installer
2. **Test basic functionality** with the web interface
3. **Run cross-platform tests** to verify compatibility
4. **Configure as a service** for production use
5. **Set up Docker** for consistent deployment
6. **Customize security modules** for your environment

The Scorpion Security Platform is designed to provide identical functionality across all supported platforms while respecting platform-specific conventions and optimizations.
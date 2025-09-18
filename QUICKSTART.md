# 🦂 Scorpion Security Platform - Quick Start Guide

Welcome to Scorpion! This guide will get you up and running in 5 minutes.

## 🚀 Quick Installation

```bash
# 1. Install dependencies
npm install

# 2. Setup will run automatically, or run manually:
npm run setup

# 3. Start the platform
npm run dev:full
```

## 🎯 First Steps

### 1. Test CLI Interface
```bash
# Get help
npm run cli -- --help

# Quick vulnerability scan
npm run cli scan -t localhost --type quick

# DNS reconnaissance  
npm run cli recon -t google.com --dns

# Check IP reputation
npm run cli threat-intel -i 8.8.8.8
```

### 2. Access Web Interface
- Open http://localhost:5173 for the web dashboard
- API server runs on http://localhost:3001

### 3. Configure API Keys (Optional)
```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your API keys:
# - VirusTotal API Key
# - AbuseIPDB API Key  
# - Shodan API Key
```

## 🔧 Common Commands

### CLI Operations
```bash
# Port scanning
npm run cli scan -t 192.168.1.1 -p 1-1000

# File integrity monitoring
npm run cli fim -p /path/to/monitor --watch

# Password security testing
npm run cli password --crack hashes.txt

# Generate reports
npm run cli scan -t target.com --type deep --output json
```

### Development
```bash
# Start web interface only
npm run dev

# Start API server only  
npm run server

# Build for production
npm run build

# Preview production build
npm run preview
```

## 📁 Project Structure

```
├── cli/                 # Command-line interface
│   ├── scorpion.js     # Main CLI entry point
│   └── lib/            # Security modules
├── server/             # API server
├── src/                # Web interface
│   └── components/     # React components
└── docs/               # Documentation
```

## 🛠️ Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Kill processes on port 3001
npx kill-port 3001

# Or use different port
PORT=3002 npm run server
```

**Permission denied on Linux/Mac:**
```bash
# Make CLI executable
chmod +x cli/scorpion.js
```

**API connection errors:**
- Check if backend server is running (`npm run server`)
- Verify VITE_API_BASE in .env matches server port
- Check firewall settings

### Getting Help

1. **Documentation**: Check README.md for detailed info
2. **CLI Help**: `npm run cli -- --help`
3. **Component Help**: `npm run cli <command> --help`
4. **Issues**: Report bugs on GitHub

## 🔐 Security Notes

- **Local Use**: Default setup is for local development
- **API Keys**: Keep your threat intelligence API keys secure
- **Scanning**: Only scan systems you own or have permission to test
- **Data**: Scan results are stored locally in `.scorpion/` directory

## 🎨 Web Interface Features

- **Dashboard**: Real-time security metrics
- **Vulnerability Scanner**: Comprehensive security testing  
- **Threat Intelligence**: IP/domain/hash reputation lookup
- **Network Reconnaissance**: DNS enumeration and discovery
- **File Integrity**: Monitor file changes
- **Password Security**: Breach checking and strength analysis

## 📈 Next Steps

1. **Configure Monitoring**: Set up file integrity monitoring for critical directories
2. **Schedule Scans**: Create automated vulnerability scanning routines
3. **Threat Feeds**: Configure threat intelligence API keys for better coverage
4. **Custom Targets**: Create target lists for regular scanning
5. **Reports**: Set up automated report generation

---

🦂 **Happy Hunting!** - Scorpion Security Platform

Need more help? Check the full README.md or ask in your next prompt!
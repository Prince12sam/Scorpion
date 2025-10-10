# Scorpion Security Platform 🦂

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Prince12sam/Scorpion)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/Prince12sam/Scorpion)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen.svg)](https://nodejs.org/)

**🌍 Professional-Grade Global Threat-Hunting & Vulnerability Assessment Platform**

Scorpion is an enterprise-ready security platform offering comprehensive vulnerability scanning, real-time threat intelligence, and advanced security testing capabilities. Built for security professionals, penetration testers, and enterprise security teams.

## 🚀 Quick Start

### **Option 1: One-Command Setup (Recommended)**
```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
npm install && npm run dev:full
```

### **Option 2: Manual Setup**
```bash
[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](https://github.com/Prince12sam/Scorpion)
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
**🌍 Professional-Grade Global Threat-Hunting & Vulnerability Assessment Platform**

# Start backend server (Terminal 1)
### **Option 2: Manual Setup**

# Start web interface (Terminal 2) 
**🌐 Access the Platform:**

# Or use CLI directly
### 🔍 **Vulnerability Scanner**
```

### 🧠 **Threat Intelligence**
- **Web Interface:** http://localhost:5173
- **API Server:** http://localhost:3001
### 👁️ **File Integrity Monitoring** (Web UI)
This feature has been moved to the web interface to keep the CLI focused on discovery/exploitation.
## ✨ Features

### � **Password Security** (Web UI)
Password breach checks, analysis, and cracking workflows are available in the web interface.
- Web application security testing
- SSL/TLS configuration analysis
### 📊 **Professional Reporting** (Web UI)
Generate executive and technical reports from the web interface.

### 🕵️ **Network Reconnaissance**
## 🧩 Installation & Setup
- WHOIS lookup
- Subdomain discovery
### **Manual Installation**
- HTTP header analysis
- Certificate information
### **Platform Verification**
### 🧠 **Threat Intelligence**
- IP reputation checking
## 💻 CLI Usage (Discovery/Exploit)
- File hash verification
- IOC (Indicators of Compromise) database
### Global Install
```bash
npm install -g
```

### Basic Commands
- Real-time threat feed updates

#### Vulnerability Scanning
- Baseline creation and comparison
- Real-time file monitoring
#### Threat Intelligence
- Integrity reporting
- Critical file protection
#### OWASP Top 10 Exploit Probes (Reconnaissance)
```bash
# Full OWASP Top 10 non-destructive probes
scorpion exploit -t https://target.com --payload owasp-top10 --mode reconnaissance -o results.json

# Focused probes
scorpion exploit -t https://target.com --payload sql-injection
scorpion exploit -t https://target.com --payload xss
scorpion exploit -t https://target.com --payload path-traversal
```
- Detailed technical reports
- Real-time dashboard
### **Penetration Testing**
## � Installation & Setup

### **Security Monitoring**
- Node.js >= 16.0.0
- npm package manager
### **Threat Hunting**

### **One-Command Installation** ⚡
### **Compliance Auditing** (Web UI)
git clone https://github.com/Prince12sam/Scorpion.git
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
npm install && npm start
```

**🎯 That's it! The platform will automatically:**
- Install all dependencies
- Configure the environment  
- Start both web interface and API server
- Open your browser to http://localhost:5173

### **Manual Installation**
```bash
# Clone the repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# Install dependencies
npm install

# Start full platform (recommended)
npm start

# Or start components separately:
npm run server  # API server only (port 3001)
npm run dev     # Web interface only (port 5173)
npm run cli     # CLI interface only
```

### **Platform Verification**
```bash
# Test the installation
node test-web-interface.js

# Check all components
curl http://localhost:3001/api/health
curl http://localhost:5173
```

### **Cross-Platform Startup Scripts**
- **Windows**: `start-scorpion.bat`
- **Linux/macOS**: `start-scorpion.sh`  
- **PowerShell**: `start-scorpion.ps1`

## 💻 CLI Usage

### Make CLI Globally Available
```bash
npm link
```

### Basic Commands

#### Vulnerability Scanning
```bash
# Quick scan
scorpion scan -t example.com --type quick

# Full port scan with custom range
scorpion scan -t 192.168.1.1 -p 1-65535 --type deep

# Save results to file
scorpion scan -t example.com -o results.json --format json
```

#### Network Reconnaissance
```bash
# DNS enumeration
scorpion recon -t example.com --dns

# Full reconnaissance
scorpion recon -t example.com --dns --whois --ports --subdomain

# WHOIS lookup only
scorpion recon -t example.com --whois
```

#### Threat Intelligence
```bash
# Check IP reputation
scorpion threat-intel -i 8.8.8.8

# Check domain reputation
scorpion threat-intel -d suspicious-domain.com

# Check file hash
scorpion threat-intel -h 5d41402abc4b2a76b9719d911017c592

# List current IOCs
scorpion threat-intel --ioc
```

#### File Integrity Monitoring
```bash
# Create baseline
scorpion fim -p /etc --baseline

# Check for changes
scorpion fim -p /etc --check

# Real-time monitoring
scorpion fim -p /var/www --watch
```

#### Password Security
```bash
# Check email breach status
scorpion password --breach user@example.com

# Generate secure password
scorpion password --generate

# Crack hash file
scorpion password -f hashes.txt -w wordlist.txt
```

## 🌐 Web Interface Usage

### Start Web Server
```bash
# Start server on default port (3001)
npm run server

# Start server on custom port
scorpion web -p 8080 --host 0.0.0.0
```

### Development Mode
```bash
# Run both frontend and backend
npm run dev:full
```

### Access Dashboard
- **Web Dashboard:** http://localhost:3001
- **Development:** http://localhost:5173

## 🛠️ Configuration

### API Keys (Optional)
Set environment variables for enhanced threat intelligence:

```bash
export VIRUSTOTAL_API_KEY="your_vt_api_key"
export ABUSEIPDB_API_KEY="your_abuse_api_key" 
export SHODAN_API_KEY="your_shodan_api_key"
```

### Custom Configuration
Create `.scorpion/config.json` in your home directory:

```json
{
  "scanner": {
    "timeout": 5000,
    "maxConcurrent": 100
  },
  "threatIntel": {
    "updateInterval": 3600,
    "feedSources": ["custom-feed-url"]
  },
  "fim": {
    "excludePatterns": ["*.log", "*.tmp", ".git/**"]
  }
}
```

## 📁 Project Structure

```
scorpion/
├── cli/                    # Command line interface
│   ├── scorpion.js        # Main CLI entry point
│   └── lib/               # Core security modules
│       ├── scanner.js     # Vulnerability scanner
│       ├── recon.js       # Network reconnaissance
│       ├── threat-intel.js # Threat intelligence
│       ├── file-integrity.js # File monitoring
│       ├── password-security.js # Password tools
│       └── reporter.js    # Report generation
├── server/                # Web server backend
│   └── index.js          # Express.js API server
├── src/                  # React frontend
│   ├── components/       # UI components
│   └── lib/             # Utilities
├── public/              # Static assets
└── dist/               # Built web application
```

## 🔧 API Endpoints

### Security Scanning
- `POST /api/scan` - Start vulnerability scan
- `GET /api/scan/:scanId` - Get scan results
- `GET /api/scans` - List all scans

### Reconnaissance
- `POST /api/recon` - Start reconnaissance
- `GET /api/recon/:taskId` - Get recon results

### Threat Intelligence
- `POST /api/threat-intel/ip` - Check IP reputation
- `POST /api/threat-intel/domain` - Check domain reputation
- `POST /api/threat-intel/hash` - Check file hash
- `GET /api/threat-intel/iocs` - Get IOCs

### File Integrity
- `POST /api/fim/baseline` - Create baseline
- `POST /api/fim/check` - Check integrity
- `POST /api/fim/watch` - Start monitoring

### Password Security
- `POST /api/password/breach` - Check breach status
- `POST /api/password/generate` - Generate password
- `POST /api/password/analyze` - Analyze password strength

## 🎯 Use Cases

### **Penetration Testing**
```bash
# Full target assessment
scorpion recon -t target.com --dns --whois --ports --subdomain
scorpion scan -t target.com --type deep -o pentest-results.html --format html
```

### **Security Monitoring**
```bash
# Monitor critical systems
scorpion fim -p /etc --baseline
scorpion fim -p /var/www --watch
scorpion web -p 3001  # Start dashboard
```

### **Threat Hunting**
```bash
# Investigate suspicious indicators
scorpion threat-intel -i 192.168.1.100
scorpion threat-intel -d suspicious.com
scorpion threat-intel --ioc
```

### **Compliance Auditing**
```bash
# Security assessment
scorpion scan -t internal-server.com --type compliance
scorpion password -f user-hashes.txt -w common-passwords.txt
```

## 🔒 Security Considerations

- **Authorized Use Only**: Only use on systems you own or have permission to test
- **Rate Limiting**: Be mindful of scan rates to avoid overwhelming targets
- **API Keys**: Store API keys securely and rotate regularly
- **Logs**: Review and secure log files containing sensitive information
- **Network**: Use VPN or controlled environments for testing

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The developers assume no liability for misuse of this software.

## 🆘 Support

- **Documentation**: Check the `/docs` directory
- **Issues**: Report bugs on GitHub Issues
- **Security**: Report security issues privately to security@scorpion-platform.com

---

**Made with ❤️ by the Scorpion Security Team**
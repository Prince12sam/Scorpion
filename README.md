# Scorpion Security Platform 🦂

[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg)](https://github.com/Prince12sam/Scorpion)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/Prince12sam/Scorpion)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen.svg)](https://nodejs.org/)

**🌍 Enterprise-Grade Threat-Hunting & Security Assessment Platform**

## 🚀 Quick Start

### Windows
```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
install-windows.bat
start-scorpion.bat
```

### Linux
```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
chmod +x install-linux.sh start-scorpion-linux.sh
./install-linux.sh
./start-scorpion-linux.sh
```

### Access
- **Web Interface**: http://localhost:5173
- **API**: http://localhost:3001
- **Login**: `admin` / `admin` (EASY_LOGIN mode for local development)

## ✨ Features

### 🌐 Web Interface
- 🎯 **API Testing**: REST API security testing with automated vulnerability detection
- 🌐 **Network Discovery**: Port scanning, service enumeration, asset inventory
- 🔍 **Threat Hunting**: OWASP Top 10 exploit testing and security assessment
- 👥 **User Management**: Multi-user support with role-based access control
- ⚙️ **Settings**: Configure VirusTotal, AbuseIPDB, and Shodan integrations
- 📊 **Monitoring**: Real-time security event tracking and alerting

### 💻 CLI Tool
```bash
npm link
scorpion --help
```
Nmap-style security discovery with comprehensive OWASP Top 10 exploit testing capabilities.
Nmap-style security discovery with comprehensive OWASP Top 10 exploit testing capabilities.

## 🛠️ Configuration

### Production Mode
Edit `.env` to disable EASY_LOGIN:
```env
EASY_LOGIN=false
JWT_SECRET=your-secure-random-secret-here
PORT=3001
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
SHODAN_API_KEY=your-shodan-key
```

## 🏗️ Architecture

- **Backend**: Node.js + Express + JWT authentication
- **Frontend**: React 18 + Vite + Tailwind CSS + Radix UI
- **CLI**: Commander.js-based security toolkit
- **Threat Intel**: VirusTotal, AbuseIPDB, Shodan integration
- **Storage**: File-based persistence with JSON storage

## 🔒 Security Features

- ✅ JWT access & refresh token authentication
- ✅ Rate limiting on all API endpoints
- ✅ Helmet.js security headers
- ✅ CORS protection with configurable origins
- ✅ Input validation and sanitization
- ✅ Secure file-based persistence
- ✅ EASY_LOGIN mode for local development only

## 📁 Project Structure

```
scorpion/
├── cli/                    # Command-line interface
│   ├── scorpion.js        # Main CLI entry point
│   ├── lib/               # Security modules
│   │   ├── scanner.js     # Vulnerability scanner
│   │   ├── recon.js       # Network reconnaissance
│   │   └── threat-intel.js # Threat intelligence
│   └── data/              # Storage for scan results
├── server/                # Backend API server
│   └── clean-server.js   # Express.js with all routes
├── src/                   # React frontend
│   ├── App.jsx           # Main application
│   └── components/       # UI components
└── public/               # Static assets
```

## 🎯 Use Cases

### Security Assessment
- Web application vulnerability scanning
- Network discovery and asset inventory
- OWASP Top 10 threat hunting

### Threat Intelligence
- IP/domain reputation checking with VirusTotal
- Abuse monitoring with AbuseIPDB
- IoT/infrastructure discovery with Shodan

### Compliance & Auditing
- Multi-user security testing workflows
- Role-based access control
- Audit logging and reporting

## 📜 License

MIT License - see [LICENSE](LICENSE) file

## ⚠️ Disclaimer

For authorized security testing only. Users are responsible for compliance with applicable laws.

---

**Built for security professionals by security engineers** 🦂
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
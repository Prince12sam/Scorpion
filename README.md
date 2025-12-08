# Scorpion CLI Security Tool 🦂

[![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)](https://github.com/Prince12sam/Scorpion)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/Prince12sam/Scorpion)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen.svg)](https://nodejs.org/)

**🔒 Professional Command-Line Security Testing & Threat-Hunting Platform**

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
npm install
npm link
```

### Basic Usage

```bash
# Display help
scorpion --help

# Scan a target
scorpion scan -t example.com --ports 1-1000

# Network reconnaissance
scorpion recon -t example.com --dns --whois

# Run OWASP Top 10 exploits
scorpion exploit -t example.com --payload owasp-top10
```

## ✨ Features

### 🎯 **Enhanced Vulnerability Reporting** ⭐ NEW
- **Exact Locations**: Precise identification of vulnerability locations
- **Impact Analysis**: Real-world consequences for each security issue
- **Remediation Steps**: Step-by-step instructions to fix vulnerabilities
- **Technical Details**: CVE references, payloads, and proof-of-concept data
- **Compliance Mapping**: OWASP, NIST, PCI DSS alignment
- **JSON Export**: Machine-readable reports for CI/CD integration

📄 **[View Full Vulnerability Reporting Guide →](VULNERABILITY_REPORTING.md)**

### 🔍 **Subdomain Takeover Detection** ⭐ NEW
- **15+ Cloud Services**: AWS S3, Azure, GitHub Pages, Heroku, Shopify, and more
- **Real DNS Resolution**: Production-ready CNAME enumeration
- **Service Fingerprinting**: Automatic vulnerable service identification
- **HTTP Verification**: Live requests to confirm unclaimed resources
- **Detailed Reports**: Exact DNS records and remediation guidance

### 🔐 **API Security Testing** ⭐ NEW
- **Endpoint Discovery**: Automatic API path enumeration
- **OpenAPI/Swagger Testing**: Documentation exposure detection
- **GraphQL Security**: Introspection and injection testing
- **Authentication Analysis**: JWT, OAuth, Basic Auth security checks
- **IDOR Detection**: Insecure Direct Object Reference testing
- **Rate Limiting Tests**: 100-request burst testing
- **Input Validation**: XSS, SQLi, Command Injection probes

### 🔒 **SSL/TLS Deep Analysis** ⭐ NEW
- **Certificate Inspection**: Expiration, key size, signature validation
- **Protocol Testing**: SSLv3, TLS 1.0-1.3 support detection
- **Cipher Analysis**: Strong vs weak cipher suite identification
- **Vulnerability Detection**: Heartbleed, POODLE, BEAST, CRIME testing
- **Security Headers**: HSTS, HPKP validation
- **Chain Validation**: Full certificate chain verification

### 🔍 **Vulnerability Scanner**
- **Port Scanning**: TCP/UDP with service detection
- **Stealth Modes**: Low, Medium, High, and Ninja level evasion
- **OS Fingerprinting**: Advanced operating system detection
- **Banner Grabbing**: Service version identification
- **Web Application Testing**: OWASP Top 10 vulnerability probes

### 🌐 **Network Reconnaissance**
- **DNS Enumeration**: A, MX, TXT, NS, CNAME record discovery
- **Subdomain Discovery**: 25+ common subdomain patterns
- **WHOIS Integration**: Domain registration and ownership data
- **Geolocation**: IP-based geographic mapping
- **HTTP Header Analysis**: Security configuration assessment
- **Network Topology Mapping**: Infrastructure visualization

### 💥 **Exploit Framework**
- **OWASP Top 10 Testing**: 18+ non-destructive security probes
- **SQL Injection**: Multiple injection vector testing
- **XSS Detection**: Reflected and stored XSS probes
- **SSRF Testing**: Server-side request forgery detection
- **Command Injection**: OS command injection testing
- **Path Traversal**: Directory traversal vulnerability detection

### 🔐 **Threat Intelligence**
- **IP Reputation**: Real-time threat feed analysis
- **Domain Analysis**: Malicious domain detection
- **Hash Verification**: File integrity and malware detection
- **IOC Management**: Indicators of Compromise database
- **Multi-Source Feeds**: VirusTotal, AbuseIPDB, Shodan integration

### 🔑 **Password Security**
- **Breach Detection**: Have I Been Pwned integration
- **Hash Cracking**: Multi-algorithm support (SHA-256/512, PBKDF2)
- **Password Analysis**: Strength scoring and recommendations
- **Secure Generation**: Cryptographically secure password creation
- **Dictionary Attacks**: Wordlist-based cracking

## 📖 Command Reference

### Help & Information

```bash
# Display all available commands
scorpion --help

# Get help for specific command
scorpion scan --help
scorpion recon --help
scorpion exploit --help

# Show advanced exploitation capabilities
scorpion help-advanced

# Show version
scorpion --version
```

### Vulnerability Scanning

```bash
# Basic port scan
scorpion scan -t example.com

# Scan specific ports with stealth
scorpion scan -t example.com --ports 80,443,8080 --stealth high

# Deep scan with service detection
scorpion scan -t example.com --type deep -A

# Ninja-level stealth scan
scorpion scan -t example.com --stealth ninja --ports 1-1000

# TCP SYN scan (requires privileges)
scorpion scan -t example.com -sS --ports 1-1000

# OS detection
scorpion scan -t example.com -O

# Output to JSON file
scorpion scan -t example.com -o results.json

# Available scan types: quick, normal, deep, custom
scorpion scan -t example.com --type deep

# Available stealth levels: low, medium, high, ninja
scorpion scan -t example.com --stealth ninja
```

### Network Reconnaissance

```bash
# DNS enumeration only
scorpion recon -t example.com --dns

# WHOIS lookup
scorpion recon -t example.com --whois

# Subdomain discovery
scorpion recon -t example.com --subdomain

# Port scanning during recon
scorpion recon -t example.com --ports

# Full reconnaissance (all options)
scorpion recon -t example.com --dns --whois --subdomain --ports

# Network information gathering
scorpion recon -t 192.168.1.1 --dns --ports
```

### Subdomain Takeover Detection ⭐ NEW

```bash
# Scan for subdomain takeover vulnerabilities
scorpion takeover -t example.com

# Check specific AWS S3 buckets
scorpion takeover -t subdomain.example.com --check-aws

# Check Azure services
scorpion takeover -t subdomain.example.com --check-azure

# Use custom subdomain list
scorpion takeover -t example.com --subdomains subdomains.txt

# Save results to file
scorpion takeover -t example.com -o takeover-report.json
```

### API Security Testing ⭐ NEW

```bash
# Full API security assessment
scorpion api-test -t https://api.example.com

# Skip specific tests
scorpion api-test -t https://api.example.com --no-graphql
scorpion api-test -t https://api.example.com --no-rate-limit

# Test authentication and authorization only
scorpion api-test -t https://api.example.com --no-discover --no-graphql

# Save detailed report
scorpion api-test -t https://api.example.com -o api-report.json
```

### SSL/TLS Security Analysis ⭐ NEW

```bash
# Analyze SSL/TLS configuration
scorpion ssl-analyze -t example.com

# Test non-standard HTTPS port
scorpion ssl-analyze -t example.com -p 8443

# Test custom API port
scorpion ssl-analyze -t api.example.com -p 8080

# Save analysis report
scorpion ssl-analyze -t example.com -o ssl-report.json
```

### Exploit Testing

```bash
# OWASP Top 10 testing
scorpion exploit -t example.com --payload owasp-top10

# Test specific vulnerability types
scorpion exploit -t example.com --payload sql-injection
scorpion exploit -t example.com --payload xss
scorpion exploit -t example.com --payload ssrf

# Test broken access control
scorpion exploit -t example.com --payload broken-access-control

# Cloud-specific exploits
scorpion exploit -t example.com --payload aws
scorpion exploit -t example.com --payload azure
scorpion exploit -t example.com --payload gcp
scorpion exploit -t example.com --payload cloud

# All available payloads
scorpion exploit -t example.com --payload all

# Target specific service
scorpion exploit -t example.com --service http -p 8080
scorpion exploit -t example.com --service ssh -p 22

# Exploitation modes
scorpion exploit -t example.com --mode reconnaissance
scorpion exploit -t example.com --mode proof-of-concept
scorpion exploit -t example.com --mode full-exploitation

# Target specific CVE
scorpion exploit -t example.com --vuln CVE-2021-44228

# Output results
scorpion exploit -t example.com --payload owasp-top10 -o exploits.json
```

### Threat Intelligence

```bash
# Check IP reputation
scorpion threat-intel -i 8.8.8.8
scorpion threat-intel -i 192.168.1.100

# Check domain reputation
scorpion threat-intel -d suspicious-domain.com
scorpion threat-intel -d malware-site.xyz

# Verify file hash (MD5, SHA-1, SHA-256)
scorpion threat-intel -h 5d41402abc4b2a76b9719d911017c592
scorpion threat-intel -h d41d8cd98f00b204e9800998ecf8427e

# List all indicators of compromise
scorpion threat-intel --ioc

# Multiple lookups
scorpion threat-intel -i 1.2.3.4 -d example.com
```

### Enterprise Vulnerability Assessment

```bash
# Comprehensive enterprise scan
scorpion enterprise-scan -t 192.168.1.0/24

# Multiple targets
scorpion enterprise-scan -t 192.168.1.1 192.168.1.2 192.168.1.3

# Scan from file
scorpion enterprise-scan -t targets.txt

# Internal network only
scorpion enterprise-scan -t 10.0.0.0/8 --internal

# External network only
scorpion enterprise-scan -t example.com --external --no-internal

# Deep vulnerability analysis
scorpion enterprise-scan -t 192.168.1.0/24 --deep

# Authenticated scanning
scorpion enterprise-scan -t 192.168.1.0/24 --authenticated --credentials creds.json

# Compliance assessment
scorpion enterprise-scan -t 192.168.1.0/24 --compliance PCI-DSS HIPAA SOC2

# Custom thread count
scorpion enterprise-scan -t 192.168.1.0/24 --threads 50

# Safe mode (no exploits)
scorpion enterprise-scan -t 192.168.1.0/24 --safe

# Output results
scorpion enterprise-scan -t 192.168.1.0/24 -o enterprise-results.json
```

### Internal Network Security Assessment

```bash
# Full internal assessment (auto-discovery)
scorpion internal-test

# Targeted assessment
scorpion internal-test --scope targeted --targets 192.168.1.0/24

# Stealth mode
scorpion internal-test --scope stealth

# Deep assessment
scorpion internal-test --depth deep

# Surface-level only
scorpion internal-test --depth surface

# Authenticated testing
scorpion internal-test --authenticated --credentials creds.json

# Compliance frameworks
scorpion internal-test --compliance PCI-DSS HIPAA

# Specific targets
scorpion internal-test --targets 192.168.1.10 192.168.1.20 192.168.1.30

# Safe mode
scorpion internal-test --safe-mode

# Output results
scorpion internal-test -o internal-assessment.json
```

### AI-Powered Autonomous Penetration Testing

```bash
# Basic AI penetration test
scorpion ai-pentest -t example.com

# Comprehensive assessment
scorpion ai-pentest -t example.com --primary-goal comprehensive_assessment

# Privilege escalation focus
scorpion ai-pentest -t example.com --primary-goal privilege_escalation

# Data access focus
scorpion ai-pentest -t example.com --primary-goal data_access

# Multiple secondary goals
scorpion ai-pentest -t example.com --secondary-goals "privilege_escalation,data_access,persistence"

# Time-limited test
scorpion ai-pentest -t example.com --time-limit 60

# Stealth levels
scorpion ai-pentest -t example.com --stealth-level low
scorpion ai-pentest -t example.com --stealth-level moderate
scorpion ai-pentest -t example.com --stealth-level high

# Autonomy levels
scorpion ai-pentest -t example.com --autonomy supervised
scorpion ai-pentest -t example.com --autonomy semi-autonomous
scorpion ai-pentest -t example.com --autonomy fully-autonomous

# Risk tolerance
scorpion ai-pentest -t example.com --risk-tolerance low
scorpion ai-pentest -t example.com --risk-tolerance medium
scorpion ai-pentest -t example.com --risk-tolerance high

# Learning mode
scorpion ai-pentest -t example.com --learning-mode enabled

# Output results
scorpion ai-pentest -t example.com -o ai-pentest-results.json

# Full autonomous test with all options
scorpion ai-pentest -t example.com \
  --primary-goal comprehensive_assessment \
  --secondary-goals "privilege_escalation,data_access" \
  --time-limit 120 \
  --stealth-level high \
  --autonomy semi-autonomous \
  --risk-tolerance medium \
  -o results.json
```

### Password Security

*Note: Password security features are available through helper scripts in the tools/ directory.*

```bash
# Check email breach status
node tools/run-password.js breach user@example.com

# Generate secure password
node tools/run-password.js generate

# Crack hash file with wordlist
node tools/run-password.js crack hashes.txt wordlist.txt

# Analyze password strength
node tools/run-password.js strength "MyPassword123"
```

### Helper Scripts

```bash
# Run comprehensive security suite
node tools/run-suite.js --target example.com --recon

# Quick vulnerability scan
node tools/run-scan.js -t example.com --ports 1-1000

# Network reconnaissance
node tools/run-recon.js -t example.com

# Threat intelligence lookup
node tools/run-intel.js -i 8.8.8.8
```

## 🛠️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# API Keys (Optional - for enhanced threat intelligence)
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key

# Scanning Configuration
DEFAULT_TIMEOUT=5000
MAX_CONCURRENT_SCANS=100

# Stealth Configuration
DEFAULT_STEALTH_LEVEL=medium
ENABLE_DECOY_TRAFFIC=false
```

### Custom Configuration

Create `.scorpion/config.json` in your home directory:

```json
{
  "scanner": {
    "timeout": 5000,
    "maxConcurrent": 100,
    "defaultStealthLevel": "medium"
  },
  "threatIntel": {
    "updateInterval": 3600,
    "feedSources": ["custom-feed-url"]
  },
  "output": {
    "defaultFormat": "json",
    "saveDirectory": "./results"
  }
}
```

## 📁 Project Structure

```
scorpion/
├── cli/
│   ├── scorpion.js              # Main CLI entry point
│   ├── lib/
│   │   ├── scanner.js           # Vulnerability scanner
│   │   ├── recon.js             # Network reconnaissance
│   │   ├── exploit-framework.js # Exploit testing
│   │   ├── threat-intel.js      # Threat intelligence
│   │   ├── password-security.js # Password tools
│   │   └── reporter.js          # Report generation
│   └── data/                    # Scan data and results
├── tools/                       # Helper scripts
├── results/                     # Scan output directory
└── logs/                        # Application logs
```

## 🎯 Use Cases

### **Penetration Testing**
```bash
# Comprehensive target assessment
scorpion recon -t target.com --full
scorpion scan -t target.com --type deep --stealth ninja
scorpion exploit -t target.com --payload owasp-top10
```

### **Security Monitoring**
```bash
# Monitor critical systems with threat intelligence
scorpion threat-intel -i 192.168.1.100
scorpion scan -t internal-server.com --type deep
```

### **Threat Hunting**
```bash
# Investigate suspicious indicators
scorpion threat-intel -i 192.168.1.100
scorpion threat-intel -d suspicious.com
```

### **Compliance Auditing**
```bash
# Security assessment
scorpion scan -t internal-server.com --type compliance
scorpion password -f user-hashes.txt -w common-passwords.txt
```

## 🥷 Stealth Capabilities

### Stealth Levels

| Level | Description | Detection Probability | Use Case |
|-------|-------------|----------------------|----------|
| **low** | Fast scanning, no evasion | High (~70%) | Internal testing |
| **medium** | Basic timing randomization | Medium (~45%) | General testing |
| **high** | Advanced evasion techniques | Low (~25%) | External testing |
| **ninja** | Maximum stealth, slowest | Very Low (<15%) | Red team ops |

### Evasion Techniques

- **User-Agent Rotation**: 50+ realistic browser signatures
- **Timing Randomization**: Variable delays with jitter
- **Decoy Traffic**: False positive generation
- **Packet Fragmentation**: TCP segment splitting
- **Connection Pooling**: Reduced network fingerprints
- **Anti-Detection**: IDS/IPS evasion patterns

## 🔒 Security Considerations

### **Authorized Use Only**
- Only use on systems you own or have explicit permission to test
- Unauthorized scanning may be illegal in your jurisdiction
- Always obtain written authorization before testing

### **Rate Limiting**
- Be mindful of scan rates to avoid overwhelming targets
- Use appropriate stealth levels for the environment
- Consider network bandwidth and target system load

### **Data Protection**
- Scan results may contain sensitive information
- Store results securely and encrypt if necessary
- Review and sanitize logs before sharing

### **API Keys**
- Store API keys securely in environment variables
- Never commit API keys to version control
- Rotate keys regularly

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**IMPORTANT**: This tool is for educational and authorized security testing purposes only. 

- Users are responsible for complying with all applicable laws and regulations
- Unauthorized use of this tool may result in criminal and/or civil penalties
- The developers assume no liability for misuse or damage caused by this software
- Always obtain explicit written permission before testing any systems you do not own

## 🆘 Support

- **Issues**: Report bugs on [GitHub Issues](https://github.com/Prince12sam/Scorpion/issues)
- **Documentation**: Check the `/docs` directory
- **Security**: Report security vulnerabilities privately

## 🙏 Acknowledgments

- OWASP Foundation for vulnerability testing frameworks
- The security research community for exploit techniques
- All contributors who have helped improve this tool

---

**Made with ❤️ for the cybersecurity community**

*"Hunt threats before they hunt you"* 🦂

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

#### Token Storage Keys
Isolate browser storage between environments by overriding the localStorage keys used by the UI:

```env
VITE_SCORPION_ACCESS_TOKEN_KEY=scorpion_access_token_dev
VITE_SCORPION_REFRESH_TOKEN_KEY=scorpion_refresh_token_dev
```
Define the variables in `.env` or `.env.local` so build artifacts pick them up.

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
# Monitor critical systems with threat intelligence
scorpion threat-intel -i 192.168.1.100
scorpion scan -t internal-server.com --type deep
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
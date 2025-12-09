# Scorpion CLI Security Tool 🦂

> Consolidation Notice (Dec 2025)
>
> - Primary CLI: Python Scorpion (`scorpion`) — cross‑platform, production‑ready.
> - Python CLI is the primary and only supported entrypoint.
> - Feature coverage: Python CLI includes scan, ssl-analyze, takeover, api-test, recon, dirbust, tech, crawl, suite/report, plus cloud, k8s, and container checks with passive/active-safe OWASP coverage.
> - Safer by default: TLS verification on, no exploit payloads by default; active tests gated by flags.
> - Linux Quickstart below shows install and test commands across common distros.

Migration guide removed; repository is Python-only.

[![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)](https://github.com/Prince12sam/Scorpion)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/Prince12sam/Scorpion)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen.svg)](https://nodejs.org/)

**🔒 Professional Command-Line Security Testing & Threat-Hunting Platform**

## Primary CLI: Python Scorpion

- Install: see `tools/python_scorpion/README.md` (or run `pip install -r tools/python_scorpion/requirements.txt` and add `scorpion` to PATH if installed as console script).
- Key commands:
  - `scorpion scan|suite|report|ssl-analyze|takeover|api-test|recon|dirbust|tech|crawl|cloud|k8s|container`
  - Modes: `--mode passive|active`, safety caps: `--safe-mode`, `--max-requests`, `--rate-limit`

### Linux Quickstart

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip git curl
cd ~/Scorpion
python3 -m pip install -r tools/python_scorpion/requirements.txt

# Run a passive web suite and generate report
scorpion --no-banner suite -t example.com --profile web --mode passive --output results/
latest=$(ls -t results/suite_example.com_*.json | head -n1)
scorpion --no-banner report --suite "$latest" --output results/suite_example_web_passive.html
```

> Note: The Node CLI has been removed. Use the Python CLI `scorpion`.

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
python -m pip install -e tools/python_scorpion
```

### Basic Usage

```bash
# Display help
scorpion --help

# Scan a target
scorpion scan -t example.com --ports 1-1000

# Network reconnaissance
scorpion recon -t example.com --dns --whois

# Active-safe web checks (Python)
scorpion suite example.com --profile web --mode active --output-dir results
# Use Python suite for active-safe checks
# scorpion suite example.com --profile web --mode active --output-dir results
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
scorpion --help  # Python CLI help

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

### Exploit Testing (Legacy Node) and Python Alternative

```bash
# OWASP Top 10 testing
scorpion-node exploit -t example.com --payload owasp-top10  # legacy

# Test specific vulnerability types
scorpion-node exploit -t example.com --payload sql-injection  # legacy
scorpion-node exploit -t example.com --payload xss  # legacy
scorpion-node exploit -t example.com --payload ssrf  # legacy

# Test broken access control
scorpion-node exploit -t example.com --payload broken-access-control  # legacy

# Cloud-specific exploits
scorpion-node exploit -t example.com --payload aws  # legacy
scorpion-node exploit -t example.com --payload azure  # legacy
scorpion-node exploit -t example.com --payload gcp  # legacy
scorpion-node exploit -t example.com --payload cloud  # legacy

# All available payloads
scorpion-node exploit -t example.com --payload all  # legacy

# Target specific service
scorpion-node exploit -t example.com --service http -p 8080  # legacy
scorpion-node exploit -t example.com --service ssh -p 22  # legacy

# Exploitation modes
scorpion-node exploit -t example.com --mode reconnaissance  # legacy
scorpion-node exploit -t example.com --mode proof-of-concept  # legacy
scorpion-node exploit -t example.com --mode full-exploitation  # legacy

# Target specific CVE
scorpion-node exploit -t example.com --vuln CVE-2021-44228  # legacy

# Output results
scorpion suite example.com --profile web --mode active --output-dir results
```

### Threat Intelligence

```bash
# Check IP reputation
Use external TI services (e.g., VirusTotal, AbuseIPDB, Shodan) alongside Scorpion outputs.

# Check domain reputation
Example: use vendor CLI/APIs. Scorpion does not ship TI lookups.

# Verify file hash (MD5, SHA-1, SHA-256)
Example: hash reputation via VirusTotal API.

# List all indicators of compromise
Threat intel examples removed; see `MIGRATION_NODE_TO_PYTHON.md` for guidance.
```

### Enterprise Assessment (Python Suite)

```bash
# Comprehensive enterprise scan
scorpion suite 192.168.1.0/24 --profile full --output-dir results

# Multiple targets
scorpion suite 192.168.1.1 --profile full --output-dir results
scorpion suite 192.168.1.2 --profile full --output-dir results
scorpion suite 192.168.1.3 --profile full --output-dir results

# Scan from file
echo "Run suite per target in targets.txt"  # one-liner scripting recommended

# Internal network only
scorpion suite 10.0.0.0/8 --profile full --output-dir results

# External network only
scorpion suite example.com --profile full --output-dir results

# Deep vulnerability analysis
scorpion suite 192.168.1.0/24 --profile full --mode active --output-dir results

# Authenticated scanning
echo "Use authenticated checks via environment/headers as appropriate"

# Compliance assessment
echo "Map findings to compliance in reports"

# Custom thread count
echo "Tune concurrency via --concurrency in Python modules"

# Safe mode (no exploits)
scorpion suite 192.168.1.0/24 --profile full --safe-mode --output-dir results

# Output results
echo "Suite outputs per target saved under results/"
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

### Python CLI (Heavy-weight)

The Python high-concurrency variant lives under `tools/python_scorpion` and provides core commands for fast network and web testing.

```powershell
# Setup (Windows PowerShell)
cd "c:\Users\prince.sam_dubizzle\Downloads\open_project\tools\python_scorpion"
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install typer rich httpx dnspython cryptography python-whois
pip install -e .

# Commands
scorpion scan dubizzle.com --ports 1-1024 --concurrency 300 --timeout 1.0
scorpion ssl-analyze dubizzle.com --port 443 --output ..\..\results\ssl_dubizzle_python.json
scorpion takeover dubizzle.com --output ..\..\results\takeover_dubizzle_python.json
scorpion api-test dubizzle.com --output ..\..\results\api_dubizzle_python.json
scorpion recon-cmd dubizzle.com --output ..\..\results\recon_dubizzle_python.json
```

Outputs follow the enhanced reporting format with Location, Impact, Remediation, and Severity, saved under `results/`.

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
scorpion suite target.com --profile web --mode active --output-dir results
```

### **Security Monitoring**
```bash
# Monitor critical systems with threat intelligence
Use vendor TI tools (VirusTotal/AbuseIPDB/Shodan) as appropriate.
scorpion scan -t internal-server.com --type deep
```

### **Threat Hunting**
```bash
# Investigate suspicious indicators
scorpion-node threat-intel -i 192.168.1.100  # legacy
scorpion-node threat-intel -d suspicious.com  # legacy
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
scorpion-node threat-intel -i 8.8.8.8  # legacy

# Check domain reputation
scorpion-node threat-intel -d suspicious-domain.com  # legacy

# Check file hash
scorpion-node threat-intel -h 5d41402abc4b2a76b9719d911017c592  # legacy

# List current IOCs
scorpion-node threat-intel --ioc  # legacy
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
scorpion-node threat-intel -i 192.168.1.100  # legacy
scorpion scan -t internal-server.com --type deep
```

### **Threat Hunting**
```bash
# Investigate suspicious indicators
Use vendor TI tools; Scorpion focuses on scanning, recon, SSL, API tests, and suite.
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
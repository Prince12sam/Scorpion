# Scorpion CLI Security Tool 🦂

[![Version](https://img.shields.io/badge/version-2.0.2-blue.svg)](https://github.com/Prince12sam/Scorpion)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/Prince12sam/Scorpion)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org/)

**Professional Command-Line Security Testing & Threat-Hunting Platform**

> Modern Python CLI with comprehensive vulnerability scanning, AI-powered penetration testing, and automated reporting.

---

## 📋 Prerequisites

- **Python 3.10 or higher**
- pip (Python package manager)
- Git

```bash
python --version    # Must be 3.10+
pip --version
git --version
```

---

## 🚀 Quick Install

```bash
# Clone repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# Install (Linux/macOS)
python3 -m venv .venv
source .venv/bin/activate
pip install -e tools/python_scorpion

# Install (Windows)
python -m venv .venv
.venv\Scripts\activate
pip install -e tools/python_scorpion

# Verify
scorpion --version
```

📖 **Detailed guides:**
- **Installation:** [INSTALLATION.md](INSTALLATION.md) - All platforms
- **Getting Started:** [GETTING_STARTED.md](GETTING_STARTED.md)

---

## ⚡ Quick Start

```bash
# Scan ALL 65535 ports (aggressive default, only shows open ports)
scorpion scan -t example.com

# Fast web scan
scorpion scan -t example.com --fast --web

# SSL/TLS analysis
scorpion ssl-analyze -t example.com -p 443

# Comprehensive suite
scorpion suite -t example.com --profile web --output-dir results
```

---

## ✨ Key Features

### 🎯 **Aggressive Port Scanning (Default)**
- **ALL 65535 ports** scanned by default
- Shows only **open ports** (like `nmap --open`)
- **500 concurrent probes** for fast scanning
- Multiple scan types: TCP, SYN, FIN, XMAS, NULL, ACK, UDP
- Service version detection & OS fingerprinting

```bash
# Default: scans all ports, shows only open
scorpion scan -t target.com

# Ultra-fast (1000 concurrency)
scorpion scan -t target.com --fast

# Stealth SYN scan (requires root)
sudo scorpion scan -t target.com --syn
```

📖 **Full guide:** [AGGRESSIVE_SCANNING.md](AGGRESSIVE_SCANNING.md)

---

### 🤖 **AI-Powered Penetration Testing**
Autonomous vulnerability discovery using OpenAI, Anthropic, or GitHub Models (FREE!):

- **OWASP Top 10** comprehensive testing
- **API Security** (REST, GraphQL, JWT)
- **Intelligent exploitation** with context-aware payloads
- **Autonomous testing** with minimal human intervention
- **⚡ FAST MODE** - 6x faster exploitation (5-10 minutes)
- **🔥 AGGRESSIVE MODE** - Maximum aggression for shell access

```bash
# Set API key (auto-detects provider)
export SCORPION_AI_API_KEY='your-api-key'

# Standard AI pentest
scorpion ai-pentest -t example.com

# 🔥 AGGRESSIVE MODE (gain shell access)
scorpion ai-pentest -t target.com -r high -g gain_shell_access \
  -a fully_autonomous --max-iterations 50

# ⚡ TURBO MODE (6x faster - 5-10 minutes!)
scorpion ai-pentest -t target.com -r high -g gain_shell_access \
  -a fully_autonomous --max-iterations 40 --time-limit 10

# FREE with GitHub Models (no credit card!)
export SCORPION_AI_API_KEY='ghp_your_github_token'
scorpion ai-pentest -t target.com
```

📖 **Guides:**
- [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md) - Complete AI testing guide
- [AGGRESSIVE_EXPLOITATION.md](AGGRESSIVE_EXPLOITATION.md) - 🔥 Gain shell access
- [FAST_MODE.md](FAST_MODE.md) - ⚡ 6x faster exploitation

---

### 🔍 **Web Vulnerability Scanning**
Comprehensive OWASP Top 10 testing:

- SQL Injection (error-based, time-based, boolean-based)
- Cross-Site Scripting (XSS)
- Command Injection
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Server-Side Template Injection (SSTI)
- Security headers & CORS

```bash
# Full web vulnerability scan
scorpion webscan https://target.com/page?id=1

# Filter critical vulnerabilities
scorpion webscan https://target.com -s critical

# Save results
scorpion webscan https://target.com -o web-vulns.json
```

📖 **Full guide:** [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md)

---

### 🛡️ **Security Analysis**

**SSL/TLS Analysis:**
```bash
scorpion ssl-analyze -t example.com -p 443
```

**Subdomain Enumeration:**
```bash
scorpion subdomain example.com --http
```

**Subdomain Takeover Detection:**
```bash
scorpion takeover -t example.com
```

**API Security Testing:**
```bash
scorpion api-test -t https://api.example.com
```

---

### 🎭 **Advanced Features**

**📡 WiFi Penetration Testing:**
```bash
# Scan WiFi networks
scorpion wifi-scan --interface wlan0 --duration 30

# WPA handshake capture
scorpion wifi-attack <ESSID> <BSSID> --type handshake

# Deauth attack
scorpion wifi-attack <ESSID> <BSSID> --type deauth --count 10
```

**📱 Mobile App Security:**
```bash
# Analyze Android APK (OWASP Mobile Top 10)
scorpion mobile-analyze app.apk --owasp --output report.json

# Bypass SSL pinning with Frida
scorpion mobile-intercept com.example.app --proxy 127.0.0.1:8080
```

**🎯 Fuzzing Framework:**
```bash
# Fuzz network protocol
scorpion fuzz-protocol 192.168.1.100 80 --protocol http --iterations 1000

# Fuzz REST API
scorpion fuzz-api https://api.target.com /login --method POST --iterations 500
```

**Decoy Scanning (IDS/IPS Evasion):**
```bash
# Random decoys (requires root)
sudo scorpion scan target.com --syn --decoy RND:10
```


**Payload Generation:**
```bash
# Reverse shells
scorpion payload --lhost 10.0.0.1 --lport 4444 --shell bash

# Web shells
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php
```


**OS Fingerprinting:**
```bash
scorpion scan example.com --os-detect --web
```


---

## 📖 Complete Documentation

| Guide | Description |
|-------|-------------|
| [GETTING_STARTED.md](GETTING_STARTED.md) | 5-minute quick start guide |
| [INSTALLATION.md](INSTALLATION.md) | Installation for all platforms |
| [COMMANDS.md](COMMANDS.md) | Complete command reference (35+ commands) |
| [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md) | Complete AI penetration testing guide |
| [AGGRESSIVE_EXPLOITATION.md](AGGRESSIVE_EXPLOITATION.md) | 🔥 Maximum aggression for shell access |
| [FAST_MODE.md](FAST_MODE.md) | ⚡ Speed optimizations (6x faster) |
| [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md) | WiFi, Mobile, Fuzzing guides |

📑 **All documentation:** [DOCS_INDEX.md](DOCS_INDEX.md)

---

## 🔒 Security & Legal

⚠️ **IMPORTANT:** Use Scorpion only on systems you own or have explicit written authorization to test.

- ✅ Authorized penetration testing
- ✅ Security research with permission
- ✅ Educational purposes on your own systems
- ❌ Unauthorized scanning is **illegal**
- ❌ Testing without permission

**Always:**
- Get written authorization before testing
- Respect rate limits and system resources
- Follow responsible disclosure practices
- Review local laws and regulations

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🆘 Support

- **Documentation:** [DOCS_INDEX.md](DOCS_INDEX.md)
- **Issues:** [GitHub Issues](https://github.com/Prince12sam/Scorpion/issues)
- **Command Help:** `scorpion --help` or `scorpion <command> --help`

---

**Made with ❤️ for the cybersecurity community**

"Hunt threats before they hunt you" 🦂

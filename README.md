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
- **Linux:** [INSTALL_LINUX.md](INSTALL_LINUX.md)
- **Windows:** [INSTALL.md](INSTALL.md)
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

```bash
# Set API key (auto-detects provider)
export SCORPION_AI_API_KEY='your-api-key'

# AI-powered pentest
scorpion ai-pentest -t example.com

# OWASP Top 10 focus
scorpion ai-pentest -t target.com -g web_exploitation -r medium

# FREE with GitHub Models (no credit card!)
export SCORPION_AI_API_KEY='ghp_your_github_token'
scorpion ai-pentest -t target.com
```

📖 **Setup guides:**
- [API_KEY_SETUP.md](API_KEY_SETUP.md) - All providers
- [GITHUB_MODELS_SETUP.md](GITHUB_MODELS_SETUP.md) - FREE AI in 2 minutes!

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

📖 **Full guide:** [WEB_PENTESTING_GUIDE.md](WEB_PENTESTING_GUIDE.md)

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

**Decoy Scanning (IDS/IPS Evasion):**
```bash
# Random decoys (requires root)
sudo scorpion scan target.com --syn --decoy RND:10
```
📖 [DECOY_SCANNING_GUIDE.md](DECOY_SCANNING_GUIDE.md)

**Payload Generation:**
```bash
# Reverse shells
scorpion payload --lhost 10.0.0.1 --lport 4444 --shell bash

# Web shells
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php
```
📖 [PAYLOAD_GENERATION_GUIDE.md](PAYLOAD_GENERATION_GUIDE.md)

**OS Fingerprinting:**
```bash
scorpion scan example.com --os-detect --web
```
📖 [OS_FINGERPRINTING_GUIDE.md](OS_FINGERPRINTING_GUIDE.md)

---

## 📖 Complete Documentation

| Guide | Description |
|-------|-------------|
| [GETTING_STARTED.md](GETTING_STARTED.md) | 5-minute quick start guide |
| [COMMANDS.md](COMMANDS.md) | Complete command reference |
| [AGGRESSIVE_SCANNING.md](AGGRESSIVE_SCANNING.md) | Port scanning best practices |
| [WEB_PENTESTING_GUIDE.md](WEB_PENTESTING_GUIDE.md) | Web security testing |
| [AI_AGENT_ENHANCED_GUIDE.md](AI_AGENT_ENHANCED_GUIDE.md) | AI-powered testing |
| [API_KEY_SETUP.md](API_KEY_SETUP.md) | Configure AI providers |
| [INSTALL_LINUX.md](INSTALL_LINUX.md) | Linux installation |
| [INSTALL.md](INSTALL.md) | Windows installation |

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

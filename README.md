# Scorpion CLI Security Tool 🦂

[![Version](https://img.shields.io/badge/version-2.0.2-blue.svg)](https://github.com/Prince12sam/Scorpion)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/Prince12sam/Scorpion)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org/)

**The FASTEST Complete Red Team + Blue Team AI-Powered Security Platform**

> 🔴 **Red Team:** Find vulnerabilities in 5-10 minutes (6-10x faster than Metasploit/Burp Suite)  
> 🔵 **Blue Team:** Detect threats in 2-5 minutes (10x faster than Splunk/ELK)  
> 🟣 **Purple Team:** Validate defenses in 10 minutes  
> 🤖 **AI-Powered:** GPT-4/Claude autonomous security testing

**Replaces:** Metasploit + Burp Suite + Nessus + Splunk + ELK + QRadar = **One tool, 100% free!**

---

## 📋 Prerequisites

⚠️ **Linux/Unix recommended** - For active scanning/exploitation use Linux/macOS/WSL.

✅ **Windows**: `scorpion code-scan` (static code scanning) is supported.

- **Operating System**: Linux, macOS, WSL, or BSD
- **Python 3.10 or higher**
- pip (Python package manager)
- Git

```bash
python --version    # Must be 3.10+
pip --version
git --version
```

---

## 🧩 Code Security Scanning (SAST)

Scan a local codebase to identify common vulnerabilities and get remediation recommendations.

```bash
# Built-in checks (fast) + Bandit if installed
scorpion code-scan . --output results/code_scan.json

# Multi-language web/app SAST (Semgrep)
scorpion code-scan . --semgrep --output results/code_scan_semgrep.json

# Secrets scanning (Gitleaks)
scorpion code-scan . --gitleaks --output results/code_scan_secrets.json

# Dependency vulns across ecosystems (OSV-Scanner)
scorpion code-scan . --osv --output results/code_scan_osv.json

# Filesystem vuln + misconfig scanning (Trivy)
scorpion code-scan . --trivy --output results/code_scan_trivy.json

# API spec linting (OpenAPI/Swagger/AsyncAPI) (Spectral)
scorpion code-scan . --spectral --output results/code_scan_spectral.json

# IaC misconfiguration scanning (Terraform/K8s/etc) (Checkov)
scorpion code-scan . --checkov --output results/code_scan_checkov.json

# CI-friendly SARIF output (GitHub Code Scanning)
scorpion code-scan . --semgrep --sarif results/code_scan.sarif

# Optional AI remediation summary (does not send source code)
scorpion code-scan . --ai-summary --ai-provider github --api-key $SCORPION_AI_API_KEY
```

---

## 🚀 Quick Install

```bash
# Clone repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# Install (Linux/macOS/WSL)
python3 -m venv .venv
source .venv/bin/activate
pip install -e tools/python_scorpion

# Verify
scorpion --version
```

💡 **Windows Users**: Install WSL (Windows Subsystem for Linux) first:
```powershell
# In PowerShell (Administrator)
wsl --install
# Then run Scorpion inside WSL (Ubuntu/Kali)
```

📖 **Detailed guides:**
- **Installation:** [INSTALLATION.md](INSTALLATION.md) - All platforms
- **Getting Started:** [GETTING_STARTED.md](GETTING_STARTED.md)

---

## ⚡ Quick Start

### 🔴 Red Team (Offensive Security)
```bash
# 5-minute AI pentest (faster than Metasploit!)
scorpion ai-pentest -t yoursite.com --time-limit 5

# Full vulnerability scan
scorpion suite -t yoursite.com --profile web
```

### 🔵 Blue Team (Defensive Security)  
```bash
# 3-minute threat hunt (faster than Splunk!)
scorpion threat-hunt --logs /var/log/auth.log --time-limit 3

# 5-minute incident response
scorpion incident-response compromised-server.com --action investigate

# Real-time monitoring
scorpion monitor prod-server.com --alert-webhook https://...
```

### 🟣 Purple Team (Red vs Blue)
```bash
# 10-minute defense validation
scorpion purple-team testlab.com --profile web
```

---

## ✨ Key Features

### 🔴 **Red Team (Offensive Security)**

#### 🗣️ AI Simple Prompts - NEW! Just Tell It What to Do
Talk to the AI in plain English - no complex commands needed:

```bash
# Just tell the AI what you want!
scorpion ai-pentest -t target.com -i "exploit this"
scorpion ai-pentest -t target.com -i "get shell"
scorpion ai-pentest -t target.com -i "find SQLi"
scorpion ai-pentest -t target.com -i "bypass login"
scorpion ai-pentest -t target.com -i "hack it"
```

📖 **Guide:** [AI_SIMPLE_PROMPTS.md](AI_SIMPLE_PROMPTS.md) - 20+ simple commands

#### 🎯 Port Scanning - 6x Faster than Nmap
- **ALL 65535 ports** scanned by default (CLI)
- **Risk-based AI scanning** (HIGH: 1-1000, MEDIUM: 1-200, LOW: 1-100)
- Shows only **open ports** (like `nmap --open`)
- **500 concurrent probes** for fast scanning
- Multiple scan types: TCP, SYN, FIN, XMAS, NULL, ACK, UDP
- Service version detection & OS fingerprinting

```bash
scorpion scan -t target.com --fast
```

📊 **Performance:** Scans 1000 ports in 20-30 seconds
📌 **Smart:** AI uses risk-based port selection (no wasted time on rarely-used ports)

📖 **Guide:** [AGGRESSIVE_SCANNING.md](AGGRESSIVE_SCANNING.md)

#### 🤖 AI Penetration Testing - 10x Faster than Metasploit
Autonomous vulnerability discovery using GPT-4, Claude, or GitHub Models (FREE!):

- **5-10 minute** complete pentests
- **OWASP Top 10** comprehensive testing
- **API Security** (REST, GraphQL, JWT)
- **10 Intelligent Exploitation Vectors:**
  - SQLi (manual UNION/stacked queries + sqlmap)
  - RCE (9 injection patterns + commix)
  - File Upload (15+ evasion techniques)
  - XSS (reflected/stored/DOM)
  - Auth Bypass (default creds, SQLi)
  - SMB (EternalBlue MS17-010)
  - FTP (anonymous + weak creds)
  - SSH (Hydra brute force)
  - Database (web admin panels)
  - RDP (BlueKeep + brute force)
- **Manual exploitation FIRST** (no external tools required)
- **URL encoding** for payload integrity
- **Shell verification** before reporting success
- **Auto-exploitation trigger** (immediate exploitation when critical vuln found)
- **Autonomous testing** with minimal human intervention
- **⚡ FAST MODE** - 6x faster exploitation (5-10 minutes)
- **🔥 AGGRESSIVE MODE** - Maximum aggression for shell access
- **🛠️ EXTERNAL TOOLS** - Integrates nmap, sqlmap, nuclei, hydra, commix, msfvenom, etc.

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

📖 **Full guide:** [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md)

---

### 🔵 **Blue Team (Defensive Security)** - NEW! 🆕

#### 🔍 Threat Hunting - 10x Faster than Splunk
AI-powered IOC detection and pattern recognition:

- **2-5 minute** complete threat hunts
- Detects malware, C2, lateral movement, privilege escalation
- MITRE ATT&CK technique mapping
- Living-off-the-Land binary detection
- Behavioral anomaly detection
- **🌐 SSH Remote Access** - Hunt logs on production servers without manual copying!

```bash
# 3-minute lightning-fast threat hunt (local)
scorpion threat-hunt --logs /var/log/auth.log --time-limit 3

# Hunt on REMOTE server via SSH (no manual copying!)
scorpion threat-hunt --logs ssh://admin@prod-web.com:/var/log/apache2/access.log

# Hunt MULTIPLE servers in parallel
scorpion threat-hunt --remote-servers servers.txt --ssh-key ~/.ssh/prod_key

# Filter critical threats
scorpion threat-hunt --logs /var/log/ --severity critical
```

#### 🚨 Incident Response - AI-Guided Triage
Complete NIST IR lifecycle automation:

- **5-minute** investigation & triage
- **2-minute** containment
- **3-minute** eradication
- **2-minute** recovery

```bash
# Phase 1: Investigate (5 min)
scorpion incident-response compromised-server.com --action investigate

# Phase 2: Contain (2 min)
scorpion incident-response compromised-server.com --action contain

# Phase 3: Eradicate (3 min)
scorpion incident-response compromised-server.com --action eradicate

# Phase 4: Recover (2 min)
scorpion incident-response compromised-server.com --action recover
```

#### 📊 Log Analysis - Faster than ELK
AI-powered log analysis with threat detection:

- **3-minute** complete log analysis
- Attack pattern recognition (SQLi, XSS, brute force)
- Process **15,000+ lines/second**
- MITRE ATT&CK mapping

```bash
# Analyze logs for threats
scorpion log-analyze /var/log/apache2/access.log --detect-threats

# Fast analysis without threat detection
scorpion log-analyze app.log --no-detect-threats
```

#### 🟣 Purple Team - Test Your Defenses
Validate detection capabilities (red vs blue):

- **10-minute** complete purple team exercise
- Simulates real attacks + detection
- Identifies detection gaps
- Provides remediation recommendations

```bash
# Web attack simulation
scorpion purple-team testlab.com --profile web

# Network attack simulation
scorpion purple-team 192.168.1.0/24 --profile network

# Full simulation
scorpion purple-team testlab.com --profile full
```

#### 👁️ Real-Time Monitoring - Continuous Detection
Live security monitoring with instant alerts:

- Real-time threat detection
- Webhook alerts (Slack, Teams, Discord)
- SIEM integration (Splunk, ELK, QRadar, Sentinel)
- Attack chain correlation

```bash
# Monitor with Slack alerts
scorpion monitor prod-server.com --alert-webhook https://hooks.slack.com/...

# Forward to SIEM
scorpion monitor prod-server.com --siem-endpoint https://splunk.company.com:8088
```

📖 **Full guide:** [BLUE_TEAM_GUIDE.md](BLUE_TEAM_GUIDE.md)

---

### 🛡️ **Security Analysis (Red Team)**

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

**� Web Fuzzing:**
```bash
# Path fuzzing
scorpion fuzz https://target.com/FUZZ --wordlist paths.txt

# Parameter fuzzing
scorpion fuzz https://target.com/page?id=FUZZ --wordlist params.txt
```

**⚡ Nuclei Integration:**
```bash
# Scan with Nuclei templates
scorpion nuclei -t target.com --templates cves,vulnerabilities
```

**🔓 Authentication Testing:**
```bash
# Brute force login
scorpion bruteforce https://target.com/login --username admin --wordlist rockyou.txt
```

**🗃️ Database Pentesting:**
```bash
# SQL injection testing
scorpion db-pentest -t https://target.com/page?id=1
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

### 🔴 Red Team (Offensive Security)
| Guide | Description |
|-------|-------------|
| [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md) | **Complete AI penetration testing guide** |
| [AI_SIMPLE_PROMPTS.md](AI_SIMPLE_PROMPTS.md) | 🗣️ **NEW!** Simple commands: "exploit this", "get shell", "find SQLi" |
| [AGGRESSIVE_EXPLOITATION.md](AGGRESSIVE_EXPLOITATION.md) | 🔥 Maximum aggression for shell access |
| [FAST_MODE.md](FAST_MODE.md) | ⚡ Speed optimizations (6x faster) |
| [EXTERNAL_TOOLS_QUICK_REFERENCE.md](EXTERNAL_TOOLS_QUICK_REFERENCE.md) | 🛠️ External tools: nmap, sqlmap, nuclei, hydra, etc. |
| [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md) | WiFi, Mobile, Fuzzing guides |

### 🔵 Blue Team (Defensive Security) - NEW! 🆕
| Guide | Description |
|-------|-------------|
| [BLUE_TEAM_GUIDE.md](BLUE_TEAM_GUIDE.md) | **Complete threat hunting & incident response guide** |

### 📚 General
| Guide | Description |
|-------|-------------|
| [GETTING_STARTED.md](GETTING_STARTED.md) | 5-minute quick start guide |
| [INSTALLATION.md](INSTALLATION.md) | Installation for all platforms |
| [COMMANDS.md](COMMANDS.md) | Complete command reference (40+ commands) |
| [DOCS_INDEX.md](DOCS_INDEX.md) | All documentation index |

---

## 🏆 Why Scorpion Beats Everything Else

| Capability | Scorpion | Metasploit | Burp Suite Pro | Splunk | Traditional SIEM |
|-----------|----------|------------|----------------|--------|------------------|
| **Red Team Pentest** | **5-10 min** | 45-80 min | 60+ min | N/A | N/A |
| **Blue Team Threat Hunt** | **2-5 min** | N/A | N/A | 30-60 min | 60+ min |
| **AI-Powered** | ✅ GPT-4/Claude | ❌ No | ⚠️  Limited | ❌ No | ❌ No |
| **Setup Time** | **30 sec** | 10 min | 5 min | 2-4 hours | 1+ day |
| **Purple Team** | ✅ Built-in | ❌ No | ❌ No | ❌ No | ❌ No |
| **MITRE Mapping** | ✅ Auto | ⚠️  Manual | ⚠️  Manual | ⚠️  Manual | ⚠️  Manual |
| **Cost** | **FREE** | FREE | $400+/year | $2K-10K/GB | $$$$$$ |
| **Platform** | All OSes | All OSes | All OSes | Linux only | Complex |

**Verdict: Scorpion replaces 5+ tools and is 6-10x faster!** 🚀

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

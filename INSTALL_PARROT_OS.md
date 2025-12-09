# Installing Scorpion CLI on Parrot OS

**Quick Guide for Security Testers**

---

## 🚀 Quick Installation (5 Minutes)

### Prerequisites

Parrot OS comes with most tools pre-installed. You just need Python 3.10+:

```bash
# Check if Python is installed
python3 --version

# If not installed or version < 3.10, install it:
sudo apt update
sudo apt install -y python3 python3-pip

# Verify installation
python3 --version  # Should show 3.10 or higher
```

---

## 📥 Installation Steps

### Step 1: Clone from GitHub

```bash
# Clone the repository
git clone https://github.com/Prince12sam/Scorpion.git

# Navigate to directory
cd Scorpion
```

### Step 2: Install Python Scorpion CLI

```bash
# Install the Python CLI (editable dev install)
python3 -m pip install --upgrade pip
python3 -m pip install -e tools/python_scorpion
```

### Step 3: Verify CLI

```bash
# Verify Python CLI is available
scorpion --help
scorpion --version
```

### Step 4: (Optional) Virtualenv

```bash
# Create and activate a venv for isolation
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e tools/python_scorpion
```

You should see:
```
╔═══════════════════════════════════════════════════════════════╗
║  ███████╗ ██████╗ ██████╗ ██████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗  ║
║                 Global Threat-Hunting Platform                ║
╚═══════════════════════════════════════════════════════════════╝

2.0.1
```

---

## 🧪 Test Your Installation

### Test 1: Basic Scan

```bash
# Test with placeholders only (do not use unauthorized targets)
scorpion scan -t example.com --ports 80,443
```

### Test 2: Subdomain Takeover Check

```bash
scorpion takeover -t example.com

# Output JSON to a file
scorpion takeover -t example.com -o takeover-results.json
```

### Test 3: API Security Test

```bash
scorpion api-test -t https://api.example.com

# Output JSON to a file
scorpion api-test -t https://api.example.com -o api-report.json
```

### Test 4: SSL/TLS Analysis

```bash
scorpion ssl-analyze -t example.com

# Output JSON to a file
scorpion ssl-analyze -t example.com -o ssl-report.json
```

---

## ⚙️ Configuration (Optional)

### Set Up Config

Some features support optional configuration via `.env`:

```bash
# Create .env file
nano .env
```

Example `.env`:
```env
# Configuration
DEFAULT_TIMEOUT=5000
MAX_CONCURRENT_SCANS=100
```

---

## 🔧 Troubleshooting

### Issue 1: Python/Pip Issues

```bash
# Ensure Python and pip are present
python3 --version
python3 -m pip --version

# Reinstall pip if needed
sudo apt install -y python3-pip
```

### Issue 2: Permission Errors

```bash
# If you get EACCES errors during npm install:
sudo chown -R $USER:$USER ~/.npm
sudo chown -R $USER:$USER /usr/local/lib/node_modules

# Then retry:
npm install
```

### Issue 3: CLI Not Found

```bash
# Ensure install succeeded
python3 -m pip install -e tools/python_scorpion
which scorpion
```

### Issue 4: Port Scanning Requires Root

Some scans need elevated privileges:

```bash
# For SYN scans and OS detection:
sudo scorpion scan -t example.com -sS -O

# OR:
sudo scorpion scan -t example.com -sS -O  # Python CLI
```

---

## 📋 All Available Commands (Python)

```bash
# Help
scorpion --help
scorpion scan --help
scorpion recon --help

# Port Scanning
scorpion scan -t example.com --ports 1-1000
scorpion scan -t example.com --type deep
scorpion scan -t example.com --stealth ninja

# Network Reconnaissance
scorpion recon -t example.com --dns --whois --subdomain

# Subdomain Takeover (NEW)
scorpion takeover -t example.com
scorpion takeover -t example.com --check-aws
scorpion takeover -t example.com -o report.json

# API Security Testing (NEW)
scorpion api-test -t https://api.example.com
scorpion api-test -t https://api.example.com --no-graphql
scorpion api-test -t https://api.example.com -o api-report.json

# SSL/TLS Analysis (NEW)
scorpion ssl-analyze -t example.com
scorpion ssl-analyze -t example.com -p 8443
scorpion ssl-analyze -t example.com -o ssl-report.json

# Web suite (safe active checks)
scorpion suite example.com --profile web --mode active --output-dir results

# Enterprise Scanning (Python)
scorpion suite example.com --profile full --output-dir results

# AI-Powered Penetration Testing
# Use suite/report flow and external tooling
```

---

## 🎯 Quick Test Workflow

### Complete Security Assessment

```bash
# 1. Clone and install
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
python3 -m pip install -e tools/python_scorpion

# 2. Run comprehensive tests (replace example.com with your target)
TARGET="example.com"

# Port scan
scorpion scan -t $TARGET --ports 1-1000 -o scan-results.json

# Reconnaissance
scorpion recon -t $TARGET --dns --subdomain --whois

# Subdomain takeover check
scorpion takeover -t $TARGET -o takeover-results.json

# API security test (if you have an API)
scorpion api-test -t https://api.$TARGET -o api-results.json

# SSL/TLS analysis
scorpion ssl-analyze -t $TARGET -o ssl-results.json

# Active-safe web checks (Python)
scorpion suite $TARGET --profile web --mode active --output-dir results

# View results
ls -lh *-results.json
```

---

## 🐧 Parrot OS Specific Tips

### 1. Use Built-in Tools Together

Parrot OS has many security tools. Combine Scorpion with them:

```bash
# Use with nmap
nmap -p- $TARGET | grep open
scorpion scan -t $TARGET --ports $(nmap -p- $TARGET | grep open | cut -d'/' -f1)

# Use with nikto
scorpion scan -t $TARGET --ports 80,443
nikto -h $TARGET

# Use with sqlmap
scorpion suite $TARGET --profile web --mode active --output-dir results
sqlmap -u "http://$TARGET/page?id=1"  # with permission only
```

### 2. Run as Regular User

Most Scorpion commands don't need root:

```bash
# These work without sudo:
scorpion takeover -t example.com
scorpion api-test -t https://api.example.com
scorpion ssl-analyze -t example.com
scorpion recon -t example.com --dns
```

### 3. Save Results in ~/results

```bash
# Create results directory
mkdir -p ~/results

# Save all reports there
scorpion scan -t example.com -o ~/results/scan.json
scorpion takeover -t example.com -o ~/results/takeover.json
scorpion api-test -t https://api.example.com -o ~/results/api.json
```

---

## 📊 Understanding Output

Scorpion provides detailed vulnerability reports with:

- **📍 Exact Location**: Where the vulnerability is
- **⚠️ Impact**: What can go wrong
- **💡 Remediation**: How to fix it

Example:
```
[!] VULNERABILITY FOUND: Subdomain Takeover
    Subdomain: api.old.example.com
    Service: AWS S3
    
    📍 LOCATION: DNS CNAME record for api.old.example.com
    
    💡 REMEDIATION:
       1. Claim the resource
       2. OR remove the DNS record
```

**See full guide:** [VULNERABILITY_REPORTING.md](VULNERABILITY_REPORTING.md)

---

## 🔐 Security & Ethics

### ⚠️ IMPORTANT: Legal Use Only

```bash
# ✅ DO: Test your own systems
scorpion scan -t your-domain.com

# ✅ DO: Test with written permission
scorpion scan -t client-approved-domain.com

# ❌ DON'T: Test without authorization
# This is ILLEGAL and can result in prosecution
```

### Best Practices

1. **Always get written permission** before testing any system
2. **Document your testing** - Keep logs of what you tested and when
3. **Use appropriate stealth levels** - Don't overwhelm targets
4. **Report findings responsibly** - Follow responsible disclosure

---

## 📚 Documentation

- **Getting Started**: [README.md](README.md)
- **Command Reference**: [COMMANDS.md](COMMANDS.md)
- **Vulnerability Reports**: [VULNERABILITY_REPORTING.md](VULNERABILITY_REPORTING.md)
- **Quick Reference**: [QUICK_REFERENCE.md](QUICK_REFERENCE.md)

---

## 🆘 Need Help?

### Command Help
```bash
scorpion --help
scorpion scan --help
scorpion api-test --help
```

### Check Issues
- GitHub Issues: https://github.com/Prince12sam/Scorpion/issues

### Common Questions

**Q: Do I need root/sudo?**  
A: Most commands work without sudo. Only SYN scans (-sS) and OS detection (-O) need root.

**Q: Can I test any website?**  
A: NO! Only test systems you own or have written permission to test.

**Q: How do I update?**  
A: `cd Scorpion && git pull && npm install`

**Q: Where are results saved?**  
A: Use `-o filename.json` to save results. Default: printed to console.

---

## 🚀 You're Ready!

```bash
# Start testing (with permission!)
scorpion scan -t your-target.com --ports 1-1000
```

**Happy (ethical) hacking! 🦂**

---

**Version**: 2.0.1  
**Platform**: Parrot OS / Debian / Ubuntu / Kali Linux  
**Last Updated**: December 9, 2025

# Installing Scorpion CLI on Parrot OS

**Quick Guide for Security Testers**

---

## 🚀 Quick Installation (5 Minutes)

### Prerequisites

Parrot OS comes with most tools pre-installed. You just need Node.js:

```bash
# Check if Node.js is installed
node --version

# If not installed or version < 16, install it:
sudo apt update
sudo apt install -y nodejs npm

# Verify installation
node --version  # Should show v16.0.0 or higher
npm --version
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

### Step 2: Install Dependencies

```bash
# Install all required packages
npm install
```

This installs:
- axios (HTTP client)
- chalk (colored output)
- commander (CLI framework)
- crypto-js (cryptography)
- dotenv (environment variables)
- node-forge (SSL/TLS toolkit)
- ora (progress spinners)

### Step 3: Link CLI Globally (Optional)

```bash
# Make 'scorpion' command available globally
sudo npm link
```

**OR** run directly without linking:
```bash
# Use node to run directly
node cli/scorpion.js --help
```

### Step 4: Verify Installation

```bash
# If you used npm link:
scorpion --version

# OR if running directly:
node cli/scorpion.js --version
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
# Test with a safe target (your own server or localhost)
scorpion scan -t scanme.nmap.org --ports 80,443

# OR without npm link:
node cli/scorpion.js scan -t scanme.nmap.org --ports 80,443
```

### Test 2: Subdomain Takeover Check

```bash
scorpion takeover -t example.com

# OR:
node cli/scorpion.js takeover -t example.com
```

### Test 3: API Security Test

```bash
scorpion api-test -t https://api.example.com

# OR:
node cli/scorpion.js api-test -t https://api.example.com
```

### Test 4: SSL/TLS Analysis

```bash
scorpion ssl-analyze -t example.com

# OR:
node cli/scorpion.js ssl-analyze -t example.com
```

---

## ⚙️ Configuration (Optional)

### Set Up API Keys

Some features work better with API keys (optional but recommended):

```bash
# Create .env file
nano .env
```

Add your API keys:
```env
# Threat Intelligence API Keys (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
SHODAN_API_KEY=your_shodan_key_here

# Configuration
DEFAULT_TIMEOUT=5000
MAX_CONCURRENT_SCANS=100
DEFAULT_STEALTH_LEVEL=medium
```

**Get Free API Keys:**
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- Shodan: https://account.shodan.io/register

---

## 🔧 Troubleshooting

### Issue 1: Node.js Version Too Old

```bash
# Check version
node --version

# If < v16, update using NodeSource:
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Verify
node --version  # Should show v18.x.x or higher
```

### Issue 2: Permission Errors

```bash
# If you get EACCES errors during npm install:
sudo chown -R $USER:$USER ~/.npm
sudo chown -R $USER:$USER /usr/local/lib/node_modules

# Then retry:
npm install
```

### Issue 3: npm link Fails

```bash
# Try with sudo:
sudo npm link

# OR just run directly without linking:
node cli/scorpion.js --help
```

### Issue 4: Port Scanning Requires Root

Some scans need elevated privileges:

```bash
# For SYN scans and OS detection:
sudo scorpion scan -t example.com -sS -O

# OR:
sudo node cli/scorpion.js scan -t example.com -sS -O
```

---

## 📋 All Available Commands

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

# Exploit Testing
scorpion exploit -t example.com --payload owasp-top10
scorpion exploit -t example.com --payload sql-injection

# Threat Intelligence
scorpion threat-intel --ip 8.8.8.8
scorpion threat-intel --domain example.com
scorpion threat-intel --hash <file_hash>

# Enterprise Scanning
scorpion enterprise-scan --targets targets.txt

# AI-Powered Penetration Testing
scorpion ai-pentest -t example.com --mode autonomous
```

---

## 🎯 Quick Test Workflow

### Complete Security Assessment

```bash
# 1. Clone and install
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
npm install
sudo npm link

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

# OWASP Top 10 testing
scorpion exploit -t $TARGET --payload owasp-top10

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
scorpion exploit -t $TARGET --payload sql-injection
sqlmap -u "http://$TARGET/page?id=1"
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
**Last Updated**: December 8, 2025

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

### Test 1: Basic Port Scan

```bash
# Test with web preset (ports 80, 443)
scorpion scan -t example.com --web

# Custom ports
scorpion scan -t example.com -p 80,443,8080 -T 5
```

### Test 2: SSL/TLS Analysis

```bash
scorpion ssl-analyze -t example.com -p 443 -T 5

# Output JSON to a file
scorpion ssl-analyze -t example.com -p 443 --output results/ssl-report.json
```

### Test 3: Reconnaissance

```bash
scorpion recon-cmd -t example.com

# Output JSON to a file
scorpion recon-cmd -t example.com --output results/recon-report.json
```

### Test 4: Directory Discovery

```bash
scorpion dirbust example.com --concurrency 10 --output results/dirb.json
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
# If you get permission errors during pip install:
python3 -m pip install --user -e tools/python_scorpion

# OR use a virtual environment:
python3 -m venv .venv
source .venv/bin/activate
pip install -e tools/python_scorpion
```

### Issue 3: CLI Not Found

```bash
# Ensure install succeeded
python3 -m pip install -e tools/python_scorpion
which scorpion
```

### Issue 4: SYN Scanning Requires Root

SYN scans need elevated privileges and Scapy:

```bash
# Install Scapy
sudo pip install scapy

# Run SYN scan with sudo
sudo scorpion scan -t example.com --syn --web --rate-limit 50

# Optional: specify network interface
sudo scorpion scan -t example.com --syn --web --iface eth0

# List available interfaces
scorpion scan --list-ifaces
```

---

## 📋 All Available Commands

```bash
# Help
scorpion --help
scorpion scan --help
scorpion ssl-analyze --help

# Port Scanning (TCP/UDP)
scorpion scan -t example.com -p 80,443,8080
scorpion scan -t example.com --web          # Preset: ports 80,443
scorpion scan -t example.com --fast         # Preset: quick scan
scorpion scan -t example.com -u 53,161      # UDP scan

# SYN Scan (requires root + scapy)
sudo scorpion scan -t example.com --syn --web --rate-limit 50

# SSL/TLS Analysis
scorpion ssl-analyze -t example.com -p 443 -T 5
scorpion ssl-analyze -t example.com -p 443 --output results/ssl.json

# Reconnaissance
scorpion recon-cmd -t example.com
scorpion recon-cmd -t example.com --output results/recon.json

# Directory Discovery
scorpion dirbust example.com --concurrency 10 --output results/dirb.json

# Technology Detection
scorpion tech example.com --output results/tech.json

# Web Crawling
scorpion crawl example.com --start https://example.com --max-pages 10 --concurrency 4 --output results/crawl.json

# Test Suites
scorpion suite -t example.com --profile web --mode passive --output-dir results
scorpion suite -t example.com --profile infra --mode active --output-dir results

# Generate Reports
scorpion report --suite results/suite_example.com_*.json --summary
scorpion report --suite results/suite_example.com_*.json --format html --output report.html
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
scorpion scan -t $TARGET --web -o results/scan.json

# SSL/TLS analysis
scorpion ssl-analyze -t $TARGET -p 443 -T 5 --output results/ssl.json

# Reconnaissance
scorpion recon-cmd -t $TARGET --output results/recon.json

# Directory discovery
scorpion dirbust $TARGET --concurrency 10 --output results/dirb.json

# Technology detection
scorpion tech $TARGET --output results/tech.json

# Web crawling
scorpion crawl $TARGET --start https://$TARGET --max-pages 10 --output results/crawl.json

# Run test suite
scorpion suite -t $TARGET --profile web --mode passive --output-dir results

# Generate report
latest=$(ls -t results/suite_${TARGET}_*.json | head -n1)
scorpion report --suite "$latest" --summary

# View results
ls -lh results/
```

---

## 🐧 Parrot OS Specific Tips

### 1. Use Built-in Tools Together

Parrot OS has many security tools. Combine Scorpion with them:

```bash
# Use with nmap
nmap -p- $TARGET
scorpion scan -t $TARGET --web

# Use with nikto
scorpion scan -t $TARGET --web
nikto -h $TARGET

# Use with other tools
scorpion suite -t $TARGET --profile web --mode passive --output-dir results
# Then use results for deeper analysis with specialized tools
```

### 2. Run as Regular User

Most Scorpion commands don't need root:

```bash
# These work without sudo:
scorpion scan -t example.com --web
scorpion ssl-analyze -t example.com -p 443
scorpion recon-cmd -t example.com
scorpion dirbust example.com --concurrency 10
scorpion tech example.com
scorpion crawl example.com --start https://example.com

# Only SYN scans need sudo:
sudo scorpion scan -t example.com --syn --web
```

### 3. Save Results in ~/results

```bash
# Create results directory
mkdir -p ~/results

# Save all reports there
scorpion scan -t example.com --web --output ~/results/scan.json
scorpion ssl-analyze -t example.com -p 443 --output ~/results/ssl.json
scorpion recon-cmd -t example.com --output ~/results/recon.json
scorpion suite -t example.com --profile web --output-dir ~/results
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
A: Most commands work without sudo. Only SYN scans (--syn) need root and Scapy.

**Q: Can I test any website?**  
A: NO! Only test systems you own or have written permission to test.

**Q: How do I update?**  
A: `cd Scorpion && git pull && pip install -e tools/python_scorpion`

**Q: Where are results saved?**  
A: Use `--output filename.json` to save results. Default: printed to console.

---

## 🚀 You're Ready!

```bash
# Start testing (with permission!)
scorpion scan -t your-target.com --web
scorpion suite -t your-target.com --profile web --mode passive --output-dir results
```

**Happy (ethical) hacking! 🦂**

---

**Version**: 2.0.1  
**Platform**: Parrot OS / Debian / Ubuntu / Kali Linux  
**Last Updated**: December 9, 2025

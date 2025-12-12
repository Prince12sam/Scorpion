# Installing Scorpion CLI on Parrot OS / Kali / Debian-based Linux

**Universal Guide for Security Testing Distributions**

> **Note:** This guide works on Parrot OS, Kali Linux, Ubuntu, Debian, and other Debian-based distributions.

---

## ⚠️ CRITICAL: Modern Linux Python Protection (PEP 668)

**Modern Linux distributions (including Parrot OS, Kali, Ubuntu 23.04+) block system-wide pip installs to protect system Python.**

### ✅ CORRECT Installation (Use Virtual Environment)

```bash
# Clone the repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install (NO sudo needed inside venv!)
pip install -e tools/python_scorpion

# Verify
scorpion --help
```

### ❌ WRONG - This Will Fail:
```bash
sudo pip install -e tools/python_scorpion  # ❌ Error: externally-managed-environment
pip install --break-system-packages ...    # ❌ DANGEROUS - Can break your OS!
```

**Why:** Modern Python (3.11+) implements PEP 668 security standard. Always use virtual environments for safety.

---

## 🚀 Quick Installation (5 Minutes)

### Prerequisites

Most security distros come with Python pre-installed. Just verify:

```bash
# Check if Python is installed
python3 --version

# If not installed or version < 3.10, install it:
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-full

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

### Step 2: Create Virtual Environment (Required!)

```bash
# Create venv
python3 -m venv .venv

# Activate it
source .venv/bin/activate

# Your prompt should now show: (.venv)
```

### Step 3: Install Scorpion CLI

```bash
# Install (NO sudo - you're inside venv!)
pip install --upgrade pip
pip install -e tools/python_scorpion
```

### Step 4: Verify Installation

```bash
# Verify CLI is available
scorpion --help
scorpion --version
```

**✅ Success!** You should see Scorpion's help menu.

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

### Issue 1: "externally-managed-environment" Error ⚠️ MOST COMMON

**Error:**
```
error: externally-managed-environment
× This environment is externally managed
```

**Cause:** You used `sudo pip install` which tries system-wide install (blocked by PEP 668).

**Solution:**
```bash
# Create and activate venv
python3 -m venv .venv
source .venv/bin/activate

# Install WITHOUT sudo
pip install -e tools/python_scorpion

# Verify
scorpion --help
```

**Why:** Modern Python (3.11+) protects system packages. ALWAYS use venv on Parrot/Kali/Ubuntu.

### Issue 2: Python/Pip Version Issues

```bash
# Ensure Python and pip are present
python3 --version
python3 -m pip --version

# Install venv if missing
sudo apt install -y python3-pip python3-venv python3-full
```

### Issue 3: Permission Errors (Old Python)

If you're on older Python without PEP 668 and get permission errors:

```bash
# Option 1: Use --user flag (NOT recommended on modern Parrot)
python3 -m pip install --user -e tools/python_scorpion

# Option 2: Use venv (RECOMMENDED)
python3 -m venv .venv
source .venv/bin/activate
pip install -e tools/python_scorpion
```

### Issue 4: CLI Not Found

```bash
# Ensure venv is activated
source .venv/bin/activate

# Ensure install succeeded
pip install -e tools/python_scorpion
which scorpion
```

### Issue 5: SYN Scanning Requires Root

SYN scans need elevated privileges and Scapy. **Important:** You need to install Scapy INSIDE your venv, then use sudo with the venv Python:

#### Method 1: Using sudo with venv (Recommended)

```bash
# First, activate venv and install Scapy
source .venv/bin/activate
pip install scapy

# Find your venv's Python path
which python3
# Example output: /path/to/Scorpion/.venv/bin/python3

# Run SYN scan with sudo using venv's Python
sudo /path/to/Scorpion/.venv/bin/python3 -m python_scorpion.cli scan -t example.com --syn --web --rate-limit 50

# Or create an alias for convenience:
alias scorpion-sudo='sudo $(which python3) -m python_scorpion.cli'
scorpion-sudo scan -t example.com --syn --web
```

#### Method 2: Using sudo -E (Keep Environment)

```bash
# Activate venv
source .venv/bin/activate

# Install Scapy in venv
pip install scapy

# Run with sudo -E to preserve environment
sudo -E env PATH=$PATH scorpion scan -t example.com --syn --web --rate-limit 50

# List available interfaces
scorpion scan --list-ifaces
```

#### Method 3: Grant Python CAP_NET_RAW capability (Advanced)

```bash
# This allows Python to use raw sockets without sudo
sudo setcap cap_net_raw+ep $(readlink -f $(which python3))

# Now you can run without sudo (after activating venv)
source .venv/bin/activate
scorpion scan -t example.com --syn --web
```

**Note:** Method 3 has security implications - it allows ANY Python script to use raw sockets.

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
# Using venv with sudo:
sudo -E env PATH=$PATH scorpion scan -t example.com --syn --web --rate-limit 50
# Or:
sudo $(which python3) -m python_scorpion.cli scan -t example.com --syn --web

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

# Only SYN scans need sudo (use with venv):\nsudo -E env PATH=$PATH scorpion scan -t example.com --syn --web
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

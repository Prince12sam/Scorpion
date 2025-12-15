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
# Remove any existing venv (if recreating)
rm -rf .venv

# Create fresh venv (ensure isolation from system)
python3 -m venv --clear .venv

# Activate it
source .venv/bin/activate

# Your prompt should now show: (.venv)

# Verify you're using venv's Python and pip
which python
which pip
# Both should show paths inside .venv directory
```

### Step 3: Install Scorpion CLI

```bash
# Upgrade pip first (inside venv)
pip install --upgrade pip

# Install (NO sudo - you're inside venv!)
pip install -e tools/python_scorpion

# If you get "externally-managed-environment" error:
# Use the venv's pip directly:
.venv/bin/pip install -e tools/python_scorpion
```

### Step 4: Verify Installation

```bash
# Verify CLI is available
scorpion --help
scorpion --version
```

**✅ Success!** You should see Scorpion's help menu.

### Step 5: Configure API Keys (Optional - for AI Features)

**For AI-powered penetration testing**, you need an OpenAI API key:

```bash
# Automated setup (recommended)
./setup-first-time.sh

# Or manual setup:
cp .env.example .env
nano .env
```

Add to `.env`:
```env
SCORPION_AI_API_KEY=sk-proj-your-actual-key-here
```

📖 **Complete setup guide:** [API_KEY_SETUP.md](API_KEY_SETUP.md)  
🔑 **Get OpenAI key:** https://platform.openai.com/api-keys

**Commands that need API key:**
- `scorpion ai-pentest` - AI-powered penetration testing

**Commands that work without API key:**
- All other commands (scan, recon, ssl-analyze, etc.)

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

## 🤖 AI Features on Parrot OS (GitHub Models Recommended)

AI-powered scans work great on Parrot OS when the API key is set in your shell or `.env`. GitHub Models works for free and is auto-detected.

### Quick Setup (GitHub Models – FREE)
```bash
# In your terminal (temporary for this shell)
export GITHUB_TOKEN="ghp_your_token_here"

# Or use unified var Scorpion auto-detects
export SCORPION_AI_API_KEY="ghp_your_token_here"

# Verify provider auto-detection
scorpion ai-pentest --help | sed -n '1,60p'
```

### Validate Your GitHub Token
```bash
echo "$GITHUB_TOKEN"                   # should print your token (masked here)
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/rate_limit
```

### Run a Safe AI Pentest
```bash
# Low risk (passive/harmless):
scorpion ai-pentest -t example.com -r low

# Medium risk (active scans, no exploitation):
scorpion ai-pentest -t example.com -r medium

# If auto-detect fails, set provider explicitly:
scorpion ai-pentest -t example.com --ai-provider github --model gpt-4o-mini
```

### Handle Rate Limits (HTTP 429 on GitHub Models)
- GitHub Models limits are typically 15–60 requests/min.
- Mitigations:
```bash
# Slow the agent (fewer AI calls)
scorpion ai-pentest -t example.com --time-limit 60

# Wait and retry
sleep 90 && scorpion ai-pentest -t example.com -r low

# Reduce iterations (if supported in your version)
scorpion ai-pentest -t example.com --max-iterations 5
```
If you still hit 429, wait 1–2 minutes and retry. You can also switch providers with `--ai-provider openai` if you have an OpenAI key set.

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

**Cause:** You used `sudo pip install` which tries system-wide install (blocked by PEP 668), OR your venv is incorrectly linked to system Python.

**Solution A - Recreate Virtual Environment (RECOMMENDED):**
```bash
# Remove old venv if exists
rm -rf .venv

# Create fresh venv without system packages
python3 -m venv --clear .venv

# Activate it
source .venv/bin/activate

# Verify you're using venv's pip (should show .venv path)
which pip
which python

# Upgrade pip first
pip install --upgrade pip

# Install WITHOUT sudo
pip install -e tools/python_scorpion

# Verify
scorpion --help
```

**Solution B - If Still Fails (Force Install in venv):**
```bash
# Activate venv
source .venv/bin/activate

# Use venv's pip directly with full path
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e tools/python_scorpion

# Verify
.venv/bin/scorpion --help
```

**Solution C - Alternative: Use python3-full and recreate:**
```bash
# Ensure python3-full is installed
sudo apt install -y python3-full python3-pip python3-venv

# Remove old venv
rm -rf .venv

# Create new venv
python3 -m venv .venv

# Activate
source .venv/bin/activate

# Install
pip install -e tools/python_scorpion
```

**Why:** Modern Python (3.11+) protects system packages. ALWAYS use venv on Parrot/Kali/Ubuntu. Sometimes the venv needs to be recreated to properly isolate from system Python.

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

## 🛠️ Diagnostics & Repair on Parrot OS

These commands fix common venv/editable-install hiccups (e.g., `ModuleNotFoundError: python_scorpion.payload_generator`).

### Quick Diagnostics
```bash
# From repo root
source .venv/bin/activate
python3 --version
pip --version
which python
which scorpion

# Show package location and modules present
python - <<'PY'
import sys, pkgutil, python_scorpion
print("package file:", python_scorpion.__file__)
mods = {m.name for m in pkgutil.iter_modules(python_scorpion.__path__)}
print("has payload_generator?:", 'payload_generator' in mods)
PY
```

### Repair Editable Install
```bash
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip uninstall -y python-scorpion
python -m pip install -e tools/python_scorpion

# Verify imports
python - <<'PY'
from python_scorpion.payload_generator import PayloadGenerator, PayloadType, PayloadFormat
print("import OK")
PY
```

### Ensure the Correct `scorpion` Script is Used
```bash
readlink -f $(which scorpion)
python - <<'PY'
import inspect, python_scorpion.cli as c
print(inspect.getsourcefile(c))
PY
# Both paths should point inside your Scorpion/.venv/
```

### AI Scan Gotchas on Parrot
- If you see `Rate limit exceeded for github`, wait 1–2 minutes or use `--time-limit` to slow down.
- If fuzzing is blocked at low risk: use `-r medium` to enable it.
- If an action reports `Invalid scan type: syn`, set a stealthier scan type (e.g., `fin`) or run without SYN:
```bash
# Example if advanced scan requires non-SYN
scorpion ai-pentest -t example.com --scan-type fin -r low
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
**Last Updated**: December 15, 2025

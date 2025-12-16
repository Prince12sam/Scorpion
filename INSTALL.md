# Scorpion CLI - Installation Guide 🦂

Complete guide to install Scorpion CLI on Linux and macOS.

---

## 📋 Prerequisites

**Required:**
- Python 3.10 or higher
- pip (Python package manager)
- Git

**Check if you have them:**
```bash
python --version   # Should show 3.10+ (use python3 on Linux/macOS)
pip --version
git --version
```

**Don't have Python?**
- **Linux:** `sudo apt install python3 python3-pip` (Ubuntu/Debian) or `sudo dnf install python3 python3-pip` (Fedora/RHEL)
- **macOS:** `brew install python@3.11` or download from [python.org](https://python.org)

---

## 🚀 Quick Install (3 Steps)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
```

### Step 2: Install Scorpion CLI

**Virtual Environment (Recommended for all platforms)**

> **Note:** Modern Linux distributions (Ubuntu 23.04+, Kali, Parrot OS) implement PEP 668 and require virtual environments.

**Linux/macOS:**
```bash
# From repo root
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e tools/python_scorpion
```

### Step 3: Verify Installation
```bash
scorpion --version
scorpion --help
```

**That's it!** You can now use `scorpion` from anywhere.

---

## 🎯 Quick Test

```bash
# Aggressive port scan (default: ALL 65535 ports, only open ports shown)
scorpion scan -t example.com

# Fast aggressive scan (ultra-fast with 1000 concurrency)
scorpion scan -t example.com --fast

# Web service scan
scorpion scan -t example.com --web

# Show ALL ports including closed/filtered (like nmap without --open)
scorpion scan -t example.com --show-all

# SSL analysis
scorpion ssl-analyze -t example.com -p 443

# Reconnaissance
scorpion recon-cmd -t example.com
```

### 🔥 Aggressive Scanning (Default Behavior)

Scorpion now scans aggressively by default, similar to nmap's `nmap -p-` mode:

- **Port Range:** Scans ALL 65535 ports by default (comprehensive coverage)
- **Only Open Ports:** Shows only open ports by default (like `nmap --open`)
- **High Concurrency:** 500 concurrent probes for faster scanning
- **Smart Filtering:** Closed and filtered ports are hidden for cleaner output

**Examples:**
```bash
# Default aggressive scan (ALL 65535 ports, only open ports)
scorpion scan -t example.com

# Ultra-fast aggressive (1000 concurrency, 0.8s timeout)
scorpion scan -t example.com --fast

# Show closed/filtered ports too (verbose output)
scorpion scan -t example.com --show-all

# Comprehensive 50+ port scan (faster than full range)
scorpion scan -t example.com --full
```

---

## 🏠 Scanning Local/Private Networks

Scorpion works great for local network scanning, Docker containers, and localhost applications:

### Localhost Scanning
```bash
# Scan localhost
scorpion scan -t localhost --web
scorpion scan -t 127.0.0.1 --ports 1-1024

# Scan local application
scorpion web-test -t http://localhost:8080
scorpion ai-pentest -t localhost:3000 -r medium
```

### Private IP Scanning
```bash
# Scan private network IPs
scorpion scan -t 192.168.1.100 --web
scorpion scan -t 10.0.0.50 --ports 1-1000
scorpion scan -t 172.17.0.2 --web

# Web application on private network
scorpion web-test -t http://192.168.1.50:8080
scorpion suite -t 192.168.1.100 --profile web --mode active
```

### Docker Container Scanning
```bash
# Scan Docker containers (typically 172.17.0.x)
scorpion scan -t 172.17.0.2 --web
scorpion web-test -t http://172.17.0.2:5000

# AI-powered scan of local container
scorpion ai-pentest -t 172.17.0.2 -r high
```

### Local Network Range Scanning
```bash
# Scan multiple local hosts
scorpion scan -t 192.168.1.1 --web
scorpion scan -t 192.168.1.10 --ports 80,443,22,21,3389

# Comprehensive local network assessment
scorpion suite -t 10.0.0.5 --profile infra --mode active
```

**Note:** Local/private IP scanning automatically uses `http://` instead of `https://` for web tests, and disables SSL verification for faster scanning.

---

## 🌐 Platform-Specific Notes

### Linux/macOS
- Use bash/zsh terminal
- Paths use forward slashes: `results/scan.json`
- For SYN scans: Use `sudo` or run as root

---

## 🔧 Advanced: SYN Scanning (Optional)

SYN scanning requires root privileges and Scapy.

**Linux/macOS (with venv - Recommended):
```bash
# Activate your venv first
source .venv/bin/activate
pip install scapy

# Run with sudo using venv's Python
sudo $(which python3) -m python_scorpion.cli scan -t example.com --syn --web --rate-limit 50

# Or use sudo -E to preserve environment
sudo -E env PATH=$PATH scorpion scan -t example.com --syn --web --rate-limit 50
```

**Note:** Modern Linux (Ubuntu 23.04+, Kali, Parrot OS) implements PEP 668, which blocks `sudo pip install`. Always install packages in a virtual environment.

---

## 📖 Next Steps

- **Command Reference:** [COMMANDS.md](COMMANDS.md)
- **Linux Guide:** [INSTALL_LINUX.md](INSTALL_LINUX.md)
- **Quick Examples:** [QUICKSTART.md](QUICKSTART.md)

# Full reconnaissance
scorpion recon -t example.com --dns --whois --subdomain
```

### Vulnerability Testing
```bash
# OWASP Top 10 testing
scorpion suite example.com --profile web --mode active

# SQL injection testing
scorpion suite example.com --profile web --mode active
```

### Threat Intelligence
Use external TI vendors (VirusTotal, AbuseIPDB, Shodan) alongside Scorpion outputs.

---

## 📖 Full Documentation

- **All Commands**: See [COMMANDS.md](COMMANDS.md)
- **Quick Reference**: See [QUICKSTART.md](QUICKSTART.md)
- **Detailed Guide**: See [README.md](README.md)

---

## 🔧 Alternative: Run Without Global Install

If you prefer not to use a global install, run directly:
```bash
# From the Scorpion directory
python -m pip install -e tools/python_scorpion
scorpion --help
```

---

## 🌍 Platform-Specific Notes

### Linux (Ubuntu, Debian, CentOS, etc.)
- Some scans require root privileges
- If using venv: `sudo -E env PATH=$PATH scorpion scan ...` or `sudo $(which python3) -m python_scorpion.cli scan ...`
- Install build tools if needed: `sudo apt install build-essential`

### macOS
- Use Terminal or iTerm2
- Some scans require root privileges
- If using venv: `sudo -E env PATH=$PATH scorpion scan ...`

---

## 🔑 Optional: API Keys for Enhanced Features

Create a `.env` file in the Scorpion directory for configuration:

```env
DEFAULT_TIMEOUT=5000
MAX_CONCURRENT_SCANS=100
```

You can also configure vendor API keys (e.g., VirusTotal, AbuseIPDB, Shodan) if you integrate external TI workflows.

---

## 🐛 Troubleshooting

### "command not found: scorpion"
**Solution:** Ensure Python CLI installed and on PATH:
```bash
python -m pip install -e tools/python_scorpion
scorpion --help
```

### Remove AI API keys (disable AI features)
If you set AI provider keys and want to remove them without uninstalling Scorpion, clear them from your environment and `.env`.

**Windows (PowerShell):**
```powershell
# Remove from current session
Remove-Item Env:SCORPION_AI_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:GITHUB_PAT -ErrorAction SilentlyContinue
Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue

# If set persistently for your user
[Environment]::SetEnvironmentVariable("SCORPION_AI_API_KEY", $null, "User")
[Environment]::SetEnvironmentVariable("GITHUB_TOKEN", $null, "User")
[Environment]::SetEnvironmentVariable("GITHUB_PAT", $null, "User")
[Environment]::SetEnvironmentVariable("OPENAI_API_KEY", $null, "User")
[Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", $null, "User")

# Optional: clear from project .env
# Edit .env and remove lines for the keys above
```

**Linux/macOS (bash/zsh):**
```bash
# Remove from current shell
unset SCORPION_AI_API_KEY
unset GITHUB_TOKEN
unset GITHUB_PAT
unset OPENAI_API_KEY
unset ANTHROPIC_API_KEY

# If added persistently, remove export lines from:
# ~/.bashrc, ~/.zshrc, ~/.profile, or ~/.bash_profile

# Optional: clear from project .env
sed -i.bak '/SCORPION_AI_API_KEY\|GITHUB_TOKEN\|GITHUB_PAT\|OPENAI_API_KEY\|ANTHROPIC_API_KEY/d' .env
```

**Verify:**
```bash
scorpion ai-pentest --help  # AI features won’t select a provider
```

### Pip/Python not found
**Solution:** Install Python and pip (see Prerequisites above)

### Permission errors on Linux/macOS
**Solution:** Use `sudo` with venv-aware commands for privileged scans:
```bash
# If using venv (modern Linux):
source .venv/bin/activate
sudo -E env PATH=$PATH scorpion scan -t example.com --syn --web

# Alternative:
sudo $(which python3) -m python_scorpion.cli scan -t example.com --syn --web
```

### Python environment issues
**Solution:** Ensure you're using Python 3.10+ and pip installed:
```bash
python --version    # Must be 3.10+
python -m pip --version
```

### Network errors during install
**Solution:** Retry pip install or check proxy settings:
```bash
python -m pip install -e tools/python_scorpion
```

---

## 🔄 Updating Scorpion

To get the latest version:
```bash
cd Scorpion
git pull origin main
python -m pip install -e tools/python_scorpion
```

---

## 🗑️ Uninstalling

To remove Scorpion:
```bash
# Deactivate and remove venv if used
deactivate

# Remove the directory
cd ..
rm -rf Scorpion
```

---

## ⚠️ Legal Notice

**IMPORTANT:** Only use Scorpion on systems you own or have explicit written authorization to test. Unauthorized security testing is illegal in most jurisdictions.

- ✅ Test your own systems
- ✅ Get written permission before testing
- ✅ Follow responsible disclosure practices
- ❌ Never test systems without authorization

---

## 🆘 Need Help?

- **Documentation**: [README.md](README.md), [COMMANDS.md](COMMANDS.md), [QUICKSTART.md](QUICKSTART.md)
- **Issues**: [GitHub Issues](https://github.com/Prince12sam/Scorpion/issues)
- **Command Help**: `scorpion --help` or `scorpion <command> --help`

---

**Ready to hunt threats?** 🦂

```bash
scorpion scan -t <your-target> --stealth ninja
```

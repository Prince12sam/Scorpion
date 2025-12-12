# Scorpion CLI - Installation Guide 🦂

Complete guide to install Scorpion CLI on Windows, Linux, and macOS.

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
- **Windows:** Install Python from [Microsoft Store](https://www.microsoft.com/store/productId/9NRWMJP3717K) or [python.org](https://python.org) (check "Add Python to PATH")
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

**Option A: Direct Install (Windows/macOS)**
```bash
python -m pip install -e tools/python_scorpion
```

**Option B: Virtual Environment (Linux - Required for modern distros)**

> **Note:** Modern Linux distributions (Ubuntu 23.04+, Kali, Parrot OS) implement PEP 668 and require virtual environments.

**Windows PowerShell:**
```powershell
# From repo root
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install -e tools\python_scorpion
```

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
# Port scan (safe, example.com)
scorpion scan -t example.com --web

# SSL analysis
scorpion ssl-analyze -t example.com -p 443

# Reconnaissance
scorpion recon-cmd -t example.com
```

---

## 🌐 Platform-Specific Notes

### Windows
- Use PowerShell or Command Prompt
- Paths use backslashes: `results\scan.json`
- For SYN scans: Run PowerShell as Administrator

### Linux/macOS
- Use bash/zsh terminal
- Paths use forward slashes: `results/scan.json`
- For SYN scans: Use `sudo` or run as root

---

## 🔧 Advanced: SYN Scanning (Optional)

SYN scanning requires admin/root privileges and Scapy.

**Windows (elevated PowerShell):**
```powershell
pip install scapy
scorpion scan -t example.com --syn --web --rate-limit 50
```

**Linux (with venv - Recommended):**
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

### Windows
- Works in PowerShell or Command Prompt (CMD)
- Some scans may require "Run as Administrator" for advanced features

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

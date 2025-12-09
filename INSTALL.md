# Scorpion CLI - Installation Guide 🦂

Quick guide to clone and start using Scorpion CLI for security testing.

---

## 📋 Prerequisites

**Required:**
- Python 3.10 or higher
- pip (Python package manager)
- Git

**Check if you have them:**
```bash
python --version   # Should show 3.10+ (or use python3)
python -m pip --version
git --version      # Any recent version
```

**Don't have Python?**
- Windows: Install Python from Microsoft Store or https://python.org and ensure `Add Python to PATH`
- Linux: `sudo apt install python3 python3-pip` (Ubuntu/Debian) or `sudo yum install python3 python3-pip` (CentOS/RHEL)
- macOS: `brew install python@3.11` or download from https://python.org

---

## 🚀 Quick Install (3 Steps)

### Step 1: Clone the Repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
```

### Step 2: Install Scorpion CLI (Python)
```bash
python -m pip install --upgrade pip
python -m pip install -e tools/python_scorpion
```

Windows (PowerShell) with a local venv:

```powershell
# From repo root
& .\.venv\Scripts\Activate.ps1
.\.venv\Scripts\python.exe -m pip install -e .\tools\python_scorpion
.\.venv\Scripts\scorpion.exe --help

# If your current directory is .\tools
& ..\.venv\Scripts\Activate.ps1
..\.venv\Scripts\python.exe -m pip install -e .\python_scorpion
..\.venv\Scripts\scorpion.exe --help
```

Note: When you are inside `tools`, do not use `./tools/python_scorpion` as it resolves to a non-existent `tools/tools/python_scorpion` path.

### Step 3: First Run
```bash
scorpion --help
scorpion --version
```

**That's it!** You can now use `scorpion` from anywhere on your system.

---

scorpion recon -t example.com --dns

Test that everything works:
scorpion recon -t example.com --dns --whois --subdomain
# Check version
scorpion --version

# Show help
scorpion --help
scorpion suite example.com --profile web --mode active --output-dir results
# Run a test scan (safe, non-intrusive; use authorized targets only)
scorpion scan -t example.com --ports 80,443
scorpion suite example.com --profile web --mode active --output-dir results

---

## 🎯 Quick Start Examples

Use external threat intel sources (VirusTotal, AbuseIPDB, Shodan).
```bash
# Scan a target
scorpion scan -t example.com

# Scan specific ports
scorpion scan -t example.com --ports 80,443,8080

# Stealthy scan
scorpion scan -t example.com --stealth ninja
```
scorpion scan -t example.com
scorpion recon -t example.com --dns
scorpion --help  # Python CLI
# DNS enumeration
scorpion recon -t example.com --dns

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
- Some scans may require root: `sudo scorpion scan -t example.com -sS`
- Install build tools if needed: `sudo apt install build-essential`

### macOS
- Use Terminal or iTerm2
- Some scans may require root: `sudo scorpion scan -t example.com -sS`

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
**Solution:** Use `sudo` for privileged scans:
```bash
sudo scorpion scan -t example.com -sS
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

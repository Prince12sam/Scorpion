# Scorpion — Linux Install & Usage Quick Guide

This guide helps you install and run Scorpion on Linux (Ubuntu/Debian/Fedora/Arch/Kali/Parrot, etc.). Commands use bash. Adjust package manager commands for your distro.

## Prerequisites
- Python 3.10+ (`python3 --version`)
- Build tools for Python packages (optional): `sudo apt-get install -y build-essential libffi-dev libssl-dev`

## ⚠️ IMPORTANT: Python Virtual Environment Required

Modern Linux distributions implement PEP 668, which blocks system-wide pip installs. **Always use a virtual environment.**

## Install
```bash
# Clone or navigate to project
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
# or: cd /path/to/open_project

python3 -m venv .venv
source .venv/bin/activate

# Install Scorpion CLI (editable)
pip install -e tools/python_scorpion

# Verify
scorpion --version
scorpion --help
```

## Common Commands
```bash
# Port scan (web preset)
scorpion scan -t example.com --web

# SSL/TLS analysis
scorpion ssl-analyze -t example.com -p 443 -T 5

# Reconnaissance
scorpion recon-cmd -t example.com

# Directory discovery
scorpion dirbust example.com --concurrency 10 --output results/dirb_example.json

# Technology detection
scorpion tech example.com --output results/tech_example.json

# Web crawler
scorpion crawl example.com --start https://example.com --max-pages 10 --concurrency 4 --output results/crawl_example.json

# Suite + Report
scorpion suite -t example.com --profile web --mode passive --output-dir results
latest=$(ls -t results/suite_example.com_*.json | head -n1)
scorpion report --suite "$latest" --summary
```

## SYN Scan (raw packets)
SYN scanning requires root privileges and Scapy. **Important:** Install Scapy in your venv, then use one of these methods:

### Method 1: Using sudo with venv Python (Recommended)
```bash
# Activate venv and install Scapy
source .venv/bin/activate
pip install scapy

# Run with sudo using venv's Python
sudo $(which python3) -m python_scorpion.cli scan -t example.com --syn --web --rate-limit 50

# Or create an alias:
alias scorpion-sudo='sudo $(which python3) -m python_scorpion.cli'
scorpion-sudo scan -t example.com --syn --web
```

### Method 2: Using sudo -E (Preserve Environment)
```bash
source .venv/bin/activate
pip install scapy

# Run with sudo -E to keep environment variables
sudo -E env PATH=$PATH scorpion scan -t example.com --syn --web --rate-limit 50 --iface <iface-name>
```

### Optional: List Network Interfaces
```bash
# List available interfaces (no root needed)
scorpion scan --list-ifaces

# Or use system commands
ip link
ifconfig
```

Notes:
- If Scapy is not installed or you're not root, `--syn` will error with guidance.
- The tool now properly detects Linux/Unix root privileges (not just Windows admin).

## Optional: Nuclei (Web Testing)
To extend web testing with ProjectDiscovery Nuclei:
- Install nuclei (see official docs):
  - Debian/Ubuntu: download binary or use `apt` via repositories
  - macOS: `brew install nuclei`
- Once installed, we can add `web-test` integration. Ask to enable this if needed.

## Tips
- Use forward slashes for paths on Linux (e.g., `results/report.html`).
- All commands are the same as Windows but without PowerShell-specific globs.
- TLS verification is on by default; for K8s, use `--insecure` to skip cert checks (not recommended).

## Troubleshooting
- "Command not found": ensure you ran `pip install -e tools/python_scorpion` inside the venv and that `source .venv/bin/activate` is active.
- Permission errors for SYN: run as root and verify `pip install scapy` succeeded.
- Network issues: check DNS/firewall; try `ping example.com` and `curl https://example.com`.

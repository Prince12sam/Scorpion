# Scorpion — Linux Install & Usage Quick Guide

This guide helps you install and run Scorpion on Linux (Ubuntu/Debian/Fedora/Arch, etc.). Commands use bash. Adjust package manager commands for your distro.

## Prerequisites
- Python 3.10+ (`python3 --version`)
- Build tools for Python packages (optional): `sudo apt-get install -y build-essential libffi-dev libssl-dev`

## Install
```bash
cd /path/to/open_project
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
SYN scanning requires root privileges and Scapy.
```bash
sudo -s
source .venv/bin/activate
pip install scapy

# Optional: list interfaces
scorpion scan --list-ifaces

# Run SYN scan with rate limit and optional interface
scorpion scan -t example.com --syn --web --rate-limit 50 --iface <iface-name>
```

Notes:
- If Scapy is not installed or you’re not root, `--syn` will error with guidance.
- For interface names, use `ip link` or `scorpion scan --list-ifaces`.

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

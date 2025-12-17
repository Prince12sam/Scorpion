# Getting Started with Scorpion CLI

**5-minute guide to install and run your first security scan.**

---

## Step 1: Install Python (if needed)

Scorpion requires **Python 3.10 or higher**.

### Check if you have Python:
```bash
python --version
# or on Linux/macOS:
python3 --version
```

### Don't have Python?

**Linux (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install -y python3 python3-pip git
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install -y python3 python3-pip git
```

**macOS:**
```bash
brew install python@3.11
```

---

## Step 2: Install Scorpion

### Clone and Install (3 commands)

```bash
# 1. Clone repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# 2. Install CLI
python -m pip install -e tools/python_scorpion

# 3. Verify
scorpion --version
```

You should see: `0.1.0` (or similar version)

---

## Step 3: Run Your First Scan

### Example: Scan example.com

```bash
scorpion scan -t example.com --web
```

**Output:**
```
          Port Scan: example.com          
  Port │ State │ Service │ Banner/Reason  
  80   │ open  │ http    │
  443  │ open  │ https   │
Open ports: [80, 443]
```

### Congratulations! 🎉

You just completed your first security scan with Scorpion.

---

## What's Next?

### Try More Commands

```bash
# SSL/TLS analysis
scorpion ssl-analyze -t example.com -p 443

# Reconnaissance
scorpion recon-cmd -t example.com

# Web crawler
scorpion crawl example.com --max-pages 10

# OS fingerprinting (requires admin/root)
sudo scorpion scan example.com --syn --os-detect

# Payload generation
scorpion payload --lhost 10.0.0.1 --lport 4444 --shell bash

# Decoy scanning (IDS/IPS evasion, requires admin/root)
sudo scorpion scan example.com --syn --decoy RND:5

# Full web suite + HTML report
scorpion suite -t example.com --profile web --mode passive --output-dir results
```

### Generate a Report

```bash
# Run suite
scorpion suite -t example.com --profile web --mode passive --output-dir results

# Find latest suite file
latest=$(ls -t results/suite_example.com_*.json | head -n1)
scorpion report --suite "$latest" --summary
```

Open `report.html` in your browser to view the professional security report!

---

## Common Commands Quick Reference

| Task | Command |
|------|---------|
| Port scan | `scorpion scan -t <host> --web` |
| SSL check | `scorpion ssl-analyze -t <host>` |
| Recon | `scorpion recon-cmd -t <host>` |
| API test | `scorpion api-test <host>` |
| OS fingerprint | `sudo scorpion scan -t <host> --syn --os-detect` |
| Payload gen | `scorpion payload --lhost <ip> --lport 4444 --shell bash` |
| Decoy scan | `sudo scorpion scan -t <host> --syn --decoy RND:5` |
| Full suite | `scorpion suite -t <host> --profile web --output-dir results` |
| Help | `scorpion --help` |

---

## Platform-Specific Tips

### Linux/macOS
- Use bash/zsh terminal
- Paths use forward slashes: `results/scan.json`
- For SYN scans: Use `sudo scorpion ...`

---

## Troubleshooting

### "Command not found: scorpion"

**Solution:** Ensure pip installed the package correctly
```bash
python -m pip install -e tools/python_scorpion
```

If using a virtual environment, make sure it's activated:
```bash
source .venv/bin/activate
```

### "Permission denied" on Linux

**Solution:** Some commands may need sudo
```bash
sudo scorpion scan -t example.com --syn --web
```

### "Module not found" errors

**Solution:** Install dependencies
```bash
cd tools/python_scorpion
pip install -r requirements.txt
```

---

## Next Steps

📖 **Detailed Guides:**
- [Installation Guide](INSTALLATION.md) - Complete install instructions
- [Quick Start](QUICKSTART.md) - More examples and use cases
- [Command Reference](COMMANDS.md) - All commands and options
- [Linux Guide](INSTALL_LINUX.md) - Linux-specific details

🔒 **Important:** Only scan systems you own or have explicit permission to test.

---

## Need Help?

- 📚 Read the [Command Reference](COMMANDS.md)
- 💬 Open an [issue on GitHub](https://github.com/Prince12sam/Scorpion/issues)
- 📧 Check existing documentation files in the repository

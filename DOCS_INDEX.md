# Scorpion CLI Documentation Index

Quick navigation for all Scorpion documentation.

---

## 🚀 New Users Start Here

**[Getting Started Guide](GETTING_STARTED.md)** ⭐  
5-minute walkthrough from installation to first scan. Perfect for beginners.

---

## 📖 Installation Guides

Choose your platform:

| Platform | Guide | Description |
|----------|-------|-------------|
| **Windows** | [INSTALL.md](INSTALL.md) | Complete Windows installation with PowerShell |
| **Linux** | [INSTALL_LINUX.md](INSTALL_LINUX.md) | Ubuntu, Debian, Fedora, Arch instructions |
| **Parrot OS** | [INSTALL_PARROT_OS.md](INSTALL_PARROT_OS.md) | Security-focused distro guide |
| **All Platforms** | [GETTING_STARTED.md](GETTING_STARTED.md) | Quick 3-step universal install |

---

## ⚡ Quick References

| Document | Purpose | Best For |
|----------|---------|----------|
| [QUICKSTART.md](QUICKSTART.md) | Fast examples and common use cases | Quick copy-paste commands |
| [COMMANDS.md](COMMANDS.md) | Complete command reference | Looking up specific options |
| [README.md](README.md) | Project overview and features | Understanding what Scorpion does |

---

## 📋 Command Categories

### Network Scanning
- `scorpion scan` - TCP/UDP port scanning ([COMMANDS.md#scan](COMMANDS.md))
- `scorpion ssl-analyze` - SSL/TLS analysis ([COMMANDS.md#ssl-analyze](COMMANDS.md))

### Reconnaissance  
- `scorpion recon-cmd` - DNS, WHOIS, headers ([COMMANDS.md#recon-cmd](COMMANDS.md))
- `scorpion tech` - Technology detection ([COMMANDS.md#tech](COMMANDS.md))

### Web Testing
- `scorpion dirbust` - Directory discovery ([COMMANDS.md#dirbust](COMMANDS.md))
- `scorpion crawl` - Web crawler ([COMMANDS.md#crawl](COMMANDS.md))
- `scorpion api-test` - API security ([COMMANDS.md#api-test](COMMANDS.md))
- `scorpion takeover` - Subdomain takeover ([COMMANDS.md#takeover](COMMANDS.md))

### Cloud & Infrastructure
- `scorpion cloud` - Cloud storage audit ([COMMANDS.md#cloud](COMMANDS.md))
- `scorpion k8s` - Kubernetes audit ([COMMANDS.md#k8s](COMMANDS.md))
- `scorpion container` - Container registry audit ([COMMANDS.md#container](COMMANDS.md))

### Reporting
- `scorpion suite` - Combined security suite ([COMMANDS.md#suite](COMMANDS.md))
- `scorpion report` - HTML report generation ([COMMANDS.md#report](COMMANDS.md))

---

## 🔍 Finding What You Need

### "How do I install Scorpion?"
→ [GETTING_STARTED.md](GETTING_STARTED.md) or [INSTALL.md](INSTALL.md)

### "What commands are available?"
→ [COMMANDS.md](COMMANDS.md)

### "Show me quick examples"
→ [QUICKSTART.md](QUICKSTART.md)

### "How do I run a full security suite?"
→ [COMMANDS.md#suite](COMMANDS.md) or [QUICKSTART.md#suite--reporting](QUICKSTART.md)

### "How do I generate a report?"
→ [COMMANDS.md#report](COMMANDS.md) or [GETTING_STARTED.md#generate-a-report](GETTING_STARTED.md)

### "Linux-specific instructions?"
→ [INSTALL_LINUX.md](INSTALL_LINUX.md)

### "I'm getting errors"
→ [GETTING_STARTED.md#troubleshooting](GETTING_STARTED.md) or [INSTALL.md](INSTALL.md)

---

## 📦 Development Documentation

| File | Purpose |
|------|---------|
| [tools/python_scorpion/README.md](tools/python_scorpion/README.md) | Python package details and build instructions |

---

## 🔒 Legal & Security

**Important:** Always obtain explicit permission before testing any system.

- Review [README.md#security--ethics](README.md) for responsible use guidelines
- Unauthorized testing may violate laws in your jurisdiction
- Follow responsible disclosure practices

---

## 🆘 Getting Help

1. **Check documentation** using this index
2. **Read error messages** - they often contain solutions
3. **Review troubleshooting** in [GETTING_STARTED.md](GETTING_STARTED.md)
4. **Open an issue** on [GitHub](https://github.com/Prince12sam/Scorpion/issues)

---

## 📝 Quick Command Cheat Sheet

```bash
# Installation
python -m pip install -e tools/python_scorpion

# Help
scorpion --help
scorpion scan --help

# Quick scans
scorpion scan -t example.com --web
scorpion ssl-analyze -t example.com
scorpion recon-cmd -t example.com

# Full suite + report
scorpion suite -t example.com --profile web --mode passive --output-dir results
latest=$(ls -t results/suite_*.json | head -n1)
scorpion report --suite "$latest" --summary
```

---

**Last Updated:** December 2025  
**Repository:** https://github.com/Prince12sam/Scorpion

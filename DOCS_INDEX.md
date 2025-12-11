# Scorpion CLI Documentation Index

Complete navigation for all Scorpion documentation - **21 essential files** (cleaned up Dec 2025).

---

## 🚀 New Users Start Here

**[Getting Started Guide](GETTING_STARTED.md)** ⭐  
5-minute walkthrough from installation to first scan. Perfect for beginners.

**[README.md](README.md)** 📖  
Complete project overview, features, and architecture.

---

## 📖 Installation Guides

| Platform | Guide | Description |
|----------|-------|-------------|
| **Windows** | [INSTALL.md](INSTALL.md) | PowerShell installation with pip/pipx |
| **Linux** | [INSTALL_LINUX.md](INSTALL_LINUX.md) | Ubuntu, Debian, Fedora, Arch, Kali |
| **Parrot OS** | [INSTALL_PARROT_OS.md](INSTALL_PARROT_OS.md) | Security-optimized distribution setup |

---

## ⚡ Core References

| Document | Purpose | Use When |
|----------|---------|----------|
| [COMMANDS.md](COMMANDS.md) | Complete CLI reference | Looking up command syntax |
| [GETTING_STARTED.md](GETTING_STARTED.md) | Quick start examples | First time using Scorpion |
| [CHANGELOG.md](CHANGELOG.md) | Version history | Checking what's new |

---

## 🎯 Feature Guides

### Web Application Security
- **[WEB_PENTESTING_GUIDE.md](WEB_PENTESTING_GUIDE.md)** - Complete web security testing (SQLi, XSS, SSRF, RCE)

### Network & Infrastructure
- **[OS_FINGERPRINTING_GUIDE.md](OS_FINGERPRINTING_GUIDE.md)** - OS detection and banner grabbing
- **[DECOY_SCANNING_GUIDE.md](DECOY_SCANNING_GUIDE.md)** - Stealth scanning with decoys
- **[PAYLOAD_GENERATION_GUIDE.md](PAYLOAD_GENERATION_GUIDE.md)** - Reverse/bind shells, web shells

### Advanced Features
- **[ADVANCED_FEATURES.md](ADVANCED_FEATURES.md)** - Rate limiting, threading, custom headers

---

## 🤖 AI Pentesting Agent

| Guide | Description |
|-------|-------------|
| **[AI_AGENT_ENHANCED_GUIDE.md](AI_AGENT_ENHANCED_GUIDE.md)** | Complete AI agent usage - OCP professional level |
| **[AI_OCP_IMPLEMENTATION.md](AI_OCP_IMPLEMENTATION.md)** | Implementation details and methodology |
| **[AI_COMMAND_EXECUTION.md](AI_COMMAND_EXECUTION.md)** | Direct command execution (Windows/Linux/macOS) |

**Quick Start**:
```bash
scorpion ai-pentest -t target.com --primary-goal web_exploitation --risk-tolerance high
```
---

## 📊 Project Information

| Document | Description |
|----------|-------------|
| [NEW_FEATURES.md](NEW_FEATURES.md) | Recently added capabilities |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Feature status and roadmap |
| [ENHANCEMENT_ROADMAP.md](ENHANCEMENT_ROADMAP.md) | Planned improvements |
| [VULNERABILITY_REPORTING.md](VULNERABILITY_REPORTING.md) | Security disclosure policy |
| [PRESENTATION.md](PRESENTATION.md) | Project presentation and demos |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## 💡 Quick Navigation

**I want to...**
- ⚡ **Get started fast** → [GETTING_STARTED.md](GETTING_STARTED.md)
- 📖 **Learn all commands** → [COMMANDS.md](COMMANDS.md)
- 🐧 **Install on Linux** → [INSTALL_LINUX.md](INSTALL_LINUX.md)
- 🌐 **Test web apps** → [WEB_PENTESTING_GUIDE.md](WEB_PENTESTING_GUIDE.md)
- 🕵️ **Stealth scanning** → [DECOY_SCANNING_GUIDE.md](DECOY_SCANNING_GUIDE.md)
- 💣 **Generate payloads** → [PAYLOAD_GENERATION_GUIDE.md](PAYLOAD_GENERATION_GUIDE.md)
- 🤖 **Use AI agent** → [AI_AGENT_ENHANCED_GUIDE.md](AI_AGENT_ENHANCED_GUIDE.md)
- 🔧 **Advanced features** → [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md)

---

## 🆘 Getting Help

1. Check this index for relevant documentation
2. Review [GETTING_STARTED.md](GETTING_STARTED.md) for troubleshooting
3. Read error messages - they contain solutions
4. Open an issue on [GitHub](https://github.com/Prince12sam/Scorpion/issues)

---

**Last Updated**: December 11, 2025  
**Total Documentation**: 21 essential files (cleaned & organized)
scorpion recon-cmd -t example.com

# Full suite + report
scorpion suite -t example.com --profile web --mode passive --output-dir results
latest=$(ls -t results/suite_*.json | head -n1)
scorpion report --suite "$latest" --summary
```

---

**Last Updated:** December 2025  
**Repository:** https://github.com/Prince12sam/Scorpion

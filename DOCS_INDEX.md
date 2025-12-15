# Scorpion CLI Documentation Index

Complete navigation for all Scorpion documentation - **13 essential files** (streamlined Dec 2025).

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
| **All Platforms** | [INSTALL.md](INSTALL.md) | Installation with pip in virtual environment |

---

## ⚡ Core References

| Document | Purpose | Use When |
|----------|---------|----------|
| [COMMANDS.md](COMMANDS.md) | Complete CLI reference | Looking up command syntax |
| [GETTING_STARTED.md](GETTING_STARTED.md) | Quick start examples | First time using Scorpion |
| [CHANGELOG.md](CHANGELOG.md) | Version history | Checking what's new |

---

## 🎯 Feature Guides

- **[PAYLOAD_GENERATION_GUIDE.md](PAYLOAD_GENERATION_GUIDE.md)** - Reverse/bind shells, web shells

---

## 🤖 AI Pentesting Agent

| Guide | Description |
|-------|-------------|
| **[AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md)** ⭐ | Complete AI pentest guide with quick start |
| **[GITHUB_MODELS_SETUP.md](GITHUB_MODELS_SETUP.md)** | Get FREE API key (2 minutes) |
| **[API_KEY_SETUP.md](API_KEY_SETUP.md)** | Detailed API key configuration |

**Quick Start**:
```bash
# 1. Setup once: Create .env file or set environment variable
echo "SCORPION_AI_API_KEY=ghp_your_token" >> .env

# 2. Use anytime (no --api-key flag needed!):
scorpion ai-pentest -t target.com
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
- 🤖 **Setup AI pentest** → [API_KEY_SETUP.md](API_KEY_SETUP.md) or [GITHUB_MODELS_SETUP.md](GITHUB_MODELS_SETUP.md)
- 📖 **Learn all commands** → [COMMANDS.md](COMMANDS.md)
- � **Generate payloads** → [PAYLOAD_GENERATION_GUIDE.md](PAYLOAD_GENERATION_GUIDE.md)
- 🤖 **Use AI agent** → [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md)

---

## 🆘 Getting Help

1. Check this index for relevant documentation
2. Review [GETTING_STARTED.md](GETTING_STARTED.md) for troubleshooting
3. Read error messages - they contain solutions
4. Open an issue on [GitHub](https://github.com/Prince12sam/Scorpion/issues)

---

**Last Updated**: December 11, 2025  
**Total Documentation**: 13 essential files (streamlined)
scorpion recon-cmd -t example.com

# Full suite + report
scorpion suite -t example.com --profile web --mode passive --output-dir results
latest=$(ls -t results/suite_*.json | head -n1)
scorpion report --suite "$latest" --summary
```

---

**Last Updated:** December 2025  
**Repository:** https://github.com/Prince12sam/Scorpion

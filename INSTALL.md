# Scorpion CLI - Installation Guide 🦂

Quick guide to clone and start using Scorpion CLI for security testing.

---

## 📋 Prerequisites

**Required:**
- Node.js version 16.0.0 or higher
- npm (comes with Node.js)
- Git

**Check if you have them:**
```bash
node --version    # Should show v16.0.0 or higher
npm --version     # Should show 8.0.0 or higher
git --version     # Any recent version
```

**Don't have Node.js?**
- Windows: Download from [nodejs.org](https://nodejs.org/)
- Linux: `sudo apt install nodejs npm` (Ubuntu/Debian) or `sudo yum install nodejs npm` (CentOS/RHEL)
- macOS: `brew install node` or download from [nodejs.org](https://nodejs.org/)

---

## 🚀 Quick Install (3 Steps)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Make it Globally Available
```bash
npm link
```

**That's it!** You can now use `scorpion` from anywhere on your system.

---

## ✅ Verify Installation

Test that everything works:
```bash
# Check version
scorpion --version

# Show help
scorpion --help

# Run a test scan (safe, non-intrusive)
scorpion scan -t scanme.nmap.org --ports 80,443
```

---

## 🎯 Quick Start Examples

### Basic Scanning
```bash
# Scan a target
scorpion scan -t example.com

# Scan specific ports
scorpion scan -t example.com --ports 80,443,8080

# Stealthy scan
scorpion scan -t example.com --stealth ninja
```

### Reconnaissance
```bash
# DNS enumeration
scorpion recon -t example.com --dns

# Full reconnaissance
scorpion recon -t example.com --dns --whois --subdomain
```

### Vulnerability Testing
```bash
# OWASP Top 10 testing
scorpion exploit -t example.com --payload owasp-top10

# SQL injection testing
scorpion exploit -t example.com --payload sql-injection
```

### Threat Intelligence
```bash
# Check IP reputation
scorpion threat-intel -i 8.8.8.8

# Check domain
scorpion threat-intel -d example.com
```

---

## 📖 Full Documentation

- **All Commands**: See [COMMANDS.md](COMMANDS.md)
- **Quick Reference**: See [QUICKSTART.md](QUICKSTART.md)
- **Detailed Guide**: See [README.md](README.md)

---

## 🔧 Alternative: Run Without Global Install

If you prefer not to use `npm link`, run directly:
```bash
# From the Scorpion directory
node cli/scorpion.js scan -t example.com
node cli/scorpion.js recon -t example.com --dns
node cli/scorpion.js --help
```

---

## 🌍 Platform-Specific Notes

### Windows
- Works in PowerShell, Command Prompt (CMD), or Git Bash
- Some scans may require "Run as Administrator" for advanced features
- Use `npm link` in an Administrator PowerShell for global access

### Linux (Ubuntu, Debian, CentOS, etc.)
- May need `sudo npm link` for global installation
- Some scans require root: `sudo scorpion scan -t example.com -sS`
- Install build tools if needed: `sudo apt install build-essential`

### macOS
- Use Terminal or iTerm2
- May need `sudo npm link` for global installation
- Some scans require root: `sudo scorpion scan -t example.com -sS`

---

## 🔑 Optional: API Keys for Enhanced Features

Create a `.env` file in the Scorpion directory for enhanced threat intelligence:

```env
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
SHODAN_API_KEY=your_shodan_key_here
```

**Get free API keys:**
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- Shodan: https://account.shodan.io/register

---

## 🐛 Troubleshooting

### "command not found: scorpion"
**Solution:** Run `npm link` again, or use the full path:
```bash
node /path/to/Scorpion/cli/scorpion.js --help
```

### "npm: command not found"
**Solution:** Install Node.js and npm first (see Prerequisites above)

### Permission errors on Linux/macOS
**Solution:** Use `sudo`:
```bash
sudo npm install
sudo npm link
```

### Module import errors
**Solution:** Ensure you're using Node.js 16+ (ES modules required):
```bash
node --version    # Must be v16.0.0+
```

### Network errors during npm install
**Solution:** Try with a different registry:
```bash
npm install --registry https://registry.npmjs.org/
```

---

## 🔄 Updating Scorpion

To get the latest version:
```bash
cd Scorpion
git pull origin main
npm install
```

---

## 🗑️ Uninstalling

To remove Scorpion:
```bash
# Remove global command
npm unlink

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

# Scorpion CLI Installation Guide

**Complete installation guide for all platforms**

---

## Prerequisites

- **Python 3.10 or higher** (required)
- pip (Python package manager)
- Git

```bash
# Verify Python version
python --version    # Must be 3.10+
```

---

## Installation Methods

### Method 1: Quick Install (Recommended)

```bash
# Clone repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# Install in virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# OR
.venv\Scripts\activate     # Windows

# Install Scorpion
pip install -e tools/python_scorpion

# Verify installation
scorpion --version
```

---

## Platform-Specific Instructions

### Windows

```powershell
# 1. Install Python from python.org (3.10+)

# 2. Clone and install
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
python -m venv .venv
.venv\Scripts\activate
pip install -e tools/python_scorpion

# 3. Verify
scorpion --version
```

### Linux (Ubuntu/Debian)

```bash
# 1. Install dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

# 2. Clone and install
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
python3 -m venv .venv
source .venv/bin/activate
pip install -e tools/python_scorpion

# 3. Verify
scorpion --version
```

### Linux (Fedora/RHEL)

```bash
sudo dnf install -y python3 python3-pip git
# Then follow Linux installation steps above
```

### macOS

```bash
# 1. Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python
brew install python@3.11

# 3. Clone and install
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
python3 -m venv .venv
source .venv/bin/activate
pip install -e tools/python_scorpion

# 4. Verify
scorpion --version
```

### Parrot OS / Kali Linux

```bash
# Python is pre-installed
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
python3 -m venv .venv
source .venv/bin/activate
pip install -e tools/python_scorpion
scorpion --version
```

---

## Optional Tools

### WiFi Pentesting Tools (Linux only)

```bash
# Ubuntu/Debian
sudo apt-get install aircrack-ng reaver hostapd dnsmasq bluez

# Fedora/RHEL
sudo dnf install aircrack-ng reaver hostapd dnsmasq bluez

# Arch Linux
sudo pacman -S aircrack-ng reaver hostapd dnsmasq bluez
```

### Mobile Security Tools

```bash
# APK analysis
sudo apt-get install apktool aapt

# Download jadx
wget https://github.com/skylot/jadx/releases/latest/download/jadx-linux.zip
unzip jadx-linux.zip -d jadx
sudo mv jadx /opt/
sudo ln -s /opt/jadx/bin/jadx /usr/local/bin/

# Frida (optional - for SSL pinning bypass)
pip install frida-tools
```

### Fuzzing Tools

```bash
# AFL++ (optional - for binary fuzzing)
sudo apt-get install afl++
```

---

## Troubleshooting

### "Python not found"
```bash
# Linux: Install Python
sudo apt-get install python3 python3-pip

# Windows: Download from python.org
```

### "pip not found"
```bash
# Linux
sudo apt-get install python3-pip

# Windows: Reinstall Python with pip enabled
```

### "scorpion command not found"
```bash
# Ensure virtual environment is activated
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Or reinstall
pip install -e tools/python_scorpion
```

### Permission errors (Linux/macOS)
```bash
# Don't use sudo with pip in venv
# If you see permission errors, ensure venv is activated
```

---

## Verification

```bash
# Test installation
scorpion --help
scorpion --version

# Run a simple scan
scorpion scan -t scanme.nmap.org --web
```

---

## Next Steps

- **Quick Start:** [GETTING_STARTED.md](GETTING_STARTED.md)
- **All Commands:** [COMMANDS.md](COMMANDS.md)
- **AI Setup:** [AI_SETUP_GUIDE.md](AI_SETUP_GUIDE.md)
- **Documentation:** [DOCS_INDEX.md](DOCS_INDEX.md)

---

**Installation complete!** 🦂✨

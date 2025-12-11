# Cross-Platform Support

Scorpion CLI is designed to work seamlessly across Windows, Linux, macOS, Parrot OS, Kali Linux, and other Unix-like operating systems.

## Supported Platforms

✅ **Windows** (10, 11, Server 2019/2022)
✅ **Linux** (Ubuntu, Debian, Fedora, Arch, CentOS, RHEL)
✅ **Security Distributions** (Parrot OS, Kali Linux, BlackArch)
✅ **macOS** (10.15+, including Apple Silicon)
✅ **BSD** (FreeBSD, OpenBSD - limited testing)

## Installation

### Universal Installation (All Platforms)

```bash
# Clone the repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1

# Install Scorpion
pip install -e tools/python_scorpion

# Verify
scorpion --help
```

### Quick Install Scripts

**Linux/macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows:**
```powershell
.\install.bat
```

## Platform-Specific Features

### Privilege Requirements

Different platforms require different privilege levels for raw packet operations (SYN scanning, OS fingerprinting, etc.):

| Platform | Requirement | Command |
|----------|-------------|---------|
| **Windows** | Administrator | Run PowerShell as Administrator |
| **Linux/Unix** | Root (uid 0) | Use `sudo` or run as root |
| **macOS** | Root (uid 0) | Use `sudo` |

### Automatic Detection

Scorpion automatically detects your platform and provides appropriate error messages:

```python
# Windows detection
if os.name == 'nt':
    # Checks for administrator privileges
    
# Unix-like detection  
else:
    # Checks for root (uid 0)
```

## Common Issues & Solutions

### Issue 1: PEP 668 - Externally Managed Environment

**Platforms affected:** Modern Linux (Ubuntu 23.04+, Debian 12+, Parrot OS, Kali 2023.1+)

**Error:**
```
error: externally-managed-environment
```

**Solution:** Always use virtual environments (already documented in install guides)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e tools/python_scorpion
```

### Issue 2: Running with Elevated Privileges

**Problem:** Need to run SYN scans with sudo, but tool is installed in venv

**Solutions:**

#### Method 1: Use venv Python with sudo (Recommended)
```bash
source .venv/bin/activate
sudo $(which python3) -m python_scorpion.cli scan -t example.com --syn --web
```

#### Method 2: Preserve environment
```bash
source .venv/bin/activate
sudo -E env PATH=$PATH scorpion scan -t example.com --syn --web
```

#### Method 3: Grant capabilities (Linux only, advanced)
```bash
sudo setcap cap_net_raw+ep $(readlink -f $(which python3))
# Now can run without sudo (security implications!)
scorpion scan -t example.com --syn --web
```

### Issue 3: Scapy Installation

Raw packet operations require Scapy:

```bash
# Install in venv
source .venv/bin/activate
pip install scapy

# Windows may require Npcap
# Download from: https://nmap.org/npcap/
```

## Platform-Specific Notes

### Windows

- **PowerShell recommended** over Command Prompt
- **Npcap required** for raw packet operations
- Path separator: `\` (backslash)
- Administrator check uses `ctypes.windll.shell32.IsUserAnAdmin()`

### Linux/Unix

- **Bash/Zsh/Fish** all supported
- Path separator: `/` (forward slash)
- Root check uses `os.geteuid() == 0`
- May need build tools for some dependencies:
  ```bash
  sudo apt-get install build-essential libffi-dev libssl-dev  # Debian/Ubuntu
  sudo yum install gcc libffi-devel openssl-devel            # RHEL/CentOS
  sudo pacman -S base-devel libffi openssl                   # Arch
  ```

### macOS

- Similar to Linux but may need Xcode Command Line Tools:
  ```bash
  xcode-select --install
  ```
- Apple Silicon (M1/M2) fully supported
- May need to allow Python in System Preferences > Security for network operations

### Parrot OS / Kali Linux

- Both implement PEP 668 by default
- **Always use virtual environments**
- Most security tools pre-installed
- Python 3.11+ by default

## Testing on Multiple Platforms

Basic smoke test:

```bash
# Activate venv
source .venv/bin/activate  # Linux/macOS
# or: .\.venv\Scripts\Activate.ps1  # Windows

# Test basic functionality
scorpion --version
scorpion scan -t scanme.nmap.org --fast
scorpion ssl-analyze -t example.com -p 443

# Test elevated privileges (as needed)
# Linux/macOS:
sudo -E env PATH=$PATH scorpion scan -t scanme.nmap.org --syn --web
# Windows (as Administrator):
scorpion scan -t scanme.nmap.org --syn --web
```

## Contributing Platform Support

If you encounter platform-specific issues:

1. **Check existing issues:** https://github.com/Prince12sam/Scorpion/issues
2. **Provide details:**
   - Operating system and version
   - Python version (`python3 --version`)
   - Error messages (full traceback)
   - Steps to reproduce

## Architecture Decision

The tool uses:
- **Python standard library** for OS detection (`os.name`, `os.geteuid()`)
- **Platform-agnostic networking** (asyncio, socket)
- **Conditional dependencies** (uvloop on Unix only)
- **Runtime privilege checks** (fail early with clear messages)

## Future Improvements

- [ ] Enhanced BSD support testing
- [ ] ARM/ARM64 architecture testing
- [ ] Docker container support
- [ ] CI/CD testing on multiple platforms
- [ ] Platform-specific optimizations

## Documentation Links

- [Windows Installation](INSTALL.md)
- [Linux Installation](INSTALL_LINUX.md)
- [Parrot OS Installation](INSTALL_PARROT_OS.md)
- [Getting Started](GETTING_STARTED.md)

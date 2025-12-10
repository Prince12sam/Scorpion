# Scorpion CLI - Quick Start Guide 🦂

Get started with Scorpion CLI in 5 minutes.

---

## Installation

### All Platforms (3 Steps)
```bash
# 1. Clone repository
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# 2. Install CLI
python -m pip install -e tools/python_scorpion

# 3. Verify
scorpion --version
scorpion --help
```

---

## Core Commands

### Help & Version
```bash
# Show all commands
scorpion --help

# Show version
scorpion --version

# Help for specific command
scorpion scan --help
```

---

## Quick Examples

### Port Scanning
```bash
# Web preset (ports 80,443,8080)
scorpion scan -t example.com --web

# Fast scan (low timeout, high concurrency)
scorpion scan -t example.com --fast

# Infrastructure scan (common server ports)
scorpion scan -t example.com --infra

# Custom ports
scorpion scan -t example.com -p 1-1024

# With UDP
scorpion scan -t example.com --web -U -u 53,123,161
```

### Reconnaissance
```bash
# DNS, HTTP headers, WHOIS
scorpion recon-cmd -t example.com

# Technology detection
scorpion tech example.com

# Directory discovery
scorpion dirbust example.com --concurrency 10
```

### Web Testing
```bash
# SSL/TLS analysis
scorpion ssl-analyze -t example.com -p 443

# API security tests
scorpion api-test example.com

# Subdomain takeover check
scorpion takeover example.com

# Web crawler
scorpion crawl example.com --max-pages 20
```

### Cloud & Container
```bash
# Cloud storage exposure
scorpion cloud examplebucket --providers aws,azure,gcp

# Kubernetes API audit
scorpion k8s https://example.com:6443

# Container registry check
scorpion container registry.example.com
```

### Suite & Reporting
```bash
# Run web suite (passive mode)
scorpion suite -t example.com --profile web --mode passive --output-dir results

# Generate HTML report
latest=$(ls -t results/suite_example.com_*.json | head -n1)
scorpion report --suite "$latest" --summary

# Active mode (with safety caps)
scorpion suite -t example.com --profile full --mode active --safe-mode --max-requests 200 --rate-limit 10 --output-dir results
```

---

## Output Options

All commands support `--output` to save JSON results:

```bash
scorpion scan -t example.com --web --output results/scan_example.json
scorpion ssl-analyze -t example.com --output results/ssl_example.json
scorpion recon-cmd -t example.com --output results/recon_example.json
```

---

## Advanced: SYN Scanning

SYN scanning requires admin/root and Scapy.

**Windows (elevated PowerShell):**
```powershell
pip install scapy
scorpion scan -t example.com --syn --web --rate-limit 50
```

**Linux (sudo):**
```bash
sudo pip install scapy
sudo scorpion scan -t example.com --syn --web --rate-limit 50
```

---

## Presets & Flags

### Scan Presets
- `--web` → ports 80,443,8080, only open
- `--fast` → timeout 2s, 60 concurrent, only open
- `--infra` → common server ports, only open

### Common Flags
- `-t, --target` → Target host
- `-p, --ports` → Port range/list
- `-C, --concurrency` → Concurrent probes
- `-T, --timeout` → Timeout seconds
- `-O, --only-open` → Show only open ports
- `-U, --udp` → Enable UDP scan
- `-u, --udp-ports` → UDP port list

---

## Platform Notes

- **Windows:** Use PowerShell, paths with `\`
- **Linux/macOS:** Use bash, paths with `/`
- **Windows SYN:** Run PowerShell as Administrator
- **Linux SYN:** Use `sudo`

---

## Next Steps

📖 Full command reference: [COMMANDS.md](COMMANDS.md)  
🐧 Linux detailed guide: [INSTALL_LINUX.md](INSTALL_LINUX.md)  
🪟 Windows detailed guide: [INSTALL.md](INSTALL.md)
Use external TI (VirusTotal/AbuseIPDB/Shodan) alongside outputs
```

### Enterprise Assessment
```bash
# Scan network range
scorpion suite 192.168.1.0/24 --profile full --output-dir results  # Python replacement

# Multiple targets
scorpion suite 192.168.1.1 --profile full --output-dir results  # run per target
scorpion suite 192.168.1.2 --profile full --output-dir results

# Deep analysis
scorpion suite 192.168.1.0/24 --profile full --mode active --output-dir results

# Compliance check
scorpion suite 192.168.1.0/24 --profile full --output-dir results  # map to suite/report

# Safe mode (no exploits)
scorpion suite 192.168.1.0/24 --profile full --safe-mode --output-dir results
```

### Internal Network Testing
```bash
# Full internal assessment (auto-discovery)
scorpion internal-test

# Targeted assessment
scorpion internal-test --scope targeted --targets 192.168.1.0/24

# Stealth mode
scorpion internal-test --scope stealth --depth deep

# Compliance assessment
scorpion internal-test --compliance PCI-DSS
```

### AI-Powered Penetration Testing
```bash
# Basic AI pentest
scorpion ai-pentest -t example.com

# Comprehensive assessment
scorpion ai-pentest -t example.com --primary-goal comprehensive_assessment

# Time-limited test
scorpion ai-pentest -t example.com --time-limit 60

# High stealth
scorpion ai-pentest -t example.com --stealth-level high

# Full autonomous
scorpion ai-pentest -t example.com \
  --primary-goal comprehensive_assessment \
  --autonomy semi-autonomous \
  --risk-tolerance medium \
  --time-limit 120
```

## Configuration

### Environment Variables
Create `.env` file:
```env
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
```

## Output Formats

```bash
# JSON output
scorpion scan -t example.com -o results.json

# Specify output file
scorpion suite example.com --profile web --mode active --output-dir results
```

## Advanced Usage

### Stealth Levels
- `low`: Fast, no evasion
- `medium`: Basic timing randomization (default)
- `high`: Advanced evasion techniques
- `ninja`: Maximum stealth, slowest

### Scan Types
- `quick`: Fast port scan
- `normal`: Standard scan (default)
- `deep`: Comprehensive analysis
- `custom`: Custom configuration

### Comprehensive Assessment Workflow
```bash
# Step 1: Reconnaissance
scorpion recon -t target.com --dns --whois --subdomain

# Step 2: Vulnerability Scanning
scorpion scan -t target.com --type deep --stealth high -o scan.json

# Step 3: Exploit Testing  
scorpion suite target.com --profile web --mode active --output-dir results

# Step 4: Threat Intelligence
Use external TI (VirusTotal/AbuseIPDB/Shodan) alongside outputs
```

### Helper Scripts

```bash
# Comprehensive suite (scan + intel + recon)
node tools/run-suite.js --target example.com --recon

# Quick scan
node tools/run-scan.js -t example.com --ports 1-1000

# Recon only
node tools/run-recon.js -t example.com

# Intel lookup
node tools/run-intel.js -i 8.8.8.8

# Password tools
node tools/run-password.js breach user@example.com
node tools/run-password.js generate
node tools/run-password.js crack hashes.txt wordlist.txt
```

## Important Notes

⚠️ **Authorization Required**: Only test systems you own or have explicit permission to test

⚠️ **Legal Compliance**: Unauthorized testing may be illegal in your jurisdiction

⚠️ **Rate Limiting**: Use appropriate stealth levels to avoid overwhelming targets

⚠️ **Ethical Use**: This tool is for authorized security testing only

## Getting Help

- Full documentation: `README.md`
- Command help: `scorpion <command> --help`
- Advanced capabilities: `scorpion help-advanced`
- Issues: https://github.com/Prince12sam/Scorpion/issues

---

**Remember**: Always obtain written authorization before testing any systems! 🦂

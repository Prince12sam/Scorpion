# Scorpion CLI - Quick Start Guide 🦂

## Installation

### Windows
```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
install.bat
```

### Linux/macOS
```bash
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion
chmod +x install.sh
./install.sh
```

## Available Commands

### Core Commands
- `scorpion scan` - Vulnerability scanning with stealth modes
- `scorpion recon` - Network reconnaissance and discovery  
- `scorpion threat-intel` - Threat intelligence lookups
- `scorpion exploit` - OWASP Top 10 exploit testing
- `scorpion enterprise-scan` - Comprehensive enterprise assessment
- `scorpion internal-test` - Internal network security testing
- `scorpion ai-pentest` - AI-powered autonomous penetration testing
- `scorpion help-advanced` - View advanced capabilities
- `scorpion --version` - Show version
- `scorpion --help` - Display help

## Basic Usage Examples

### Display Help
```bash
# Show all commands
scorpion --help

# Show help for specific command
scorpion scan --help
scorpion exploit --help
```

### Vulnerability Scanning
```bash
# Basic scan
scorpion scan -t example.com

# Scan specific ports
scorpion scan -t example.com --ports 80,443,8080

# Stealth scan (ninja mode)
scorpion scan -t example.com --stealth ninja --ports 1-1000

# Deep scan with service detection
scorpion scan -t example.com --type deep -A -O

# Save results
scorpion scan -t example.com -o results.json
```

### Network Reconnaissance
```bash
# DNS enumeration
scorpion recon -t example.com --dns

# Full reconnaissance
scorpion recon -t example.com --dns --whois --subdomain

# With port scanning
scorpion recon -t example.com --dns --ports
```

### Exploit Testing
```bash
# OWASP Top 10 testing
scorpion exploit -t example.com --payload owasp-top10

# Specific vulnerability types
scorpion exploit -t example.com --payload sql-injection
scorpion exploit -t example.com --payload xss
scorpion exploit -t example.com --payload ssrf

# Cloud exploits
scorpion exploit -t example.com --payload aws
scorpion exploit -t example.com --payload cloud

# All payloads
scorpion exploit -t example.com --payload all
```

### Threat Intelligence
```bash
# Check IP reputation
scorpion threat-intel -i 8.8.8.8

# Check domain
scorpion threat-intel -d suspicious-domain.com

# Check file hash
scorpion threat-intel -h d41d8cd98f00b204e9800998ecf8427e

# List IOCs
scorpion threat-intel --ioc
```

### Enterprise Assessment
```bash
# Scan network range
scorpion enterprise-scan -t 192.168.1.0/24

# Multiple targets
scorpion enterprise-scan -t 192.168.1.1 192.168.1.2

# Deep analysis
scorpion enterprise-scan -t 192.168.1.0/24 --deep

# Compliance check
scorpion enterprise-scan -t 192.168.1.0/24 --compliance PCI-DSS HIPAA

# Safe mode (no exploits)
scorpion enterprise-scan -t 192.168.1.0/24 --safe
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
scorpion exploit -t example.com --payload owasp-top10 -o exploits.json
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
scorpion exploit -t target.com --payload owasp-top10 -o exploits.json

# Step 4: Threat Intelligence
scorpion threat-intel -d target.com
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

# Scorpion CLI - Command Reference Card

Quick reference for all available commands and options.

## 📋 Main Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Vulnerability scanning | `scorpion scan -t example.com` |
| `recon` | Network reconnaissance | `scorpion recon -t example.com --dns` |
| `threat-intel` | Threat intelligence | `scorpion threat-intel -i 8.8.8.8` |
| `exploit` | OWASP Top 10 testing | `scorpion exploit -t example.com --payload owasp-top10` |
| `enterprise-scan` | Enterprise assessment | `scorpion enterprise-scan -t 192.168.1.0/24` |
| `internal-test` | Internal network test | `scorpion internal-test --scope full` |
| `ai-pentest` | AI-powered pentest | `scorpion ai-pentest -t example.com` |
| `takeover` | Subdomain takeover detection | `scorpion takeover -t example.com` |
| `api-test` | API security testing | `scorpion api-test -t https://api.example.com` |
| `ssl-analyze` | SSL/TLS deep analysis | `scorpion ssl-analyze -t example.com` |
| `help-advanced` | Show advanced features | `scorpion help-advanced` |

## 🔍 Scan Command

```bash
scorpion scan [options]
```

### Options
- `-t, --target <target>` - Target IP, domain, or URL (required)
- `-p, --ports <ports>` - Port range (e.g., 1-1000, 80,443)
- `--type <type>` - Scan type: quick, normal, deep, custom
- `--technique <technique>` - tcp-connect, syn-scan, udp-scan, stealth
- `-sT` - TCP connect scan
- `-sS` - TCP SYN scan (requires privileges)
- `-sU` - UDP scan
- `-A` - Aggressive: enable service/version detection
- `-O` - OS detection
- `-v, --verbose` - Verbose output
- `--stealth <level>` - low, medium, high, ninja
- `--output-mode <mode>` - nmap or json
- `-o, --output <file>` - Save results to file

### Examples
```bash
scorpion scan -t example.com
scorpion scan -t example.com --ports 80,443,8080 --stealth high
scorpion scan -t example.com -sS --type deep -A -O
scorpion scan -t example.com --stealth ninja -o results.json
```

## 🌐 Recon Command

```bash
scorpion recon [options]
```

### Options
- `-t, --target <target>` - Target IP, domain, or network (required)
- `--dns` - Perform DNS enumeration
- `--whois` - Perform WHOIS lookup
- `--ports` - Perform port scanning
- `--subdomain` - Subdomain enumeration

### Examples
```bash
scorpion recon -t example.com --dns
scorpion recon -t example.com --dns --whois --subdomain
scorpion recon -t 192.168.1.1 --dns --ports
```

## 🛡️ Threat Intel Command

```bash
scorpion threat-intel [options]
```

### Options
- `-i, --ip <ip>` - Check IP reputation
- `-d, --domain <domain>` - Check domain reputation
- `-h, --hash <hash>` - Check file hash (MD5/SHA1/SHA256)
- `--ioc` - List indicators of compromise

### Examples
```bash
scorpion threat-intel -i 8.8.8.8
scorpion threat-intel -d suspicious-domain.com
scorpion threat-intel -h d41d8cd98f00b204e9800998ecf8427e
scorpion threat-intel --ioc
```

## 💥 Exploit Command

```bash
scorpion exploit [options]
```

### Options
- `-t, --target <target>` - Target IP, domain, or URL (required)
- `-p, --port <port>` - Specific port to test
- `--service <service>` - Target service (ssh, http, ftp, smtp)
- `--vuln <cve>` - Target specific CVE (e.g., CVE-2021-44228)
- `--payload <type>` - Payload type (see below)
- `--mode <mode>` - reconnaissance, proof-of-concept, full-exploitation
- `-o, --output <file>` - Save results

### Payload Types
- `owasp-top10` - All OWASP Top 10 tests
- `sql-injection` - SQL injection tests
- `xss` - Cross-site scripting
- `ssrf` - Server-side request forgery
- `broken-access-control` - Access control tests
- `aws`, `azure`, `gcp`, `cloud` - Cloud-specific exploits
- `all` - All available payloads

### Examples
```bash
scorpion exploit -t example.com --payload owasp-top10
scorpion exploit -t example.com --payload sql-injection
scorpion exploit -t example.com --service http -p 8080
scorpion exploit -t example.com --vuln CVE-2021-44228
scorpion exploit -t example.com --payload cloud --mode proof-of-concept
```

## 🏢 Enterprise Scan Command

```bash
scorpion enterprise-scan [options]
```

### Options
- `-t, --targets <targets...>` - Target systems (IPs, ranges, or file)
- `--internal` - Include internal network scanning (default: true)
- `--external` - Include external network scanning (default: true)
- `--deep` - Enable deep vulnerability analysis
- `--authenticated` - Enable authenticated scanning
- `--compliance <frameworks...>` - PCI-DSS, HIPAA, SOC2, etc.
- `--credentials <file>` - Credentials file path
- `--threads <number>` - Concurrent threads (default: 100)
- `--safe` - Safe mode, no exploits (default: true)
- `-o, --output <file>` - Output file

### Examples
```bash
scorpion enterprise-scan -t 192.168.1.0/24
scorpion enterprise-scan -t 192.168.1.1 192.168.1.2 192.168.1.3
scorpion enterprise-scan -t targets.txt --deep
scorpion enterprise-scan -t 192.168.1.0/24 --compliance PCI-DSS HIPAA
scorpion enterprise-scan -t 192.168.1.0/24 --authenticated --credentials creds.json
```

## 🏠 Internal Test Command

```bash
scorpion internal-test [options]
```

### Options
- `--scope <scope>` - full, targeted, stealth (default: full)
- `--targets <targets...>` - Specific targets (auto-discover if not provided)
- `--depth <depth>` - surface, normal, deep (default: deep)
- `--compliance <frameworks...>` - Compliance frameworks
- `--authenticated` - Use authenticated testing
- `--credentials <file>` - Credentials file path
- `--safe-mode` - Safe mode, no exploits
- `-o, --output <file>` - Output file

### Examples
```bash
scorpion internal-test
scorpion internal-test --scope targeted --targets 192.168.1.0/24
scorpion internal-test --scope stealth --depth deep
scorpion internal-test --compliance PCI-DSS --authenticated
```

## 🤖 AI Pentest Command

```bash
scorpion ai-pentest [options]
```

### Options
- `-t, --target <target>` - Target for AI penetration test (required)
- `--primary-goal <goal>` - Primary objective (see below)
- `--secondary-goals <goals>` - Comma-separated secondary goals
- `--time-limit <minutes>` - Time limit in minutes (default: 120)
- `--stealth-level <level>` - low, moderate, high (default: moderate)
- `--autonomy <level>` - supervised, semi-autonomous, fully-autonomous
- `--risk-tolerance <level>` - low, medium, high (default: medium)
- `--learning-mode <mode>` - enabled or disabled
- `-o, --output <file>` - Output file

### Primary Goals
- `comprehensive_assessment` - Full security assessment
- `privilege_escalation` - Focus on privilege escalation
- `data_access` - Focus on data access

### Examples
```bash
scorpion ai-pentest -t example.com
scorpion ai-pentest -t example.com --primary-goal comprehensive_assessment
scorpion ai-pentest -t example.com --stealth-level high --time-limit 60
scorpion ai-pentest -t example.com --autonomy semi-autonomous --risk-tolerance medium
```

## 🎯 Stealth Levels

| Level | Speed | Detection Probability | Use Case |
|-------|-------|----------------------|----------|
| `low` | Fast | High (~70%) | Internal testing |
| `medium` | Moderate | Medium (~45%) | General testing |
| `high` | Slow | Low (~25%) | External testing |
| `ninja` | Very Slow | Very Low (<15%) | Red team operations |

## 📊 Output Formats

All commands support JSON output:
```bash
scorpion scan -t example.com -o results.json
scorpion recon -t example.com --dns -o recon.json
scorpion exploit -t example.com --payload owasp-top10 -o exploits.json
```

## 🔧 Helper Scripts

Located in `tools/` directory:

```bash
# Comprehensive security suite
node tools/run-suite.js --target example.com --recon

# Quick vulnerability scan
node tools/run-scan.js -t example.com --ports 1-1000

# Network reconnaissance
node tools/run-recon.js -t example.com

# Threat intelligence lookup
node tools/run-intel.js -i 8.8.8.8

# Password security
node tools/run-password.js breach user@example.com
node tools/run-password.js generate
node tools/run-password.js crack hashes.txt wordlist.txt
node tools/run-password.js strength "MyPassword123"
```

## 🔍 Subdomain Takeover Command

```bash
scorpion takeover [options]
```

### Options
- `-t, --target <domain>` - Target domain to check (required)
- `--subdomains <file>` - File containing list of subdomains to check
- `--check-aws` - Check specifically for AWS S3 takeovers
- `--check-azure` - Check specifically for Azure takeovers
- `-o, --output <file>` - Output results to file

### What It Tests
- DNS CNAME resolution
- 15+ cloud services (AWS S3, Azure, GitHub Pages, Heroku, Shopify, etc.)
- Unclaimed resource detection
- Service fingerprinting

### Examples
```bash
# Scan domain for takeover vulnerabilities
scorpion takeover -t example.com

# Check specific AWS S3 configuration
scorpion takeover -t subdomain.example.com --check-aws

# Check Azure services
scorpion takeover -t subdomain.example.com --check-azure

# Scan custom subdomain list
scorpion takeover -t example.com --subdomains subdomains.txt

# Save results
scorpion takeover -t example.com -o takeover-results.json
```

## 🔐 API Security Testing Command

```bash
scorpion api-test [options]
```

### Options
- `-t, --target <url>` - Target API base URL (required)
- `--no-discover` - Skip API endpoint discovery
- `--no-swagger` - Skip OpenAPI/Swagger testing
- `--no-graphql` - Skip GraphQL testing
- `--no-auth` - Skip authentication testing
- `--no-authz` - Skip authorization/IDOR testing
- `--no-rate-limit` - Skip rate limiting tests
- `--no-validation` - Skip input validation tests
- `-o, --output <file>` - Output results to file

### What It Tests
- API endpoint discovery
- OpenAPI/Swagger documentation exposure
- GraphQL introspection
- Authentication mechanisms (Basic, JWT, OAuth)
- Authorization/IDOR vulnerabilities
- Rate limiting bypass
- Input validation (XSS, SQLi, Command Injection)
- JWT security (HttpOnly, Secure flags)
- GraphQL query batching abuse
- Weak credentials

### Examples
```bash
# Full API security test
scorpion api-test -t https://api.example.com

# Test without GraphQL checks
scorpion api-test -t https://api.example.com --no-graphql

# Skip rate limiting tests
scorpion api-test -t https://api.example.com --no-rate-limit

# Test only authentication and authorization
scorpion api-test -t https://api.example.com --no-discover --no-graphql --no-validation

# Save detailed results
scorpion api-test -t https://api.example.com -o api-security-report.json
```

## 🔒 SSL/TLS Analysis Command

```bash
scorpion ssl-analyze [options]
```

### Options
- `-t, --target <host>` - Target hostname (required)
- `-p, --port <port>` - Target port (default: 443)
- `-o, --output <file>` - Output results to file

### What It Tests
- Certificate validation and expiration
- Key size and signature algorithm
- SSL/TLS protocol support (SSLv3, TLS 1.0-1.3)
- Cipher suite strength
- Known vulnerabilities:
  - Heartbleed (CVE-2014-0160)
  - POODLE (CVE-2014-3566)
  - BEAST (CVE-2011-3389)
  - CRIME (CVE-2012-4929)
- Security headers (HSTS, HPKP)
- Certificate chain validation
- Self-signed certificate detection
- Weak cipher identification

### Examples
```bash
# Analyze SSL/TLS configuration
scorpion ssl-analyze -t example.com

# Test specific port
scorpion ssl-analyze -t example.com -p 8443

# Test custom HTTPS port
scorpion ssl-analyze -t api.example.com -p 8080

# Save detailed analysis
scorpion ssl-analyze -t example.com -o ssl-analysis.json
```

## ⚙️ Environment Variables

Create `.env` file:
```env
# API Keys (Optional)
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key

# Configuration
DEFAULT_TIMEOUT=5000
MAX_CONCURRENT_SCANS=100
DEFAULT_STEALTH_LEVEL=medium
```

## 🆘 Getting Help

```bash
# General help
scorpion --help

# Command-specific help
scorpion scan --help
scorpion recon --help
scorpion exploit --help
scorpion enterprise-scan --help
scorpion internal-test --help
scorpion ai-pentest --help
scorpion takeover --help
scorpion api-test --help
scorpion ssl-analyze --help

# Advanced capabilities
scorpion help-advanced

# Version
scorpion --version
```

## ⚠️ Legal & Ethical Use

**IMPORTANT**: This tool is for authorized security testing only.

- ✅ Only test systems you own or have explicit written permission to test
- ✅ Follow all applicable laws and regulations
- ✅ Use appropriate stealth levels to avoid overwhelming targets
- ✅ Document all testing activities
- ❌ Never use for unauthorized access or malicious activities

---

**Quick Reference Version**: 2.0.1 (Enhanced)  
**Last Updated**: December 8, 2025  
**Documentation**: See README.md for full details

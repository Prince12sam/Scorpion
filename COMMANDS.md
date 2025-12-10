# Scorpion CLI - Command Reference

Complete reference for all Scorpion CLI commands and options.

---

## 📋 Core Commands

| Command | Description | Quick Example |
|---------|-------------|---------------|
| `scan` | TCP/UDP port scanning | `scorpion scan -t example.com --web` |
| `ssl-analyze` | SSL/TLS analysis | `scorpion ssl-analyze -t example.com` |
| `recon-cmd` | Reconnaissance | `scorpion recon-cmd -t example.com` |
| `takeover` | Subdomain takeover check | `scorpion takeover example.com` |
| `api-test` | API security testing | `scorpion api-test example.com` |
| `dirbust` | Directory discovery | `scorpion dirbust example.com` |
| `tech` | Technology detection | `scorpion tech example.com` |
| `crawl` | Web crawler | `scorpion crawl example.com` |
| `cloud` | Cloud storage audit | `scorpion cloud bucket` |
| `k8s` | Kubernetes API audit | `scorpion k8s https://host:6443` |
| `container` | Container registry audit | `scorpion container registry.host` |
| `suite` | Combined security suite | `scorpion suite -t example.com --profile web` |
| `report` | Generate HTML report | `scorpion report --suite results.json` |

---

## 🔍 scan - Port Scanning

```bash
scorpion scan -t <target> [options]
```

### Options
| Flag | Description | Example |
|------|-------------|---------|
| `-t, --target` | Target host (required) | `-t example.com` |
| `-p, --ports` | Port range/list | `-p 1-1024` or `-p 80,443` |
| `-C, --concurrency` | Concurrent probes | `-C 200` |
| `-T, --timeout` | Timeout seconds | `-T 2.0` |
| `-R, --retries` | Retry count | `-R 1` |
| `-U, --udp` | Enable UDP scan | `-U` |
| `-u, --udp-ports` | UDP ports | `-u 53,123,161` |
| `-O, --only-open` | Show only open ports | `-O` |
| `--raw` | Raw banner only | `--raw` |
| `--no-write` | Connect-only mode | `--no-write` |
| `--syn` | SYN scan (requires admin) | `--syn` |
| `--fin` | FIN scan (requires admin) | `--fin` |
| `--xmas` | XMAS scan (requires admin) | `--xmas` |
| `--null` | NULL scan (requires admin) | `--null` |
| `--ack` | ACK scan (requires admin) | `--ack` |
| `-D, --decoy` | Decoy scan (IDS/IPS evasion) | `--decoy RND:5` |
| `-T` | Timing template | `-T sneaky` |
| `--rate-limit` | SYN rate limit | `--rate-limit 50` |
| `--iface` | Network interface | `--iface eth0` |
| `--list-ifaces` | List interfaces | `--list-ifaces` |
| `-sV, --version-detect` | Service version detection | `--version-detect` |
| `-O, --os-detect` | OS fingerprinting | `--os-detect` |
| `--fast` | Fast preset | `--fast` |
| `--web` | Web preset (80,443,8080) | `--web` |
| `--infra` | Infrastructure preset | `--infra` |
| `--output` | Save JSON output | `--output scan.json` |

### Examples
```bash
# Web scan
scorpion scan -t example.com --web

# Fast scan
scorpion scan -t example.com --fast

# Custom ports with UDP
scorpion scan -t example.com -p 1-1024 -U -u 53,123,161

# SYN scan (admin required)
scorpion scan -t example.com --syn --web --rate-limit 50

# OS fingerprinting
scorpion scan -t example.com --syn --os-detect

# Decoy scanning (IDS/IPS evasion, admin required)
scorpion scan -t example.com --syn --decoy RND:5
scorpion scan -t example.com --fin --decoy RND:10 -T sneaky
scorpion scan -t example.com --syn --decoy 10.0.0.1,ME,10.0.0.3

# Advanced scans with timing templates
scorpion scan -t example.com --syn -T aggressive
scorpion scan -t example.com --xmas -T sneaky --decoy RND:8
```

---

## 🔐 ssl-analyze - SSL/TLS Analysis

```bash
scorpion ssl-analyze -t <target> [options]
```

### Options
| Flag | Description | Example |
|------|-------------|---------|
| `-t, --target` | Target host | `-t example.com` |
| `-p, --port` | TLS port | `-p 443` |
| `-T, --timeout` | Timeout seconds | `-T 5` |
| `--output` | Save JSON | `--output ssl.json` |

### Example
```bash
scorpion ssl-analyze -t example.com -p 443 -T 5 --output results/ssl.json
```

---

## 🌐 recon-cmd - Reconnaissance

```bash
scorpion recon-cmd -t <target> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `-t, --target` | Target host |
| `--output` | Save JSON |

### Example
```bash
scorpion recon-cmd -t example.com --output results/recon.json
```

---

## 🎯 takeover - Subdomain Takeover

```bash
scorpion takeover <host> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--output` | Save JSON |
| `--timeout` | Timeout seconds |

### Example
```bash
scorpion takeover example.com --output results/takeover.json
```

---

## 🔌 api-test - API Security

```bash
scorpion api-test <host> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--output` | Save JSON |
| `--bursts` | Rate limit test bursts |

### Example
```bash
scorpion api-test example.com --output results/api.json
```

---

## 📁 dirbust - Directory Discovery

```bash
scorpion dirbust <host> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--wordlist` | Custom wordlist path |
| `--concurrency` | Concurrent requests |
| `--https` | Use HTTPS |
| `--output` | Save JSON |

### Example
```bash
scorpion dirbust example.com --concurrency 10 --output results/dirb.json
```

---

## 🔬 tech - Technology Detection

```bash
scorpion tech <host> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--output` | Save JSON |

### Example
```bash
scorpion tech example.com --output results/tech.json
```

---

## 🕷️ crawl - Web Crawler

```bash
scorpion crawl <host> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--start` | Start URL |
| `--max-pages` | Maximum pages |
| `--concurrency` | Concurrent requests |
| `--output` | Save JSON |

### Example
```bash
scorpion crawl example.com --start https://example.com --max-pages 20 --output results/crawl.json
```

---

## ☁️ cloud - Cloud Storage Audit

```bash
scorpion cloud <name> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--providers` | Providers (aws,azure,gcp) |
| `--output` | Save JSON |

### Example
```bash
scorpion cloud examplebucket --providers aws,azure,gcp --output results/cloud.json
```

---

## ☸️ k8s - Kubernetes Audit

```bash
scorpion k8s <api-base> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--insecure` | Skip TLS verification |
| `--output` | Save JSON |

### Example
```bash
scorpion k8s https://example.com:6443 --output results/k8s.json
```

---

## 📦 container - Container Registry Audit

```bash
scorpion container <registry> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--output` | Save JSON |

### Example
```bash
scorpion container registry.example.com --output results/container.json
```

---

## 🎭 suite - Combined Security Suite

```bash
scorpion suite -t <target> [options]
```

### Options
| Flag | Description | Example |
|------|-------------|---------|
| `-t, --target` | Target host | `-t example.com` |
| `--profile` | Scan profile | `--profile web` |
| `--mode` | Testing mode | `--mode passive` |
| `--output-dir` | Output directory | `--output-dir results` |
| `--ports` | Port range | `--ports 1-1024` |
| `--udp` | Include UDP | `--udp` |
| `--cloud-name` | Cloud bucket name | `--cloud-name bucket` |
| `--k8s-api` | K8s API URL | `--k8s-api https://host:6443` |
| `--registry` | Container registry | `--registry registry.host` |
| `--safe-mode` | Enable safety caps | `--safe-mode` |
| `--max-requests` | Request cap | `--max-requests 200` |
| `--rate-limit` | Rate limit | `--rate-limit 10` |

### Profiles
- `web` - Web application testing
- `api` - API security testing
- `infra` - Infrastructure scanning
- `full` - Complete suite

### Modes
- `passive` - Non-intrusive checks
- `active` - Active testing (with safety caps)

### Example
```bash
scorpion suite -t example.com --profile web --mode passive --output-dir results
```

---

## 📊 report - HTML Report Generation

```bash
scorpion report --suite <file> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `--suite` | Suite JSON file |
| `--output` | HTML output file |
| `--summary` | Generate summary report |

### Example
```bash
scorpion report --suite results/suite_example.com_*.json --summary --output report.html
```

---

## 🚀 Quick Command Chains

```bash
# Web suite + report
scorpion suite -t example.com --profile web --mode passive --output-dir results
latest=$(ls -t results/suite_example.com_*.json | head -n1)
scorpion report --suite "$latest" --summary

# Multi-tool scan
scorpion scan -t example.com --web --output results/scan.json
scorpion ssl-analyze -t example.com --output results/ssl.json
scorpion recon-cmd -t example.com --output results/recon.json
```
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
scorpion suite example.com --profile web --mode active

Python alternative (safe active checks):
```bash
scorpion suite example.com --profile web --mode active --output-dir results
```
```

## 🏢 Enterprise Assessment (Python Suite)

```bash
Use the Python `suite` command to orchestrate comprehensive assessments.
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
scorpion suite 192.168.1.0/24 --profile full --output-dir results
scorpion suite 192.168.1.1 --profile full --output-dir results
scorpion suite 192.168.1.2 --profile full --output-dir results
scorpion suite example.com --profile full --mode active --output-dir results
```

## 🏠 Internal Test Command (Legacy)

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
Internal testing: use `suite` or targeted `scan/recon`
scorpion internal-test --scope targeted --targets 192.168.1.0/24
scorpion internal-test --scope stealth --depth deep
scorpion internal-test --compliance PCI-DSS --authenticated
```

## 🤖 AI Pentest Command ⭐ NEW

**Autonomous penetration testing using AI (OpenAI, Anthropic, etc.)**

```bash
scorpion ai-pentest -t <target> [options]
```

### Requirements
- AI API key (OpenAI, Anthropic, or custom endpoint)
- Set `SCORPION_AI_API_KEY` environment variable or use `--api-key` flag

### Options
| Flag | Description | Default |
|------|-------------|---------||
| `-t, --target` | Target for AI penetration test | Required |
| `--primary-goal` | Primary objective | `comprehensive_assessment` |
| `--secondary-goals` | Comma-separated goals | None |
| `--time-limit` | Time limit in minutes | `120` |
| `--stealth-level` | low, moderate, high | `moderate` |
| `--autonomy` | supervised, semi_autonomous, fully_autonomous | `semi_autonomous` |
| `--risk-tolerance` | low, medium, high | `medium` |
| `--ai-provider` | openai, anthropic, custom | `openai` |
| `--api-key` | AI API key | `$SCORPION_AI_API_KEY` |
| `--model` | AI model name | `gpt-4` |
| `--api-endpoint` | Custom API endpoint | None |
| `--max-iterations` | Maximum AI decision loops | `10` |
| `-o, --output` | Output JSON file | Auto-generated |

### Primary Goals
- `comprehensive_assessment` - Full security assessment (default)
- `privilege_escalation` - Focus on privilege escalation paths
- `data_access` - Focus on data exposure vulnerabilities
- `network_mapping` - Network discovery and mapping
- `web_exploitation` - Deep web application testing

### Examples
```bash
# Set API key
export SCORPION_AI_API_KEY='sk-...'

# Basic AI pentest
scorpion ai-pentest -t example.com

# Comprehensive with OpenAI GPT-4
scorpion ai-pentest -t example.com --primary-goal comprehensive_assessment --model gpt-4

# High stealth with Anthropic Claude
scorpion ai-pentest -t example.com --ai-provider anthropic --api-key sk-ant-... --stealth-level high

# Local AI model (free, private)
scorpion ai-pentest -t example.com --ai-provider custom --api-endpoint http://localhost:11434/v1/chat/completions

# Web exploitation focus
scorpion ai-pentest -t example.com --primary-goal web_exploitation --risk-tolerance medium

# Fully autonomous (dangerous, requires authorization)
scorpion ai-pentest -t example.com --autonomy fully_autonomous --risk-tolerance high
```

### Documentation
See [AI_PENTESTING_GUIDE.md](AI_PENTESTING_GUIDE.md) for complete guide.

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
scorpion suite example.com --profile web --mode active --output-dir results
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
scorpion suite --help
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

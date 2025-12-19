# Nuclei Templates Guide

Complete reference for Nuclei vulnerability detection templates in Scorpion.

## Quick Reference

| Use Case | Nuclei Template/Tag | Severity | Command Example |
|----------|-------------------|----------|-----------------|
| **Detect known CVEs** | CVE-2021-44228 (Log4Shell) | Critical | `scorpion nuclei -t target.com -tags cve,log4j` |
| **Out-of-Band vulnerabilities** | Blind SQL Injection via OOB | High | `scorpion nuclei -t target.com -tags oob,sqli` |
| **SQL Injection detection** | Generic SQL Injection | High | `scorpion nuclei -t target.com -tags sqli` |
| **Cross-Site Scripting (XSS)** | Reflected XSS Detection | Medium | `scorpion nuclei -t target.com -tags xss` |
| **Default or weak passwords** | Default Credentials Check | High | `scorpion nuclei -t target.com -tags default-login` |
| **Secret files or data exposure** | Sensitive File Disclosure | Medium | `scorpion nuclei -t target.com -tags exposure,config` |
| **Open redirects** | Open Redirect Detection | Low | `scorpion nuclei -t target.com -tags redirect` |
| **Subdomain takeovers** | Subdomain Takeover Templates | High | `scorpion nuclei -t target.com -tags takeover` |
| **Security misconfigurations** | Unprotected Jenkins Console | High | `scorpion nuclei -t target.com -tags misconfig` |
| **Weak SSL/TLS configurations** | SSL Certificate Expiry | Info | `scorpion nuclei -t target.com -tags ssl` |
| **Misconfigured cloud services** | Open S3 Bucket Detection | Critical | `scorpion nuclei -t target.com -tags aws,s3,exposure` |
| **Remote code execution** | RCE Detection Templates | Critical | `scorpion nuclei -t target.com -tags rce` |
| **Directory traversal** | Path Traversal Detection | High | `scorpion nuclei -t target.com -tags lfi,traversal` |
| **File inclusion vulnerabilities** | Local/Remote File Inclusion | High | `scorpion nuclei -t target.com -tags lfi,rfi` |

---

## Severity Levels

| Severity | Risk Level | Action Required |
|----------|-----------|-----------------|
| **CRITICAL** | Immediate exploit risk | Patch immediately, disable service |
| **HIGH** | Significant security risk | Patch within 24-48 hours |
| **MEDIUM** | Moderate security risk | Patch within 1 week |
| **LOW** | Minor security concern | Patch during maintenance window |
| **INFO** | Informational finding | Review and document |

---

## Common Tag Combinations

### OWASP Top 10 Scanning
```bash
scorpion nuclei -t target.com -tags owasp,sqli,xss,xxe,ssrf,idor
```

### CVE Hunting (Latest Vulnerabilities)
```bash
scorpion nuclei -t target.com -tags cve -s critical,high --update
```

### Default Credentials & Exposure
```bash
scorpion nuclei -t target.com -tags default-login,exposure,config,misconfig
```

### Web Application Security
```bash
scorpion nuclei -t target.com -tags sqli,xss,rce,lfi,ssrf,idor,redirect
```

### Cloud Security Assessment
```bash
scorpion nuclei -t target.com -tags aws,azure,gcp,s3,kubernetes,docker
```

### API Security Testing
```bash
scorpion nuclei -t api.target.com -tags api,graphql,jwt,swagger
```

### Authentication & Authorization
```bash
scorpion nuclei -t target.com -tags auth,default-login,jwt,oauth,bypass
```

---

## Template Categories

### 1. CVE Detection
**What it does:** Scans for known Common Vulnerabilities and Exposures (CVEs)

**Examples:**
- CVE-2021-44228 (Log4Shell)
- CVE-2021-26855 (ProxyLogon)
- CVE-2020-5902 (F5 BIG-IP RCE)
- CVE-2017-5638 (Apache Struts2 RCE)

**Usage:**
```bash
# All CVEs
scorpion nuclei -t target.com -tags cve -s critical,high

# Specific CVE
scorpion nuclei -t target.com -T cves/2021/CVE-2021-44228.yaml

# Recent CVEs (update first)
scorpion nuclei -t target.com -tags cve --update
```

### 2. OWASP Top 10
**What it does:** Tests for OWASP Top 10 web application vulnerabilities

**Categories:**
- SQL Injection (sqli)
- Cross-Site Scripting (xss)
- Broken Authentication (auth, bypass)
- Sensitive Data Exposure (exposure)
- XML External Entities (xxe)
- Broken Access Control (idor)
- Security Misconfiguration (misconfig)
- Insecure Deserialization (deserialization)
- Using Components with Known Vulnerabilities (cve)
- Insufficient Logging & Monitoring (info)

**Usage:**
```bash
scorpion nuclei -t target.com -tags owasp
```

### 3. Default Credentials
**What it does:** Tests for default/weak credentials on common services

**Services Covered:**
- Admin panels (admin/admin, admin/password)
- Databases (root/root, postgres/postgres)
- Routers/IoT devices
- Jenkins, Grafana, Kibana
- WordPress, Joomla

**Usage:**
```bash
scorpion nuclei -t target.com -tags default-login
```

### 4. Exposure Detection
**What it does:** Finds exposed sensitive files, directories, and configurations

**Detects:**
- .git directory exposure
- .env files
- Configuration files (config.php, database.yml)
- Backup files (.bak, .old)
- API keys in source code
- Debug endpoints

**Usage:**
```bash
scorpion nuclei -t target.com -tags exposure,config
```

### 5. Remote Code Execution (RCE)
**What it does:** Detects command injection and remote code execution vulnerabilities

**Types:**
- OS command injection
- Template injection (SSTI)
- Deserialization RCE
- File upload → RCE
- Eval-based RCE

**Usage:**
```bash
scorpion nuclei -t target.com -tags rce -s critical,high
```

### 6. Cloud Security
**What it does:** Tests for cloud misconfigurations

**Providers:**
- AWS (S3, EC2, Lambda, IAM)
- Azure (Storage, Functions, KeyVault)
- GCP (Storage, Cloud Functions, IAM)
- Kubernetes (exposed dashboards, RBAC)
- Docker (exposed registries, APIs)

**Usage:**
```bash
# AWS specific
scorpion nuclei -t target.com -tags aws,s3

# All cloud providers
scorpion nuclei -t target.com -tags aws,azure,gcp,kubernetes,docker
```

### 7. Subdomain Takeover
**What it does:** Detects dangling DNS records vulnerable to takeover

**Services Checked:**
- GitHub Pages
- Heroku
- AWS S3
- Azure
- WordPress.com
- Shopify
- Unbounce

**Usage:**
```bash
scorpion nuclei -t target.com -tags takeover
```

### 8. SSL/TLS Issues
**What it does:** Checks SSL/TLS configuration and certificate issues

**Checks:**
- Expired certificates
- Self-signed certificates
- Weak ciphers (SSLv3, TLS 1.0)
- Missing HSTS headers
- Certificate mismatches

**Usage:**
```bash
scorpion nuclei -t target.com -tags ssl,tls
```

---

## AI Integration

When using `scorpion ai-pentest`, the AI automatically uses Nuclei based on findings:

### Automatic Nuclei Triggering
```bash
# AI will run Nuclei after initial reconnaissance
scorpion ai-pentest -t target.com

# Force specific vulnerability focus
scorpion ai-pentest -t target.com -i "find SQLi using nuclei"
scorpion ai-pentest -t target.com -i "scan for CVEs"
```

### Custom Nuclei Instructions
```bash
# Use custom instructions to guide AI
scorpion ai-pentest -t target.com -i "use nuclei to check for Log4Shell"
scorpion ai-pentest -t target.com -i "run nuclei with critical CVE templates"
scorpion ai-pentest -t target.com -i "scan for cloud misconfigurations"
```

---

## Advanced Usage

### 1. High-Speed Scanning
```bash
scorpion nuclei -t target.com -tags cve -rl 300 -c 50
```

### 2. Exclude False Positives
```bash
scorpion nuclei -t target.com -tags cve --exclude-tags intrusive,dos
```

### 3. Save Results
```bash
scorpion nuclei -t target.com -tags owasp -o results.json
```

### 4. Stealth Scanning
```bash
scorpion nuclei -t target.com -tags cve -rl 5 -c 1 --timeout 30
```

### 5. Multiple Targets
```bash
# Create targets.txt with URLs
scorpion nuclei -t targets.txt -tags cve,owasp
```

---

## Performance Tuning

| Parameter | Default | Recommended | Use Case |
|-----------|---------|-------------|----------|
| `--rate-limit` | 150 | 300+ | Fast scanning (good bandwidth) |
| | | 50 | Stealth scanning |
| `--concurrency` | 25 | 50+ | Fast scanning (powerful CPU) |
| | | 10 | Limited resources |
| `--timeout` | 10 | 30 | Slow targets |
| | | 5 | Fast internal networks |
| `--retries` | 1 | 3 | Unstable networks |

---

## Template Development

### Custom Template Structure
```yaml
id: custom-vuln-check
info:
  name: Custom Vulnerability Check
  author: YourName
  severity: high
  tags: custom,sqli

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/user?id=1'"
    matchers:
      - type: word
        words:
          - "SQL syntax error"
          - "mysql_fetch"
```

### Add Custom Templates
```bash
# Place in ~/.config/nuclei/templates/custom/
scorpion nuclei -t target.com -T ~/.config/nuclei/templates/custom/
```

---

## Troubleshooting

### Nuclei Not Found
```bash
# Install on Kali/Debian
sudo apt update && sudo apt install nuclei

# Install on macOS
brew install nuclei

# Update templates
scorpion nuclei -t target.com --update
```

### Rate Limiting / Blocking
```bash
# Reduce rate and concurrency
scorpion nuclei -t target.com -rl 10 -c 5

# Add delays
scorpion nuclei -t target.com -rl 1 -c 1 --timeout 30
```

### No Results Found
```bash
# Update templates first
scorpion nuclei -t target.com --update -tags cve

# Try different tags
scorpion nuclei -t target.com -tags owasp,misconfig,exposure

# Check with verbose output
scorpion nuclei -t target.com -tags cve --silent=false
```

---

## Best Practices

1. **Always update templates before important scans**
   ```bash
   scorpion nuclei -t target.com --update
   ```

2. **Start with critical severity only**
   ```bash
   scorpion nuclei -t target.com -s critical,high
   ```

3. **Use specific tags for focused testing**
   ```bash
   scorpion nuclei -t target.com -tags cve,rce,sqli
   ```

4. **Save results for reporting**
   ```bash
   scorpion nuclei -t target.com -tags owasp -o scan_$(date +%Y%m%d).json
   ```

5. **Respect rate limits and target stability**
   ```bash
   scorpion nuclei -t target.com -rl 50 -c 10
   ```

---

## Integration with Other Tools

### With SQLMap
```bash
# Find SQLi with Nuclei, exploit with SQLMap
scorpion nuclei -t target.com -tags sqli -o sqli.json
scorpion sqlmap --url "http://target.com/page?id=1" --action dump
```

### With Nmap
```bash
# Port scan first, then Nuclei
scorpion port-scan -t target.com
scorpion nuclei -t target.com -tags cve,default-login
```

### With AI Pentest
```bash
# AI orchestrates Nuclei with other tools
scorpion ai-pentest -t target.com -i "use nuclei to find CVEs then exploit them"
```

---

## Template Statistics

- **Total Templates**: 8900+
- **CVE Templates**: 2500+
- **Technology Templates**: 1500+
- **Exposure Templates**: 800+
- **Misconfiguration Templates**: 600+
- **Default Login Templates**: 200+

---

## References

- Official Documentation: https://docs.projectdiscovery.io/tools/nuclei
- Template Repository: https://github.com/projectdiscovery/nuclei-templates
- Community Templates: https://github.com/topics/nuclei-templates
- CVE Database: https://cve.mitre.org/

---

**⚠️ Legal Notice**: Always obtain written authorization before scanning. Unauthorized security testing is illegal.

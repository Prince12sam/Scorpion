# 🚀 Scorpion Quick Command Reference

## Essential Scan Commands

### 1. Web Vulnerability Scan (Direct Target)
**Best for:** Testing specific vulnerable pages you already know about
```bash
python -m python_scorpion.cli webscan "http://testphp.vulnweb.com/artists.php?artist=1"
```
**Output:**
- Real-time vulnerability detection: `[🎯 VULN] Error-based SQLi in artist: SQL syntax`
- Stops after 10 findings per type for speed
- Detects: SQLi, XSS, RCE, SSRF, security headers

**Use when:** You know the vulnerable page/parameter already

---

### 2. AI-Driven Autonomous Pentest (Full Methodology)
**Best for:** Complete penetration testing following OWASP + ethical hacking methodology
```bash
python -m python_scorpion.cli ai-pentest --target testphp.vulnweb.com --risk-tolerance high
```
**What it does (AUTONOMOUS):**
1. **Reconnaissance** - DNS, WHOIS, subdomains
2. **Technology Detection** - Frameworks, CMS, WAF
3. **OS Fingerprinting** - For payload targeting
4. **Port Scanning** - Discovers all open ports
5. **Service Enumeration** - Versions, banners
6. **Nuclei Scan** - 8900+ CVE templates
7. **Directory Busting** - Discovers hidden pages (.php, .asp, .jsp)
8. **Web Vulnerability Testing** - Tests ALL discovered pages for SQLi/XSS/RCE
9. **Bruteforce** - Default credentials on discovered services
10. **Exploitation** - Actually exploits found vulnerabilities
11. **Payload Generation** - Reverse/bind shells

**Autonomous Discovery:**
- Finds `/artists.php`, `/listproducts.php`, `/login.php` automatically
- Tests EVERY discovered page for vulnerabilities
- No manual URL specification needed!

**Use when:** You want full autonomous pentesting with OWASP methodology

---

### 3. Quick Web Scan (Base URL Discovery)
```bash
python -m python_scorpion.cli webscan http://testphp.vulnweb.com
```
**What it does:**
- Tests base URL + 3 common endpoints
- Tests 3 most likely parameters (id, search, cmd)
- Fast scan (5-10 minutes)

**Use when:** Quick assessment of base URL

---

### 4. Specific Vulnerability Type Scans

#### SQL Injection Only
```bash
python -m python_scorpion.cli sqli --target "http://testphp.vulnweb.com/artists.php?artist=1"
```

#### XSS Only
```bash
python -m python_scorpion.cli xss --target "http://testphp.vulnweb.com/artists.php?artist=1"
```

#### Directory Bruteforce
```bash
python -m python_scorpion.cli dirbuster --target http://testphp.vulnweb.com
```

---

## Performance Settings

### Aggressive (Maximum Speed)
```bash
python -m python_scorpion.cli webscan "http://target.com" --concurrency 100
```
- 100 concurrent connections
- Tests 15-20 payloads in parallel batches
- Completes in 3-5 minutes

### Balanced (Stable + Fast)
```bash
python -m python_scorpion.cli webscan "http://target.com" --concurrency 50
```
- 50 concurrent connections (default)
- Prevents timeouts while maintaining speed
- Completes in 5-10 minutes

### Stealth (Low Detection)
```bash
python -m python_scorpion.cli webscan "http://target.com" --concurrency 10
```
- 10 concurrent connections
- Slower but harder to detect
- Completes in 15-20 minutes

---

## AI Configuration

### Set API Key (Required for AI features)
**FREE GitHub Models (Recommended):**
```bash
export SCORPION_AI_API_KEY='ghp_your_github_token_here'
```
Get free token: https://github.com/marketplace/models

**OpenAI (Paid):**
```bash
export SCORPION_AI_API_KEY='sk-proj-your_openai_key_here'
```

**Anthropic (Paid):**
```bash
export SCORPION_AI_API_KEY='sk-ant-your_anthropic_key_here'
```

---

## Risk Tolerance Levels

### LOW Risk (Safe, Passive Only)
```bash
python -m python_scorpion.cli ai-pentest --target example.com --risk-tolerance low
```
- No exploitation attempts
- Reconnaissance only
- No bruteforce

### MEDIUM Risk (Active Scanning)
```bash
python -m python_scorpion.cli ai-pentest --target example.com --risk-tolerance medium
```
- Active vulnerability scanning
- No automatic exploitation
- No shell attempts

### HIGH Risk (Full Exploitation)
```bash
python -m python_scorpion.cli ai-pentest --target example.com --risk-tolerance high
```
- ⚠️ **AUTOMATIC EXPLOITATION**
- Attempts to gain shell access
- SQLi → `sqlmap --os-shell`
- RCE → Command execution
- File upload exploitation
- Bruteforce with 10+ attempts per vuln
- Parallel exploitation (5 simultaneous)

---

## Example Workflows

### Workflow 1: Full Autonomous Assessment
```bash
# Step 1: Run AI pentest with HIGH risk (autonomous discovery + exploitation)
python -m python_scorpion.cli ai-pentest --target testphp.vulnweb.com --risk-tolerance high

# Step 2: Review detailed findings
cat ai_pentest_testphp.vulnweb.com_*.json
```

### Workflow 2: Manual Discovery + Exploitation
```bash
# Step 1: Discover pages
python -m python_scorpion.cli dirbuster --target http://testphp.vulnweb.com

# Step 2: Test discovered pages
python -m python_scorpion.cli webscan "http://testphp.vulnweb.com/artists.php?artist=1"
python -m python_scorpion.cli webscan "http://testphp.vulnweb.com/listproducts.php?cat=1"

# Step 3: Exploit specific vulnerabilities
python -m python_scorpion.cli exploit-sqli --url "http://testphp.vulnweb.com/artists.php?artist=1"
```

### Workflow 3: Quick Scan + Deep Dive
```bash
# Step 1: Quick scan to identify vulnerabilities
python -m python_scorpion.cli webscan http://testphp.vulnweb.com

# Step 2: If vulns found, run AI pentest for exploitation
python -m python_scorpion.cli ai-pentest --target testphp.vulnweb.com --risk-tolerance high
```

---

## Output Interpretation

### Real-Time Logging
```
[🎯 VULN] Time-based SQLi in id: 5.8s delay       → Time-based blind SQLi confirmed
[🎯 VULN] Error-based SQLi in name: SQL syntax    → Error-based SQLi confirmed
[🎯 VULN] Boolean SQLi in username: 234 byte diff → Boolean-based blind SQLi likely
[🎯 VULN] HIGH XSS in search: <script>alert(1)    → Reflected XSS confirmed
[🎯 VULN] Time-based RCE in cmd: 6.1s delay       → Command injection confirmed
[SPEED] Found 10 SQLi vulns, stopping for speed   → Early exit optimization
[SKIP] Already found 10 XSS vulns, skipping       → Duplicate prevention
```

### Severity Levels
- **CRITICAL** - SQLi, RCE, Authentication Bypass (immediate exploitation risk)
- **HIGH** - XSS, File Upload, SSRF (significant security impact)
- **MEDIUM** - Missing security headers, CORS misconfiguration
- **LOW** - Information disclosure, minor misconfigurations
- **INFO** - Server fingerprinting, technology detection

---

## Best Practices

### ✅ DO:
- Always get **written authorization** before scanning
- Start with `--risk-tolerance low` for initial assessment
- Use specific URLs with parameters when known
- Review AI findings before manual exploitation
- Export results: `--output json` or `--output html`

### ❌ DON'T:
- Scan production systems without approval
- Use HIGH risk mode without understanding impact
- Ignore rate limiting (respect `--concurrency` settings)
- Run multiple scans simultaneously (resource exhaustion)
- Skip the legal warning prompts

---

## Troubleshooting

### Issue: "No vulnerabilities found"
**Solution:** Target specific pages with parameters
```bash
# Instead of:
python -m python_scorpion.cli webscan http://testphp.vulnweb.com

# Use:
python -m python_scorpion.cli webscan "http://testphp.vulnweb.com/artists.php?artist=1"
```

### Issue: "Timeout after 120s"
**Solution:** Reduce concurrency
```bash
python -m python_scorpion.cli webscan http://target.com --concurrency 10
```

### Issue: "API key invalid"
**Solution:** Check key format
```bash
# GitHub Models: starts with ghp_
export SCORPION_AI_API_KEY='ghp_...'

# OpenAI: starts with sk-proj-
export SCORPION_AI_API_KEY='sk-proj-...'
```

### Issue: "AI loops 20 iterations without finding vulns"
**Solution:** This means base URL has no real vulnerabilities. The AI will now:
1. Discover pages via dirbuster/crawler
2. Test ALL discovered .php/.asp/.jsp pages automatically
3. Find and exploit real vulnerabilities

---

## Performance Benchmarks

| Target Type | Concurrency | Time | Findings |
|-------------|-------------|------|----------|
| Single vulnerable page | 50 | 30-60s | 20-30 vulns |
| Base URL (autonomous) | 50 | 5-10 min | 5-15 vulns |
| Full AI pentest | 50 | 6-15 min | 10-50 findings |
| Large site (100+ pages) | 50 | 15-30 min | 50-100+ findings |

---

## Advanced Usage

### Custom Wordlists
```bash
python -m python_scorpion.cli dirbuster --target http://target.com --wordlist /path/to/custom.txt
```

### Save Results
```bash
python -m python_scorpion.cli webscan http://target.com --output json --output-file results.json
```

### Specific Port Scanning
```bash
python -m python_scorpion.cli portscan --target 192.168.1.1 --ports 80,443,8080,8443
```

### External Tool Integration
The AI automatically uses these when built-in tests fail:
- **sqlmap** - SQL injection exploitation
- **nikto** - Web server scanning
- **commix** - Command injection
- **gobuster** - Directory bruteforce

---

## Quick Reference Card

| Command | Use Case | Speed | Risk |
|---------|----------|-------|------|
| `webscan "url?param=1"` | Known vulnerable page | ⚡⚡⚡ Fast | Low |
| `webscan http://target` | Base URL assessment | ⚡⚡ Medium | Low |
| `ai-pentest --risk low` | Reconnaissance only | ⚡ Slow | None |
| `ai-pentest --risk medium` | Active scanning | ⚡⚡ Medium | Medium |
| `ai-pentest --risk high` | Full exploitation | ⚡⚡ Medium | ⚠️ High |

---

**Last Updated:** December 20, 2025  
**Version:** 2.0 (Speed Optimized + Autonomous Discovery)

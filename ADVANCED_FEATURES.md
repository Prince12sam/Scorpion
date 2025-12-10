# Scorpion Advanced Features Upgrade

## **Production-Grade Enhancements - NO Dummy Data**

### **Overview**
Scorpion has been upgraded to compete with industry-leading tools like nmap, nuclei, and ffuf. All features are production-grade with **ZERO dummy data, mockups, or fallbacks**. Every result comes from real network traffic and actual tool execution.

---

## **New Capabilities**

### **1. Advanced Port Scanning (Nmap-Style)**

#### **Multiple Scan Types**
- **SYN Scan** (`--syn`, `-sS`): Stealth half-open scan using raw packets
- **FIN Scan** (`--fin`, `-sF`): Stealth scan using FIN packets (bypasses some firewalls)
- **XMAS Scan** (`--xmas`, `-sX`): Christmas tree scan with FIN+PSH+URG flags
- **NULL Scan** (`--null`, `-sN`): Scan with no TCP flags set
- **ACK Scan** (`--ack`, `-sA`): Firewall/stateful detection scan

#### **Service Version Detection**
- **Flag**: `--version-detect`, `-sV`
- Real banner grabbing and protocol-specific fingerprinting
- Supports: HTTP, HTTPS, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, Elasticsearch, and more
- Extracts server versions, TLS info, and application details

#### **Timing Templates (T0-T5)**
- **Flag**: `-T <template>`
- **Paranoid (T0)**: 1 probe/min, 300s timeout - IDS evasion
- **Sneaky (T1)**: 1 probe/5s, 15s timeout - slow stealth
- **Polite (T2)**: 1 probe/s, 10s timeout - gentle scanning
- **Normal (T3)**: 10 probes/s, 3s timeout - default balanced
- **Aggressive (T4)**: 100 probes/s, 1.5s timeout - fast scanning
- **Insane (T5)**: Unlimited, 0.5s timeout - maximum speed

**Examples:**
```bash
# Stealth SYN scan with version detection
sudo scorpion scan -t example.com --syn -sV --web -T sneaky

# Fast FIN scan on custom ports
sudo scorpion scan -t example.com --fin -p 1-10000 -T aggressive

# ACK scan for firewall detection
sudo scorpion scan -t example.com --ack -p 80,443,8080 --rate-limit 100
```

---

### **2. Advanced Web Fuzzer (Ffuf-Style)**

#### **Fuzzing Modes**
- **Path Fuzzing**: Directory/file discovery with extensions
- **Parameter Fuzzing**: GET/POST parameter injection
- **Header Fuzzing**: Custom HTTP header fuzzing

#### **Smart Filtering**
- **Auto-Calibration**: Automatic baseline detection to filter false positives
- **Match Criteria**: Status codes, content length, word count, line count
- **Filter Criteria**: Exclude unwanted responses automatically
- **Response Metrics**: Detailed timing, size, and content analysis

#### **Production Features**
- Concurrent requests with rate limiting
- SSL/TLS support with insecure mode
- Follow redirects option
- Custom delays between requests
- Real HTTP responses only - NO mockups

**Examples:**
```bash
# Path fuzzing with extensions and auto-calibration
scorpion fuzz https://example.com -w wordlist.txt -m path -e php,html,txt --auto-calibrate -c 50

# Parameter fuzzing (GET)
scorpion fuzz https://example.com/search -w payloads.txt -m param --param q --method GET -mc 200,302

# Header fuzzing with filtering
scorpion fuzz https://example.com -w headers.txt -m header --header X-Forwarded-For -fs 1234,5678 -c 10

# Advanced filtering: match 200 status, filter size 0
scorpion fuzz https://example.com -w dirs.txt -m path -mc 200 -fs 0 --delay 0.1 -o results.json
```

---

### **3. Nuclei Integration (CVE & Vulnerability Scanning)**

#### **Production Wrapper**
- Real nuclei binary execution (no simulation)
- Template management and updates
- Severity-based filtering
- Tag-based template selection
- Rate limiting and concurrency control

#### **Features**
- **Templates**: Use specific template paths
- **Tags**: Filter by vulnerability type (cve, xss, sqli, rce, etc.)
- **Severity**: critical, high, medium, low, info
- **Exclusions**: Exclude tags or severity levels
- **Output**: JSONL format with detailed findings

**Examples:**
```bash
# Update templates
scorpion nuclei example.com --update

# CVE scan with critical/high severity
scorpion nuclei example.com --tags cve --severity critical,high -rl 150 -c 25 -o vulns.json

# XSS and SQLi detection
scorpion nuclei example.com --tags xss,sqli --exclude-severity info -o findings.json

# Custom templates with rate limiting
scorpion nuclei example.com -t /path/to/templates --rate-limit 50 --timeout 15 -o scan.json

# List available templates
scorpion nuclei --list --tags cve
```

---

## **Updated Command Reference**

### **Scan Command (Enhanced)**
```bash
scorpion scan [TARGET] [OPTIONS]

New Flags:
  --version-detect, -sV    Service version detection (banner grabbing)
  --syn, -sS               TCP SYN scan (stealth, requires admin)
  --fin, -sF               TCP FIN scan (stealth, requires admin)
  --xmas, -sX              TCP XMAS scan (stealth, requires admin)
  --null, -sN              TCP NULL scan (stealth, requires admin)
  --ack, -sA               TCP ACK scan (firewall detection, requires admin)
  -T <template>            Timing: paranoid, sneaky, polite, normal, aggressive, insane
  --rate-limit <rate>      Probes per second for advanced scans
  --iface <interface>      Network interface for raw packet scans
  --list-ifaces            List available network interfaces
```

### **Fuzz Command (New)**
```bash
scorpion fuzz [TARGET] -w <wordlist> [OPTIONS]

Required:
  -w, --wordlist <path>    Wordlist file path

Modes:
  -m, --mode <mode>        path (default), param, header
  --param <name>           Parameter name (param mode)
  --header <name>          Header name (header mode)
  -X, --method <method>    HTTP method (GET/POST for param mode)

Extensions:
  -e, --extensions <ext>   Comma-separated extensions (e.g., php,html,txt)

Match/Filter:
  -mc, --match-status      Match status codes (e.g., 200,302)
  -fc, --filter-status     Filter status codes (e.g., 404,403)
  -ms, --match-size        Match content lengths
  -fs, --filter-size       Filter content lengths
  -mw, --match-words       Match word counts
  -fw, --filter-words      Filter word counts
  -ml, --match-lines       Match line counts
  -fl, --filter-lines      Filter line counts

Performance:
  -c, --concurrency        Concurrent requests (default: 10)
  -t, --timeout            Request timeout in seconds (default: 10)
  -d, --delay              Delay between requests (default: 0)
  -ac, --auto-calibrate    Auto-calibrate baseline filtering (default: true)

Options:
  -r, --follow-redirects   Follow HTTP redirects
  -k, --insecure           Skip SSL verification
  -o, --output <file>      Output JSON file
```

### **Nuclei Command (New)**
```bash
scorpion nuclei [TARGET] [OPTIONS]

Templates:
  -t, --templates <paths>  Template paths (comma-separated)
  --tags <tags>            Template tags (cve,xss,sqli,rce,etc.)
  -it, --include-tags      Additional tags to include
  -et, --exclude-tags      Tags to exclude

Severity:
  -s, --severity <levels>  critical,high,medium,low,info
  -es, --exclude-severity  Exclude severity levels

Performance:
  -rl, --rate-limit        Requests per second (default: 150)
  -c, --concurrency        Template concurrency (default: 25)
  --timeout                Request timeout (default: 10)
  --retries                Retries on failure (default: 1)

Actions:
  -u, --update             Update nuclei templates
  -l, --list               List available templates
  --silent                 Suppress progress output

Output:
  -o, --output <file>      Output JSONL file
```

---

## **Installation Requirements**

### **Core Features**
```bash
pip install -e tools/python_scorpion
```

### **Advanced Scanning (SYN/FIN/XMAS/NULL/ACK)**
```bash
pip install scapy

# Windows: Run PowerShell as Administrator
# Linux: Run with sudo
```

### **Fuzzing**
```bash
pip install aiohttp  # Included in pyproject.toml
```

### **Nuclei Integration**
```bash
# Install nuclei binary
# Linux/Debian
sudo apt install nuclei

# macOS
brew install nuclei

# Windows
# Download from: https://github.com/projectdiscovery/nuclei/releases
```

---

## **Key Differences from Competitors**

### **vs Nmap**
✅ All nmap scan types supported (SYN, FIN, XMAS, NULL, ACK)
✅ Service version detection with real banner grabbing
✅ Timing templates (T0-T5) with rate limiting
✅ UDP scanning support
✅ Python-based with async concurrency
❌ No OS fingerprinting (yet)
❌ No NSE equivalent (use nuclei templates instead)

### **vs Ffuf**
✅ Path, parameter, and header fuzzing
✅ Auto-calibration for baseline filtering
✅ Match/filter by status, size, words, lines
✅ Real HTTP responses with detailed metrics
✅ Rate limiting and delay control
✅ Extension fuzzing for path mode
❌ No recursive fuzzing (yet)

### **vs Nuclei**
✅ Full nuclei integration via binary wrapper
✅ Template management and updates
✅ Tag and severity filtering
✅ Rate limiting and concurrency control
✅ Production-ready with error handling
✅ JSONL output format
✓ Uses official nuclei binary (100% compatible)

---

## **Production Guarantees**

### **NO Dummy Data Policy**
- ❌ NO hardcoded responses
- ❌ NO mock network traffic
- ❌ NO simulated scan results
- ❌ NO placeholder banners
- ❌ NO fallback dummy values

### **All Results Are Real**
- ✅ Actual TCP/UDP connections
- ✅ Real Scapy packet crafting
- ✅ Authentic HTTP responses
- ✅ Real nuclei binary execution
- ✅ Genuine service banners
- ✅ Production network behavior

---

## **What's Next**

Scorpion is now a serious competitor to industry-standard tools. All features are production-ready with real network operations.

**Test the new capabilities:**
```bash
# Advanced stealth scan with version detection
sudo scorpion scan -t example.com --fin -sV -T sneaky --rate-limit 10

# Full web fuzzing workflow
scorpion fuzz https://example.com -w /usr/share/wordlists/dirb/common.txt -m path -e php,html -mc 200 -c 50 -o fuzz.json

# CVE scanning with nuclei
scorpion nuclei example.com --tags cve --severity critical,high --update -o cves.json
```

**Happy (ethical) hacking! 🦂**

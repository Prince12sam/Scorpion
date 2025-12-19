# AI Simple Prompts - Natural Language Commands

## 🚀 Quick Start

Just tell the AI what you want in plain English! No need to memorize complex flags.

```bash
# Basic syntax
scorpion ai-pentest -t TARGET -i "YOUR_COMMAND"

# Even simpler (if API key is set in environment)
export SCORPION_AI_API_KEY='your-key'
scorpion ai-pentest -t target.com -i "hack it"
```

## 📝 Simple Commands

### General Exploitation
```bash
# Tell AI to exploit everything
scorpion ai-pentest -t target.com -i "exploit this"
scorpion ai-pentest -t target.com -i "hack it"
scorpion ai-pentest -t target.com -i "pwn this"
scorpion ai-pentest -t target.com -i "own it"

# Get shell access
scorpion ai-pentest -t target.com -i "get shell"
scorpion ai-pentest -t target.com -i "get shell access"
scorpion ai-pentest -t target.com -i "gain remote access"
```

### Specific Vulnerability Focus
```bash
# SQL Injection
scorpion ai-pentest -t target.com -i "find SQLi"
scorpion ai-pentest -t target.com -i "test SQL injection"
scorpion ai-pentest -t target.com -i "sql"

# Cross-Site Scripting (XSS)
scorpion ai-pentest -t target.com -i "test XSS"
scorpion ai-pentest -t target.com -i "find cross-site scripting"
scorpion ai-pentest -t target.com -i "xss"

# Remote Code Execution (RCE)
scorpion ai-pentest -t target.com -i "find RCE"
scorpion ai-pentest -t target.com -i "command injection"
scorpion ai-pentest -t target.com -i "remote code execution"

# Authentication Bypass
scorpion ai-pentest -t target.com -i "bypass login"
scorpion ai-pentest -t target.com -i "hack login page"
scorpion ai-pentest -t target.com -i "authentication bypass"

# File Upload Vulnerabilities
scorpion ai-pentest -t target.com -i "test file upload"
scorpion ai-pentest -t target.com -i "upload shell"
scorpion ai-pentest -t target.com -i "file upload bypass"

# SSRF (Server-Side Request Forgery)
scorpion ai-pentest -t target.com -i "test SSRF"
scorpion ai-pentest -t target.com -i "ssrf"

# IDOR (Insecure Direct Object Reference)
scorpion ai-pentest -t target.com -i "test IDOR"
scorpion ai-pentest -t target.com -i "idor"
```

### Reconnaissance & Enumeration
```bash
# Subdomain enumeration
scorpion ai-pentest -t target.com -i "find subdomains"
scorpion ai-pentest -t target.com -i "subdomain enumeration"
scorpion ai-pentest -t target.com -i "subdomain takeover"

# API Testing
scorpion ai-pentest -t target.com -i "test API"
scorpion ai-pentest -t target.com -i "api security"
scorpion ai-pentest -t target.com -i "test GraphQL"
```

## 🎯 How It Works

The AI automatically interprets your simple commands:

| Your Command | AI Interprets As |
|--------------|------------------|
| "exploit this" | Actively exploit all discovered vulnerabilities for shell access |
| "get shell" | Focus on gaining shell access via RCE, file upload, SQLi |
| "find SQLi" | Test all parameters for SQL injection, use sqlmap |
| "test XSS" | Test reflected, stored, and DOM-based XSS everywhere |
| "bypass login" | Test default creds, SQL injection in login, JWT flaws |
| "hack it" | Full exploitation mode - try everything |

## 💡 Examples with Context

### Example 1: Quick Exploitation Test
```bash
# Short and simple
scorpion ai-pentest -t testphp.vulnweb.com -i "exploit this"

# AI will:
# 1. Run reconnaissance (ports, services, tech stack)
# 2. Identify vulnerabilities (SQLi, XSS, RCE, etc.)
# 3. Actively exploit everything found
# 4. Attempt to gain shell access
```

### Example 2: Focused SQLi Testing
```bash
# Focus on one vulnerability type
scorpion ai-pentest -t target.com -i "find SQLi"

# AI will:
# 1. Enumerate all parameters
# 2. Test for SQL injection (error-based, time-based, boolean)
# 3. Use sqlmap for automated exploitation
# 4. Attempt database extraction if successful
```

### Example 3: Authentication Bypass
```bash
# Test login security
scorpion ai-pentest -t target.com/login -i "bypass login"

# AI will:
# 1. Try default credentials (admin/admin, admin/password)
# 2. Test SQL injection in login form
# 3. Test JWT vulnerabilities
# 4. Try session hijacking techniques
```

### Example 4: Combined with Risk Level
```bash
# Use with other flags for more control
scorpion ai-pentest -t target.com -r high -i "get shell access"

# AI will:
# - Run in HIGH risk mode (enables active exploitation)
# - Focus specifically on gaining shell access
# - Try multiple exploitation techniques
# - Generate and deploy payloads
```

## 📋 Detailed vs Simple Prompts

### Simple Prompts (New!)
```bash
# Just tell AI what to do
scorpion ai-pentest -t target.com -i "exploit this"
scorpion ai-pentest -t target.com -i "find SQLi"
scorpion ai-pentest -t target.com -i "get shell"
```

### Detailed Prompts (Also Supported)
```bash
# Give specific technical instructions
scorpion ai-pentest -t target.com -i "Focus on API endpoints and test for IDOR vulnerabilities in user profile access"
scorpion ai-pentest -t target.com -i "Test GraphQL introspection and injection attacks, check for authentication bypass"
scorpion ai-pentest -t target.com -i "Look for SSRF in file upload features and image processing endpoints"
```

Both work! Use simple commands for quick tests, or detailed instructions for precise control.

## 🔥 Real-World Examples

### Bug Bounty Hunting
```bash
# Quick vulnerability discovery
scorpion ai-pentest -t bugbounty-target.com -i "find SQLi and XSS"

# API-focused testing
scorpion ai-pentest -t api.target.com -i "test API for IDOR and auth bypass"
```

### CTF Challenges
```bash
# Full exploitation for CTF
scorpion ai-pentest -t ctf.challenge.com -r high -i "get shell access"

# Specific challenge focus
scorpion ai-pentest -t ctf.challenge.com -i "bypass login and find flag"
```

### Penetration Testing
```bash
# Comprehensive pentest with exploitation
scorpion ai-pentest -t client-app.com -r high -a semi_autonomous -i "exploit this"

# Specific service testing
scorpion ai-pentest -t app.client.com -i "test file upload for RCE"
```

## 🛡️ Safety Notes

⚠️ **Authorization Required**:
- Simple prompts like "exploit this" trigger HIGH-RISK actions
- Always have written authorization before testing
- Unauthorized testing is illegal

⚠️ **Risk Levels**:
```bash
# Safe (only passive scanning)
scorpion ai-pentest -t target.com -r low -i "scan for vulnerabilities"

# Medium (active scanning, no exploitation)
scorpion ai-pentest -t target.com -r medium -i "find vulnerabilities"

# High (active exploitation - REQUIRES AUTHORIZATION)
scorpion ai-pentest -t target.com -r high -i "exploit this"
```

## 🚀 Pro Tips

1. **Combine with risk levels** for better control:
   ```bash
   scorpion ai-pentest -t target.com -r high -i "get shell"
   ```

2. **Use time limits** to prevent long scans:
   ```bash
   scorpion ai-pentest -t target.com --time-limit 10 -i "quick exploit"
   ```

3. **Set API key once**, use forever:
   ```bash
   echo "SCORPION_AI_API_KEY=ghp_..." >> ~/.bashrc
   source ~/.bashrc
   # Now just: scorpion ai-pentest -t target.com -i "hack it"
   ```

4. **Use GitHub Models for FREE testing**:
   ```bash
   export SCORPION_AI_API_KEY='ghp_your_github_token'
   scorpion ai-pentest -t target.com --ai-provider github -i "exploit this"
   ```

## 🎓 Learning Examples

### Beginner
```bash
# Start simple
scorpion ai-pentest -t testphp.vulnweb.com -r medium -i "find vulnerabilities"
```

### Intermediate
```bash
# Test specific vulnerability
scorpion ai-pentest -t testphp.vulnweb.com -r high -i "find SQLi and exploit it"
```

### Advanced
```bash
# Full exploitation chain
scorpion ai-pentest -t target.com -r high -a fully_autonomous \
  --time-limit 60 -i "exploit everything and get shell access"
```

## 📚 More Resources

- **Full AI Guide**: [AI_PENTEST_GUIDE.md](AI_PENTEST_GUIDE.md)
- **External Tools**: [EXTERNAL_TOOLS_QUICK_REFERENCE.md](EXTERNAL_TOOLS_QUICK_REFERENCE.md)
- **Command Reference**: [COMMANDS.md](COMMANDS.md)

---

**TL;DR**: Just use `-i "YOUR_COMMAND"` to tell the AI what to do in plain English! 🎉

```bash
scorpion ai-pentest -t target.com -i "exploit this"
```

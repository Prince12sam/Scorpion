#!/usr/bin/env python3
"""
Fuzzing Framework Module
Protocol fuzzing, file format fuzzing, API fuzzing, binary fuzzing with AFL++,
coverage-guided fuzzing, crash analysis, and automatic exploit generation.
"""

import subprocess
import socket
import time
import random
import struct
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import tempfile
import shutil


class FuzzTarget(Enum):
    """Fuzzing target types"""
    PROTOCOL = "Protocol"
    FILE_FORMAT = "File Format"
    API = "API"
    BINARY = "Binary"
    BROWSER = "Browser"
    NETWORK_SERVICE = "Network Service"


class FuzzStrategy(Enum):
    """Fuzzing strategies"""
    RANDOM = "Random"
    MUTATION = "Mutation-based"
    GENERATION = "Generation-based"
    COVERAGE_GUIDED = "Coverage-guided"
    SMART = "Smart/Grammar-based"


@dataclass
class FuzzInput:
    """Fuzzing test case"""
    data: bytes
    generation: int = 0
    mutation_count: int = 0
    coverage: int = 0
    interesting: bool = False
    crash: bool = False
    hash: str = ""
    
    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(self.data).hexdigest()[:16]


@dataclass
class Crash:
    """Crash information"""
    input_hash: str
    input_data: bytes
    crash_type: str  # SIGSEGV, SIGABRT, etc.
    stack_trace: str
    registers: Dict[str, str] = field(default_factory=dict)
    exploitability: str = "Unknown"  # High, Medium, Low, Unknown
    duplicate: bool = False
    crash_file: Optional[Path] = None
    
    def to_dict(self) -> Dict:
        return {
            "input_hash": self.input_hash,
            "crash_type": self.crash_type,
            "stack_trace": self.stack_trace,
            "registers": self.registers,
            "exploitability": self.exploitability,
            "duplicate": self.duplicate,
            "crash_file": str(self.crash_file) if self.crash_file else None
        }


class Mutator:
    """Mutation engine for fuzzing"""
    
    @staticmethod
    def bit_flip(data: bytes, bit_count: int = 1) -> bytes:
        """Flip random bits"""
        data = bytearray(data)
        for _ in range(bit_count):
            if len(data) == 0:
                break
            byte_pos = random.randint(0, len(data) - 1)
            bit_pos = random.randint(0, 7)
            data[byte_pos] ^= (1 << bit_pos)
        return bytes(data)
    
    @staticmethod
    def byte_flip(data: bytes, byte_count: int = 1) -> bytes:
        """Flip random bytes"""
        data = bytearray(data)
        for _ in range(byte_count):
            if len(data) == 0:
                break
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= 0xFF
        return bytes(data)
    
    @staticmethod
    def insert_byte(data: bytes, value: Optional[int] = None) -> bytes:
        """Insert random byte"""
        if len(data) == 0:
            return bytes([value or random.randint(0, 255)])
        
        pos = random.randint(0, len(data))
        value = value or random.randint(0, 255)
        return data[:pos] + bytes([value]) + data[pos:]
    
    @staticmethod
    def delete_byte(data: bytes) -> bytes:
        """Delete random byte"""
        if len(data) <= 1:
            return data
        
        pos = random.randint(0, len(data) - 1)
        return data[:pos] + data[pos+1:]
    
    @staticmethod
    def insert_interesting_value(data: bytes) -> bytes:
        """Insert interesting integer values (0, -1, MAX, etc.)"""
        interesting_values = [
            0x00, 0xFF,  # Min/Max byte
            0x7F, 0x80,  # Boundary bytes
            0x00000000, 0xFFFFFFFF,  # Min/Max 32-bit
            0x7FFFFFFF, 0x80000000,  # INT_MAX, INT_MIN
            0x0000FFFF, 0xFFFF0000,  # Boundaries
        ]
        
        if len(data) == 0:
            return data
        
        value = random.choice(interesting_values)
        pos = random.randint(0, max(0, len(data) - 4))
        
        # Insert as little-endian 32-bit
        value_bytes = struct.pack('<I', value & 0xFFFFFFFF)
        return data[:pos] + value_bytes + data[pos+4:]
    
    @staticmethod
    def splice(data1: bytes, data2: bytes) -> bytes:
        """Splice two inputs together"""
        if len(data1) == 0:
            return data2
        if len(data2) == 0:
            return data1
        
        split1 = random.randint(0, len(data1))
        split2 = random.randint(0, len(data2))
        
        return data1[:split1] + data2[split2:]
    
    @staticmethod
    def mutate(data: bytes, strategy: str = "random") -> bytes:
        """Apply random mutation"""
        mutations = [
            Mutator.bit_flip,
            Mutator.byte_flip,
            Mutator.insert_byte,
            Mutator.delete_byte,
            Mutator.insert_interesting_value
        ]
        
        mutation = random.choice(mutations)
        return mutation(data)


class ProtocolFuzzer:
    """Network protocol fuzzer"""
    
    def __init__(self, host: str, port: int, protocol: str = "TCP"):
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
    
    def fuzz(self, iterations: int = 1000, timeout: int = 5,
             seed_inputs: Optional[List[bytes]] = None) -> List[Crash]:
        """
        Fuzz network protocol
        
        Args:
            iterations: Number of test cases
            timeout: Socket timeout in seconds
            seed_inputs: Initial test cases
        """
        print(f"🎯 Fuzzing {self.protocol} {self.host}:{self.port}")
        print(f"   Iterations: {iterations}")
        
        crashes = []
        corpus = seed_inputs or [b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"]
        
        for i in range(iterations):
            # Select or mutate input
            if random.random() < 0.1 and len(corpus) > 0:
                # Use seed input
                data = random.choice(corpus)
            else:
                # Mutate
                base = random.choice(corpus) if corpus else b"A" * 100
                data = Mutator.mutate(base)
            
            # Send to target
            try:
                if self.protocol == "TCP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((self.host, self.port))
                    sock.send(data)
                    
                    try:
                        response = sock.recv(4096)
                        # Check for interesting responses
                        if b"error" in response.lower() or b"exception" in response.lower():
                            print(f"  [!] Interesting response at iteration {i}")
                    except socket.timeout:
                        pass
                    
                    sock.close()
                
                elif self.protocol == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(timeout)
                    sock.sendto(data, (self.host, self.port))
                    
                    try:
                        response, _ = sock.recvfrom(4096)
                    except socket.timeout:
                        pass
                    
                    sock.close()
            
            except ConnectionRefusedError:
                print(f"  [!] Connection refused - possible crash at iteration {i}")
                crashes.append(Crash(
                    input_hash=hashlib.sha256(data).hexdigest()[:16],
                    input_data=data,
                    crash_type="Connection Refused",
                    stack_trace="Service not responding",
                    exploitability="Unknown"
                ))
                
                # Wait for service to restart
                time.sleep(5)
            
            except Exception as e:
                if "reset" in str(e).lower() or "abort" in str(e).lower():
                    print(f"  [!] Possible crash at iteration {i}: {e}")
            
            # Progress
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{iterations} ({(i+1)*100//iterations}%)")
        
        print(f"\n✅ Fuzzing complete")
        print(f"   Total crashes: {len(crashes)}")
        
        return crashes
    
    def fuzz_http(self, iterations: int = 500) -> List[Crash]:
        """Specialized HTTP fuzzing"""
        http_templates = [
            b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
            b"OPTIONS * HTTP/1.1\r\nHost: %s\r\n\r\n",
            b"PUT / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
        ]
        
        seed_inputs = []
        for template in http_templates:
            if b"%s" in template:
                if template.count(b"%s") == 1:
                    seed_inputs.append(template % self.host.encode())
                elif template.count(b"%s") == 2:
                    payload = b"A" * 100
                    seed_inputs.append(template % (self.host.encode(), len(payload), payload))
        
        return self.fuzz(iterations=iterations, seed_inputs=seed_inputs)


class FileFuzzer:
    """File format fuzzer"""
    
    def __init__(self, target_app: str, file_extension: str = ".bin"):
        self.target_app = target_app
        self.file_extension = file_extension
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def fuzz(self, seed_file: Path, iterations: int = 1000) -> List[Crash]:
        """
        Fuzz file format by mutating seed file
        
        Args:
            seed_file: Valid file to mutate
            iterations: Number of mutations to test
        """
        print(f"📄 Fuzzing file format: {self.file_extension}")
        print(f"   Target: {self.target_app}")
        print(f"   Seed: {seed_file.name}")
        print(f"   Iterations: {iterations}")
        
        crashes = []
        
        # Read seed file
        with open(seed_file, 'rb') as f:
            seed_data = f.read()
        
        for i in range(iterations):
            # Mutate seed
            mutated_data = seed_data
            num_mutations = random.randint(1, 10)
            
            for _ in range(num_mutations):
                mutated_data = Mutator.mutate(mutated_data)
            
            # Write mutated file
            test_file = self.temp_dir / f"fuzz_{i}{self.file_extension}"
            with open(test_file, 'wb') as f:
                f.write(mutated_data)
            
            # Test with target application
            try:
                result = subprocess.run(
                    [self.target_app, str(test_file)],
                    capture_output=True,
                    timeout=10
                )
                
                # Check for crash
                if result.returncode < 0:
                    signal = -result.returncode
                    print(f"  [!] Crash at iteration {i}: Signal {signal}")
                    
                    crash = Crash(
                        input_hash=hashlib.sha256(mutated_data).hexdigest()[:16],
                        input_data=mutated_data,
                        crash_type=f"Signal {signal}",
                        stack_trace=result.stderr.decode('utf-8', errors='ignore'),
                        crash_file=test_file
                    )
                    
                    crashes.append(crash)
                    
                    # Save crash input
                    crash_file = Path(f"crashes/crash_{i}_{crash.input_hash}{self.file_extension}")
                    crash_file.parent.mkdir(exist_ok=True)
                    shutil.copy(test_file, crash_file)
            
            except subprocess.TimeoutExpired:
                print(f"  [!] Timeout at iteration {i}")
            except Exception as e:
                pass
            
            # Progress
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{iterations} ({(i+1)*100//iterations}%)")
        
        print(f"\n✅ File fuzzing complete")
        print(f"   Total crashes: {len(crashes)}")
        
        # Cleanup
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        return crashes


class APIFuzzer:
    """REST API fuzzer"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.requests_available = False
        
        try:
            import requests
            self.requests = requests
            self.requests_available = True
        except ImportError:
            pass
    
    def fuzz_endpoint(self, method: str, endpoint: str,
                      iterations: int = 500) -> List[Dict]:
        """
        Fuzz API endpoint with various payloads
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            iterations: Number of test cases
        """
        if not self.requests_available:
            print("❌ requests library not installed. Install: pip install requests")
            return []
        
        print(f"🌐 Fuzzing API: {method} {self.base_url}{endpoint}")
        
        interesting_findings = []
        
        # Payload templates
        payloads = [
            # SQL Injection
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin'--",
            "' UNION SELECT NULL--",
            
            # XSS
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            
            # Command Injection
            "; ls -la",
            "| whoami",
            "`id`",
            "$(whoami)",
            
            # Path Traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            
            # XXE
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            
            # SSRF
            "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/",
            
            # Buffer Overflow
            "A" * 1000,
            "A" * 10000,
            
            # Format String
            "%s%s%s%s%s",
            "%x%x%x%x",
            
            # NULL byte
            "test\x00.txt",
            
            # Unicode
            "\u0000",
            "\uFFFE",
        ]
        
        for i in range(iterations):
            # Select payload
            if i < len(payloads):
                payload = payloads[i]
            else:
                payload = "A" * random.randint(1, 10000)
            
            try:
                # Prepare request
                url = f"{self.base_url}{endpoint}"
                
                if method == "GET":
                    # Inject in query parameter
                    response = self.requests.get(
                        url,
                        params={"input": payload},
                        timeout=10
                    )
                elif method == "POST":
                    # Inject in body
                    response = self.requests.post(
                        url,
                        json={"input": payload},
                        timeout=10
                    )
                elif method == "PUT":
                    response = self.requests.put(
                        url,
                        json={"input": payload},
                        timeout=10
                    )
                elif method == "DELETE":
                    response = self.requests.delete(
                        url,
                        params={"id": payload},
                        timeout=10
                    )
                else:
                    continue
                
                # Check for interesting responses
                if response.status_code >= 500:
                    print(f"  [!] Server error (500) with payload: {payload[:50]}")
                    interesting_findings.append({
                        "payload": payload,
                        "status_code": response.status_code,
                        "response": response.text[:500]
                    })
                
                elif "error" in response.text.lower() and len(response.text) > 100:
                    print(f"  [!] Error disclosure with payload: {payload[:50]}")
                    interesting_findings.append({
                        "payload": payload,
                        "status_code": response.status_code,
                        "response": response.text[:500]
                    })
                
                elif "exception" in response.text.lower():
                    print(f"  [!] Exception found with payload: {payload[:50]}")
                    interesting_findings.append({
                        "payload": payload,
                        "status_code": response.status_code,
                        "response": response.text[:500]
                    })
            
            except self.requests.exceptions.Timeout:
                print(f"  [!] Timeout with payload: {payload[:50]}")
            except Exception:
                pass
            
            # Progress
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{iterations} ({(i+1)*100//iterations}%)")
        
        print(f"\n✅ API fuzzing complete")
        print(f"   Interesting findings: {len(interesting_findings)}")
        
        return interesting_findings


class AFLWrapper:
    """Wrapper for AFL++ (American Fuzzy Lop) fuzzer"""
    
    def __init__(self, target_binary: Path):
        self.target_binary = target_binary
        self.afl_available = self._check_afl()
    
    def _check_afl(self) -> bool:
        """Check if AFL++ is installed"""
        try:
            result = subprocess.run(
                ["afl-fuzz", "-h"],
                capture_output=True,
                timeout=5
            )
            return result.returncode in [0, 1]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def fuzz(self, input_dir: Path, output_dir: Path,
             timeout: str = "24h") -> bool:
        """
        Run AFL++ fuzzing campaign
        
        Args:
            input_dir: Directory with seed inputs
            output_dir: Output directory for findings
            timeout: Fuzzing timeout (e.g., "24h", "1d")
        """
        if not self.afl_available:
            print("❌ AFL++ not installed. Install: https://github.com/AFLplusplus/AFLplusplus")
            return False
        
        print(f"🔥 Starting AFL++ fuzzing")
        print(f"   Target: {self.target_binary}")
        print(f"   Input: {input_dir}")
        print(f"   Output: {output_dir}")
        print(f"   Timeout: {timeout}")
        
        try:
            cmd = [
                "afl-fuzz",
                "-i", str(input_dir),
                "-o", str(output_dir),
                "-t", "1000+",  # Timeout per exec
                "--",
                str(self.target_binary),
                "@@"  # Placeholder for input file
            ]
            
            # Run AFL
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            print(f"✅ AFL++ started (PID: {process.pid})")
            print(f"   Monitor progress: afl-whatsup {output_dir}")
            print(f"   View UI: screen -r afl-fuzz")
            
            # Let it run (user can kill with Ctrl+C)
            try:
                process.wait()
            except KeyboardInterrupt:
                print(f"\n⏸️ Stopping AFL++...")
                process.terminate()
                process.wait()
            
            # Parse results
            crashes_dir = output_dir / "default" / "crashes"
            if crashes_dir.exists():
                crashes = list(crashes_dir.glob("id:*"))
                print(f"\n✅ AFL++ complete")
                print(f"   Crashes found: {len(crashes)}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ AFL++ fuzzing failed: {e}")
            return False


class CrashAnalyzer:
    """Analyze crashes for exploitability"""
    
    @staticmethod
    def analyze_crash(crash: Crash) -> Crash:
        """
        Analyze crash for exploitability
        
        Exploitability heuristics:
        - SIGSEGV in writable memory: High
        - Stack overflow: High  
        - Heap overflow: Medium
        - NULL pointer dereference: Low
        - Assertion failure: Low
        """
        
        # Simple heuristic based on crash type
        if "SIGSEGV" in crash.crash_type or "segmentation fault" in crash.stack_trace.lower():
            if "write" in crash.stack_trace.lower():
                crash.exploitability = "High"
            elif "null" in crash.stack_trace.lower() or "0x0" in crash.stack_trace:
                crash.exploitability = "Low"
            else:
                crash.exploitability = "Medium"
        
        elif "SIGABRT" in crash.crash_type or "abort" in crash.stack_trace.lower():
            crash.exploitability = "Low"
        
        elif "stack overflow" in crash.stack_trace.lower():
            crash.exploitability = "High"
        
        elif "heap" in crash.stack_trace.lower():
            crash.exploitability = "Medium"
        
        return crash
    
    @staticmethod
    def deduplicate_crashes(crashes: List[Crash]) -> List[Crash]:
        """Remove duplicate crashes based on stack trace"""
        unique_crashes = []
        seen_stacks = set()
        
        for crash in crashes:
            # Simple stack trace hash
            stack_hash = hashlib.md5(crash.stack_trace.encode()).hexdigest()
            
            if stack_hash not in seen_stacks:
                seen_stacks.add(stack_hash)
                unique_crashes.append(crash)
            else:
                crash.duplicate = True
        
        return unique_crashes


def main():
    """Demo fuzzing framework"""
    
    print("="*60)
    print("FUZZING FRAMEWORK DEMO")
    print("="*60)
    
    # Example 1: Protocol fuzzing
    print("\n[1] Protocol Fuzzing Example")
    print("="*60)
    # fuzzer = ProtocolFuzzer("example.com", 80, "TCP")
    # crashes = fuzzer.fuzz_http(iterations=100)
    print("Skipped (requires live target)")
    
    # Example 2: File fuzzing
    print("\n[2] File Format Fuzzing Example")
    print("="*60)
    print("Skipped (requires target application)")
    
    # Example 3: API fuzzing
    print("\n[3] API Fuzzing Example")
    print("="*60)
    # api_fuzzer = APIFuzzer("https://api.example.com")
    # findings = api_fuzzer.fuzz_endpoint("POST", "/api/v1/login", iterations=100)
    print("Skipped (requires API endpoint)")
    
    # Example 4: Mutation demo
    print("\n[4] Mutation Engine Demo")
    print("="*60)
    seed = b"Hello, World!"
    print(f"Seed: {seed}")
    
    for i in range(5):
        mutated = Mutator.mutate(seed)
        print(f"Mutation {i+1}: {mutated[:50]}")


if __name__ == "__main__":
    main()

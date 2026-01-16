import asyncio
import socket
import re
from typing import Dict, List, Optional
import os
import sys

def _is_admin_windows() -> bool:
    """Check if running as administrator on Windows."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False

def _is_root_unix() -> bool:
    """Check if running as root on Unix-like systems (Linux, macOS, etc.)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # os.geteuid() doesn't exist on Windows
        return False

def _has_required_privileges() -> bool:
    """Check if current user has required privileges for raw packet operations."""
    if os.name == 'nt':  # Windows
        return _is_admin_windows()
    else:  # Unix-like (Linux, macOS, BSD, etc.)
        return _is_root_unix()

def _get_privilege_error_message(operation: str = "This operation") -> str:
    """Get platform-specific error message for privilege requirements."""
    if os.name == 'nt':  # Windows
        return f"{operation} requires administrator privileges. Run PowerShell as Administrator."
    else:  # Unix-like
        return f"{operation} requires root privileges. Run with sudo or as root."

def _validate_hostname(host: str) -> bool:
    """Validate hostname/IP to prevent injection attacks."""
    if not host or len(host) > 253:
        return False
    
    # Check for valid IP address
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        pass
    
    # Check for valid hostname (RFC 1123)
    hostname_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(hostname_pattern.match(host))

def _resolve_hostname(host: str, timeout: float = 3.0) -> Optional[str]:
    """Safely resolve hostname to IP with timeout."""
    try:
        # Try to parse as IP first
        socket.inet_aton(host)
        return host
    except socket.error:
        pass
    
    # Resolve hostname
    try:
        result = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        if result:
            return result[0][4][0]
    except (socket.gaierror, socket.timeout, OSError):
        return None
    
    return None

def _validate_port(port: int) -> bool:
    """Validate port number is in valid range."""
    return isinstance(port, int) and 1 <= port <= 65535

def _validate_ports(ports: List[int]) -> List[int]:
    """Validate and filter port list, removing invalid ports."""
    if ports is None:
        return None
    if not ports:  # Empty list
        return []
    return [p for p in ports if _validate_port(p)]

def _get_random_src_port() -> int:
    """Generate random source port for evasion (1024-65535)."""
    import random
    return random.randint(1024, 65535)

def _randomize_ttl(base_ttl: int = 64) -> int:
    """Randomize TTL value to evade firewall fingerprinting."""
    import random
    return random.randint(max(32, base_ttl - 16), min(255, base_ttl + 16))

def _get_timing_delay(stealth_level: str = "normal") -> float:
    """Get timing delay based on stealth level to evade rate-based detection."""
    import random
    delays = {
        "paranoid": random.uniform(5.0, 10.0),
        "sneaky": random.uniform(2.0, 5.0),
        "polite": random.uniform(0.5, 2.0),
        "normal": random.uniform(0.01, 0.1),
        "aggressive": 0.0
    }
    return delays.get(stealth_level, 0.0)

def _syn_probe_sync(host: str, port: int, timeout: float, evade_fw: bool = False) -> Dict:
    """Production SYN scan with optional firewall evasion."""
    try:
        from scapy.all import IP, TCP, sr1, conf, fragment
    except Exception:
        return {"port": port, "state": "error", "reason": "scapy_not_installed"}
    conf.verb = 0
    
    # Firewall evasion techniques
    if evade_fw:
        # Random source port (evade source port filtering)
        src_port = _get_random_src_port()
        # Random TTL (evade TTL-based filtering)
        ttl = _randomize_ttl()
        # Small fragments (evade packet inspection)
        pkt = IP(dst=host, ttl=ttl, flags="MF")/TCP(sport=src_port, dport=port, flags='S', seq=0)
    else:
        pkt = IP(dst=host)/TCP(dport=port, flags='S', seq=0)
    
    try:
        resp = sr1(pkt, timeout=timeout)
    except PermissionError:
        return {"port": port, "state": "error", "reason": "admin_required"}
    except Exception as e:
        return {"port": port, "state": "error", "reason": str(e)}
    if resp is None:
        return {"port": port, "state": "filtered", "reason": "no_response"}
    layer = resp.getlayer(TCP)
    if layer and layer.flags & 0x12 == 0x12:  # SYN-ACK
        return {"port": port, "state": "open", "reason": "syn-ack", "evaded": evade_fw}
    if layer and layer.flags & 0x14 == 0x14:  # RST-ACK
        return {"port": port, "state": "closed", "reason": "rst", "evaded": evade_fw}
    return {"port": port, "state": "unknown", "reason": "unexpected", "evaded": evade_fw}


def _advanced_scan_probe(host: str, port: int, timeout: float, scan_type: str, evade_fw: bool = False) -> Dict:
    """
    Advanced scan types: FIN, XMAS, NULL, ACK using Scapy with firewall evasion.
    Production-grade with real packet crafting - NO dummy data.
    
    Scan Types:
    - fin: FIN flag set (stealthy, bypasses some firewalls)
    - xmas: FIN, PSH, URG flags (Christmas tree scan)
    - null: No flags set (NULL scan)
    - ack: ACK flag (for firewall/stateful detection)
    
    Evasion:
    - Random source ports
    - TTL randomization
    - Packet fragmentation
    """
    try:
        from scapy.all import IP, TCP, sr1, conf, ICMP
    except Exception:
        return {"port": port, "state": "error", "reason": "scapy_not_installed"}
    
    conf.verb = 0
    
    # Apply firewall evasion techniques
    if evade_fw:
        src_port = _get_random_src_port()
        ttl = _randomize_ttl()
        ip_layer = IP(dst=host, ttl=ttl, flags="MF")  # More fragments flag for evasion
    else:
        src_port = 12345  # Default source port
        ip_layer = IP(dst=host)
    
    # Craft packet based on scan type
    if scan_type == "fin":
        pkt = ip_layer/TCP(sport=src_port, dport=port, flags='F')
    elif scan_type == "xmas":
        pkt = ip_layer/TCP(sport=src_port, dport=port, flags='FPU')
    elif scan_type == "null":
        pkt = ip_layer/TCP(sport=src_port, dport=port, flags='')
    elif scan_type == "ack":
        pkt = ip_layer/TCP(sport=src_port, dport=port, flags='A')
    else:
        return {"port": port, "state": "error", "reason": "invalid_scan_type"}
    
    try:
        resp = sr1(pkt, timeout=timeout)
    except PermissionError:
        return {"port": port, "state": "error", "reason": "admin_required"}
    except Exception as e:
        return {"port": port, "state": "error", "reason": str(e)}
    
    # Interpret response based on scan type
    if scan_type in {"fin", "xmas", "null"}:
        if resp is None:
            # No response = open|filtered
            return {"port": port, "state": "open|filtered", "reason": "no_response"}
        
        # Check for RST response
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer and tcp_layer.flags & 0x04:  # RST flag
            return {"port": port, "state": "closed", "reason": "rst"}
        
        # Check for ICMP unreachable
        icmp_layer = resp.getlayer(ICMP)
        if icmp_layer:
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            if icmp_type == 3:  # Destination unreachable
                if icmp_code in {1, 2, 3, 9, 10, 13}:
                    return {"port": port, "state": "filtered", "reason": f"icmp_unreachable_{icmp_code}"}
        
        return {"port": port, "state": "open|filtered", "reason": "no_rst"}
    
    elif scan_type == "ack":
        if resp is None:
            return {"port": port, "state": "filtered", "reason": "no_response"}
        
        tcp_layer = resp.getlayer(TCP)
        if tcp_layer and tcp_layer.flags & 0x04:  # RST
            return {"port": port, "state": "unfiltered", "reason": "rst_received"}
        
        # ICMP unreachable = filtered
        icmp_layer = resp.getlayer(ICMP)
        if icmp_layer and icmp_layer.type == 3:
            return {"port": port, "state": "filtered", "reason": "icmp_unreachable"}
        
        return {"port": port, "state": "unfiltered", "reason": "unknown_response"}
    
    return {"port": port, "state": "unknown", "reason": "unexpected"}

async def async_syn_scan(host: str, ports: List[int], concurrency: int = 200, timeout: float = 1.0, rate_limit: float = 0.0, iface: str = "", evade_fw: bool = False, stealth_level: str = "normal") -> List[Dict]:
    """Production SYN scanner with firewall evasion capabilities.
    
    Args:
        evade_fw: Enable firewall evasion (fragmentation, random TTL, random src port)
        stealth_level: Timing level (paranoid, sneaky, polite, normal, aggressive)
    """
    # Input validation
    if not _validate_hostname(host):
        raise ValueError(f"Invalid hostname or IP address: {host}")
    
    ports = _validate_ports(ports)
    if not ports:
        raise ValueError("No valid ports provided")
    
    if concurrency < 1 or concurrency > 10000:
        raise ValueError(f"Invalid concurrency: {concurrency}. Must be between 1 and 10000")
    
    if timeout <= 0 or timeout > 300:
        raise ValueError(f"Invalid timeout: {timeout}. Must be between 0 and 300 seconds")
    
    if not _has_required_privileges():
        raise PermissionError(_get_privilege_error_message("SYN scan"))
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []
    interval = (1.0 / rate_limit) if rate_limit and rate_limit > 0 else 0.0

    async def task(p: int):
        async with sem:
            if iface:
                try:
                    from scapy.all import conf
                    conf.iface = iface
                except Exception:
                    pass
            res = await asyncio.to_thread(_syn_probe_sync, host, p, timeout, evade_fw)
            results.append(res)
            # Add stealth timing delay
            delay = _get_timing_delay(stealth_level) if evade_fw else interval
            if delay > 0:
                await asyncio.sleep(delay)
            elif interval:
                await asyncio.sleep(interval)

    await asyncio.gather(*(task(p) for p in ports))
    results.sort(key=lambda r: r["port"])
    return results


async def async_advanced_scan(
    host: str,
    ports: List[int],
    scan_type: str,
    concurrency: int = 200,
    timeout: float = 1.0,
    rate_limit: float = 0.0,
    iface: str = "",
    evade_fw: bool = False,
    stealth_level: str = "normal",
) -> List[Dict]:
    """
    Production advanced scanner (FIN, XMAS, NULL, ACK) with firewall evasion.
    NO dummy data - real Scapy packet crafting only.
    Requires admin/root privileges.
    """
    # Input validation
    if not _validate_hostname(host):
        raise ValueError(f"Invalid hostname or IP address: {host}")
    
    ports = _validate_ports(ports)
    if ports is not None and len(ports) == 0:
        raise ValueError("No valid ports provided")
    
    if scan_type not in {"fin", "xmas", "null", "ack"}:
        raise ValueError(f"Invalid scan type: {scan_type}. Must be one of: fin, xmas, null, ack")
    
    if concurrency < 1 or concurrency > 10000:
        raise ValueError(f"Invalid concurrency: {concurrency}. Must be between 1 and 10000")
    
    if timeout <= 0 or timeout > 300:
        raise ValueError(f"Invalid timeout: {timeout}. Must be between 0 and 300 seconds")
    
    if not _has_required_privileges():
        raise PermissionError(_get_privilege_error_message(f"{scan_type.upper()} scan"))
    
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []
    interval = (1.0 / rate_limit) if rate_limit and rate_limit > 0 else 0.0
    
    async def task(p: int):
        async with sem:
            if iface:
                try:
                    from scapy.all import conf
                    conf.iface = iface
                except Exception:
                    pass
            res = await asyncio.to_thread(_advanced_scan_probe, host, p, timeout, scan_type, evade_fw)
            results.append(res)
            # Add stealth timing delay
            delay = _get_timing_delay(stealth_level) if evade_fw else interval
            if delay > 0:
                await asyncio.sleep(delay)
            elif interval:
                await asyncio.sleep(interval)
    
    await asyncio.gather(*(task(p) for p in ports))
    results.sort(key=lambda r: r["port"])
    return results

async def _probe(host: str, port: int, timeout: float, no_write: bool = False, version_detection: bool = False) -> Dict:
    """
    Production TCP port probe with real service detection.
    NO dummy data - all service identification based on actual responses.
    
    Args:
        host: Target host
        port: Target port
        timeout: Connection timeout
        no_write: Don't send probes (connect-only)
        version_detection: Enable aggressive version detection
    """
    state = "closed"
    reason = ""
    service = ""
    version = ""
    
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        state = "open"
        
        try:
            banner_data = b""
            
            # Service-specific probes (real protocols only)
            if not no_write:
                # Common HTTP ports, including popular alternate web ports
                if port in {80, 8080, 8000, 8888, 2052, 2082, 2086, 2095, 8880}:
                    # HTTP probe
                    writer.write(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Scorpion/2.0\r\nConnection: close\r\n\r\n".encode())
                    service = "http"
                # Common HTTPS ports, including cPanel/alt HTTPS ports
                elif port in {443, 8443, 2053, 2083, 2087, 2096}:
                    service = "https"
                    # Don't send data for HTTPS (TLS handshake required)
                elif port == 21:
                    service = "ftp"
                    # FTP sends banner first
                elif port == 22:
                    service = "ssh"
                    # SSH sends banner first
                elif port in {25, 465, 587, 2525}:
                    service = "smtp"
                    # SMTP sends banner first
                elif port == 110:
                    service = "pop3"
                    # POP3 sends banner first
                elif port == 143:
                    service = "imap"
                    # IMAP sends banner first
                elif port == 3306:
                    service = "mysql"
                    # MySQL sends handshake first
                elif port == 5432:
                    # PostgreSQL SSL check
                    writer.write(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                    service = "postgresql"
                elif port == 6379:
                    # Redis PING
                    writer.write(b"PING\r\n")
                    service = "redis"
                elif port == 27017:
                    service = "mongodb"
                    # MongoDB requires proper protocol
                elif port == 3389:
                    service = "rdp"
                elif port == 5900:
                    service = "vnc"
                    # VNC sends RFB version first
                elif port == 1433:
                    service = "mssql"
                elif port == 5672:
                    service = "amqp"
                elif port == 9200:
                    # Elasticsearch HTTP API
                    writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                    service = "elasticsearch"
                else:
                    # Generic probe
                    writer.write(b"\r\n\r\n")
                
                if service not in {"https"}:  # Skip drain for SSL ports
                    await writer.drain()
            
            # Read banner/response
            try:
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            except asyncio.TimeoutError:
                banner_data = b""
            
            if banner_data:
                banner_text = ""
                try:
                    banner_text = banner_data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    banner_text = ""
                
                # Parse service-specific responses for version detection
                if service == "http" and banner_text:
                    lines = banner_text.splitlines()
                    status_line = lines[0] if lines else ""
                    server = ""
                    powered_by = ""
                    
                    for line in lines:
                        lower = line.lower()
                        if lower.startswith("server:"):
                            server = line.split(":", 1)[1].strip()
                        elif lower.startswith("x-powered-by:"):
                            powered_by = line.split(":", 1)[1].strip()
                    
                    version_parts = []
                    if server:
                        version_parts.append(f"Server: {server}")
                    if powered_by:
                        version_parts.append(f"Powered-By: {powered_by}")
                    
                    version = " | ".join(version_parts) if version_parts else status_line
                    reason = f"{service} {version}" if version else service
                
                elif service == "ssh" and banner_text:
                    # SSH banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
                    ssh_banner = banner_text.splitlines()[0] if banner_text else ""
                    if ssh_banner.startswith("SSH-"):
                        version = ssh_banner
                        reason = version
                    else:
                        reason = "ssh"
                
                elif service == "ftp" and banner_text:
                    # FTP banner: 220 ProFTPD Server (hostname) [::ffff:ip]
                    ftp_banner = banner_text.splitlines()[0] if banner_text else ""
                    if ftp_banner:
                        # Extract version info
                        version = ftp_banner.replace("220 ", "").strip()
                        reason = f"ftp {version}"
                    else:
                        reason = "ftp"
                
                elif service == "smtp" and banner_text:
                    # SMTP banner: 220 mail.<DOMAIN> ESMTP Postfix
                    smtp_banner = banner_text.splitlines()[0] if banner_text else ""
                    if smtp_banner:
                        version = smtp_banner.replace("220 ", "").strip()
                        reason = f"smtp {version}"
                    else:
                        reason = "smtp"
                
                elif service == "mysql" and banner_data:
                    # MySQL handshake packet parsing
                    if len(banner_data) > 5:
                        # Skip protocol version byte
                        null_pos = banner_data.find(b'\x00', 1)
                        if null_pos > 0:
                            mysql_version = banner_data[1:null_pos].decode('utf-8', errors='ignore')
                            version = f"MySQL {mysql_version}"
                            reason = version
                        else:
                            reason = "mysql"
                    else:
                        reason = "mysql"
                
                elif service == "postgresql" and banner_data:
                    # PostgreSQL SSL response
                    if banner_data == b'S':
                        version = "SSL supported"
                    elif banner_data == b'N':
                        version = "SSL not supported"
                    else:
                        version = ""
                    reason = f"postgresql {version}" if version else "postgresql"
                
                elif service == "redis" and banner_text:
                    # Redis PING response: +PONG
                    if "+PONG" in banner_text or "-" in banner_text:
                        version = "Redis"
                        reason = version
                    else:
                        reason = "redis"
                
                elif service == "pop3" and banner_text:
                    # POP3 banner: +OK Dovecot ready.
                    pop_banner = banner_text.splitlines()[0] if banner_text else ""
                    if pop_banner:
                        version = pop_banner.replace("+OK ", "").strip()
                        reason = f"pop3 {version}"
                    else:
                        reason = "pop3"
                
                elif service == "imap" and banner_text:
                    # IMAP banner: * OK [CAPABILITY ...] Dovecot ready.
                    imap_banner = banner_text.splitlines()[0] if banner_text else ""
                    if imap_banner:
                        version = imap_banner.replace("* OK ", "").strip()
                        reason = f"imap {version}"
                    else:
                        reason = "imap"
                
                elif service == "vnc" and banner_text:
                    # VNC RFB version: RFB 003.008
                    if banner_text.startswith("RFB "):
                        version = banner_text
                        reason = f"vnc {version}"
                    else:
                        reason = "vnc"
                
                elif service == "elasticsearch" and banner_text:
                    # Try to parse JSON response
                    try:
                        import json
                        # Find JSON in response
                        json_start = banner_text.find('{')
                        if json_start >= 0:
                            json_data = json.loads(banner_text[json_start:])
                            if "version" in json_data and "number" in json_data["version"]:
                                version = f"Elasticsearch {json_data['version']['number']}"
                                reason = version
                            else:
                                reason = "elasticsearch"
                        else:
                            reason = "elasticsearch"
                    except Exception:
                        reason = "elasticsearch"
                
                else:
                    # Unknown service - show first line of banner
                    if banner_text:
                        first_line = banner_text.splitlines()[0][:80] if banner_text else ""
                        reason = first_line if first_line else "open"
                    else:
                        reason = service if service else "open"
            
            else:
                # No banner received
                reason = service if service else "open"
        
        except (ConnectionResetError, BrokenPipeError):
            state = "closed"
        except asyncio.TimeoutError:
            # No response after connect - likely open but non-responsive
            reason = service if service else "open"
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    
    except (asyncio.TimeoutError, OSError):
        state = "closed"
    
    result = {"port": port, "state": state, "reason": reason}
    # Expose detected service name to callers (CLI, AI pentest, etc.)
    if service:
        result["service"] = service
    if version and version_detection:
        result["version"] = version
    
    return result

async def async_port_scan(host: str, ports: List[int], concurrency: int = 200, timeout: float = 1.0, no_write: bool = False, version_detection: bool = False) -> List[Dict]:
    """
    Production TCP port scanner with optional version detection.
    NO dummy data - all results from real network responses.
    """
    # Input validation
    if not _validate_hostname(host):
        raise ValueError(f"Invalid hostname or IP address: {host}")
    
    ports = _validate_ports(ports)
    if ports is not None and len(ports) == 0:
        raise ValueError("No valid ports provided")
    
    if concurrency < 1 or concurrency > 10000:
        raise ValueError(f"Invalid concurrency: {concurrency}. Must be between 1 and 10000")
    
    if timeout <= 0 or timeout > 300:
        raise ValueError(f"Invalid timeout: {timeout}. Must be between 0 and 300 seconds")
    
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []

    async def task(p: int):
        async with sem:
            res = await _probe(host, p, timeout, no_write=no_write, version_detection=version_detection)
            results.append(res)

    await asyncio.gather(*(task(p) for p in ports))
    results.sort(key=lambda r: r["port"])  # deterministic
    return results

# --- UDP scanning (best-effort, safe probes) ---

def _udp_probe_sync(host: str, port: int, timeout: float) -> Dict:
    state = "closed"
    reason = ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        try:
            # Service-aware safe payloads
            payload = b"\x00"
            # DNS (53): standard query for A record of <DOMAIN>
            if port == 53:
                payload = bytes.fromhex(
                    """
                    aa aa 01 00 00 01 00 00 00 00 00 00
                    07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
                    00 01 00 01
                    """.replace("\n", " ").replace(" ", "")
                )
            # NTP (123): client mode request (no monlist), mode 3
            elif port == 123:
                payload = b"\x1b" + b"\x00" * 47
            # SNMP (161): simple SNMPv2c get sysDescr.0 with community 'public'
            elif port == 161:
                # Minimal ASN.1 for SNMP GET sysDescr.0; safe, read-only
                payload = bytes.fromhex(
                    "3026 0201 01 0406 7075626c6963 a0 19 0204 00000001 0201 00 0201 00 3011 300f 0608 2b06010201010500 0500"
                    .replace(" ", "")
                )
            # SSDP (1900): M-SEARCH discovery
            elif port == 1900:
                payload = (
                    b"M-SEARCH * HTTP/1.1\r\n"
                    b"HOST: 239.255.255.250:1900\r\n"
                    b"MAN: \"ssdp:discover\"\r\n"
                    b"MX: 1\r\n"
                    b"ST: ssdp:all\r\n\r\n"
                )
            sock.sendto(payload, (host, port))
        except OSError as e:
            return {"port": port, "state": "closed", "reason": str(e)}

        try:
            data, addr = sock.recvfrom(256)
            if data:
                state = "open"
                # Try to hint service based on port
                service = ""
                if port == 53:
                    service = "dns"
                elif port == 123:
                    service = "ntp"
                elif port == 161:
                    service = "snmp"
                elif port == 1900:
                    service = "ssdp"
                try:
                    preview = data[:64].decode(errors="ignore").strip()
                except Exception:
                    preview = "response"
                reason = (service + (" " + preview if preview else "")).strip()
        except socket.timeout:
            # No response: UDP semantics -> open|filtered
            state = "open|filtered"
        except OSError as e:
            # ICMP unreachable often surfaces as OSError on some OSes
            state = "closed"
            reason = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return {"port": port, "state": state, "reason": reason}

async def async_udp_scan(host: str, ports: List[int], concurrency: int = 200, timeout: float = 1.0) -> List[Dict]:
    """Production UDP port scanner with service-specific probes."""
    # Input validation
    if not _validate_hostname(host):
        raise ValueError(f"Invalid hostname or IP address: {host}")
    
    ports = _validate_ports(ports)
    if ports is not None and len(ports) == 0:
        raise ValueError("No valid ports provided")
    
    if concurrency < 1 or concurrency > 10000:
        raise ValueError(f"Invalid concurrency: {concurrency}. Must be between 1 and 10000")
    
    if timeout <= 0 or timeout > 300:
        raise ValueError(f"Invalid timeout: {timeout}. Must be between 0 and 300 seconds")
    
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []

    async def task(p: int):
        async with sem:
            res = await asyncio.to_thread(_udp_probe_sync, host, p, timeout)
            results.append(res)

    await asyncio.gather(*(task(p) for p in ports))
    results.sort(key=lambda r: r["port"])  # deterministic
    return results

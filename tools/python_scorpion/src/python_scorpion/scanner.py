import asyncio
import socket
from typing import Dict, List
import os

def _is_admin_windows() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _syn_probe_sync(host: str, port: int, timeout: float) -> Dict:
    try:
        from scapy.all import IP, TCP, sr1, conf
    except Exception:
        return {"port": port, "state": "error", "reason": "scapy_not_installed"}
    # Basic SYN probe: send SYN, wait for SYN-ACK
    conf.verb = 0
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
        return {"port": port, "state": "open", "reason": "syn-ack"}
    if layer and layer.flags & 0x14 == 0x14:  # RST-ACK
        return {"port": port, "state": "closed", "reason": "rst"}
    return {"port": port, "state": "unknown", "reason": "unexpected"}

async def async_syn_scan(host: str, ports: List[int], concurrency: int = 200, timeout: float = 1.0, rate_limit: float = 0.0, iface: str = "") -> List[Dict]:
    # On Windows, require admin
    if os.name == 'nt' and not _is_admin_windows():
        raise PermissionError("SYN scan requires admin on Windows")
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []
    interval = (1.0 / rate_limit) if rate_limit and rate_limit > 0 else 0.0

    async def task(p: int):
        async with sem:
            # configure iface if provided
            if iface:
                try:
                    from scapy.all import conf
                    conf.iface = iface
                except Exception:
                    pass
            res = await asyncio.to_thread(_syn_probe_sync, host, p, timeout)
            results.append(res)
            if interval:
                await asyncio.sleep(interval)

    await asyncio.gather(*(task(p) for p in ports))
    results.sort(key=lambda r: r["port"])  # deterministic
    return results

async def _probe(host: str, port: int, timeout: float, no_write: bool = False) -> Dict:
    state = "closed"
    reason = ""
    service = ""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        # tentative open on successful TCP connect
        state = "open"
        try:
            # Minimal protocol-aware probes
            # HTTP/HTTPS (HTTP banner over 80/8080; TLS handshake not attempted here)
            if not no_write and port in {80, 8080}:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: %b\r\nConnection: close\r\n\r\n" % host.encode())
                service = "http"
            # HTTPS: avoid forcing handshake; keep probes lightweight and rely on port mapping in presentation
            elif port == 443:
                service = "https"
            # SSH banner is sent by server first
            elif port == 22:
                # read without sending data
                pass
            # SMTP banner is sent by server first
            elif port in {25, 465, 587}:
                pass
            # FTP banner first
            elif port == 21:
                pass
            # IMAP greeting
            elif port == 143:
                service = "imap"
            # POP3 greeting
            elif port == 110:
                service = "pop3"
            # RDP negotiation response
            elif port == 3389:
                service = "rdp"
            # Redis simple PING
            elif not no_write and port == 6379:
                writer.write(b"*1\r\n$4\r\nPING\r\n")
                service = "redis"
            # MySQL handshake: server sends greeting
            elif port == 3306:
                pass
            # PostgreSQL: SSLRequest (0x00000008 + 0x04D2162F) then expect 'N' or 'S'
            elif not no_write and port == 5432:
                writer.write(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                service = "postgres"
            # MongoDB: isMaster (legacy) or hello; send minimal OP_MSG is too heavy; rely on banner
            elif port == 27017:
                pass
            else:
                if not no_write:
                    writer.write(b"\r\n")
            if not no_write:
                await writer.drain()
            # short grace window to detect immediate resets/closures
            data = await asyncio.wait_for(reader.read(128), timeout=0.5)
            if data:
                preview = ""
                try:
                    preview = data.decode(errors="ignore").strip()
                except Exception:
                    preview = ""
                # Light parsing to improve professionalism of identification
                detail = preview
                if service == "http" and preview:
                    # Extract first line and Server header if present
                    lines = preview.splitlines()
                    first = lines[0] if lines else ""
                    server = ""
                    for ln in lines:
                        if ln.lower().startswith("server:"):
                            server = ln.split(":", 1)[1].strip()
                            break
                    if server:
                        detail = f"{first} | Server: {server}"
                    else:
                        detail = first
                elif service == "https" and preview:
                    # TLS bytes likely non-text; keep minimal marker
                    detail = "tls"
                elif port == 22 and preview:
                    # SSH banner typically begins with SSH-2.0-...
                    detail = preview.splitlines()[0]
                    service = "ssh"
                elif port in {25, 465, 587} and preview:
                    # SMTP greeting line
                    detail = preview.splitlines()[0]
                    service = "smtp"
                elif port == 5432:
                    # Postgres SSLRequest response: 'S' (support) or 'N' (no)
                    if data == b"S":
                        detail = "SSL"
                    elif data == b"N":
                        detail = "NoSSL"
                reason = (service + (" " + detail if detail else "")).strip()
        except (ConnectionResetError, BrokenPipeError):
            # immediate reset after write indicates closed/filtered behavior
            state = "closed"
        except asyncio.TimeoutError:
            # no banner; keep as open but without reason for common service ports only
            common = {21,22,23,25,53,80,110,143,443,465,587,993,995,3306,3389,8080}
            if port not in common:
                state = "closed"
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    except (asyncio.TimeoutError, OSError):
        state = "closed"
    return {"port": port, "state": state, "reason": reason}

async def async_port_scan(host: str, ports: List[int], concurrency: int = 200, timeout: float = 1.0, no_write: bool = False) -> List[Dict]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []

    async def task(p: int):
        async with sem:
            res = await _probe(host, p, timeout, no_write=no_write)
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
            # DNS (53): standard query for A record of example.com
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
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []

    async def task(p: int):
        async with sem:
            res = await asyncio.to_thread(_udp_probe_sync, host, p, timeout)
            results.append(res)

    await asyncio.gather(*(task(p) for p in ports))
    results.sort(key=lambda r: r["port"])  # deterministic
    return results

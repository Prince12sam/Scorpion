import asyncio
import ssl
import socket
import datetime
from typing import Dict, List

import httpx
from cryptography import x509

async def _fetch_cert(host: str, port: int) -> Dict:
    loop = asyncio.get_event_loop()
    def blocking() -> Dict:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(True) or b""
                cert = x509.load_der_x509_certificate(der)
                cipher = ssock.cipher()
                tls_version = ssock.version()
        return {"cert": cert, "cipher": cipher, "version": tls_version}
    return await loop.run_in_executor(None, blocking)

async def _check_headers(host: str, insecure_fallback: bool = True) -> Dict:
    url_https = f"https://{host}"
    url_http = f"http://{host}"
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=True) as client:
            r = await client.get(url_https)
            hsts = r.headers.get("strict-transport-security")
            return {"hsts": bool(hsts), "headers": dict(r.headers), "insecure_fetch": False}
    except Exception:
        if not insecure_fallback:
            return {"hsts": False, "headers": {}, "insecure_fetch": False}
        # Best-effort header fetch over plain HTTP to avoid disabling TLS verification
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(url_http)
                hsts = r.headers.get("strict-transport-security")
                return {"hsts": bool(hsts), "headers": dict(r.headers), "insecure_fetch": True}
        except Exception:
            return {"hsts": False, "headers": {}, "insecure_fetch": False}

async def analyze_ssl(host: str, port: int = 443) -> Dict:
    try:
        data = await _fetch_cert(host, port)
        cert: x509.Certificate = data["cert"]
        cipher_name, protocol, secret_bits = data["cipher"]
        tls_version = data["version"]

        now = datetime.datetime.now(datetime.timezone.utc)
        expires = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
        days_left = (expires - now).days

        headers = await _check_headers(host)

        remediation: List[str] = []
        if days_left < 30:
            remediation.append("Renew certificate within 30 days")
        if not headers["hsts"]:
            remediation.append("Enable HSTS header with max-age >= 6 months")
        if tls_version in {"TLSv1", "TLSv1.1"}:
            remediation.append("Disable deprecated TLS versions (1.0/1.1)")

        return {
            "target": host,
            "port": port,
            "certificate": {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "expires": expires.isoformat(),
                "days_left": days_left,
            },
            "tls": {
                "version": tls_version,
                "cipher": cipher_name,
                "bits": secret_bits,
                "protocol": protocol,
            },
            "security_headers": headers,
            "location": {
                "endpoint": f"https://{host}:{port}",
                "evidence": "TLS handshake + HTTP headers",
            },
            "remediation": remediation,
            "severity": "info" if not remediation else "medium",
        }
    except ssl.SSLCertVerificationError as e:
        headers = await _check_headers(host, insecure_fallback=True)
        remediation = [
            "Fix certificate chain/issuer; ensure full intermediate chain is served",
            "Verify host SNI and certificate SANs match the domain",
        ]
        evidence = "Handshake failed; headers fetched insecurely" if headers.get("insecure_fetch") else "Handshake failed; headers unavailable"
        return {
            "target": host,
            "port": port,
            "certificate": None,
            "tls": None,
            "security_headers": headers,
            "location": {
                "endpoint": f"https://{host}:{port}",
                "evidence": evidence,
            },
            "errors": {
                "handshake": "SSLCertVerificationError",
                "detail": str(e),
            },
            "remediation": remediation,
            "severity": "medium",
        }
    except Exception as e:
        headers = await _check_headers(host, insecure_fallback=True)
        evidence = "Handshake failed; headers fetched insecurely" if headers.get("insecure_fetch") else "Handshake failed; headers unavailable"
        return {
            "target": host,
            "port": port,
            "certificate": None,
            "tls": None,
            "security_headers": headers,
            "location": {
                "endpoint": f"https://{host}:{port}",
                "evidence": evidence,
            },
            "errors": {
                "handshake": e.__class__.__name__,
                "detail": str(e),
            },
            "remediation": ["Investigate TLS connectivity; check firewall/WAF, DNS, and server availability"],
            "severity": "info",
        }

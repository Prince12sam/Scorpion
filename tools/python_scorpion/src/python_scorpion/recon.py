import asyncio
from typing import Dict, List

import dns.resolver
import httpx

try:
    import whois  # type: ignore
except Exception:
    whois = None  # optional dependency

async def dns_records(host: str) -> Dict:
    recs: Dict[str, List[str]] = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS"]:
        vals: List[str] = []
        try:
            answers = dns.resolver.resolve(host, rtype)
            for ans in answers:
                vals.append(str(ans).rstrip("."))
        except Exception:
            pass
        recs[rtype] = vals
    return recs

async def http_headers(host: str) -> Dict:
    url = f"https://{host}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(url)
            headers = dict(r.headers)
            server = headers.get("server")
            waf = headers.get("x-cdn") or headers.get("x-iinfo") or headers.get("x-imperva")
            return {"endpoint": url, "status_code": r.status_code, "server": server, "headers": headers, "waf_hint": bool(waf)}
    except Exception:
        return {"endpoint": url, "status_code": 0, "server": None, "headers": {}, "waf_hint": False}

async def whois_info(host: str) -> Dict:
    if not whois:
        return {"available": False}
    loop = asyncio.get_event_loop()
    def blocking():
        try:
            data = whois.whois(host)
            return {"available": True, "registrar": data.registrar, "creation_date": str(data.creation_date), "expiration_date": str(data.expiration_date)}
        except Exception:
            return {"available": False}
    return await loop.run_in_executor(None, blocking)

async def recon(host: str) -> Dict:
    dns = await dns_records(host)
    http = await http_headers(host)
    wi = await whois_info(host)

    findings = []
    if http.get("waf_hint"):
        findings.append({
            "type": "waf_or_cdn_hint",
            "location": http["endpoint"],
            "impact": "WAF/CDN present; may affect scanning",
            "remediation": "Plan tests accordingly and add allowlist if needed",
            "severity": "info",
        })

    return {
        "target": host,
        "dns": dns,
        "http": http,
        "whois": wi,
        "findings": findings,
    }

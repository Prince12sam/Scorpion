import asyncio
from typing import Dict, List, Optional

import json
import pathlib
import httpx
import dns.resolver

def load_provider_fingerprints() -> Dict[str, List[str]]:
    here = pathlib.Path(__file__).resolve().parent.parent
    cfg = here / "providers.json"
    try:
        with open(cfg, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

async def resolve_cname(host: str) -> Optional[str]:
    try:
        answers = dns.resolver.resolve(host, "CNAME")
        for ans in answers:
            # dnspython CNAME answer string includes a trailing dot
            return str(getattr(ans, "target", ans)).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    return None

def identify_service(cname: str) -> Optional[str]:
    low = cname.lower()
    providers = load_provider_fingerprints()
    for service, patterns in providers.items():
        for p in patterns:
            if p in low:
                return service
    return None

async def check_claimability(url: str) -> Dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(url)
            text = r.text.lower()
            indicators = [
                "there isn't a github pages site here",
                "no such app",
                "not found",
                "does not exist",
            ]
            claimable = any(i in text for i in indicators)
            return {"status_code": r.status_code, "claimable": claimable}
    except Exception:
        return {"status_code": 0, "claimable": False}

async def takeover_scan(host: str) -> Dict:
    cname = await resolve_cname(host)
    service = identify_service(cname or "") if cname else None
    url = f"http://{host}"
    http = await check_claimability(url)

    vulnerable = bool(service and http.get("claimable"))
    remediation = []
    if vulnerable:
        remediation.append("Create/claim the resource at the provider or remove CNAME record.")
    else:
        if service:
            remediation.append("Ensure the resource exists and is correctly mapped at the provider.")

    return {
        "target": host,
        "dns": {
            "cname": cname,
            "service": service,
        },
        "http": http,
        "vulnerable": vulnerable,
        "location": {
            "dns_record": "CNAME",
            "evidence": f"CNAME={cname}, service={service}, GET {url} status={http['status_code']}",
        },
        "remediation": remediation,
        "severity": "high" if vulnerable else "info",
    }

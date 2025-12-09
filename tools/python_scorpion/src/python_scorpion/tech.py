import asyncio
from typing import Dict, List

import httpx


def _header_contains(headers: Dict[str, str], key: str, needle: str) -> bool:
    val = headers.get(key) or headers.get(key.lower())
    return bool(val and needle.lower() in val.lower())


async def detect_tech(host: str) -> Dict:
    url = f"https://{host}"
    headers: Dict[str, str] = {}
    html = ""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(url)
            headers = {k.lower(): v for k, v in r.headers.items()}
            html = r.text[:200_000] if r.text else ""
    except Exception:
        pass

    detected: List[Dict] = []

    def add(name: str, evidence: str):
        detected.append({"name": name, "evidence": evidence})

    # Servers/Backends
    if _header_contains(headers, "server", "nginx"):
        add("nginx", "server header contains 'nginx'")
    if _header_contains(headers, "server", "apache"):
        add("Apache HTTPD", "server header contains 'apache'")
    if _header_contains(headers, "x-powered-by", "php"):
        add("PHP", "x-powered-by contains 'php'")
    if _header_contains(headers, "x-aspnet-version", "") or _header_contains(headers, "x-powered-by", "asp.net"):
        add("ASP.NET", "ASP.NET header observed")
    if _header_contains(headers, "x-powered-by", "express"):
        add("Node.js (Express)", "x-powered-by contains 'express'")

    # Frameworks/CMS
    if "wp-content" in html.lower() or "wp-includes" in html.lower():
        add("WordPress", "HTML references 'wp-content'/'wp-includes'")
    if "drupal.settings" in html.lower():
        add("Drupal", "HTML contains 'Drupal.settings'")
    if "data-reactroot" in html.lower():
        add("React", "HTML contains 'data-reactroot'")
    if "ng-version" in html.lower():
        add("Angular", "HTML contains 'ng-version'")
    if "__NUXT__" in html or "nuxt-speedkit" in html.lower():
        add("Nuxt", "HTML contains nuxt markers")

    # CDN/WAF
    if any(k in headers for k in ["cf-ray", "cf-cache-status", "cf-connecting-ip"]):
        add("Cloudflare", "Cloudflare response headers present")
    if any("akamai" in v.lower() for v in headers.values() if isinstance(v, str)):
        add("Akamai", "Headers mention 'akamai'")
    if any("incap" in v.lower() for v in headers.values() if isinstance(v, str)):
        add("Imperva/Incapsula", "Headers mention 'incap'")
    if any("fastly" in v.lower() for v in headers.values() if isinstance(v, str)):
        add("Fastly", "Headers mention 'fastly'")

    return {
        "target": host,
        "endpoint": url,
        "detected": detected,
        "counts": len(detected),
    }

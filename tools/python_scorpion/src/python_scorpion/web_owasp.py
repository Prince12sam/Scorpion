import asyncio
from typing import Dict, List, Tuple

import httpx


def _has(text: str, subs: List[str]) -> bool:
    t = (text or "").lower()
    return any(s.lower() in t for s in subs)


async def _fetch(url: str, timeout: float = 6.0) -> Tuple[int, Dict[str, str], str]:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            body = r.text[:4000] if r.text else ""
            return r.status_code, dict(r.headers), body
    except Exception:
        return 0, {}, ""


async def web_owasp_passive(host: str) -> Dict:
    """Passive OWASP checks against root and an invalid path (no state changes)."""
    base_https = f"https://{host}"
    base_http = f"http://{host}"
    status, headers, body = await _fetch(base_https)
    if status == 0:
        status, headers, body = await _fetch(base_http)

    # Probe an invalid path to elicit error signatures
    bad_status, bad_headers, bad_body = await _fetch(base_https + "/this-path-should-not-exist-owasp-check")
    if bad_status == 0:
        bad_status, bad_headers, bad_body = await _fetch(base_http + "/this-path-should-not-exist-owasp-check")

    findings: List[Dict] = []
    def add(name: str, impact: str, severity: str, remediation: str, evidence: str = ""):
        findings.append({
            "name": name,
            "impact": impact,
            "severity": severity,
            "remediation": remediation,
            "evidence": evidence,
        })

    # Security headers
    # HSTS (only meaningful over HTTPS)
    if base_https and status != 0:
        if not headers.get("strict-transport-security"):
            add("Missing HSTS", "Users may downgrade to HTTP and be vulnerable to MITM", "medium", "Add Strict-Transport-Security with max-age>=15552000; includeSubDomains; preload")

    if not headers.get("content-security-policy"):
        add("Missing CSP", "XSS risk without content security policy", "medium", "Add a restrictive CSP (default-src 'none'; img-src 'self' data:; script-src 'self'; style-src 'self'; connect-src 'self')")
    if not headers.get("x-frame-options") and not headers.get("content-security-policy", "").lower().find("frame-ancestors") >= 0:
        add("Missing X-Frame-Options", "Clickjacking risk", "medium", "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'")
    if headers.get("content-type") and not headers.get("x-content-type-options"):
        add("Missing X-Content-Type-Options", "MIME sniffing risk", "low", "Add X-Content-Type-Options: nosniff")
    if not headers.get("referrer-policy"):
        add("Missing Referrer-Policy", "Referrer leakage risk", "low", "Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin")
    if not headers.get("permissions-policy"):
        add("Missing Permissions-Policy", "Unrestricted powerful features", "low", "Add Permissions-Policy to restrict camera, microphone, geolocation, etc.")

    # Basic CORS analysis
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao:
        if acao.strip() == "*" and acac == "true":
            add("Overly broad CORS with credentials", "Cross-site origin can read responses with credentials", "high", "Do not use wildcard with credentials; scope ACAO to trusted origins")
        elif acao.strip() == "*":
            add("Wildcard CORS", "Any origin can read responses (no credentials)", "medium", "Restrict ACAO to specific trusted origins")

    # Mixed content heuristic: HTTPS page referencing HTTP resources
    if status != 0 and base_https.startswith("https://") and body:
        if _has(body, ["http://", "src=\"http://", "href=\"http://"]):
            add("Potential mixed content", "HTTPS page may load HTTP resources", "medium", "Ensure all resources are served over HTTPS", evidence="Found HTTP references in HTML body")

    # Cookies flags
    set_cookie = ", ".join([k for k in headers.keys() if k.lower() == "set-cookie"]) or "set-cookie"
    cookies = headers.get(set_cookie)
    if cookies:
        c = cookies.lower()
        if "secure" not in c:
            add("Cookie missing Secure", "Cookies may be sent over HTTP", "medium", "Mark cookies as Secure and serve only over HTTPS")
        if "httponly" not in c:
            add("Cookie missing HttpOnly", "Client-side script can access cookies", "medium", "Mark cookies as HttpOnly to mitigate XSS cookie theft")
        # samesite check
        if "samesite" not in c:
            add("Cookie missing SameSite", "CSRF risk via cross-site requests", "low", "Use SameSite=Lax or Strict where appropriate")

    # Error page fingerprints
    if bad_status >= 500 or _has(bad_body, ["exception", "stacktrace", "traceback", "warning:"]):
        add("Verbose error pages", "Information disclosure via detailed errors", "low", "Disable verbose error pages; return generic error responses in production",
            evidence=f"status={bad_status}")

    return {
        "target": host,
        "http": {"status": status, "headers": headers},
        "error_probe": {"status": bad_status},
        "findings": findings,
    }

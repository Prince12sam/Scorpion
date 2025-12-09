import asyncio
from typing import Dict, Optional, List

import httpx

async def fetch_swagger(host: str) -> Optional[str]:
    paths = ["/swagger.json", "/v2/api-docs", "/openapi.json"]
    base = f"https://{host}"
    async with httpx.AsyncClient(timeout=5.0) as client:
        for p in paths:
            try:
                r = await client.get(base + p)
                if r.status_code == 200 and r.headers.get("content-type", "").startswith("application/json"):
                    return base + p
            except Exception:
                continue
    return None

async def check_graphql(host: str) -> Dict:
    url = f"https://{host}/graphql"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # probe introspection
            payload = {"query": "query IntrospectionQuery{__schema{queryType{name}}}"}
            r = await client.post(url, json=payload)
            open_introspection = (r.status_code == 200 and "__schema" in r.text)
            return {"endpoint": url, "status_code": r.status_code, "open_introspection": open_introspection}
    except Exception:
        return {"endpoint": url, "status_code": 0, "open_introspection": False}

async def jwt_headers(host: str) -> Dict:
    url = f"https://{host}/"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(url)
            # naive header checks
            leaks = []
            if r.headers.get("x-jwt-token"):
                leaks.append("JWT token disclosed in header")
            if r.headers.get("authorization"):
                leaks.append("Authorization header echoed back")
            return {"endpoint": url, "leaks": leaks}
    except Exception:
        return {"endpoint": url, "leaks": []}

async def idor_heuristic(host: str) -> Dict:
    # very conservative unauthenticated probe against common REST patterns
    base = f"https://{host}"
    endpoints = ["/api/items/1", "/api/users/1", "/api/orders/1"]
    results: List[Dict] = []
    async with httpx.AsyncClient(timeout=5.0) as client:
        for ep in endpoints:
            url = base + ep
            try:
                r1 = await client.get(url)
                r2 = await client.get(base + ep.replace("1", "2"))
                indicative = (r1.status_code == 200 and r2.status_code == 200 and r1.text != r2.text)
                results.append({"endpoint": url, "status_codes": [r1.status_code, r2.status_code], "indicative_idor": indicative})
            except Exception:
                results.append({"endpoint": url, "status_codes": [0,0], "indicative_idor": False})
    return {"tests": results}

async def improved_rate_limit(host: str, bursts: int = 20) -> Dict:
    url = f"https://{host}/"
    status_codes = []
    async with httpx.AsyncClient(timeout=3.0) as client:
        for _ in range(bursts):
            try:
                r = await client.get(url)
                status_codes.append(r.status_code)
            except Exception:
                status_codes.append(0)
    rl_hit = 429 in status_codes
    return {"endpoint": url, "status_codes": status_codes, "rate_limit_detected": rl_hit}

async def api_probe(host: str) -> Dict:
    swagger = await fetch_swagger(host)
    graphql = await check_graphql(host)
    jwt = await jwt_headers(host)
    idor = await idor_heuristic(host)
    rate = await improved_rate_limit(host)

    findings = []
    if swagger:
        findings.append({
            "type": "swagger_exposed",
            "location": swagger,
            "impact": "Information disclosure enables easier enumeration",
            "remediation": "Restrict public access or require auth for API docs",
            "severity": "low",
        })
    else:
        findings.append({
            "type": "swagger_missing_or_protected",
            "location": f"https://{host}",
            "impact": "Less discoverable but not a vuln by itself",
            "remediation": "Ensure docs exist for developers and protect if sensitive",
            "severity": "info",
        })

    if graphql["status_code"] == 200 and graphql["open_introspection"]:
        findings.append({
            "type": "graphql_introspection_enabled",
            "location": graphql["endpoint"],
            "impact": "Schema discovery may aid attackers",
            "remediation": "Disable public introspection or require auth",
            "severity": "medium",
        })

    for leak in jwt["leaks"]:
        findings.append({
            "type": "jwt_header_leak",
            "location": jwt["endpoint"],
            "impact": leak,
            "remediation": "Avoid reflecting auth headers; ensure secure headers",
            "severity": "medium",
        })

    for t in idor["tests"]:
        if t["indicative_idor"]:
            findings.append({
                "type": "idor_indicator",
                "location": t["endpoint"],
                "impact": "Changing IDs returns different objects without auth",
                "remediation": "Enforce object-level authorization; validate ownership",
                "severity": "high",
            })

    if rate["rate_limit_detected"]:
        findings.append({
            "type": "rate_limit_present",
            "location": rate["endpoint"],
            "impact": "429 detected; basic rate limiting present",
            "remediation": "Tune thresholds and add IP/user-based policies",
            "severity": "info",
        })
    else:
        findings.append({
            "type": "rate_limit_not_detected",
            "location": rate["endpoint"],
            "impact": "No 429 observed under bursts; may allow abuse",
            "remediation": "Implement rate limiting and anomaly detection",
            "severity": "low",
        })

    return {
        "target": host,
        "findings": findings,
        "details": {
            "graphql": graphql,
            "jwt": jwt,
            "idor": idor,
            "rate_limit_check": rate,
        }
    }

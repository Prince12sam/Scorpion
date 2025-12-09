import asyncio
from typing import Dict

import httpx


async def _get(client: httpx.AsyncClient, url: str) -> Dict:
    try:
        r = await client.get(url)
        return {"url": url, "status": r.status_code}
    except Exception:
        return {"url": url, "status": 0}


async def container_audit(registry: str) -> Dict:
    """Check for open Docker registry APIs (v2/_catalog) and common UIs (Harbor)."""
    base = registry.rstrip("/")
    urls = [
        f"https://{base}/v2/_catalog",
        f"http://{base}/v2/_catalog",
        f"https://{base}/api/v2.0/projects",  # Harbor v2
    ]
    async with httpx.AsyncClient(timeout=6.0) as client:
        results = await asyncio.gather(*(_get(client, u) for u in urls))
    findings = []
    if any(r["status"] == 200 and r["url"].endswith("/v2/_catalog") for r in results):
        findings.append({
            "type": "docker_registry_open",
            "impact": "Anonymous registry catalog accessible",
            "remediation": "Disable anonymous access, enforce auth, restrict network",
            "severity": "high",
        })
    if any(r["status"] == 200 and "/api/v2.0/projects" in r["url"] for r in results):
        findings.append({
            "type": "harbor_api_open",
            "impact": "Harbor API accessible anonymously",
            "remediation": "Require authentication and restrict from public internet",
            "severity": "medium",
        })
    return {"target": registry, "results": results, "findings": findings}

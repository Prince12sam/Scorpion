import asyncio
from typing import Dict

import httpx


async def _probe(client: httpx.AsyncClient, base: str, path: str) -> Dict:
    url = base.rstrip("/") + path
    try:
        r = await client.get(url)
        return {"endpoint": url, "status": r.status_code}
    except Exception:
        return {"endpoint": url, "status": 0}


async def k8s_audit(api_base: str, verify_cert: bool = True) -> Dict:
    """Probe common unauthenticated K8s API/kubelet endpoints (safe GETs)."""
    paths = [
        "/version",
        "/healthz",
        "/metrics",
        "/api/v1/namespaces/kube-system/pods",
    ]
    async with httpx.AsyncClient(timeout=6.0, verify=verify_cert) as client:
        results = await asyncio.gather(*(_probe(client, api_base, p) for p in paths))
    findings = []
    for r in results:
        if r["status"] == 200 and r["endpoint"].endswith("/metrics"):
            findings.append({
                "type": "metrics_exposed",
                "impact": "Metrics endpoint accessible without auth",
                "remediation": "Require auth/authorization, restrict from public",
                "severity": "medium",
                "location": r["endpoint"],
            })
    return {"target": api_base, "results": results, "findings": findings}

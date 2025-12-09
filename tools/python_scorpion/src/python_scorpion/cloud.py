import asyncio
from typing import Dict, List, Optional

import httpx


async def _check_aws_bucket(name: str) -> Dict:
    urls = [
        f"https://{name}.s3.amazonaws.com/?list-type=2",
        f"https://s3.amazonaws.com/{name}?list-type=2",
    ]
    status: List[int] = []
    async with httpx.AsyncClient(timeout=6.0) as client:
        for u in urls:
            try:
                r = await client.get(u)
                status.append(r.status_code)
            except Exception:
                status.append(0)
    exposure = any(s == 200 for s in status)
    return {"provider": "aws", "name": name, "endpoints": urls, "status": status, "public_listing": exposure}


async def _check_azure_account(name: str) -> Dict:
    # List containers anonymously
    urls = [f"https://{name}.blob.core.windows.net/?comp=list"]
    status: List[int] = []
    async with httpx.AsyncClient(timeout=6.0) as client:
        for u in urls:
            try:
                r = await client.get(u)
                status.append(r.status_code)
            except Exception:
                status.append(0)
    exposure = any(s == 200 for s in status)
    return {"provider": "azure", "name": name, "endpoints": urls, "status": status, "public_listing": exposure}


async def _check_gcp_bucket(name: str) -> Dict:
    urls = [
        f"https://storage.googleapis.com/storage/v1/b/{name}/o",
        f"https://storage.googleapis.com/{name}/",
    ]
    status: List[int] = []
    async with httpx.AsyncClient(timeout=6.0) as client:
        for u in urls:
            try:
                r = await client.get(u)
                status.append(r.status_code)
            except Exception:
                status.append(0)
    exposure = any(s == 200 for s in status)
    return {"provider": "gcp", "name": name, "endpoints": urls, "status": status, "public_listing": exposure}


async def cloud_audit(name: str, providers: Optional[List[str]] = None) -> Dict:
    """Check public listing on common cloud storage endpoints for a given name.

    Non-destructive, anonymous HTTP checks only. Useful for quickly spotting
    exposed buckets/accounts derived from org/app names.
    """
    pv = set((providers or ["aws", "azure", "gcp"]))
    tasks = []
    if "aws" in pv:
        tasks.append(_check_aws_bucket(name))
    if "azure" in pv:
        tasks.append(_check_azure_account(name))
    if "gcp" in pv:
        tasks.append(_check_gcp_bucket(name))

    results = await asyncio.gather(*tasks)
    findings: List[Dict] = []
    for r in results:
        if r.get("public_listing"):
            findings.append({
                "provider": r.get("provider"),
                "name": r.get("name"),
                "impact": "Publicly listable storage",
                "remediation": "Restrict anonymous listing, enforce IAM/ACL, use block public access",
                "severity": "high",
                "endpoints": r.get("endpoints"),
                "status": r.get("status"),
            })

    return {"target": name, "results": results, "findings": findings}

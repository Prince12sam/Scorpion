import asyncio
import pathlib
from typing import Dict, List, Optional

import httpx


def _default_wordlist_path() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve().parent
    return here / "data" / "common-paths.txt"


def load_wordlist(path: Optional[str] = None, limit: Optional[int] = None) -> List[str]:
    p = pathlib.Path(path) if path else _default_wordlist_path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            items = [line.strip().lstrip("/") for line in f if line.strip() and not line.startswith("#")]
        if limit:
            return items[:limit]
        return items
    except Exception:
        # minimal fallback list
        base = [
            "robots.txt", "sitemap.xml", "admin", "login", "api", "graphql",
            ".git/HEAD", ".env", "wp-admin", "wp-login.php", "server-status",
        ]
        return base[:limit] if limit else base


async def _fetch(client: httpx.AsyncClient, url: str) -> Dict:
    try:
        r = await client.get(url, follow_redirects=False)
        return {"url": url, "status": r.status_code, "length": int(r.headers.get("content-length", len(r.content) if r.content else 0))}
    except Exception:
        return {"url": url, "status": 0, "length": 0}


async def dirbust_scan(host: str, wordlist_path: Optional[str] = None, concurrency: int = 50, https: bool = True) -> Dict:
    # Handle both full URLs and bare hostnames
    if host.startswith("http://") or host.startswith("https://"):
        base = host.rstrip("/")
    else:
        scheme = "https" if https else "http"
        base = f"{scheme}://{host}"
    
    paths = load_wordlist(wordlist_path)

    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []

    async with httpx.AsyncClient(timeout=5.0) as client:
        # baseline length for a guaranteed-miss path
        miss = await _fetch(client, f"{base}/this-path-should-not-exist-404-check")

        async def task(pth: str):
            url = f"{base}/{pth}"
            async with sem:
                r = await _fetch(client, url)
                # simple wildcard filter: if same status and near-identical length as miss, drop low-signal 404s
                if not (r["status"] == miss["status"] and abs(r["length"] - miss["length"]) < 32):
                    results.append(r)

        await asyncio.gather(*(task(p) for p in paths))

    # prioritize interesting statuses
    results.sort(key=lambda x: (0 if x["status"] in (200, 204, 301, 302, 401, 403) else 1, x["status"], x["url"]))

    summary = {
        "count": len(results),
        "by_status": {}
    }
    for r in results:
        summary["by_status"].setdefault(str(r["status"]), 0)
        summary["by_status"][str(r["status"])] += 1

    return {
        "target": host,
        "base": base,
        "results": results,
        "summary": summary,
    }

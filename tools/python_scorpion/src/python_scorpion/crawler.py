import asyncio
import re
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

import httpx


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.title: Optional[str] = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = None
            for k, v in attrs:
                if k.lower() == "href":
                    href = v
                    break
            if href:
                self.links.append(href)
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            txt = data.strip()
            if txt:
                self.title = (self.title + " " + txt) if self.title else txt


_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws(.{0,20})?(secret|access)_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{20,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Private Key", re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Generic apiKey", re.compile(r"(?i)api_?key\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}")),
]


def _normalize_url(base_host: str, href: str) -> Optional[str]:
    href = href.strip()
    if not href or href.startswith("javascript:") or href.startswith("mailto:"):
        return None
    if href.startswith("//"):
        return "https:" + href
    if href.startswith("http://") or href.startswith("https://"):
        return href
    if href.startswith("#"):
        return None
    # relative
    return f"https://{base_host}/" + href.lstrip("/")


async def _fetch(client: httpx.AsyncClient, url: str) -> Dict:
    try:
        r = await client.get(url, follow_redirects=True)
        content = r.text or ""
        headers = {k.lower(): v for k, v in r.headers.items()}
        parser = _LinkParser()
        try:
            parser.feed(content[:500_000])
        except Exception:
            pass
        findings: List[Dict] = []
        # Secrets scan
        for name, pat in _SECRET_PATTERNS:
            if pat.search(content):
                findings.append({"type": "secret", "name": name})
        # Security headers
        csp = headers.get("content-security-policy")
        xfo = headers.get("x-frame-options")
        cors = headers.get("access-control-allow-origin")
        if not csp:
            findings.append({"type": "header_missing", "name": "CSP"})
        if not xfo:
            findings.append({"type": "header_missing", "name": "X-Frame-Options"})
        if cors == "*":
            findings.append({"type": "cors_overly_permissive", "name": "Access-Control-Allow-Origin: *"})

        return {
            "url": url,
            "status": r.status_code,
            "length": int(headers.get("content-length", len(r.content) if r.content else 0)),
            "title": parser.title,
            "links": parser.links,
            "findings": findings,
        }
    except Exception:
        return {"url": url, "status": 0, "length": 0, "title": None, "links": [], "findings": []}


async def crawl(host: str, start: Optional[str] = None, max_pages: int = 30, concurrency: int = 8) -> Dict:
    base_host = host
    # Use http:// for localhost/private IPs
    is_local = any(term in host.lower() for term in ["localhost", "127.0.0.1", "::1", "0.0.0.0", "192.168.", "10."])
    protocol = "http" if is_local else "https"
    start_url = start or f"{protocol}://{host}"
    visited: Set[str] = set()
    queue: List[str] = [start_url]
    results: List[Dict] = []

    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=8.0) as client:
        async def task(url: str):
            async with sem:
                res = await _fetch(client, url)
                results.append(res)
                links = res.get("links", [])
                for href in links:
                    nu = _normalize_url(base_host, href)
                    if nu and nu not in visited and (f"://{base_host}/" in nu or nu.startswith(f"https://{base_host}") or nu.startswith(f"http://{base_host}")):
                        queue.append(nu)

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            await task(url)

    # Summarize findings
    secret_counts: Dict[str, int] = {}
    header_issues: Dict[str, int] = {}
    cors_permissive = 0
    for r in results:
        for f in r.get("findings", []):
            if f.get("type") == "secret":
                n = f.get("name")
                secret_counts[n] = secret_counts.get(n, 0) + 1
            elif f.get("type") == "header_missing":
                n = f.get("name")
                header_issues[n] = header_issues.get(n, 0) + 1
            elif f.get("type") == "cors_overly_permissive":
                cors_permissive += 1

    return {
        "target": host,
        "start": start_url,
        "pages_crawled": len(results),
        "results": results,
        "summary": {
            "secret_counts": secret_counts,
            "header_missing": header_issues,
            "cors_overly_permissive": cors_permissive,
        },
    }

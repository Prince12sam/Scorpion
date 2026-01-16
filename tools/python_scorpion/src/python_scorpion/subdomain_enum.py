"""
Subdomain Enumeration Module
Discovers subdomains through multiple techniques:
- DNS brute-forcing
- Certificate Transparency logs
- Common subdomain patterns
"""

import asyncio
import socket
from typing import Dict, List, Set, Optional
import dns.resolver
import httpx

# Common subdomain wordlist (top 100 most common)
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
    "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
    "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
    "wiki", "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns",
    "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1",
    "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
    "info", "apps", "download", "remote", "db", "forums", "store", "relay", "files",
    "newsletter", "app", "live", "owa", "en", "start", "sms", "office", "exchange",
    "ipv4"
]

async def resolve_subdomain(subdomain: str, domain: str, timeout: float = 2.0) -> Optional[Dict]:
    """
    Try to resolve a subdomain and return its IP addresses.
    
    Args:
        subdomain: Subdomain prefix (e.g., 'www')
        domain: Base domain (e.g., '<DOMAIN>')
        timeout: DNS resolution timeout
    
    Returns:
        Dict with subdomain info if found, None otherwise
    """
    fqdn = f"{subdomain}.{domain}" if subdomain else domain
    
    try:
        # Try A record
        answers = dns.resolver.resolve(fqdn, "A", lifetime=timeout)
        ips = [str(rdata) for rdata in answers]
        
        return {
            "subdomain": fqdn,
            "type": "A",
            "ips": ips,
            "status": "active"
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
        pass
    except Exception as e:
        return {
            "subdomain": fqdn,
            "type": "error",
            "error": str(e),
            "status": "error"
        }
    
    return None

async def get_cname_record(subdomain: str, domain: str) -> Optional[str]:
    """Get CNAME record for subdomain."""
    fqdn = f"{subdomain}.{domain}" if subdomain else domain
    
    try:
        answers = dns.resolver.resolve(fqdn, "CNAME", lifetime=2.0)
        for ans in answers:
            return str(ans.target).rstrip(".")
    except:
        pass
    
    return None

async def check_http_status(subdomain: str, timeout: float = 5.0) -> Optional[Dict]:
    """
    Check if subdomain responds to HTTP/HTTPS.
    
    Args:
        subdomain: Full subdomain (e.g., 'www.<DOMAIN>')
        timeout: HTTP request timeout
    
    Returns:
        Dict with HTTP info if accessible
    """
    results = {}
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        # Try HTTPS first
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain}"
            try:
                response = await client.get(url)
                results[protocol] = {
                    "status_code": response.status_code,
                    "accessible": True,
                    "title": extract_title(response.text) if response.status_code == 200 else None
                }
                break  # If one works, we're good
            except:
                results[protocol] = {"accessible": False}
    
    return results if any(r.get("accessible") for r in results.values()) else None

def extract_title(html: str) -> Optional[str]:
    """Extract title tag from HTML (simple regex)."""
    import re
    match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else None

async def bruteforce_subdomains(
    domain: str,
    wordlist: Optional[List[str]] = None,
    concurrency: int = 50,
    timeout: float = 2.0,
    check_http: bool = False
) -> List[Dict]:
    """
    Brute-force subdomain discovery using wordlist.
    
    Args:
        domain: Target domain
        wordlist: List of subdomain prefixes to try
        concurrency: Number of concurrent DNS queries
        timeout: Timeout per query
        check_http: Also check HTTP/HTTPS accessibility
    
    Returns:
        List of discovered subdomains with details
    """
    if wordlist is None:
        wordlist = DEFAULT_SUBDOMAINS
    
    sem = asyncio.Semaphore(concurrency)
    found_subdomains = []
    
    async def check_subdomain(sub: str):
        async with sem:
            result = await resolve_subdomain(sub, domain, timeout)
            if result:
                # Get CNAME if exists
                cname = await get_cname_record(sub, domain)
                if cname:
                    result["cname"] = cname
                
                # Check HTTP if requested
                if check_http:
                    http_info = await check_http_status(result["subdomain"])
                    if http_info:
                        result["http"] = http_info
                
                found_subdomains.append(result)
    
    tasks = [check_subdomain(sub) for sub in wordlist]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return sorted(found_subdomains, key=lambda x: x.get("subdomain", ""))

async def query_certificate_transparency(domain: str, timeout: float = 10.0) -> List[str]:
    """
    Query Certificate Transparency logs for subdomains.
    Uses crt.sh API.
    
    Args:
        domain: Target domain
        timeout: API request timeout
    
    Returns:
        List of unique subdomains found
    """
    subdomains = set()
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Query crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    # Split by newlines (crt.sh returns multiple names)
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        # Remove wildcards and ensure it's under our domain
                        name = name.replace("*.", "")
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
    except Exception as e:
        # Fail silently if CT logs unavailable
        pass
    
    return sorted(list(subdomains))

async def enumerate_subdomains(
    domain: str,
    wordlist: Optional[List[str]] = None,
    use_ct_logs: bool = True,
    check_http: bool = False,
    concurrency: int = 50,
    timeout: float = 2.0
) -> Dict:
    """
    Complete subdomain enumeration using multiple techniques.
    
    Args:
        domain: Target domain
        wordlist: Custom wordlist (uses default if None)
        use_ct_logs: Query Certificate Transparency logs
        check_http: Check HTTP/HTTPS accessibility
        concurrency: Concurrent DNS queries
        timeout: Timeout per operation
    
    Returns:
        Dict with discovered subdomains and statistics
    """
    all_subdomains = []
    methods_used = []
    
    # 1. Brute-force with wordlist
    methods_used.append("dns_bruteforce")
    bruteforce_results = await bruteforce_subdomains(
        domain, wordlist, concurrency, timeout, check_http
    )
    all_subdomains.extend(bruteforce_results)
    
    # 2. Certificate Transparency logs
    ct_subdomains = []
    if use_ct_logs:
        methods_used.append("certificate_transparency")
        ct_domains = await query_certificate_transparency(domain, timeout=10.0)
        
        # Verify CT log findings with DNS
        sem = asyncio.Semaphore(concurrency)
        
        async def verify_ct_subdomain(fqdn: str):
            async with sem:
                # Extract subdomain prefix
                prefix = fqdn.replace(f".{domain}", "").replace(domain, "")
                if prefix:
                    result = await resolve_subdomain(prefix, domain, timeout)
                    if result:
                        result["source"] = "certificate_transparency"
                        
                        # Check HTTP if requested
                        if check_http:
                            http_info = await check_http_status(result["subdomain"])
                            if http_info:
                                result["http"] = http_info
                        
                        ct_subdomains.append(result)
        
        tasks = [verify_ct_subdomain(fqdn) for fqdn in ct_domains]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        all_subdomains.extend(ct_subdomains)
    
    # Deduplicate by subdomain name
    seen = set()
    unique_subdomains = []
    for sub in all_subdomains:
        name = sub.get("subdomain")
        if name and name not in seen:
            seen.add(name)
            unique_subdomains.append(sub)
    
    # Statistics
    stats = {
        "total_found": len(unique_subdomains),
        "from_bruteforce": len(bruteforce_results),
        "from_ct_logs": len(ct_subdomains),
        "methods_used": methods_used,
        "wordlist_size": len(wordlist) if wordlist else len(DEFAULT_SUBDOMAINS)
    }
    
    return {
        "domain": domain,
        "subdomains": unique_subdomains,
        "statistics": stats
    }

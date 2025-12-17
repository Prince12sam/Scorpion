"""
Threat Intelligence Integration Module
Queries multiple threat feeds and provides IOC enrichment
"""
import asyncio
import httpx
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import os
import hashlib

@dataclass
class ThreatIntelResult:
    """Threat intelligence query result"""
    source: str
    indicator: str
    indicator_type: str  # ip, domain, hash, url
    threat_score: int  # 0-100
    categories: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    malware_families: List[str] = None
    c2_server: bool = False
    in_blocklist: bool = False
    references: List[str] = None
    cve_associations: List[str] = None
    
    def __post_init__(self):
        if self.malware_families is None:
            self.malware_families = []
        if self.references is None:
            self.references = []
        if self.cve_associations is None:
            self.cve_associations = []


class ThreatIntelligence:
    """Threat intelligence aggregator with multiple source support"""
    
    def __init__(self, config: Optional[Dict[str, str]] = None):
        """
        Initialize with API keys from config or environment
        
        config = {
            'virustotal_api_key': 'your_vt_key',
            'alienvault_api_key': 'your_otx_key',
            'shodan_api_key': 'your_shodan_key',
            'abuseipdb_api_key': 'your_abuseipdb_key'
        }
        """
        self.config = config or {}
        
        # Try environment variables if not in config
        self.vt_key = self.config.get('virustotal_api_key') or os.getenv('VIRUSTOTAL_API_KEY')
        self.otx_key = self.config.get('alienvault_api_key') or os.getenv('ALIENVAULT_API_KEY')
        self.shodan_key = self.config.get('shodan_api_key') or os.getenv('SHODAN_API_KEY')
        self.abuseipdb_key = self.config.get('abuseipdb_api_key') or os.getenv('ABUSEIPDB_API_KEY')
        
        self.results_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
    async def query_all_sources(self, indicator: str, indicator_type: str = "auto") -> Dict[str, ThreatIntelResult]:
        """Query all available threat intelligence sources"""
        
        # Auto-detect indicator type
        if indicator_type == "auto":
            indicator_type = self._detect_indicator_type(indicator)
        
        tasks = []
        
        if self.vt_key:
            tasks.append(self._query_virustotal(indicator, indicator_type))
        
        if self.otx_key:
            tasks.append(self._query_alienvault(indicator, indicator_type))
        
        if self.shodan_key and indicator_type == "ip":
            tasks.append(self._query_shodan(indicator))
        
        if self.abuseipdb_key and indicator_type == "ip":
            tasks.append(self._query_abuseipdb(indicator))
        
        # Always query free sources
        tasks.append(self._query_threatfox(indicator, indicator_type))
        tasks.append(self._query_urlhaus(indicator, indicator_type))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and None results
        valid_results = {}
        for result in results:
            if isinstance(result, ThreatIntelResult):
                valid_results[result.source] = result
            elif isinstance(result, Exception):
                # Log error but continue
                pass
        
        return valid_results
    
    def _detect_indicator_type(self, indicator: str) -> str:
        """Auto-detect indicator type"""
        import re
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):
            return "md5"
        elif re.match(r'^[a-fA-F0-9]{40}$', indicator):
            return "sha1"
        elif re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return "sha256"
        
        # IP pattern
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
            return "ip"
        
        # URL pattern
        elif indicator.startswith(('http://', 'https://')):
            return "url"
        
        # Assume domain
        else:
            return "domain"
    
    async def _query_virustotal(self, indicator: str, indicator_type: str) -> ThreatIntelResult:
        """Query VirusTotal API v3"""
        
        endpoint_map = {
            "ip": f"ip_addresses/{indicator}",
            "domain": f"domains/{indicator}",
            "url": f"urls/{self._encode_url_for_vt(indicator)}",
            "md5": f"files/{indicator}",
            "sha1": f"files/{indicator}",
            "sha256": f"files/{indicator}"
        }
        
        endpoint = endpoint_map.get(indicator_type)
        if not endpoint:
            raise ValueError(f"Unsupported indicator type for VT: {indicator_type}")
        
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        headers = {"x-apikey": self.vt_key}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code != 200:
                raise Exception(f"VirusTotal API error: {response.status_code}")
            
            data = response.json()
            attrs = data.get('data', {}).get('attributes', {})
            
            # Extract malicious/suspicious counts
            last_analysis = attrs.get('last_analysis_stats', {})
            malicious = last_analysis.get('malicious', 0)
            suspicious = last_analysis.get('suspicious', 0)
            total = sum(last_analysis.values())
            
            # Calculate threat score (0-100)
            threat_score = 0
            if total > 0:
                threat_score = min(100, int(((malicious * 2 + suspicious) / total) * 100))
            
            # Extract categories
            categories = []
            if malicious > 0:
                categories.append("malicious")
            if suspicious > 0:
                categories.append("suspicious")
            
            # Extract malware families
            malware_families = []
            if indicator_type in ["md5", "sha1", "sha256"]:
                popular_names = attrs.get('popular_threat_classification', {}).get('suggested_threat_label', '')
                if popular_names:
                    malware_families.append(popular_names)
            
            return ThreatIntelResult(
                source="VirusTotal",
                indicator=indicator,
                indicator_type=indicator_type,
                threat_score=threat_score,
                categories=categories,
                first_seen=attrs.get('first_submission_date'),
                last_seen=attrs.get('last_analysis_date'),
                malware_families=malware_families,
                c2_server=malicious > 5,
                in_blocklist=malicious > 0,
                references=[f"https://www.virustotal.com/gui/{indicator_type}/{indicator}"]
            )
    
    def _encode_url_for_vt(self, url: str) -> str:
        """Encode URL for VirusTotal API (base64 without padding)"""
        import base64
        encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        return encoded
    
    async def _query_alienvault(self, indicator: str, indicator_type: str) -> ThreatIntelResult:
        """Query AlienVault OTX API"""
        
        type_map = {
            "ip": "IPv4",
            "domain": "domain",
            "url": "url",
            "md5": "file",
            "sha1": "file",
            "sha256": "file"
        }
        
        otx_type = type_map.get(indicator_type, "IPv4")
        url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general"
        
        headers = {"X-OTX-API-KEY": self.otx_key}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code != 200:
                raise Exception(f"AlienVault OTX API error: {response.status_code}")
            
            data = response.json()
            
            # Calculate threat score from pulse count and validation
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            validation = data.get('validation', [])
            
            threat_score = min(100, pulse_count * 10)
            
            categories = []
            if pulse_count > 0:
                categories.append("associated_with_threats")
            
            malware_families = []
            for pulse in data.get('pulse_info', {}).get('pulses', [])[:5]:
                family = pulse.get('malware_families', [])
                malware_families.extend(family)
            
            return ThreatIntelResult(
                source="AlienVault OTX",
                indicator=indicator,
                indicator_type=indicator_type,
                threat_score=threat_score,
                categories=categories,
                malware_families=list(set(malware_families)),
                c2_server=any('c2' in str(v).lower() for v in validation),
                in_blocklist=pulse_count > 5,
                references=[f"https://otx.alienvault.com/indicator/{otx_type}/{indicator}"]
            )
    
    async def _query_shodan(self, ip: str) -> ThreatIntelResult:
        """Query Shodan API for IP information"""
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            
            if response.status_code != 200:
                raise Exception(f"Shodan API error: {response.status_code}")
            
            data = response.json()
            
            # Analyze open services
            ports = data.get('ports', [])
            vulns = data.get('vulns', [])
            tags = data.get('tags', [])
            
            # Calculate threat score
            threat_score = 0
            threat_score += min(30, len(ports) * 3)  # More ports = higher risk
            threat_score += min(50, len(vulns) * 10)  # Vulnerabilities
            threat_score += 20 if 'malware' in tags else 0
            
            categories = tags if tags else []
            
            return ThreatIntelResult(
                source="Shodan",
                indicator=ip,
                indicator_type="ip",
                threat_score=min(100, threat_score),
                categories=categories,
                malware_families=[],
                c2_server='honeypot' in tags or 'botnet' in tags,
                in_blocklist='compromised' in tags,
                cve_associations=vulns[:10],
                references=[f"https://www.shodan.io/host/{ip}"]
            )
    
    async def _query_abuseipdb(self, ip: str) -> ThreatIntelResult:
        """Query AbuseIPDB API"""
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers, params=params)
            
            if response.status_code != 200:
                raise Exception(f"AbuseIPDB API error: {response.status_code}")
            
            data = response.json().get('data', {})
            
            abuse_score = data.get('abuseConfidenceScore', 0)
            categories = []
            
            # Map category IDs to names
            category_map = {
                3: "fraud_orders", 4: "ddos", 9: "phishing", 10: "web_spam",
                14: "port_scan", 15: "hacking", 18: "brute_force", 21: "web_attack", 22: "ssh"
            }
            
            for cat_id in data.get('reports', []):
                if cat_id in category_map:
                    categories.append(category_map[cat_id])
            
            return ThreatIntelResult(
                source="AbuseIPDB",
                indicator=ip,
                indicator_type="ip",
                threat_score=abuse_score,
                categories=list(set(categories)),
                malware_families=[],
                c2_server=abuse_score > 80,
                in_blocklist=abuse_score > 50,
                references=[f"https://www.abuseipdb.com/check/{ip}"]
            )
    
    async def _query_threatfox(self, indicator: str, indicator_type: str) -> ThreatIntelResult:
        """Query ThreatFox (free source from abuse.ch)"""
        
        url = "https://threatfox-api.abuse.ch/api/v1/"
        
        # ThreatFox uses POST with JSON body
        payload = {"query": "search_ioc", "search_term": indicator}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, json=payload)
            
            if response.status_code != 200:
                raise Exception(f"ThreatFox API error: {response.status_code}")
            
            data = response.json()
            
            if data.get('query_status') != "ok":
                # Not found - return low threat score
                return ThreatIntelResult(
                    source="ThreatFox",
                    indicator=indicator,
                    indicator_type=indicator_type,
                    threat_score=0,
                    categories=[],
                    malware_families=[],
                    c2_server=False,
                    in_blocklist=False,
                    references=["https://threatfox.abuse.ch/"]
                )
            
            # Found in ThreatFox - high threat score
            iocs = data.get('data', [])
            malware_families = list(set([ioc.get('malware', '') for ioc in iocs]))
            
            return ThreatIntelResult(
                source="ThreatFox",
                indicator=indicator,
                indicator_type=indicator_type,
                threat_score=90,  # High threat if in ThreatFox
                categories=["known_malware"],
                malware_families=malware_families,
                c2_server=True,
                in_blocklist=True,
                references=["https://threatfox.abuse.ch/browse/"]
            )
    
    async def _query_urlhaus(self, indicator: str, indicator_type: str) -> ThreatIntelResult:
        """Query URLhaus (free source from abuse.ch)"""
        
        if indicator_type not in ["url", "domain"]:
            # URLhaus only for URLs/domains
            return None
        
        url = "https://urlhaus-api.abuse.ch/v1/url/"
        payload = {"url": indicator}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, data=payload)
            
            if response.status_code != 200:
                raise Exception(f"URLhaus API error: {response.status_code}")
            
            data = response.json()
            
            if data.get('query_status') != "ok":
                # Not found
                return ThreatIntelResult(
                    source="URLhaus",
                    indicator=indicator,
                    indicator_type=indicator_type,
                    threat_score=0,
                    categories=[],
                    malware_families=[],
                    c2_server=False,
                    in_blocklist=False,
                    references=["https://urlhaus.abuse.ch/"]
                )
            
            # Found in URLhaus
            threat = data.get('threat', 'unknown')
            tags = data.get('tags', [])
            
            return ThreatIntelResult(
                source="URLhaus",
                indicator=indicator,
                indicator_type=indicator_type,
                threat_score=85,
                categories=["malware_distribution"] + tags,
                malware_families=[threat] if threat else [],
                c2_server=False,
                in_blocklist=True,
                references=[f"https://urlhaus.abuse.ch/url/{data.get('id', '')}"]
            )
    
    def aggregate_results(self, results: Dict[str, ThreatIntelResult]) -> Dict[str, Any]:
        """Aggregate results from multiple sources into unified assessment"""
        
        if not results:
            return {
                "indicator": "",
                "overall_threat_score": 0,
                "confidence": "low",
                "verdict": "clean",
                "sources_queried": 0,
                "details": {}
            }
        
        # Calculate average threat score
        scores = [r.threat_score for r in results.values()]
        avg_score = sum(scores) / len(scores)
        max_score = max(scores)
        
        # Aggregate categories and malware families
        all_categories = []
        all_malware = []
        all_cves = []
        
        for result in results.values():
            all_categories.extend(result.categories)
            all_malware.extend(result.malware_families)
            all_cves.extend(result.cve_associations)
        
        # Determine verdict
        if max_score >= 70:
            verdict = "malicious"
            confidence = "high" if len(results) >= 3 else "medium"
        elif max_score >= 40:
            verdict = "suspicious"
            confidence = "medium" if len(results) >= 2 else "low"
        else:
            verdict = "clean"
            confidence = "low"
        
        # Check if C2 server
        is_c2 = any(r.c2_server for r in results.values())
        in_blocklist = any(r.in_blocklist for r in results.values())
        
        return {
            "indicator": list(results.values())[0].indicator,
            "indicator_type": list(results.values())[0].indicator_type,
            "overall_threat_score": int(avg_score),
            "max_threat_score": int(max_score),
            "confidence": confidence,
            "verdict": verdict,
            "is_c2_server": is_c2,
            "in_blocklist": in_blocklist,
            "sources_queried": len(results),
            "categories": list(set(all_categories)),
            "malware_families": list(set(all_malware)),
            "associated_cves": list(set(all_cves))[:10],
            "source_details": {source: asdict(result) for source, result in results.items()}
        }


async def check_threat_intel(indicator: str, config: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Convenience function to check threat intelligence for an indicator
    
    Args:
        indicator: IP, domain, URL, or hash to check
        config: Optional API keys configuration
    
    Returns:
        Aggregated threat intelligence report
    """
    ti = ThreatIntelligence(config)
    results = await ti.query_all_sources(indicator)
    aggregated = ti.aggregate_results(results)
    return aggregated


# CLI usage example
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python threat_intel.py <indicator>")
        print("Example: python threat_intel.py 8.8.8.8")
        sys.exit(1)
    
    indicator = sys.argv[1]
    result = asyncio.run(check_threat_intel(indicator))
    
    print(json.dumps(result, indent=2))

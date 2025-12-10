"""
Production OS fingerprinting module.
TCP/IP stack fingerprinting based on packet characteristics - NO dummy data.

Techniques:
- TCP window size analysis
- TTL (Time To Live) values
- TCP options order and values
- ICMP responses
- TCP timestamp behavior
- IP DF (Don't Fragment) flag
"""
import asyncio
import socket
from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class OSSignature:
    """OS fingerprint signature"""
    name: str
    family: str  # windows, linux, unix, network_device, etc.
    ttl_range: tuple
    window_size_range: tuple
    tcp_options: List[str]
    df_flag: bool
    confidence: int  # 0-100


class OSFingerprinter:
    """
    Production OS fingerprinting - NO dummy data.
    All detections based on real TCP/IP stack behavior.
    """
    
    def __init__(self):
        # Real OS signatures based on TCP/IP stack behavior
        self.signatures = [
            # Windows signatures
            OSSignature(
                name="Windows 10/11",
                family="windows",
                ttl_range=(128, 128),
                window_size_range=(64240, 65535),
                tcp_options=["mss", "nop", "ws", "nop", "nop", "sackperm"],
                df_flag=True,
                confidence=90
            ),
            OSSignature(
                name="Windows 7/8",
                family="windows",
                ttl_range=(128, 128),
                window_size_range=(8192, 65535),
                tcp_options=["mss", "nop", "ws", "nop", "nop", "sackperm"],
                df_flag=True,
                confidence=85
            ),
            OSSignature(
                name="Windows Server 2019/2022",
                family="windows",
                ttl_range=(128, 128),
                window_size_range=(64240, 65535),
                tcp_options=["mss", "nop", "nop", "sackperm", "nop", "ws"],
                df_flag=True,
                confidence=90
            ),
            
            # Linux signatures
            OSSignature(
                name="Linux 4.x/5.x",
                family="linux",
                ttl_range=(64, 64),
                window_size_range=(5840, 29200),
                tcp_options=["mss", "sackperm", "timestamp", "nop", "ws"],
                df_flag=True,
                confidence=90
            ),
            OSSignature(
                name="Linux 3.x",
                family="linux",
                ttl_range=(64, 64),
                window_size_range=(5840, 14600),
                tcp_options=["mss", "sackperm", "timestamp", "nop", "ws"],
                df_flag=True,
                confidence=85
            ),
            OSSignature(
                name="Ubuntu/Debian",
                family="linux",
                ttl_range=(64, 64),
                window_size_range=(29200, 29200),
                tcp_options=["mss", "sackperm", "timestamp", "nop", "ws"],
                df_flag=True,
                confidence=88
            ),
            
            # macOS signatures
            OSSignature(
                name="macOS 11+ (Big Sur/Monterey/Ventura)",
                family="macos",
                ttl_range=(64, 64),
                window_size_range=(65535, 65535),
                tcp_options=["mss", "nop", "ws", "nop", "nop", "timestamp", "sackperm", "eol"],
                df_flag=True,
                confidence=90
            ),
            OSSignature(
                name="macOS 10.x",
                family="macos",
                ttl_range=(64, 64),
                window_size_range=(65535, 65535),
                tcp_options=["mss", "nop", "ws", "nop", "nop", "timestamp"],
                df_flag=True,
                confidence=85
            ),
            
            # BSD signatures
            OSSignature(
                name="FreeBSD",
                family="bsd",
                ttl_range=(64, 64),
                window_size_range=(65535, 65535),
                tcp_options=["mss", "nop", "ws", "nop", "nop", "timestamp", "sackperm"],
                df_flag=True,
                confidence=85
            ),
            OSSignature(
                name="OpenBSD",
                family="bsd",
                ttl_range=(64, 64),
                window_size_range=(16384, 16384),
                tcp_options=["mss", "nop", "nop", "sackperm", "nop", "ws", "nop", "nop", "timestamp"],
                df_flag=True,
                confidence=90
            ),
            
            # Network devices
            OSSignature(
                name="Cisco IOS",
                family="network_device",
                ttl_range=(255, 255),
                window_size_range=(4128, 4128),
                tcp_options=["mss"],
                df_flag=False,
                confidence=85
            ),
            OSSignature(
                name="Juniper JunOS",
                family="network_device",
                ttl_range=(64, 64),
                window_size_range=(16384, 16384),
                tcp_options=["mss", "nop", "ws", "sackperm", "timestamp"],
                df_flag=True,
                confidence=85
            ),
        ]
    
    def _analyze_ttl(self, ttl: int) -> Dict:
        """
        Analyze TTL value to determine OS family.
        Common initial TTL values: 32, 64, 128, 255
        """
        # Estimate original TTL (accounting for hops)
        if ttl <= 32:
            original_ttl = 32
            hops = 32 - ttl
        elif ttl <= 64:
            original_ttl = 64
            hops = 64 - ttl
        elif ttl <= 128:
            original_ttl = 128
            hops = 128 - ttl
        elif ttl <= 255:
            original_ttl = 255
            hops = 255 - ttl
        else:
            original_ttl = ttl
            hops = 0
        
        os_hints = {
            32: ["Old Windows (Win95/98)"],
            64: ["Linux/Unix/macOS/BSD"],
            128: ["Windows"],
            255: ["Network devices (routers/switches)", "Solaris/AIX"],
        }
        
        return {
            "ttl_value": ttl,
            "original_ttl": original_ttl,
            "estimated_hops": hops,
            "os_hints": os_hints.get(original_ttl, ["Unknown"])
        }
    
    async def fingerprint_tcp_syn(self, host: str, port: int = 80) -> Optional[Dict]:
        """
        OS fingerprinting using TCP SYN response analysis.
        Requires Scapy for packet crafting.
        """
        try:
            from scapy.all import IP, TCP, sr1, conf
        except ImportError:
            return {"error": "scapy_not_installed", "message": "Install scapy: pip install scapy"}
        
        conf.verb = 0
        
        try:
            # Send SYN packet
            pkt = IP(dst=host)/TCP(dport=port, flags='S', seq=1000)
            resp = sr1(pkt, timeout=2.0)
            
            if resp is None:
                return {"error": "no_response", "message": "No response received"}
            
            if not resp.haslayer(TCP):
                return {"error": "no_tcp_layer", "message": "Response doesn't contain TCP layer"}
            
            tcp_layer = resp.getlayer(TCP)
            ip_layer = resp.getlayer(IP)
            
            # Extract fingerprint features
            ttl = ip_layer.ttl
            window_size = tcp_layer.window
            df_flag = bool(ip_layer.flags & 0x02)  # Don't Fragment flag
            
            # Extract TCP options
            tcp_options = []
            if tcp_layer.options:
                for opt in tcp_layer.options:
                    if isinstance(opt, tuple):
                        tcp_options.append(opt[0])
                    else:
                        tcp_options.append(opt)
            
            # Analyze TTL
            ttl_analysis = self._analyze_ttl(ttl)
            
            # Match against signatures
            matches = []
            for sig in self.signatures:
                score = 0
                reasons = []
                
                # TTL matching
                if sig.ttl_range[0] <= ttl_analysis["original_ttl"] <= sig.ttl_range[1]:
                    score += 30
                    reasons.append(f"TTL match ({ttl_analysis['original_ttl']})")
                
                # Window size matching
                if sig.window_size_range[0] <= window_size <= sig.window_size_range[1]:
                    score += 30
                    reasons.append(f"Window size match ({window_size})")
                
                # TCP options matching (order matters)
                if tcp_options:
                    option_matches = sum(1 for i, opt in enumerate(sig.tcp_options) 
                                       if i < len(tcp_options) and tcp_options[i] == opt)
                    option_score = (option_matches / len(sig.tcp_options)) * 30
                    score += option_score
                    if option_score > 15:
                        reasons.append(f"TCP options match ({option_matches}/{len(sig.tcp_options)})")
                
                # DF flag matching
                if df_flag == sig.df_flag:
                    score += 10
                    reasons.append("DF flag match")
                
                if score >= 50:  # Threshold for potential match
                    matches.append({
                        "os": sig.name,
                        "family": sig.family,
                        "confidence": int(score),
                        "reasons": reasons
                    })
            
            # Sort by confidence
            matches.sort(key=lambda x: x["confidence"], reverse=True)
            
            return {
                "target": host,
                "port": port,
                "fingerprint": {
                    "ttl": ttl_analysis,
                    "window_size": window_size,
                    "df_flag": df_flag,
                    "tcp_options": tcp_options,
                },
                "matches": matches[:5],  # Top 5 matches
                "best_match": matches[0] if matches else None,
            }
            
        except Exception as e:
            return {"error": "fingerprint_failed", "message": str(e)}
    
    async def fingerprint_icmp(self, host: str) -> Optional[Dict]:
        """
        OS fingerprinting using ICMP echo (ping) analysis.
        Analyzes TTL and ICMP response characteristics.
        """
        try:
            from scapy.all import IP, ICMP, sr1, conf
        except ImportError:
            return {"error": "scapy_not_installed"}
        
        conf.verb = 0
        
        try:
            # Send ICMP echo request
            pkt = IP(dst=host)/ICMP(type=8, code=0, id=12345, seq=1)
            resp = sr1(pkt, timeout=2.0)
            
            if resp is None:
                return {"error": "no_response", "message": "Host may be down or blocking ICMP"}
            
            if not resp.haslayer(ICMP):
                return {"error": "no_icmp_layer"}
            
            ip_layer = resp.getlayer(IP)
            icmp_layer = resp.getlayer(ICMP)
            
            ttl = ip_layer.ttl
            ttl_analysis = self._analyze_ttl(ttl)
            
            return {
                "target": host,
                "protocol": "icmp",
                "ttl": ttl_analysis,
                "icmp_type": icmp_layer.type,
                "icmp_code": icmp_layer.code,
                "os_hints": ttl_analysis["os_hints"],
            }
            
        except Exception as e:
            return {"error": "icmp_fingerprint_failed", "message": str(e)}
    
    async def comprehensive_fingerprint(self, host: str, open_ports: List[int]) -> Dict:
        """
        Comprehensive OS fingerprinting using multiple techniques.
        Combines TCP SYN, ICMP, and multiple port analysis.
        """
        results = {
            "target": host,
            "techniques_used": [],
            "fingerprints": [],
            "consensus": None,
        }
        
        # Try ICMP first (non-intrusive)
        icmp_result = await self.fingerprint_icmp(host)
        if icmp_result and "error" not in icmp_result:
            results["techniques_used"].append("icmp")
            results["fingerprints"].append(icmp_result)
        
        # Try TCP SYN on multiple ports for better accuracy
        tcp_results = []
        test_ports = open_ports[:3] if len(open_ports) >= 3 else open_ports  # Test up to 3 ports
        
        for port in test_ports:
            tcp_result = await self.fingerprint_tcp_syn(host, port)
            if tcp_result and "error" not in tcp_result and tcp_result.get("best_match"):
                results["techniques_used"].append(f"tcp_syn_{port}")
                tcp_results.append(tcp_result)
        
        results["fingerprints"].extend(tcp_results)
        
        # Determine consensus from multiple measurements
        if tcp_results:
            os_votes = {}
            for result in tcp_results:
                if result.get("best_match"):
                    os_name = result["best_match"]["os"]
                    os_family = result["best_match"]["family"]
                    confidence = result["best_match"]["confidence"]
                    
                    if os_name not in os_votes:
                        os_votes[os_name] = {"family": os_family, "confidence": [], "count": 0}
                    
                    os_votes[os_name]["confidence"].append(confidence)
                    os_votes[os_name]["count"] += 1
            
            # Find most common OS with highest average confidence
            if os_votes:
                best_os = max(os_votes.items(), 
                            key=lambda x: (x[1]["count"], sum(x[1]["confidence"]) / len(x[1]["confidence"])))
                
                avg_confidence = sum(best_os[1]["confidence"]) / len(best_os[1]["confidence"])
                
                results["consensus"] = {
                    "os": best_os[0],
                    "family": best_os[1]["family"],
                    "confidence": int(avg_confidence),
                    "measurements": best_os[1]["count"],
                }
        
        return results

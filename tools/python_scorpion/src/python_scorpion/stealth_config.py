"""
Stealth Level Configuration for Scorpion Security Testing Framework

Implements 4 stealth levels with precise timing, evasion, and detection probability control.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional
import random
import time


class StealthLevel(Enum):
    """Stealth levels for security testing operations"""
    LOW = "low"           # Fast, High detection (~70%), Internal testing
    MEDIUM = "medium"     # Moderate, Medium detection (~45%), General testing
    HIGH = "high"         # Slow, Low detection (~25%), External testing
    NINJA = "ninja"       # Very Slow, Very Low detection (<15%), Red team operations


@dataclass
class StealthConfig:
    """Configuration for stealth level behavior"""
    level: StealthLevel
    speed: str
    detection_probability: float  # 0.0 to 1.0
    use_case: str
    
    # Timing controls
    scan_delay_min: float  # Seconds between scans (minimum)
    scan_delay_max: float  # Seconds between scans (maximum)
    connection_timeout: int  # Connection timeout in seconds
    max_concurrent_requests: int  # Maximum parallel requests
    
    # Evasion techniques
    randomize_user_agent: bool
    randomize_source_port: bool
    fragment_packets: bool
    spoof_mac_address: bool
    use_proxies: bool
    rotate_ips: bool
    
    # Rate limiting
    requests_per_second: float
    max_bandwidth_mbps: Optional[float]
    
    # Obfuscation
    payload_encoding_layers: int  # Number of encoding layers (base64, xor, gzip)
    jitter_percentage: int  # Timing jitter (0-100%)
    
    # Anti-detection
    mimic_legitimate_traffic: bool
    avoid_signature_patterns: bool
    encrypt_communications: bool
    use_living_off_land: bool  # LOLBins only


# Predefined stealth configurations
STEALTH_CONFIGS: Dict[StealthLevel, StealthConfig] = {
    StealthLevel.LOW: StealthConfig(
        level=StealthLevel.LOW,
        speed="Fast",
        detection_probability=0.70,  # 70% chance of detection
        use_case="Internal testing, development, trusted networks",
        
        # Timing - Fast
        scan_delay_min=0.0,
        scan_delay_max=0.1,
        connection_timeout=5,
        max_concurrent_requests=100,
        
        # Evasion - Minimal
        randomize_user_agent=False,
        randomize_source_port=False,
        fragment_packets=False,
        spoof_mac_address=False,
        use_proxies=False,
        rotate_ips=False,
        
        # Rate limiting - Aggressive
        requests_per_second=50.0,
        max_bandwidth_mbps=None,  # Unlimited
        
        # Obfuscation - None
        payload_encoding_layers=0,
        jitter_percentage=0,
        
        # Anti-detection - Minimal
        mimic_legitimate_traffic=False,
        avoid_signature_patterns=False,
        encrypt_communications=False,
        use_living_off_land=False
    ),
    
    StealthLevel.MEDIUM: StealthConfig(
        level=StealthLevel.MEDIUM,
        speed="Moderate",
        detection_probability=0.45,  # 45% chance of detection
        use_case="General penetration testing, authorized assessments",
        
        # Timing - Moderate
        scan_delay_min=0.5,
        scan_delay_max=2.0,
        connection_timeout=10,
        max_concurrent_requests=25,
        
        # Evasion - Moderate
        randomize_user_agent=True,
        randomize_source_port=True,
        fragment_packets=True,
        spoof_mac_address=False,
        use_proxies=False,
        rotate_ips=False,
        
        # Rate limiting - Balanced
        requests_per_second=10.0,
        max_bandwidth_mbps=10.0,
        
        # Obfuscation - Basic
        payload_encoding_layers=1,  # Single layer (base64)
        jitter_percentage=20,
        
        # Anti-detection - Moderate
        mimic_legitimate_traffic=True,
        avoid_signature_patterns=True,
        encrypt_communications=True,
        use_living_off_land=False
    ),
    
    StealthLevel.HIGH: StealthConfig(
        level=StealthLevel.HIGH,
        speed="Slow",
        detection_probability=0.25,  # 25% chance of detection
        use_case="External testing, covert operations, high-security targets",
        
        # Timing - Slow
        scan_delay_min=3.0,
        scan_delay_max=10.0,
        connection_timeout=30,
        max_concurrent_requests=5,
        
        # Evasion - Aggressive
        randomize_user_agent=True,
        randomize_source_port=True,
        fragment_packets=True,
        spoof_mac_address=True,
        use_proxies=True,
        rotate_ips=True,
        
        # Rate limiting - Conservative
        requests_per_second=2.0,
        max_bandwidth_mbps=2.0,
        
        # Obfuscation - Multi-layer
        payload_encoding_layers=2,  # Double encoding (base64 + xor)
        jitter_percentage=40,
        
        # Anti-detection - High
        mimic_legitimate_traffic=True,
        avoid_signature_patterns=True,
        encrypt_communications=True,
        use_living_off_land=True
    ),
    
    StealthLevel.NINJA: StealthConfig(
        level=StealthLevel.NINJA,
        speed="Very Slow",
        detection_probability=0.15,  # <15% chance of detection
        use_case="Red team operations, APT simulation, maximum stealth",
        
        # Timing - Very Slow (mimics human behavior)
        scan_delay_min=10.0,
        scan_delay_max=60.0,
        connection_timeout=60,
        max_concurrent_requests=1,  # Sequential only
        
        # Evasion - Maximum
        randomize_user_agent=True,
        randomize_source_port=True,
        fragment_packets=True,
        spoof_mac_address=True,
        use_proxies=True,
        rotate_ips=True,
        
        # Rate limiting - Ultra-conservative
        requests_per_second=0.5,  # 1 request every 2 seconds
        max_bandwidth_mbps=0.5,
        
        # Obfuscation - Maximum
        payload_encoding_layers=3,  # Triple encoding (base64 + xor + gzip)
        jitter_percentage=60,
        
        # Anti-detection - Maximum
        mimic_legitimate_traffic=True,
        avoid_signature_patterns=True,
        encrypt_communications=True,
        use_living_off_land=True
    )
}


class StealthManager:
    """Manages stealth operations and timing controls"""
    
    def __init__(self, level: StealthLevel = StealthLevel.MEDIUM):
        self.config = STEALTH_CONFIGS[level]
        self.level = level
        self.request_count = 0
        self.last_request_time = 0.0
        
    def get_config(self) -> StealthConfig:
        """Get current stealth configuration"""
        return self.config
    
    def apply_delay(self) -> None:
        """Apply random delay between operations based on stealth level"""
        delay = random.uniform(
            self.config.scan_delay_min,
            self.config.scan_delay_max
        )
        
        # Add jitter (random variation)
        if self.config.jitter_percentage > 0:
            jitter = delay * (self.config.jitter_percentage / 100.0)
            jitter_offset = random.uniform(-jitter, jitter)
            delay += jitter_offset
        
        # Ensure delay is never negative
        delay = max(0.0, delay)
        
        time.sleep(delay)
    
    def rate_limit(self) -> None:
        """Apply rate limiting based on requests per second"""
        if self.config.requests_per_second <= 0:
            return
        
        min_interval = 1.0 / self.config.requests_per_second
        elapsed = time.time() - self.last_request_time
        
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def get_user_agents(self) -> List[str]:
        """Get list of legitimate user agents for mimicking"""
        return [
            # Chrome (most common)
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            
            # Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            
            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            
            # Mobile
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
        ]
    
    def get_random_user_agent(self) -> str:
        """Get random legitimate user agent"""
        if self.config.randomize_user_agent:
            return random.choice(self.get_user_agents())
        return self.get_user_agents()[0]  # Default Chrome
    
    def get_nmap_timing(self) -> str:
        """Get Nmap timing template based on stealth level"""
        timing_map = {
            StealthLevel.LOW: "T5",      # Insane speed
            StealthLevel.MEDIUM: "T3",   # Normal speed
            StealthLevel.HIGH: "T2",     # Polite
            StealthLevel.NINJA: "T1"     # Sneaky
        }
        return timing_map[self.level]
    
    def get_masscan_rate(self) -> int:
        """Get Masscan packet rate based on stealth level"""
        rate_map = {
            StealthLevel.LOW: 10000,     # 10k packets/sec
            StealthLevel.MEDIUM: 1000,   # 1k packets/sec
            StealthLevel.HIGH: 100,      # 100 packets/sec
            StealthLevel.NINJA: 10       # 10 packets/sec (ultra-slow)
        }
        return rate_map[self.level]
    
    def should_use_evasion(self, technique: str) -> bool:
        """Check if specific evasion technique should be used"""
        evasion_map = {
            "randomize_user_agent": self.config.randomize_user_agent,
            "randomize_source_port": self.config.randomize_source_port,
            "fragment_packets": self.config.fragment_packets,
            "spoof_mac_address": self.config.spoof_mac_address,
            "use_proxies": self.config.use_proxies,
            "rotate_ips": self.config.rotate_ips,
            "mimic_legitimate_traffic": self.config.mimic_legitimate_traffic,
            "avoid_signature_patterns": self.config.avoid_signature_patterns,
            "encrypt_communications": self.config.encrypt_communications,
            "use_living_off_land": self.config.use_living_off_land
        }
        return evasion_map.get(technique, False)
    
    def get_detection_probability(self) -> float:
        """Get current detection probability (0.0 to 1.0)"""
        return self.config.detection_probability
    
    def get_summary(self) -> Dict:
        """Get stealth configuration summary"""
        return {
            "level": self.level.value,
            "speed": self.config.speed,
            "detection_probability": f"{self.config.detection_probability * 100:.0f}%",
            "use_case": self.config.use_case,
            "timing": {
                "delay_range": f"{self.config.scan_delay_min}-{self.config.scan_delay_max}s",
                "max_concurrent": self.config.max_concurrent_requests,
                "requests_per_second": self.config.requests_per_second,
                "jitter": f"{self.config.jitter_percentage}%"
            },
            "evasion": {
                "user_agent_rotation": self.config.randomize_user_agent,
                "source_port_randomization": self.config.randomize_source_port,
                "packet_fragmentation": self.config.fragment_packets,
                "proxy_chains": self.config.use_proxies,
                "ip_rotation": self.config.rotate_ips
            },
            "obfuscation": {
                "encoding_layers": self.config.payload_encoding_layers,
                "encrypted_comms": self.config.encrypt_communications,
                "signature_avoidance": self.config.avoid_signature_patterns
            }
        }


# Global stealth manager instance
_stealth_manager: Optional[StealthManager] = None


def initialize_stealth(level: StealthLevel = StealthLevel.MEDIUM) -> StealthManager:
    """Initialize global stealth manager"""
    global _stealth_manager
    _stealth_manager = StealthManager(level)
    return _stealth_manager


def get_stealth_manager() -> StealthManager:
    """Get global stealth manager instance"""
    global _stealth_manager
    if _stealth_manager is None:
        _stealth_manager = StealthManager(StealthLevel.MEDIUM)
    return _stealth_manager


def set_stealth_level(level: StealthLevel) -> None:
    """Set global stealth level"""
    global _stealth_manager
    _stealth_manager = StealthManager(level)


# Convenience functions
def apply_delay() -> None:
    """Apply stealth delay"""
    get_stealth_manager().apply_delay()


def rate_limit() -> None:
    """Apply rate limiting"""
    get_stealth_manager().rate_limit()


def get_user_agent() -> str:
    """Get random user agent"""
    return get_stealth_manager().get_random_user_agent()


def get_detection_probability() -> float:
    """Get current detection probability"""
    return get_stealth_manager().get_detection_probability()

"""
Scorpion Decoy Scanner - IDS/IPS Evasion through IP Spoofing
Implements decoy scanning to obscure real source IP by mixing traffic with spoofed sources
"""

import random
import socket
import struct
import asyncio
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass
from enum import Enum
import ipaddress


class DecoyMode(Enum):
    """Decoy generation modes"""
    RANDOM = "random"          # Generate random decoy IPs
    MANUAL = "manual"          # User-provided decoy list
    SUBNET = "subnet"          # Generate decoys from target subnet
    ME = "me"                  # Position of real IP in decoy list


@dataclass
class DecoyConfig:
    """Configuration for decoy scanning"""
    enabled: bool = False
    decoy_ips: List[str] = None
    real_ip_position: Optional[int] = None  # Position of real IP (None = random)
    count: int = 5                          # Number of random decoys
    mode: DecoyMode = DecoyMode.RANDOM
    
    def __post_init__(self):
        if self.decoy_ips is None:
            self.decoy_ips = []


class DecoyScannerError(Exception):
    """Base exception for decoy scanner errors"""
    pass


class DecoyGenerator:
    """Generate decoy IP addresses for scan obfuscation"""
    
    def __init__(self):
        self.used_ips = set()
    
    def generate_random_ip(self, exclude: Optional[List[str]] = None) -> str:
        """
        Generate random IP address (avoiding reserved ranges)
        
        Args:
            exclude: List of IPs to exclude from generation
            
        Returns:
            Random IP address as string
        """
        exclude = exclude or []
        exclude_set = set(exclude)
        
        # Reserved ranges to avoid
        reserved_ranges = [
            ipaddress.ip_network("0.0.0.0/8"),       # Current network
            ipaddress.ip_network("10.0.0.0/8"),      # Private
            ipaddress.ip_network("127.0.0.0/8"),     # Loopback
            ipaddress.ip_network("169.254.0.0/16"),  # Link-local
            ipaddress.ip_network("172.16.0.0/12"),   # Private
            ipaddress.ip_network("192.168.0.0/16"),  # Private
            ipaddress.ip_network("224.0.0.0/4"),     # Multicast
            ipaddress.ip_network("240.0.0.0/4"),     # Reserved
        ]
        
        max_attempts = 1000
        for _ in range(max_attempts):
            # Generate random IP
            octets = [random.randint(1, 254) for _ in range(4)]
            ip_str = f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"
            
            # Check if IP is already used or excluded
            if ip_str in exclude_set or ip_str in self.used_ips:
                continue
                
            # Check if IP is in reserved range
            ip_obj = ipaddress.ip_address(ip_str)
            is_reserved = any(ip_obj in network for network in reserved_ranges)
            
            if not is_reserved:
                self.used_ips.add(ip_str)
                return ip_str
        
        raise DecoyScannerError("Failed to generate unique random IP after maximum attempts")
    
    def generate_subnet_ips(self, target_ip: str, count: int, exclude: Optional[List[str]] = None) -> List[str]:
        """
        Generate decoy IPs from target's subnet
        
        Args:
            target_ip: Target IP address
            count: Number of decoys to generate
            exclude: List of IPs to exclude
            
        Returns:
            List of decoy IP addresses
        """
        exclude = exclude or []
        exclude_set = set(exclude)
        decoys = []
        
        try:
            # Assume /24 subnet for simplicity
            ip_obj = ipaddress.ip_address(target_ip)
            octets = target_ip.split('.')
            subnet_base = f"{octets[0]}.{octets[1]}.{octets[2]}"
            
            available_hosts = [f"{subnet_base}.{i}" for i in range(1, 255)]
            available_hosts = [ip for ip in available_hosts if ip not in exclude_set and ip not in self.used_ips]
            
            if len(available_hosts) < count:
                raise DecoyScannerError(f"Not enough available IPs in subnet to generate {count} decoys")
            
            decoys = random.sample(available_hosts, count)
            self.used_ips.update(decoys)
            
            return decoys
            
        except Exception as e:
            raise DecoyScannerError(f"Failed to generate subnet decoys: {e}")
    
    def generate_decoy_list(self, config: DecoyConfig, target_ip: str, real_ip: str) -> List[str]:
        """
        Generate complete decoy list with real IP positioned appropriately
        
        Args:
            config: Decoy configuration
            target_ip: Target IP being scanned
            real_ip: Real source IP (attacker)
            
        Returns:
            List of IP addresses (decoys + real IP)
        """
        decoys = []
        
        # Generate decoy IPs based on mode
        if config.mode == DecoyMode.MANUAL:
            decoys = config.decoy_ips.copy()
        elif config.mode == DecoyMode.RANDOM:
            exclude = [target_ip, real_ip]
            for _ in range(config.count):
                decoys.append(self.generate_random_ip(exclude=exclude))
        elif config.mode == DecoyMode.SUBNET:
            exclude = [target_ip, real_ip]
            decoys = self.generate_subnet_ips(target_ip, config.count, exclude=exclude)
        
        # Insert real IP at specified position
        if config.real_ip_position is not None:
            position = min(config.real_ip_position, len(decoys))
            decoys.insert(position, real_ip)
        else:
            # Random position
            position = random.randint(0, len(decoys))
            decoys.insert(position, real_ip)
        
        return decoys


class DecoyScanner:
    """
    Implements decoy scanning for IDS/IPS evasion
    Sends packets from multiple source IPs to obfuscate real attacker
    """
    
    def __init__(self):
        self.generator = DecoyGenerator()
        self._raw_socket = None
    
    def _create_raw_socket(self) -> socket.socket:
        """Create raw socket for IP spoofing (requires root/admin)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            return sock
        except PermissionError:
            raise DecoyScannerError(
                "Decoy scanning requires administrator/root privileges for raw socket access"
            )
        except Exception as e:
            raise DecoyScannerError(f"Failed to create raw socket: {e}")
    
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate IP/TCP checksum"""
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        # Add carry bits
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        
        return ~checksum & 0xffff
    
    def _create_ip_header(self, source_ip: str, dest_ip: str, protocol: int, payload_length: int) -> bytes:
        """
        Create IP header with spoofed source
        
        Args:
            source_ip: Source IP (can be spoofed)
            dest_ip: Destination IP
            protocol: Protocol number (6=TCP, 17=UDP)
            payload_length: Length of payload
            
        Returns:
            IP header bytes
        """
        # IP header fields
        version_ihl = (4 << 4) | 5  # Version 4, header length 5 (20 bytes)
        tos = 0
        total_length = 20 + payload_length  # IP header + payload
        identification = random.randint(0, 65535)
        flags_fragment = 0
        ttl = 64
        checksum = 0  # Calculated later
        
        # Convert IPs to binary
        source_ip_bin = socket.inet_aton(source_ip)
        dest_ip_bin = socket.inet_aton(dest_ip)
        
        # Pack IP header (checksum = 0 for now)
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl, tos, total_length, identification,
            flags_fragment, ttl, protocol, checksum,
            source_ip_bin, dest_ip_bin
        )
        
        # Calculate checksum
        checksum = self._calculate_checksum(ip_header)
        
        # Repack with correct checksum
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl, tos, total_length, identification,
            flags_fragment, ttl, protocol, checksum,
            source_ip_bin, dest_ip_bin
        )
        
        return ip_header
    
    def _create_tcp_header(self, source_ip: str, dest_ip: str, source_port: int, 
                          dest_port: int, flags: int, seq: int = 0) -> bytes:
        """
        Create TCP header for decoy packets
        
        Args:
            source_ip: Source IP
            dest_ip: Destination IP
            source_port: Source port
            dest_port: Destination port
            flags: TCP flags
            seq: Sequence number
            
        Returns:
            TCP header bytes
        """
        # TCP header fields
        ack_seq = 0
        data_offset = 5 << 4  # 5 * 4 = 20 bytes
        window = socket.htons(5840)
        checksum = 0
        urgent_ptr = 0
        
        # Pack TCP header
        tcp_header = struct.pack(
            '!HHLLBBHHH',
            source_port, dest_port, seq, ack_seq,
            data_offset, flags, window, checksum, urgent_ptr
        )
        
        # Pseudo header for checksum calculation
        source_ip_bin = socket.inet_aton(source_ip)
        dest_ip_bin = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        pseudo_header = struct.pack(
            '!4s4sBBH',
            source_ip_bin, dest_ip_bin, placeholder, protocol, tcp_length
        )
        
        # Calculate checksum
        checksum = self._calculate_checksum(pseudo_header + tcp_header)
        
        # Repack with correct checksum
        tcp_header = struct.pack(
            '!HHLLBBHHH',
            source_port, dest_port, seq, ack_seq,
            data_offset, flags, window, checksum, urgent_ptr
        )
        
        return tcp_header
    
    async def send_decoy_packet(self, decoy_ip: str, target_ip: str, target_port: int, 
                               scan_type: str = "syn") -> bool:
        """
        Send single packet with spoofed source IP
        
        Args:
            decoy_ip: Spoofed source IP
            target_ip: Target IP
            target_port: Target port
            scan_type: Type of scan (syn, fin, xmas, null, ack)
            
        Returns:
            True if packet sent successfully
        """
        try:
            if not self._raw_socket:
                self._raw_socket = self._create_raw_socket()
            
            # Determine TCP flags based on scan type
            flag_map = {
                "syn": 0x02,      # SYN
                "fin": 0x01,      # FIN
                "xmas": 0x29,     # FIN|PSH|URG
                "null": 0x00,     # None
                "ack": 0x10,      # ACK
            }
            flags = flag_map.get(scan_type.lower(), 0x02)
            
            # Random source port
            source_port = random.randint(1024, 65535)
            
            # Random sequence number
            seq = random.randint(0, 2**32 - 1)
            
            # Create headers
            tcp_header = self._create_tcp_header(
                decoy_ip, target_ip, source_port, target_port, flags, seq
            )
            ip_header = self._create_ip_header(
                decoy_ip, target_ip, socket.IPPROTO_TCP, len(tcp_header)
            )
            
            # Combine and send
            packet = ip_header + tcp_header
            self._raw_socket.sendto(packet, (target_ip, 0))
            
            return True
            
        except Exception as e:
            # Don't raise - just log and continue with other decoys
            return False
    
    async def perform_decoy_scan(self, target_ip: str, ports: List[int], 
                                config: DecoyConfig, scan_type: str = "syn",
                                real_ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform decoy scan with multiple spoofed sources
        
        Args:
            target_ip: Target IP address
            ports: List of ports to scan
            config: Decoy configuration
            scan_type: Type of scan (syn, fin, xmas, null, ack)
            real_ip: Real source IP (if None, will be detected)
            
        Returns:
            Dictionary with scan results and decoy information
        """
        if not config.enabled:
            raise DecoyScannerError("Decoy scanning not enabled in configuration")
        
        # Get real IP if not provided
        if not real_ip:
            try:
                # Connect to Google DNS to determine local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                real_ip = s.getsockname()[0]
                s.close()
            except:
                real_ip = "127.0.0.1"
        
        # Generate decoy list
        decoy_list = self.generator.generate_decoy_list(config, target_ip, real_ip)
        
        results = {
            "target": target_ip,
            "scan_type": scan_type,
            "decoys_used": decoy_list,
            "real_ip": real_ip,
            "real_ip_position": decoy_list.index(real_ip),
            "total_packets_sent": 0,
            "success_rate": 0.0,
        }
        
        successful_packets = 0
        total_packets = 0
        
        # Send packets from each decoy to each port
        for port in ports:
            for decoy_ip in decoy_list:
                try:
                    success = await self.send_decoy_packet(decoy_ip, target_ip, port, scan_type)
                    if success:
                        successful_packets += 1
                    total_packets += 1
                    
                    # Small delay to avoid overwhelming target
                    await asyncio.sleep(0.001)
                    
                except Exception as e:
                    total_packets += 1
                    continue
        
        results["total_packets_sent"] = total_packets
        results["success_rate"] = (successful_packets / total_packets * 100) if total_packets > 0 else 0
        
        return results
    
    def close(self):
        """Close raw socket"""
        if self._raw_socket:
            self._raw_socket.close()
            self._raw_socket = None


def parse_decoy_option(decoy_str: str, target_ip: str, count: int = 5) -> DecoyConfig:
    """
    Parse decoy option string (nmap-style)
    
    Formats:
        RND:count - Generate 'count' random decoys
        ME - Only use real IP (no decoys, for comparison)
        IP1,IP2,IP3,ME - Manual decoy list with ME for real IP position
        
    Args:
        decoy_str: Decoy option string
        target_ip: Target IP (for subnet mode)
        count: Default number of random decoys
        
    Returns:
        DecoyConfig object
    """
    config = DecoyConfig(enabled=True)
    
    if decoy_str.upper().startswith("RND"):
        # Random decoys
        config.mode = DecoyMode.RANDOM
        if ":" in decoy_str:
            try:
                config.count = int(decoy_str.split(":")[1])
            except ValueError:
                config.count = count
        else:
            config.count = count
            
    elif decoy_str.upper() == "ME":
        # Only real IP
        config.mode = DecoyMode.MANUAL
        config.decoy_ips = []
        config.real_ip_position = 0
        
    else:
        # Manual decoy list
        config.mode = DecoyMode.MANUAL
        ips = [ip.strip() for ip in decoy_str.split(",")]
        
        # Check for ME position
        if "ME" in [ip.upper() for ip in ips]:
            me_index = [ip.upper() for ip in ips].index("ME")
            config.real_ip_position = me_index
            ips = [ip for ip in ips if ip.upper() != "ME"]
        
        config.decoy_ips = ips
    
    return config


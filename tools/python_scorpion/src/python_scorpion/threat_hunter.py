"""
Blue Team Threat Hunting Module
Behavioral anomaly detection, IOC scanning, and attack pattern recognition
"""
import asyncio
import json
import re
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
import hashlib


@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_type: str  # ip, domain, hash, url, file_path, registry_key
    value: str
    description: str
    severity: str  # low, medium, high, critical
    confidence: int  # 0-100
    source: str
    first_seen: str
    last_seen: str
    tags: List[str] = field(default_factory=list)


@dataclass
class ThreatSignature:
    """Known attack pattern signature"""
    signature_id: str
    name: str
    description: str
    patterns: List[str]  # Regex patterns or exact matches
    mitre_techniques: List[str]
    severity: str
    references: List[str] = field(default_factory=list)


@dataclass
class Anomaly:
    """Detected behavioral anomaly"""
    anomaly_type: str
    description: str
    severity: str
    confidence: int
    timestamp: str
    source_data: Dict[str, Any]
    indicators: List[str]
    recommended_actions: List[str]


class ThreatHunter:
    """Blue team threat hunting and detection system"""
    
    def __init__(self):
        self.ioc_database = []
        self.threat_signatures = self._initialize_threat_signatures()
        self.behavioral_baselines = {}
        self.lolbin_patterns = self._initialize_lolbin_patterns()
        
    def _initialize_threat_signatures(self) -> List[ThreatSignature]:
        """Initialize known attack patterns"""
        
        signatures = [
            ThreatSignature(
                signature_id="SIG001",
                name="PowerShell Download Cradle",
                description="PowerShell downloading and executing remote code",
                patterns=[
                    r"powershell.*IEX.*\(New-Object.*Net\.WebClient\)",
                    r"powershell.*DownloadString",
                    r"powershell.*Invoke-Expression.*Net\.WebClient",
                    r"powershell.*iwr.*iex",
                    r"powershell.*curl.*iex"
                ],
                mitre_techniques=["T1059.001", "T1105"],
                severity="high",
                references=["https://attack.mitre.org/techniques/T1059/001/"]
            ),
            
            ThreatSignature(
                signature_id="SIG002",
                name="Encoded PowerShell",
                description="Base64 encoded PowerShell commands (common evasion)",
                patterns=[
                    r"powershell.*-encodedcommand",
                    r"powershell.*-enc\s+[A-Za-z0-9+/=]{50,}",
                    r"powershell.*-e\s+[A-Za-z0-9+/=]{50,}"
                ],
                mitre_techniques=["T1027", "T1059.001"],
                severity="high"
            ),
            
            ThreatSignature(
                signature_id="SIG003",
                name="Suspicious Certutil Usage",
                description="Certutil used to download files (LOLBin)",
                patterns=[
                    r"certutil.*-urlcache.*http",
                    r"certutil.*-decode",
                    r"certutil.*-verifyctl"
                ],
                mitre_techniques=["T1105", "T1140"],
                severity="medium"
            ),
            
            ThreatSignature(
                signature_id="SIG004",
                name="Credential Dumping - Mimikatz",
                description="Mimikatz credential dumping indicators",
                patterns=[
                    r"sekurlsa::logonpasswords",
                    r"lsadump::sam",
                    r"privilege::debug",
                    r"mimikatz",
                    r"procdump.*lsass"
                ],
                mitre_techniques=["T1003.001"],
                severity="critical"
            ),
            
            ThreatSignature(
                signature_id="SIG005",
                name="SSH/RDP Brute Force",
                description="Multiple failed authentication attempts",
                patterns=[
                    r"Failed password.*ssh",
                    r"authentication failure.*ssh",
                    r"Invalid user.*ssh",
                    r"EventID 4625.*RDP"  # Windows failed logon
                ],
                mitre_techniques=["T1110", "T1021"],
                severity="high"
            ),
            
            ThreatSignature(
                signature_id="SIG006",
                name="Reverse Shell Activity",
                description="Common reverse shell patterns",
                patterns=[
                    r"bash.*-i.*>&.*\/dev\/tcp",
                    r"nc.*-e.*\/bin\/(ba)?sh",
                    r"python.*socket.*subprocess",
                    r"perl.*socket.*exec",
                    r"ruby.*TCPSocket.*exec"
                ],
                mitre_techniques=["T1071", "T1059"],
                severity="critical"
            ),
            
            ThreatSignature(
                signature_id="SIG007",
                name="Web Shell Upload",
                description="Potential web shell upload patterns",
                patterns=[
                    r"POST.*\.php.*system\(",
                    r"POST.*\.php.*shell_exec",
                    r"POST.*\.php.*passthru",
                    r"POST.*\.aspx.*System\.Diagnostics\.Process",
                    r"POST.*\.jsp.*Runtime\.getRuntime"
                ],
                mitre_techniques=["T1505.003"],
                severity="critical"
            ),
            
            ThreatSignature(
                signature_id="SIG008",
                name="Data Exfiltration",
                description="Large data transfers to external IPs",
                patterns=[
                    r"curl.*-X POST.*--data",
                    r"wget.*--post-file",
                    r"scp.*@.*:",
                    r"rsync.*@.*:"
                ],
                mitre_techniques=["T1048"],
                severity="high"
            ),
            
            ThreatSignature(
                signature_id="SIG009",
                name="Suspicious DNS Queries",
                description="DNS tunneling or C2 beaconing",
                patterns=[
                    r"DNS.*[A-Za-z0-9]{40,}\..*",  # Long subdomain (potential tunneling)
                    r"DNS.*\.(tk|ml|ga|cf|gq)$"  # Free TLDs often used for malware
                ],
                mitre_techniques=["T1071.004"],
                severity="medium"
            ),
            
            ThreatSignature(
                signature_id="SIG010",
                name="Registry Persistence",
                description="Registry modification for persistence",
                patterns=[
                    r"reg add.*\\Run",
                    r"reg add.*\\RunOnce",
                    r"reg add.*\\Startup",
                    r"New-ItemProperty.*Run"
                ],
                mitre_techniques=["T1547.001"],
                severity="medium"
            ),
            
            ThreatSignature(
                signature_id="SIG011",
                name="Scheduled Task Creation",
                description="Suspicious scheduled task creation",
                patterns=[
                    r"schtasks.*\/create.*\/ru system",
                    r"at.*\\\\.*cmd",
                    r"crontab -e",
                    r"echo.*>.*\/etc\/cron"
                ],
                mitre_techniques=["T1053"],
                severity="medium"
            ),
            
            ThreatSignature(
                signature_id="SIG012",
                name="Privilege Escalation Attempt",
                description="Common privilege escalation techniques",
                patterns=[
                    r"sudo\s+-l",
                    r"find.*-perm.*-u=s",
                    r"find.*SUID",
                    r"whoami /priv",
                    r"getsystem"
                ],
                mitre_techniques=["T1068"],
                severity="high"
            ),
        ]
        
        return signatures
    
    def _initialize_lolbin_patterns(self) -> Dict[str, List[str]]:
        """Initialize Living-off-the-Land Binaries patterns"""
        
        return {
            "windows": [
                "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
                "rundll32.exe", "wmic.exe", "wscript.exe", "cscript.exe",
                "msiexec.exe", "regasm.exe", "regsvcs.exe", "installutil.exe",
                "ieexec.exe", "msxsl.exe", "odbcconf.exe", "forfiles.exe"
            ],
            "linux": [
                "curl", "wget", "nc", "ncat", "socat", "python", "perl",
                "ruby", "php", "gcc", "ld", "as", "base64", "xxd"
            ]
        }
    
    async def hunt_iocs(self, data_source: Dict[str, Any]) -> List[IOC]:
        """
        Scan data source for known IOCs
        
        Args:
            data_source: Dict with 'type' and 'data' keys
                        type: 'network_traffic', 'file_system', 'process_list', 'logs'
                        data: Relevant data to scan
        
        Returns:
            List of detected IOCs
        """
        
        detected_iocs = []
        source_type = data_source.get('type')
        data = data_source.get('data', [])
        
        if source_type == 'network_traffic':
            detected_iocs.extend(await self._scan_network_iocs(data))
        
        elif source_type == 'file_system':
            detected_iocs.extend(await self._scan_file_iocs(data))
        
        elif source_type == 'process_list':
            detected_iocs.extend(await self._scan_process_iocs(data))
        
        elif source_type == 'logs':
            detected_iocs.extend(await self._scan_log_iocs(data))
        
        return detected_iocs
    
    async def _scan_network_iocs(self, network_data: List[Dict]) -> List[IOC]:
        """Scan network traffic for suspicious IPs/domains"""
        
        iocs = []
        
        # Suspicious IPs (private IPs connecting externally, tor exit nodes, etc.)
        for conn in network_data:
            dst_ip = conn.get('dst_ip')
            dst_port = conn.get('dst_port')
            
            # Check for connections to suspicious ports
            suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]
            if dst_port in suspicious_ports:
                iocs.append(IOC(
                    ioc_type="network_connection",
                    value=f"{dst_ip}:{dst_port}",
                    description=f"Connection to suspicious port {dst_port}",
                    severity="medium",
                    confidence=70,
                    source="network_traffic",
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    tags=["suspicious_port", "c2_indicator"]
                ))
            
            # Check for unusual traffic volume
            bytes_sent = conn.get('bytes_sent', 0)
            if bytes_sent > 10_000_000:  # >10MB
                iocs.append(IOC(
                    ioc_type="data_exfiltration",
                    value=f"{dst_ip} ({bytes_sent} bytes)",
                    description="Large data transfer detected",
                    severity="high",
                    confidence=60,
                    source="network_traffic",
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    tags=["exfiltration", "large_transfer"]
                ))
        
        return iocs
    
    async def _scan_file_iocs(self, file_data: List[Dict]) -> List[IOC]:
        """Scan file system for malicious files"""
        
        iocs = []
        
        suspicious_extensions = ['.vbs', '.js', '.hta', '.scr', '.bat', '.cmd', '.ps1']
        suspicious_paths = ['/tmp/', 'C:\\Windows\\Temp\\', 'C:\\Users\\Public\\']
        
        for file_info in file_data:
            file_path = file_info.get('path', '')
            file_hash = file_info.get('hash', '')
            
            # Check suspicious locations
            if any(path in file_path for path in suspicious_paths):
                iocs.append(IOC(
                    ioc_type="file_path",
                    value=file_path,
                    description="File in suspicious location",
                    severity="medium",
                    confidence=50,
                    source="file_system",
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    tags=["suspicious_location"]
                ))
            
            # Check suspicious extensions
            if any(file_path.endswith(ext) for ext in suspicious_extensions):
                iocs.append(IOC(
                    ioc_type="file_path",
                    value=file_path,
                    description="Script file in unusual location",
                    severity="medium",
                    confidence=60,
                    source="file_system",
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    tags=["suspicious_script"]
                ))
        
        return iocs
    
    async def _scan_process_iocs(self, process_data: List[Dict]) -> List[IOC]:
        """Scan running processes for suspicious activity"""
        
        iocs = []
        
        for proc in process_data:
            command_line = proc.get('command_line', '')
            process_name = proc.get('name', '')
            parent_process = proc.get('parent', '')
            
            # Detect LOLBin abuse
            for platform, binaries in self.lolbin_patterns.items():
                if any(binary in command_line.lower() for binary in binaries):
                    # Check context - LOLBins used suspiciously
                    if any(keyword in command_line.lower() for keyword in ['download', 'http', 'exec', 'invoke']):
                        iocs.append(IOC(
                            ioc_type="process",
                            value=command_line[:100],
                            description=f"Suspicious LOLBin usage: {process_name}",
                            severity="high",
                            confidence=80,
                            source="process_list",
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                            tags=["lolbin", "suspicious_execution"]
                        ))
            
            # Detect process injection patterns
            if parent_process in ['explorer.exe', 'winlogon.exe'] and process_name in ['powershell.exe', 'cmd.exe']:
                iocs.append(IOC(
                    ioc_type="process",
                    value=f"{parent_process} -> {process_name}",
                    description="Suspicious parent-child process relationship",
                    severity="high",
                    confidence=75,
                    source="process_list",
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    tags=["process_injection", "anomalous_parent"]
                ))
        
        return iocs
    
    async def _scan_log_iocs(self, log_data: List[str]) -> List[IOC]:
        """Scan logs for attack patterns"""
        
        iocs = []
        
        # Detect patterns using threat signatures
        for log_line in log_data:
            for signature in self.threat_signatures:
                for pattern in signature.patterns:
                    if re.search(pattern, log_line, re.IGNORECASE):
                        iocs.append(IOC(
                            ioc_type="log_pattern",
                            value=log_line[:100],
                            description=f"Matched threat signature: {signature.name}",
                            severity=signature.severity,
                            confidence=85,
                            source="logs",
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                            tags=signature.mitre_techniques + [signature.signature_id]
                        ))
                        break
        
        return iocs
    
    async def detect_behavioral_anomalies(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> List[Anomaly]:
        """
        Detect anomalies by comparing current behavior to baseline
        
        Args:
            baseline: Historical baseline behavior
            current: Current behavior to analyze
        
        Returns:
            List of detected anomalies
        """
        
        anomalies = []
        
        # Compare process counts
        if 'process_count' in baseline and 'process_count' in current:
            baseline_count = baseline['process_count']
            current_count = current['process_count']
            
            # 50% increase in processes
            if current_count > baseline_count * 1.5:
                anomalies.append(Anomaly(
                    anomaly_type="process_count",
                    description=f"Unusual process count: {current_count} (baseline: {baseline_count})",
                    severity="medium",
                    confidence=70,
                    timestamp=datetime.now().isoformat(),
                    source_data={"baseline": baseline_count, "current": current_count},
                    indicators=[f"process_count: {current_count}"],
                    recommended_actions=["Review newly created processes", "Check for crypto miners"]
                ))
        
        # Compare network connections
        if 'network_connections' in baseline and 'network_connections' in current:
            baseline_ips = set(baseline['network_connections'])
            current_ips = set(current['network_connections'])
            
            new_ips = current_ips - baseline_ips
            
            if len(new_ips) > 10:
                anomalies.append(Anomaly(
                    anomaly_type="network_behavior",
                    description=f"Unusual network activity: {len(new_ips)} new connections",
                    severity="high",
                    confidence=75,
                    timestamp=datetime.now().isoformat(),
                    source_data={"new_ips": list(new_ips)[:10]},
                    indicators=[f"new_ip: {ip}" for ip in list(new_ips)[:5]],
                    recommended_actions=["Investigate new connections", "Check for C2 communication"]
                ))
        
        # Compare user login patterns
        if 'login_times' in baseline and 'login_times' in current:
            baseline_hours = set(baseline['login_times'])
            current_login_hour = current.get('login_hour')
            
            # Login at unusual hour
            if current_login_hour and current_login_hour not in baseline_hours:
                anomalies.append(Anomaly(
                    anomaly_type="authentication",
                    description=f"Login at unusual hour: {current_login_hour}:00",
                    severity="medium",
                    confidence=60,
                    timestamp=datetime.now().isoformat(),
                    source_data={"baseline_hours": list(baseline_hours), "current_hour": current_login_hour},
                    indicators=[f"login_hour: {current_login_hour}"],
                    recommended_actions=["Verify user identity", "Check for credential compromise"]
                ))
        
        # Check for unusual file access patterns
        if 'file_access_rate' in baseline and 'file_access_rate' in current:
            baseline_rate = baseline['file_access_rate']
            current_rate = current['file_access_rate']
            
            # 3x increase in file access (potential ransomware)
            if current_rate > baseline_rate * 3:
                anomalies.append(Anomaly(
                    anomaly_type="file_system",
                    description=f"Unusual file access rate: {current_rate}/min (baseline: {baseline_rate}/min)",
                    severity="critical",
                    confidence=85,
                    timestamp=datetime.now().isoformat(),
                    source_data={"baseline_rate": baseline_rate, "current_rate": current_rate},
                    indicators=[f"file_access_rate: {current_rate}"],
                    recommended_actions=["Check for ransomware", "Isolate system immediately", "Review file modifications"]
                ))
        
        return anomalies
    
    def correlate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate multiple events to identify attack patterns
        
        Args:
            events: List of security events with timestamps
        
        Returns:
            List of correlated attack chains
        """
        
        correlations = []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''))
        
        # Look for common attack patterns
        
        # Pattern 1: Port Scan -> Exploitation -> Reverse Shell
        port_scan_idx = None
        exploit_idx = None
        
        for i, event in enumerate(sorted_events):
            event_type = event.get('type')
            
            if event_type == 'port_scan' and port_scan_idx is None:
                port_scan_idx = i
            
            elif event_type == 'exploitation_attempt' and port_scan_idx is not None:
                exploit_idx = i
            
            elif event_type == 'reverse_shell' and exploit_idx is not None:
                correlations.append({
                    "attack_chain": "Reconnaissance -> Exploitation -> Command & Control",
                    "events": [
                        sorted_events[port_scan_idx],
                        sorted_events[exploit_idx],
                        event
                    ],
                    "severity": "critical",
                    "confidence": 90,
                    "mitre_techniques": ["T1595", "T1190", "T1071"],
                    "description": "Complete attack chain detected: Port scan followed by exploitation and C2 establishment"
                })
        
        # Pattern 2: Multiple Failed Logins -> Successful Login -> Privilege Escalation
        failed_logins = []
        for i, event in enumerate(sorted_events):
            event_type = event.get('type')
            
            if event_type == 'failed_login':
                failed_logins.append(i)
            
            elif event_type == 'successful_login' and len(failed_logins) >= 5:
                # Check for privilege escalation within 10 events
                for j in range(i+1, min(i+11, len(sorted_events))):
                    if sorted_events[j].get('type') == 'privilege_escalation':
                        correlations.append({
                            "attack_chain": "Brute Force -> Initial Access -> Privilege Escalation",
                            "events": [sorted_events[failed_logins[0]], event, sorted_events[j]],
                            "severity": "critical",
                            "confidence": 85,
                            "mitre_techniques": ["T1110", "T1078", "T1068"],
                            "description": "Brute force attack succeeded, followed by privilege escalation"
                        })
                        break
        
        return correlations
    
    async def generate_threat_report(self, iocs: List[IOC], anomalies: List[Anomaly], correlations: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive threat hunting report"""
        
        # Count by severity
        ioc_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for ioc in iocs:
            ioc_severity[ioc.severity] = ioc_severity.get(ioc.severity, 0) + 1
        
        anomaly_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for anomaly in anomalies:
            anomaly_severity[anomaly.severity] = anomaly_severity.get(anomaly.severity, 0) + 1
        
        # Extract MITRE techniques
        mitre_techniques = set()
        for ioc in iocs:
            mitre_techniques.update(ioc.tags)
        
        for correlation in correlations:
            mitre_techniques.update(correlation.get('mitre_techniques', []))
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_iocs": len(iocs),
                "total_anomalies": len(anomalies),
                "total_correlations": len(correlations),
                "critical_findings": ioc_severity["critical"] + anomaly_severity["critical"]
            },
            "ioc_breakdown": ioc_severity,
            "anomaly_breakdown": anomaly_severity,
            "mitre_techniques_detected": sorted(list(mitre_techniques)),
            "top_iocs": sorted([asdict(ioc) for ioc in iocs], key=lambda x: x['confidence'], reverse=True)[:10],
            "top_anomalies": sorted([asdict(a) for a in anomalies], key=lambda x: x['confidence'], reverse=True)[:10],
            "attack_chains": correlations,
            "recommendations": self._generate_hunt_recommendations(iocs, anomalies, correlations)
        }
        
        return report
    
    def _generate_hunt_recommendations(self, iocs: List[IOC], anomalies: List[Anomaly], correlations: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        if any(ioc.severity == "critical" for ioc in iocs):
            recommendations.append("IMMEDIATE: Isolate affected systems - critical IOCs detected")
        
        if any(anomaly.anomaly_type == "file_system" and anomaly.severity == "critical" for anomaly in anomalies):
            recommendations.append("IMMEDIATE: Potential ransomware activity - initiate incident response")
        
        if len(correlations) > 0:
            recommendations.append("HIGH PRIORITY: Complete attack chains detected - investigate attacker persistence")
        
        if any("T1003" in ioc.tags for ioc in iocs):
            recommendations.append("Reset all user credentials - credential dumping detected")
        
        if any("lolbin" in ioc.tags for ioc in iocs):
            recommendations.append("Review application whitelisting - LOLBin abuse detected")
        
        recommendations.append("Enable enhanced logging for detected techniques")
        recommendations.append("Update threat intelligence feeds")
        recommendations.append("Conduct forensic investigation of flagged systems")
        
        return recommendations


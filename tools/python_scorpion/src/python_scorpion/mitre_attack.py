"""
MITRE ATT&CK Framework Integration
Maps findings to ATT&CK tactics, techniques, and provides mitigation recommendations
"""
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class Tactic(Enum):
    """MITRE ATT&CK Tactics (Enterprise Matrix)"""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class ATTACKTechnique:
    """MITRE ATT&CK Technique"""
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    detection: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    subtechniques: List[str] = field(default_factory=list)


@dataclass
class ATTACKMapping:
    """Mapping of a finding to ATT&CK framework"""
    finding: str
    severity: str
    techniques: List[ATTACKTechnique]
    kill_chain_phase: str
    recommended_mitigations: List[str]
    detection_rules: List[str]


class MITREAttackMapper:
    """Map security findings to MITRE ATT&CK framework"""
    
    def __init__(self):
        # Comprehensive technique database (subset - full matrix has 200+ techniques)
        self.technique_db = self._initialize_technique_db()
        
        # Vulnerability to technique mapping
        self.vuln_to_technique = self._initialize_vuln_mappings()
    
    def _initialize_technique_db(self) -> Dict[str, ATTACKTechnique]:
        """Initialize MITRE ATT&CK technique database"""
        
        techniques = {
            "T1595": ATTACKTechnique(
                technique_id="T1595",
                technique_name="Active Scanning",
                tactic="Reconnaissance",
                description="Adversaries may execute active reconnaissance scans to gather information",
                detection=["Monitor for suspicious port scans", "Network IDS alerts", "Firewall logs"],
                mitigations=["Network segmentation", "Intrusion prevention systems"],
                data_sources=["Network Traffic", "Firewall Logs"],
                platforms=["PRE"],
                subtechniques=["T1595.001: Scanning IP Blocks", "T1595.002: Vulnerability Scanning"]
            ),
            
            "T1190": ATTACKTechnique(
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic="Initial Access",
                description="Exploit software vulnerabilities in Internet-facing systems",
                detection=["WAF alerts", "IDS signatures", "Application logs with errors"],
                mitigations=["Update software", "WAF deployment", "Virtual patching", "Disable unnecessary services"],
                data_sources=["Application Logs", "Web Proxy", "Network Traffic"],
                platforms=["Linux", "Windows", "macOS", "Network"],
                subtechniques=[]
            ),
            
            "T1133": ATTACKTechnique(
                technique_id="T1133",
                technique_name="External Remote Services",
                tactic="Initial Access",
                description="Adversaries may leverage external-facing remote services (VPN, RDP, SSH)",
                detection=["Monitor failed authentication attempts", "VPN/RDP/SSH logs", "Unusual login times"],
                mitigations=["MFA enforcement", "Disable unused remote services", "IP whitelist"],
                data_sources=["Authentication Logs", "Network Traffic"],
                platforms=["Windows", "Linux"],
                subtechniques=[]
            ),
            
            "T1059": ATTACKTechnique(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactic="Execution",
                description="Execute commands via command-line interfaces or scripts",
                detection=["Process monitoring", "Command-line logging", "Script execution logs"],
                mitigations=["Execution prevention", "Restrict script execution", "Application control"],
                data_sources=["Process Command-Line", "Process Creation", "Script Execution"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=["T1059.001: PowerShell", "T1059.003: Windows Command Shell", "T1059.004: Unix Shell"]
            ),
            
            "T1078": ATTACKTechnique(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access",
                description="Use of valid credentials obtained through credential dumping",
                detection=["Monitor for unusual login patterns", "Failed login attempts", "Account usage"],
                mitigations=["MFA", "Password policies", "Account monitoring", "Privileged account management"],
                data_sources=["Authentication Logs", "Process Creation"],
                platforms=["Linux", "macOS", "Windows", "Cloud"],
                subtechniques=["T1078.001: Default Accounts", "T1078.002: Domain Accounts", "T1078.003: Local Accounts"]
            ),
            
            "T1110": ATTACKTechnique(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                description="Adversaries may use brute force techniques to gain access",
                detection=["Multiple failed authentication attempts", "Account lockouts", "IDS alerts"],
                mitigations=["Account lockout policies", "MFA", "Strong passwords", "Rate limiting"],
                data_sources=["Authentication Logs", "Windows Event Logs"],
                platforms=["Linux", "macOS", "Windows", "Cloud"],
                subtechniques=["T1110.001: Password Guessing", "T1110.002: Password Cracking", "T1110.003: Password Spraying"]
            ),
            
            "T1046": ATTACKTechnique(
                technique_id="T1046",
                technique_name="Network Service Discovery",
                tactic="Discovery",
                description="Adversaries may attempt to enumerate network services",
                detection=["Network scans from internal hosts", "Unusual service queries"],
                mitigations=["Network segmentation", "Disable unnecessary services"],
                data_sources=["Network Traffic", "Process Command-Line"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=[]
            ),
            
            "T1082": ATTACKTechnique(
                technique_id="T1082",
                technique_name="System Information Discovery",
                tactic="Discovery",
                description="Gather information about the system (OS version, hardware, patches)",
                detection=["Process monitoring for system commands", "Command-line logging"],
                mitigations=["Limit information disclosure", "Network segmentation"],
                data_sources=["Process Command-Line", "Process Creation"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=[]
            ),
            
            "T1071": ATTACKTechnique(
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                tactic="Command and Control",
                description="Use application layer protocols (HTTP/HTTPS/DNS) for C2",
                detection=["Network traffic analysis", "DNS query monitoring", "Proxy logs"],
                mitigations=["Network intrusion prevention", "SSL/TLS inspection", "DNS filtering"],
                data_sources=["Network Traffic", "DNS Query", "Packet Capture"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=["T1071.001: Web Protocols", "T1071.004: DNS"]
            ),
            
            "T1105": ATTACKTechnique(
                technique_id="T1105",
                technique_name="Ingress Tool Transfer",
                tactic="Command and Control",
                description="Transfer tools or files from external systems into compromised environment",
                detection=["File creation monitoring", "Network connections", "Process creation"],
                mitigations=["Network intrusion prevention", "Execution prevention"],
                data_sources=["File Creation", "Network Traffic", "Network Connection Creation"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=[]
            ),
            
            "T1505": ATTACKTechnique(
                technique_id="T1505",
                technique_name="Server Software Component",
                tactic="Persistence",
                description="Install malicious components on servers (web shells, backdoors)",
                detection=["File integrity monitoring", "Web shell detection", "Anomalous web traffic"],
                mitigations=["Code signing", "Execution prevention", "Privileged account management"],
                data_sources=["File Creation", "Network Traffic", "Application Logs"],
                platforms=["Linux", "Windows", "Network"],
                subtechniques=["T1505.003: Web Shell"]
            ),
            
            "T1068": ATTACKTechnique(
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
                tactic="Privilege Escalation",
                description="Exploit software vulnerabilities to elevate privileges",
                detection=["Process monitoring", "System call monitoring", "Unusual child processes"],
                mitigations=["Exploit protection", "Update software", "Execution prevention"],
                data_sources=["Process Creation", "Windows Error Reporting"],
                platforms=["Linux", "Windows", "macOS"],
                subtechniques=[]
            ),
            
            "T1055": ATTACKTechnique(
                technique_id="T1055",
                technique_name="Process Injection",
                tactic="Defense Evasion",
                description="Inject code into processes to evade detection",
                detection=["Process monitoring", "DLL monitoring", "API call monitoring"],
                mitigations=["Behavior prevention on endpoint", "Privileged account management"],
                data_sources=["Process Access", "Process Modification"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=["T1055.001: Dynamic-link Library Injection", "T1055.012: Process Hollowing"]
            ),
            
            "T1027": ATTACKTechnique(
                technique_id="T1027",
                technique_name="Obfuscated Files or Information",
                tactic="Defense Evasion",
                description="Make files or information difficult to discover or analyze",
                detection=["Binary file analysis", "Entropy analysis", "Sandbox analysis"],
                mitigations=["Antivirus/anti-malware", "Binary analysis tools"],
                data_sources=["File Metadata", "Process Command-Line"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=["T1027.002: Software Packing", "T1027.004: Compile After Delivery"]
            ),
            
            "T1003": ATTACKTechnique(
                technique_id="T1003",
                technique_name="OS Credential Dumping",
                tactic="Credential Access",
                description="Dump credentials from OS credential stores",
                detection=["LSASS access monitoring", "Memory read operations", "Registry access"],
                mitigations=["Credential guard", "Privileged account management", "User training"],
                data_sources=["Process Access", "Windows Registry", "Command Execution"],
                platforms=["Windows", "Linux", "macOS"],
                subtechniques=["T1003.001: LSASS Memory", "T1003.002: Security Account Manager", "T1003.003: NTDS"]
            ),
            
            "T1021": ATTACKTechnique(
                technique_id="T1021",
                technique_name="Remote Services",
                tactic="Lateral Movement",
                description="Use remote services (RDP, SSH, SMB) for lateral movement",
                detection=["Authentication logs", "Network connections", "Process creation"],
                mitigations=["MFA", "Disable unnecessary services", "Network segmentation"],
                data_sources=["Authentication Logs", "Network Traffic", "Process Creation"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=["T1021.001: RDP", "T1021.002: SMB/Windows Admin Shares", "T1021.004: SSH"]
            ),
            
            "T1560": ATTACKTechnique(
                technique_id="T1560",
                technique_name="Archive Collected Data",
                tactic="Collection",
                description="Compress and encrypt data before exfiltration",
                detection=["Archive file creation", "Compression tool usage", "File access patterns"],
                mitigations=["Audit collection activities", "Data loss prevention"],
                data_sources=["File Creation", "Process Command-Line"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=["T1560.001: Archive via Utility"]
            ),
            
            "T1048": ATTACKTechnique(
                technique_id="T1048",
                technique_name="Exfiltration Over Alternative Protocol",
                tactic="Exfiltration",
                description="Exfiltrate data using protocols other than typical command channel",
                detection=["Network traffic analysis", "DNS exfiltration detection", "ICMP monitoring"],
                mitigations=["Network intrusion prevention", "Data loss prevention"],
                data_sources=["Network Traffic", "Network Connection Creation"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=["T1048.003: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"]
            ),
            
            "T1486": ATTACKTechnique(
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                tactic="Impact",
                description="Encrypt data on target systems (ransomware)",
                detection=["File modification patterns", "Entropy changes", "Ransom notes"],
                mitigations=["Data backup", "Behavior prevention on endpoint"],
                data_sources=["File Modification", "Process Creation", "Command Execution"],
                platforms=["Linux", "macOS", "Windows"],
                subtechniques=[]
            ),
            
            "T1498": ATTACKTechnique(
                technique_id="T1498",
                technique_name="Network Denial of Service",
                tactic="Impact",
                description="Perform DoS attacks to disrupt availability",
                detection=["Network traffic baselines", "IDS alerts", "Resource monitoring"],
                mitigations=["Filter network traffic", "Rate limiting", "Redundancy"],
                data_sources=["Network Traffic", "Sensor Health"],
                platforms=["Linux", "macOS", "Windows", "Network"],
                subtechniques=["T1498.001: Direct Network Flood", "T1498.002: Reflection Amplification"]
            ),
        }
        
        return techniques
    
    def _initialize_vuln_mappings(self) -> Dict[str, List[str]]:
        """Map vulnerability types to ATT&CK techniques"""
        
        return {
            # Web vulnerabilities
            "sql_injection": ["T1190", "T1078"],
            "xss": ["T1190", "T1059"],
            "command_injection": ["T1190", "T1059"],
            "file_upload": ["T1190", "T1105", "T1505"],
            "lfi": ["T1190", "T1552"],
            "rfi": ["T1190", "T1105"],
            "ssrf": ["T1190", "T1071"],
            "xxe": ["T1190", "T1552"],
            "ssti": ["T1190", "T1059"],
            "csrf": ["T1190"],
            "idor": ["T1190"],
            "path_traversal": ["T1190", "T1552"],
            "deserialize": ["T1190", "T1059"],
            
            # Network vulnerabilities
            "open_port": ["T1046", "T1595"],
            "weak_tls": ["T1040", "T1557"],
            "expired_cert": ["T1040"],
            "anonymous_ftp": ["T1078"],
            "default_credentials": ["T1078", "T1110"],
            "weak_password": ["T1110"],
            "ssh_bruteforce": ["T1110", "T1021"],
            "rdp_exposed": ["T1021", "T1133"],
            "smb_exposed": ["T1021"],
            
            # System vulnerabilities
            "unpatched_cve": ["T1068", "T1190"],
            "kernel_exploit": ["T1068"],
            "privilege_escalation": ["T1068"],
            "suid_binary": ["T1068"],
            "writable_cron": ["T1053"],
            "sudo_misconfiguration": ["T1068"],
            
            # Cloud/Container
            "exposed_cloud_metadata": ["T1552"],
            "s3_public_bucket": ["T1530"],
            "kubernetes_api_exposed": ["T1552"],
            "docker_socket_exposed": ["T1552"],
            
            # Reconnaissance
            "subdomain_enumeration": ["T1595"],
            "dns_zone_transfer": ["T1595"],
            "service_fingerprint": ["T1046", "T1082"],
            "os_detection": ["T1082"],
            
            # Data exposure
            "sensitive_file_exposed": ["T1552"],
            "git_exposed": ["T1552"],
            "backup_file": ["T1552"],
            "directory_listing": ["T1552"],
            
            # C2 indicators
            "reverse_shell": ["T1071", "T1105"],
            "web_shell": ["T1505", "T1071"],
            "dns_tunneling": ["T1071"],
            "http_c2": ["T1071"],
        }
    
    def map_finding(self, finding_type: str, finding_details: Dict[str, Any]) -> ATTACKMapping:
        """
        Map a security finding to MITRE ATT&CK framework
        
        Args:
            finding_type: Type of finding (e.g., "sql_injection", "open_port")
            finding_details: Details about the finding (target, severity, etc.)
        
        Returns:
            ATTACKMapping with techniques, mitigations, and detections
        """
        
        # Get applicable techniques
        technique_ids = self.vuln_to_technique.get(finding_type, [])
        techniques = [self.technique_db[tid] for tid in technique_ids if tid in self.technique_db]
        
        # Determine kill chain phase
        if not techniques:
            kill_chain_phase = "Unknown"
        else:
            # Use first technique's tactic
            kill_chain_phase = techniques[0].tactic
        
        # Aggregate mitigations
        all_mitigations = []
        for tech in techniques:
            all_mitigations.extend(tech.mitigations)
        
        # Remove duplicates, keep order
        mitigations = list(dict.fromkeys(all_mitigations))
        
        # Aggregate detection rules
        all_detections = []
        for tech in techniques:
            all_detections.extend(tech.detection)
        
        detections = list(dict.fromkeys(all_detections))
        
        return ATTACKMapping(
            finding=finding_type,
            severity=finding_details.get('severity', 'unknown'),
            techniques=techniques,
            kill_chain_phase=kill_chain_phase,
            recommended_mitigations=mitigations,
            detection_rules=detections
        )
    
    def generate_attack_matrix(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate ATT&CK matrix visualization data from multiple findings
        
        Args:
            findings: List of findings with 'type' and other details
        
        Returns:
            Matrix data structure for visualization
        """
        
        # Map all findings
        mappings = []
        for finding in findings:
            finding_type = finding.get('type', 'unknown')
            mapping = self.map_finding(finding_type, finding)
            mappings.append(mapping)
        
        # Count techniques by tactic
        tactic_counts = {}
        technique_usage = {}
        
        for mapping in mappings:
            for technique in mapping.techniques:
                tactic = technique.tactic
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                
                tech_id = technique.technique_id
                if tech_id not in technique_usage:
                    technique_usage[tech_id] = {
                        "technique": technique,
                        "count": 0,
                        "findings": []
                    }
                
                technique_usage[tech_id]["count"] += 1
                technique_usage[tech_id]["findings"].append(mapping.finding)
        
        # Generate matrix
        matrix = {
            "total_findings": len(findings),
            "total_techniques": len(technique_usage),
            "tactics_covered": len(tactic_counts),
            "tactic_breakdown": tactic_counts,
            "top_techniques": sorted(
                [
                    {
                        "technique_id": tid,
                        "technique_name": data["technique"].technique_name,
                        "tactic": data["technique"].tactic,
                        "count": data["count"],
                        "findings": data["findings"]
                    }
                    for tid, data in technique_usage.items()
                ],
                key=lambda x: x["count"],
                reverse=True
            )[:10],
            "kill_chain_phases": self._generate_kill_chain(mappings)
        }
        
        return matrix
    
    def _generate_kill_chain(self, mappings: List[ATTACKMapping]) -> List[Dict[str, Any]]:
        """Generate ordered kill chain from mappings"""
        
        # Standard order
        phase_order = [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact"
        ]
        
        # Group by phase
        phases = {}
        for mapping in mappings:
            phase = mapping.kill_chain_phase
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(mapping.finding)
        
        # Order by kill chain
        ordered = []
        for phase in phase_order:
            if phase in phases:
                ordered.append({
                    "phase": phase,
                    "findings": list(set(phases[phase])),
                    "count": len(phases[phase])
                })
        
        return ordered
    
    def suggest_defenses(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Generate prioritized defense recommendations based on findings
        
        Returns:
            Dictionary with 'immediate', 'short_term', 'long_term' recommendations
        """
        
        # Map all findings
        all_mitigations = []
        critical_mitigations = []
        
        for finding in findings:
            mapping = self.map_finding(finding.get('type'), finding)
            all_mitigations.extend(mapping.recommended_mitigations)
            
            # Critical findings get priority
            if finding.get('severity') in ['critical', 'high']:
                critical_mitigations.extend(mapping.recommended_mitigations)
        
        # Count occurrences
        mitigation_counts = {}
        for mit in all_mitigations:
            mitigation_counts[mit] = mitigation_counts.get(mit, 0) + 1
        
        # Sort by frequency
        sorted_mitigations = sorted(
            mitigation_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Prioritize based on impact and ease
        immediate = []  # Quick wins
        short_term = []  # Medium effort
        long_term = []   # Strategic
        
        for mitigation, count in sorted_mitigations:
            # Categorize by keywords
            if any(keyword in mitigation.lower() for keyword in ['mfa', 'patch', 'update', 'disable']):
                if len(immediate) < 5:
                    immediate.append(f"{mitigation} (found in {count} findings)")
            elif any(keyword in mitigation.lower() for keyword in ['policy', 'monitoring', 'log']):
                if len(short_term) < 5:
                    short_term.append(f"{mitigation} (found in {count} findings)")
            else:
                if len(long_term) < 5:
                    long_term.append(f"{mitigation} (found in {count} findings)")
        
        return {
            "immediate_actions": immediate,
            "short_term_improvements": short_term,
            "long_term_strategic": long_term
        }


# CLI usage example
if __name__ == "__main__":
    import sys
    
    mapper = MITREAttackMapper()
    
    # Example findings
    findings = [
        {"type": "sql_injection", "severity": "critical", "target": "https://example.com/login"},
        {"type": "open_port", "severity": "medium", "port": 22},
        {"type": "default_credentials", "severity": "high", "service": "SSH"},
        {"type": "weak_tls", "severity": "medium", "target": "example.com"},
    ]
    
    # Generate matrix
    matrix = mapper.generate_attack_matrix(findings)
    print(json.dumps(matrix, indent=2, default=str))
    
    # Get defense recommendations
    defenses = mapper.suggest_defenses(findings)
    print("\n=== DEFENSE RECOMMENDATIONS ===")
    print(json.dumps(defenses, indent=2))

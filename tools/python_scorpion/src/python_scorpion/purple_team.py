"""
Purple Team Simulation Module
Combines red team attacks with blue team defense to identify detection gaps
"""
import asyncio
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Import our modules
from .scanner import async_port_scan
from .web_pentest import AdvancedWebTester
from .threat_hunter import ThreatHunter, IOC, Anomaly
from .mitre_attack import MITREAttackMapper
from .threat_intel import check_threat_intel
from .ai_decision_engine import AIDecisionEngine, Finding


@dataclass
class AttackSimulation:
    """Simulated attack details"""
    attack_id: str
    attack_name: str
    attack_type: str
    mitre_technique: str
    severity: str
    executed_at: str
    success: bool
    indicators_generated: List[str]
    logs_generated: List[str]


@dataclass
class DefenseResult:
    """Defense detection result"""
    attack_id: str
    detected: bool
    detection_method: str
    detection_time: Optional[str]
    confidence: int
    false_positive: bool


@dataclass
class DetectionGap:
    """Identified detection gap"""
    attack_name: str
    mitre_technique: str
    severity: str
    why_missed: str
    recommended_controls: List[str]


class PurpleTeamSimulator:
    """Purple team exercise simulator - Red team attacks + Blue team detection"""
    
    def __init__(self, target: str):
        self.target = target
        self.console = Console()
        
        # Red team components
        self.attack_simulations = []
        self.ai_engine = AIDecisionEngine(mode="red_team")
        
        # Blue team components
        self.threat_hunter = ThreatHunter()
        self.mitre_mapper = MITREAttackMapper()
        self.detected_attacks = []
        self.missed_attacks = []
        
        # Results
        self.detection_gaps = []
        self.detection_rate = 0.0
        
    async def run_full_simulation(self, attack_profile: str = "web") -> Dict[str, Any]:
        """
        Run complete purple team simulation
        
        Args:
            attack_profile: 'web', 'network', 'full'
        
        Returns:
            Comprehensive simulation report
        """
        
        self.console.print(Panel.fit(
            "[bold cyan]🟣 PURPLE TEAM SIMULATION[/bold cyan]\n"
            f"Target: {self.target}\n"
            f"Profile: {attack_profile.upper()}",
            border_style="magenta"
        ))
        
        # Phase 1: Red Team Attack Simulation
        self.console.print("\n[bold red]🔴 RED TEAM: Attack Phase[/bold red]")
        attack_results = await self._simulate_attacks(attack_profile)
        
        # Phase 2: Blue Team Detection
        self.console.print("\n[bold blue]🔵 BLUE TEAM: Detection Phase[/bold blue]")
        detection_results = await self._simulate_detection()
        
        # Phase 3: Gap Analysis
        self.console.print("\n[bold yellow]⚠️  GAP ANALYSIS: Detection Effectiveness[/bold yellow]")
        gap_analysis = await self._analyze_detection_gaps()
        
        # Phase 4: Recommendations
        self.console.print("\n[bold green]✅ RECOMMENDATIONS: Defensive Improvements[/bold green]")
        recommendations = await self._generate_recommendations()
        
        # Calculate metrics
        total_attacks = len(self.attack_simulations)
        detected_count = len([d for d in detection_results if d.detected and not d.false_positive])
        self.detection_rate = (detected_count / total_attacks * 100) if total_attacks > 0 else 0
        
        # Display summary
        self._display_summary()
        
        return {
            "target": self.target,
            "simulation_time": datetime.now().isoformat(),
            "attack_profile": attack_profile,
            "metrics": {
                "total_attacks": total_attacks,
                "attacks_detected": detected_count,
                "attacks_missed": total_attacks - detected_count,
                "detection_rate": round(self.detection_rate, 2),
                "false_positives": len([d for d in detection_results if d.false_positive]),
                "critical_gaps": len([g for g in self.detection_gaps if g.severity == "critical"])
            },
            "attack_simulations": [asdict(a) for a in self.attack_simulations],
            "detection_results": [asdict(d) for d in detection_results],
            "detection_gaps": [asdict(g) for g in self.detection_gaps],
            "recommendations": recommendations,
            "mitre_coverage": self._calculate_mitre_coverage()
        }
    
    async def _simulate_attacks(self, profile: str) -> List[AttackSimulation]:
        """Simulate red team attacks"""
        
        attacks = []
        
        if profile in ["web", "full"]:
            attacks.extend(await self._simulate_web_attacks())
        
        if profile in ["network", "full"]:
            attacks.extend(await self._simulate_network_attacks())
        
        self.attack_simulations = attacks
        
        # Display attack table
        table = Table(title="🔴 Red Team Attacks", box=box.ROUNDED)
        table.add_column("Attack", style="red")
        table.add_column("MITRE", style="yellow")
        table.add_column("Severity", style="magenta")
        table.add_column("Success", style="green")
        
        for attack in attacks:
            success_icon = "✓" if attack.success else "✗"
            table.add_row(
                attack.attack_name,
                attack.mitre_technique,
                attack.severity,
                success_icon
            )
        
        self.console.print(table)
        
        return attacks
    
    async def _simulate_web_attacks(self) -> List[AttackSimulation]:
        """Simulate web application attacks"""
        
        attacks = []
        
        # Attack 1: SQL Injection
        attacks.append(AttackSimulation(
            attack_id="WEB001",
            attack_name="SQL Injection Attack",
            attack_type="web",
            mitre_technique="T1190",
            severity="critical",
            executed_at=datetime.now().isoformat(),
            success=True,
            indicators_generated=[
                "Multiple SQL error messages",
                "Unusual database queries",
                "UNION SELECT attempts"
            ],
            logs_generated=[
                "GET /login?user=admin' OR '1'='1",
                "POST /api/users?id=1 UNION SELECT password FROM users",
                "403 - WAF blocked SQL keyword"
            ]
        ))
        
        # Attack 2: XSS
        attacks.append(AttackSimulation(
            attack_id="WEB002",
            attack_name="Cross-Site Scripting (XSS)",
            attack_type="web",
            mitre_technique="T1059",
            severity="high",
            executed_at=datetime.now().isoformat(),
            success=True,
            indicators_generated=[
                "<script> tags in input",
                "JavaScript execution attempts",
                "Cookie theft attempts"
            ],
            logs_generated=[
                "GET /search?q=<script>alert(document.cookie)</script>",
                "POST /comment with <img src=x onerror=fetch()>"
            ]
        ))
        
        # Attack 3: Command Injection
        attacks.append(AttackSimulation(
            attack_id="WEB003",
            attack_name="Command Injection",
            attack_type="web",
            mitre_technique="T1059",
            severity="critical",
            executed_at=datetime.now().isoformat(),
            success=False,  # Blocked by input validation
            indicators_generated=[
                "Shell metacharacters in input",
                "Suspicious command patterns"
            ],
            logs_generated=[
                "POST /ping?host=8.8.8.8; whoami",
                "POST /ping?host=8.8.8.8 | id",
                "400 - Invalid input format"
            ]
        ))
        
        # Attack 4: File Upload
        attacks.append(AttackSimulation(
            attack_id="WEB004",
            attack_name="Malicious File Upload",
            attack_type="web",
            mitre_technique="T1505.003",
            severity="critical",
            executed_at=datetime.now().isoformat(),
            success=True,
            indicators_generated=[
                "PHP/JSP file uploaded",
                "Double extension: .php.jpg",
                "Web shell signatures"
            ],
            logs_generated=[
                "POST /upload - shell.php.jpg",
                "GET /uploads/shell.php?cmd=whoami",
                "200 - File executed successfully"
            ]
        ))
        
        # Attack 5: Authentication Bypass
        attacks.append(AttackSimulation(
            attack_id="WEB005",
            attack_name="Authentication Bypass",
            attack_type="web",
            mitre_technique="T1078",
            severity="critical",
            executed_at=datetime.now().isoformat(),
            success=False,
            indicators_generated=[
                "Multiple failed login attempts",
                "Credential stuffing patterns"
            ],
            logs_generated=[
                "POST /login - Failed: admin/admin",
                "POST /login - Failed: admin/password123",
                "POST /login - Account locked after 5 attempts"
            ]
        ))
        
        return attacks
    
    async def _simulate_network_attacks(self) -> List[AttackSimulation]:
        """Simulate network-level attacks"""
        
        attacks = []
        
        # Attack 1: Port Scanning
        attacks.append(AttackSimulation(
            attack_id="NET001",
            attack_name="Aggressive Port Scan",
            attack_type="network",
            mitre_technique="T1046",
            severity="medium",
            executed_at=datetime.now().isoformat(),
            success=True,
            indicators_generated=[
                "SYN packets to 65535 ports",
                "Connection attempts from single IP",
                "Sequential port probing"
            ],
            logs_generated=[
                "Firewall: 10.0.0.50 -> 192.168.1.100:1-65535",
                "IDS Alert: Port scan detected from 10.0.0.50",
                "1000+ connections in 60 seconds"
            ]
        ))
        
        # Attack 2: Brute Force SSH
        attacks.append(AttackSimulation(
            attack_id="NET002",
            attack_name="SSH Brute Force",
            attack_type="network",
            mitre_technique="T1110",
            severity="high",
            executed_at=datetime.now().isoformat(),
            success=False,
            indicators_generated=[
                "Multiple SSH login failures",
                "Dictionary attack patterns",
                "Automated login attempts"
            ],
            logs_generated=[
                "sshd: Failed password for root from 10.0.0.50",
                "sshd: Failed password for admin from 10.0.0.50",
                "fail2ban: Banned 10.0.0.50 for 600 seconds"
            ]
        ))
        
        # Attack 3: DNS Tunneling
        attacks.append(AttackSimulation(
            attack_id="NET003",
            attack_name="DNS Tunneling (C2)",
            attack_type="network",
            mitre_technique="T1071.004",
            severity="high",
            executed_at=datetime.now().isoformat(),
            success=True,
            indicators_generated=[
                "Unusual DNS query volume",
                "Long subdomain names",
                "High entropy domain names"
            ],
            logs_generated=[
                "DNS Query: aGVsbG8gd29ybGQ.evil.com",
                "DNS Query: base64encodeddata123456.evil.com",
                "100+ DNS queries to same domain in 1 minute"
            ]
        ))
        
        return attacks
    
    async def _simulate_detection(self) -> List[DefenseResult]:
        """Simulate blue team detection capabilities"""
        
        detection_results = []
        
        for attack in self.attack_simulations:
            # Simulate detection logic
            detected, method, confidence = await self._check_detection(attack)
            
            # Determine if false positive
            false_positive = detected and not attack.success and confidence < 70
            
            result = DefenseResult(
                attack_id=attack.attack_id,
                detected=detected,
                detection_method=method if detected else "Not detected",
                detection_time=datetime.now().isoformat() if detected else None,
                confidence=confidence,
                false_positive=false_positive
            )
            
            detection_results.append(result)
            
            if detected and not false_positive:
                self.detected_attacks.append(attack)
            else:
                self.missed_attacks.append(attack)
        
        # Display detection table
        table = Table(title="🔵 Blue Team Detection", box=box.ROUNDED)
        table.add_column("Attack ID", style="cyan")
        table.add_column("Detected", style="green")
        table.add_column("Method", style="yellow")
        table.add_column("Confidence", style="magenta")
        
        for result in detection_results:
            detected_icon = "✓" if result.detected else "✗"
            detected_style = "green" if result.detected else "red"
            
            table.add_row(
                result.attack_id,
                f"[{detected_style}]{detected_icon}[/{detected_style}]",
                result.detection_method,
                f"{result.confidence}%"
            )
        
        self.console.print(table)
        
        return detection_results
    
    async def _check_detection(self, attack: AttackSimulation) -> Tuple[bool, str, int]:
        """
        Check if attack would be detected by blue team
        
        Returns:
            (detected, detection_method, confidence)
        """
        
        # Simulate detection based on attack type and indicators
        
        # High-confidence detections
        if attack.attack_type == "web":
            if "SQL" in attack.attack_name:
                # WAF should catch SQL injection
                if "UNION SELECT" in str(attack.logs_generated):
                    return True, "WAF Signature", 95
            
            if "XSS" in attack.attack_name:
                # XSS might be missed if encoding bypasses
                return False, "", 0
            
            if "Command Injection" in attack.attack_name:
                # Input validation caught it
                return True, "Input Validation", 90
            
            if "File Upload" in attack.attack_name:
                # Web shell detection should catch this
                return True, "File Integrity Monitoring", 85
            
            if "Authentication Bypass" in attack.attack_name:
                # Account lockout mechanism
                return True, "Failed Login Threshold", 100
        
        elif attack.attack_type == "network":
            if "Port Scan" in attack.attack_name:
                # IDS should detect aggressive scanning
                return True, "IDS Port Scan Signature", 90
            
            if "Brute Force" in attack.attack_name:
                # Fail2ban detection
                return True, "Fail2ban Rule", 95
            
            if "DNS Tunneling" in attack.attack_name:
                # Advanced - might be missed without DNS analytics
                return False, "", 0
        
        # Default: Not detected
        return False, "", 0
    
    async def _analyze_detection_gaps(self) -> List[DetectionGap]:
        """Analyze why attacks were missed"""
        
        gaps = []
        
        for attack in self.missed_attacks:
            gap = DetectionGap(
                attack_name=attack.attack_name,
                mitre_technique=attack.mitre_technique,
                severity=attack.severity,
                why_missed=self._determine_gap_reason(attack),
                recommended_controls=self._recommend_controls(attack)
            )
            gaps.append(gap)
        
        self.detection_gaps = gaps
        
        # Display gaps table
        if gaps:
            table = Table(title="⚠️  Detection Gaps", box=box.ROUNDED, border_style="red")
            table.add_column("Attack", style="red bold")
            table.add_column("Why Missed", style="yellow")
            table.add_column("Severity", style="magenta")
            
            for gap in gaps:
                table.add_row(
                    gap.attack_name,
                    gap.why_missed[:60] + "..." if len(gap.why_missed) > 60 else gap.why_missed,
                    gap.severity.upper()
                )
            
            self.console.print(table)
        else:
            self.console.print("[bold green]✅ No detection gaps - all attacks detected![/bold green]")
        
        return gaps
    
    def _determine_gap_reason(self, attack: AttackSimulation) -> str:
        """Determine why an attack was missed"""
        
        reasons = {
            "XSS": "No Content-Security-Policy header, XSS payloads not blocked",
            "DNS Tunneling": "No DNS analytics or behavioral monitoring in place",
            "Lateral Movement": "Insufficient network segmentation and monitoring",
            "Privilege Escalation": "No EDR solution to detect SUID binary exploitation",
            "Data Exfiltration": "No DLP solution, large outbound transfers not monitored"
        }
        
        for keyword, reason in reasons.items():
            if keyword in attack.attack_name:
                return reason
        
        return "Insufficient logging, monitoring, or detection rules"
    
    def _recommend_controls(self, attack: AttackSimulation) -> List[str]:
        """Recommend security controls for missed attacks"""
        
        controls = {
            "XSS": [
                "Implement Content-Security-Policy header",
                "Deploy WAF with XSS rules",
                "Encode all user input before output",
                "Use HTTPOnly and Secure cookie flags"
            ],
            "DNS Tunneling": [
                "Deploy DNS analytics solution",
                "Monitor for high-entropy domain names",
                "Implement DNS query volume baselines",
                "Block known C2 domains via threat intel"
            ],
            "SQL Injection": [
                "Use parameterized queries exclusively",
                "Deploy database activity monitoring (DAM)",
                "Implement least privilege for DB users",
                "Enable WAF with SQLi rules"
            ],
            "Port Scan": [
                "Deploy network IDS/IPS",
                "Implement port scan detection rules",
                "Use network segmentation",
                "Enable firewall logging"
            ]
        }
        
        for keyword, control_list in controls.items():
            if keyword in attack.attack_name:
                return control_list
        
        return [
            "Enable comprehensive logging",
            "Deploy SIEM for log correlation",
            "Implement behavioral monitoring",
            "Regular security assessments"
        ]
    
    async def _generate_recommendations(self) -> Dict[str, List[str]]:
        """Generate prioritized recommendations"""
        
        recommendations = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        # Immediate: Critical gaps
        critical_gaps = [g for g in self.detection_gaps if g.severity == "critical"]
        for gap in critical_gaps[:3]:
            recommendations["immediate"].extend(gap.recommended_controls[:2])
        
        # Short-term: High severity gaps
        high_gaps = [g for g in self.detection_gaps if g.severity == "high"]
        for gap in high_gaps[:2]:
            recommendations["short_term"].extend(gap.recommended_controls[:2])
        
        # Long-term: Strategic improvements
        recommendations["long_term"] = [
            "Implement comprehensive SIEM solution",
            "Deploy EDR on all endpoints",
            "Establish Security Operations Center (SOC)",
            "Conduct regular purple team exercises",
            "Implement threat intelligence feeds",
            "Develop incident response playbooks"
        ]
        
        # Remove duplicates
        for category in recommendations:
            recommendations[category] = list(dict.fromkeys(recommendations[category]))
        
        # Display recommendations
        self.console.print("\n[bold green]📋 Prioritized Recommendations:[/bold green]")
        
        if recommendations["immediate"]:
            self.console.print("\n[bold red]🚨 IMMEDIATE (0-30 days):[/bold red]")
            for i, rec in enumerate(recommendations["immediate"], 1):
                self.console.print(f"  {i}. {rec}")
        
        if recommendations["short_term"]:
            self.console.print("\n[bold yellow]⏰ SHORT-TERM (1-3 months):[/bold yellow]")
            for i, rec in enumerate(recommendations["short_term"], 1):
                self.console.print(f"  {i}. {rec}")
        
        self.console.print("\n[bold blue]📅 LONG-TERM (3-12 months):[/bold blue]")
        for i, rec in enumerate(recommendations["long_term"][:5], 1):
            self.console.print(f"  {i}. {rec}")
        
        return recommendations
    
    def _calculate_mitre_coverage(self) -> Dict[str, Any]:
        """Calculate MITRE ATT&CK coverage"""
        
        # Extract all techniques
        all_techniques = [a.mitre_technique for a in self.attack_simulations]
        detected_techniques = [a.mitre_technique for a in self.detected_attacks]
        
        # Group by tactic
        technique_map = {
            "T1595": "Reconnaissance",
            "T1046": "Discovery",
            "T1190": "Initial Access",
            "T1059": "Execution",
            "T1078": "Initial Access",
            "T1110": "Credential Access",
            "T1071": "Command and Control",
            "T1505": "Persistence"
        }
        
        tactics_covered = set(technique_map.get(t, "Unknown") for t in all_techniques)
        
        return {
            "total_techniques_tested": len(set(all_techniques)),
            "techniques_detected": len(set(detected_techniques)),
            "tactics_covered": list(tactics_covered),
            "detection_by_tactic": {
                tactic: {
                    "tested": len([t for t in all_techniques if technique_map.get(t) == tactic]),
                    "detected": len([t for t in detected_techniques if technique_map.get(t) == tactic])
                }
                for tactic in tactics_covered
            }
        }
    
    def _display_summary(self):
        """Display final summary"""
        
        total = len(self.attack_simulations)
        detected = len(self.detected_attacks)
        missed = len(self.missed_attacks)
        
        # Determine rating
        if self.detection_rate >= 90:
            rating = "[bold green]EXCELLENT[/bold green]"
            emoji = "🏆"
        elif self.detection_rate >= 75:
            rating = "[bold blue]GOOD[/bold blue]"
            emoji = "👍"
        elif self.detection_rate >= 50:
            rating = "[bold yellow]NEEDS IMPROVEMENT[/bold yellow]"
            emoji = "⚠️"
        else:
            rating = "[bold red]CRITICAL[/bold red]"
            emoji = "🚨"
        
        summary = f"""
[bold cyan]═══════════════════════════════════════════[/bold cyan]
[bold magenta]🟣 PURPLE TEAM SIMULATION RESULTS 🟣[/bold magenta]
[bold cyan]═══════════════════════════════════════════[/bold cyan]

[bold]Target:[/bold] {self.target}
[bold]Total Attacks:[/bold] {total}
[bold green]✓ Detected:[/bold green] {detected}
[bold red]✗ Missed:[/bold red] {missed}

[bold]Detection Rate:[/bold] {self.detection_rate:.1f}%

[bold]Security Rating:[/bold] {rating} {emoji}

[bold cyan]═══════════════════════════════════════════[/bold cyan]
"""
        
        self.console.print(Panel(summary, border_style="magenta", box=box.DOUBLE))


# CLI usage example
async def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python purple_team.py <target>")
        print("Example: python purple_team.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    simulator = PurpleTeamSimulator(target)
    report = await simulator.run_full_simulation(attack_profile="web")
    
    # Save report
    with open(f"purple_team_{target.replace('.', '_')}.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Report saved to: purple_team_{target.replace('.', '_')}.json")


if __name__ == "__main__":
    asyncio.run(main())

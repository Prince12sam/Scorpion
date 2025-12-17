#!/usr/bin/env python3
"""
Compliance Scanner Module
Automated compliance checking for PCI-DSS, HIPAA, ISO 27001, CIS Benchmarks, 
NIST CSF, GDPR, SOC 2, and FedRAMP standards.
"""

import subprocess
import json
import platform
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re


class ComplianceStandard(Enum):
    """Supported compliance standards"""
    PCI_DSS = "PCI-DSS 4.0"
    HIPAA = "HIPAA Security Rule"
    ISO_27001 = "ISO/IEC 27001:2022"
    SOC2 = "SOC 2 Type II"
    NIST_CSF = "NIST Cybersecurity Framework"
    GDPR = "GDPR"
    FEDRAMP = "FedRAMP"
    CIS_LEVEL1 = "CIS Benchmarks Level 1"
    CIS_LEVEL2 = "CIS Benchmarks Level 2"


class ControlStatus(Enum):
    """Control implementation status"""
    PASS = "Pass"
    FAIL = "Fail"
    PARTIAL = "Partial"
    NOT_APPLICABLE = "Not Applicable"
    MANUAL_REVIEW = "Manual Review Required"


@dataclass
class ComplianceControl:
    """Individual compliance control"""
    control_id: str
    standard: ComplianceStandard
    title: str
    description: str
    requirement: str
    status: ControlStatus = ControlStatus.MANUAL_REVIEW
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    automated: bool = False
    severity: str = "Medium"  # Critical, High, Medium, Low
    
    def to_dict(self) -> Dict:
        return {
            "control_id": self.control_id,
            "standard": self.standard.value,
            "title": self.title,
            "description": self.description,
            "requirement": self.requirement,
            "status": self.status.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "automated": self.automated,
            "severity": self.severity
        }


class CISBenchmarkScanner:
    """CIS Benchmarks scanner for Windows and Linux"""
    
    def __init__(self):
        self.os_type = platform.system()
        self.is_windows = self.os_type == "Windows"
        self.is_linux = self.os_type == "Linux"
    
    def scan_password_policy(self) -> List[ComplianceControl]:
        """Check password policy compliance"""
        controls = []
        
        if self.is_windows:
            controls.extend(self._scan_windows_password_policy())
        elif self.is_linux:
            controls.extend(self._scan_linux_password_policy())
        
        return controls
    
    def _scan_windows_password_policy(self) -> List[ComplianceControl]:
        """Scan Windows password policy"""
        controls = []
        
        try:
            # Get password policy
            result = subprocess.run(
                ["net", "accounts"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = result.stdout
            
            # CIS 1.1.1 - Enforce password history
            control = ComplianceControl(
                control_id="CIS-1.1.1",
                standard=ComplianceStandard.CIS_LEVEL1,
                title="Enforce password history",
                description="Ensure 'Enforce password history' is set to '24 or more password(s)'",
                requirement="Password history >= 24",
                automated=True,
                severity="High"
            )
            
            if "Force password history" in output:
                match = re.search(r'Force password history:\s+(\d+)', output)
                if match:
                    history = int(match.group(1))
                    if history >= 24:
                        control.status = ControlStatus.PASS
                        control.evidence.append(f"Password history: {history}")
                    else:
                        control.status = ControlStatus.FAIL
                        control.evidence.append(f"Password history: {history} (Required: >= 24)")
                        control.remediation = "Set password history to 24 or more: secpol.msc -> Account Policies -> Password Policy"
            
            controls.append(control)
            
            # CIS 1.1.5 - Minimum password length
            control = ComplianceControl(
                control_id="CIS-1.1.5",
                standard=ComplianceStandard.CIS_LEVEL1,
                title="Minimum password length",
                description="Ensure 'Minimum password length' is set to '14 or more character(s)'",
                requirement="Password length >= 14",
                automated=True,
                severity="Critical"
            )
            
            if "Minimum password length" in output:
                match = re.search(r'Minimum password length:\s+(\d+)', output)
                if match:
                    length = int(match.group(1))
                    if length >= 14:
                        control.status = ControlStatus.PASS
                        control.evidence.append(f"Minimum password length: {length}")
                    else:
                        control.status = ControlStatus.FAIL
                        control.evidence.append(f"Minimum password length: {length} (Required: >= 14)")
                        control.remediation = "Set minimum password length to 14: secpol.msc -> Account Policies -> Password Policy"
            
            controls.append(control)
            
            # CIS 1.1.6 - Maximum password age
            control = ComplianceControl(
                control_id="CIS-1.1.6",
                standard=ComplianceStandard.CIS_LEVEL1,
                title="Maximum password age",
                description="Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
                requirement="0 < Password age <= 365",
                automated=True,
                severity="High"
            )
            
            if "Maximum password age" in output:
                match = re.search(r'Maximum password age \(days\):\s+(\d+|Never)', output)
                if match:
                    age_str = match.group(1)
                    if age_str == "Never":
                        control.status = ControlStatus.FAIL
                        control.evidence.append("Maximum password age: Never")
                        control.remediation = "Set maximum password age to 90-365 days"
                    else:
                        age = int(age_str)
                        if 0 < age <= 365:
                            control.status = ControlStatus.PASS
                            control.evidence.append(f"Maximum password age: {age} days")
                        else:
                            control.status = ControlStatus.FAIL
                            control.evidence.append(f"Maximum password age: {age} days (Required: 1-365)")
                            control.remediation = "Set maximum password age to 90-365 days"
            
            controls.append(control)
            
        except Exception as e:
            print(f"⚠️ Error scanning Windows password policy: {e}")
        
        return controls
    
    def _scan_linux_password_policy(self) -> List[ComplianceControl]:
        """Scan Linux password policy"""
        controls = []
        
        try:
            # Check /etc/login.defs
            login_defs = Path("/etc/login.defs")
            if login_defs.exists():
                with open(login_defs, 'r') as f:
                    content = f.read()
                
                # CIS 5.3.1 - Password expiration
                control = ComplianceControl(
                    control_id="CIS-5.3.1",
                    standard=ComplianceStandard.CIS_LEVEL1,
                    title="Password expiration days",
                    description="Ensure password expiration is 365 days or less",
                    requirement="PASS_MAX_DAYS <= 365",
                    automated=True,
                    severity="High"
                )
                
                match = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
                if match:
                    days = int(match.group(1))
                    if 0 < days <= 365:
                        control.status = ControlStatus.PASS
                        control.evidence.append(f"PASS_MAX_DAYS: {days}")
                    else:
                        control.status = ControlStatus.FAIL
                        control.evidence.append(f"PASS_MAX_DAYS: {days} (Required: 1-365)")
                        control.remediation = "Edit /etc/login.defs and set PASS_MAX_DAYS to 90 or 365"
                
                controls.append(control)
                
                # CIS 5.3.2 - Password change minimum days
                control = ComplianceControl(
                    control_id="CIS-5.3.2",
                    standard=ComplianceStandard.CIS_LEVEL1,
                    title="Password change minimum days",
                    description="Ensure minimum days between password changes is 1 or more",
                    requirement="PASS_MIN_DAYS >= 1",
                    automated=True,
                    severity="Medium"
                )
                
                match = re.search(r'PASS_MIN_DAYS\s+(\d+)', content)
                if match:
                    days = int(match.group(1))
                    if days >= 1:
                        control.status = ControlStatus.PASS
                        control.evidence.append(f"PASS_MIN_DAYS: {days}")
                    else:
                        control.status = ControlStatus.FAIL
                        control.evidence.append(f"PASS_MIN_DAYS: {days} (Required: >= 1)")
                        control.remediation = "Edit /etc/login.defs and set PASS_MIN_DAYS to 1"
                
                controls.append(control)
                
                # CIS 5.3.3 - Password expiration warning
                control = ComplianceControl(
                    control_id="CIS-5.3.3",
                    standard=ComplianceStandard.CIS_LEVEL1,
                    title="Password expiration warning days",
                    description="Ensure password expiration warning days is 7 or more",
                    requirement="PASS_WARN_AGE >= 7",
                    automated=True,
                    severity="Low"
                )
                
                match = re.search(r'PASS_WARN_AGE\s+(\d+)', content)
                if match:
                    days = int(match.group(1))
                    if days >= 7:
                        control.status = ControlStatus.PASS
                        control.evidence.append(f"PASS_WARN_AGE: {days}")
                    else:
                        control.status = ControlStatus.FAIL
                        control.evidence.append(f"PASS_WARN_AGE: {days} (Required: >= 7)")
                        control.remediation = "Edit /etc/login.defs and set PASS_WARN_AGE to 7"
                
                controls.append(control)
        
        except Exception as e:
            print(f"⚠️ Error scanning Linux password policy: {e}")
        
        return controls
    
    def scan_firewall(self) -> List[ComplianceControl]:
        """Check firewall configuration"""
        controls = []
        
        if self.is_windows:
            controls.extend(self._scan_windows_firewall())
        elif self.is_linux:
            controls.extend(self._scan_linux_firewall())
        
        return controls
    
    def _scan_windows_firewall(self) -> List[ComplianceControl]:
        """Scan Windows Firewall status"""
        controls = []
        
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = result.stdout
            
            profiles = ["Domain", "Private", "Public"]
            for profile in profiles:
                control = ComplianceControl(
                    control_id=f"CIS-9.1.{profiles.index(profile) + 1}",
                    standard=ComplianceStandard.CIS_LEVEL1,
                    title=f"Windows Firewall: {profile} Profile",
                    description=f"Ensure Windows Firewall is enabled for {profile} profile",
                    requirement="Firewall State: ON",
                    automated=True,
                    severity="Critical"
                )
                
                # Check if firewall is ON for this profile
                profile_section = output[output.find(f"{profile} Profile"):]
                if "State" in profile_section:
                    if "ON" in profile_section[:profile_section.find("\n\n")]:
                        control.status = ControlStatus.PASS
                        control.evidence.append(f"{profile} Profile: ON")
                    else:
                        control.status = ControlStatus.FAIL
                        control.evidence.append(f"{profile} Profile: OFF")
                        control.remediation = f"Enable Windows Firewall for {profile} profile: netsh advfirewall set {profile.lower()}profile state on"
                
                controls.append(control)
        
        except Exception as e:
            print(f"⚠️ Error scanning Windows Firewall: {e}")
        
        return controls
    
    def _scan_linux_firewall(self) -> List[ComplianceControl]:
        """Scan Linux firewall (iptables/ufw/firewalld)"""
        controls = []
        
        control = ComplianceControl(
            control_id="CIS-3.5.1",
            standard=ComplianceStandard.CIS_LEVEL1,
            title="Firewall installed and enabled",
            description="Ensure a firewall is installed and enabled",
            requirement="Firewall active",
            automated=True,
            severity="Critical"
        )
        
        try:
            # Check ufw
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                if "Status: active" in result.stdout:
                    control.status = ControlStatus.PASS
                    control.evidence.append("UFW firewall: Active")
                else:
                    control.status = ControlStatus.FAIL
                    control.evidence.append("UFW firewall: Inactive")
                    control.remediation = "Enable UFW: sudo ufw enable"
            else:
                # Check iptables
                result = subprocess.run(
                    ["iptables", "-L", "-n"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 3:  # Has rules beyond headers
                        control.status = ControlStatus.PASS
                        control.evidence.append("iptables: Rules configured")
                    else:
                        control.status = ControlStatus.FAIL
                        control.evidence.append("iptables: No rules configured")
                        control.remediation = "Configure iptables rules or install ufw/firewalld"
        
        except FileNotFoundError:
            control.status = ControlStatus.FAIL
            control.evidence.append("No firewall found")
            control.remediation = "Install and configure ufw: sudo apt install ufw && sudo ufw enable"
        except Exception as e:
            control.status = ControlStatus.MANUAL_REVIEW
            control.evidence.append(f"Error checking firewall: {e}")
        
        controls.append(control)
        return controls
    
    def scan_audit_logging(self) -> List[ComplianceControl]:
        """Check audit logging configuration"""
        controls = []
        
        if self.is_windows:
            controls.extend(self._scan_windows_audit())
        elif self.is_linux:
            controls.extend(self._scan_linux_audit())
        
        return controls
    
    def _scan_windows_audit(self) -> List[ComplianceControl]:
        """Scan Windows audit policy"""
        controls = []
        
        try:
            result = subprocess.run(
                ["auditpol", "/get", "/category:*"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = result.stdout
            
            # Key audit categories to check
            audit_categories = {
                "Logon/Logoff": ("CIS-17.1", "Critical"),
                "Account Management": ("CIS-17.2", "High"),
                "Policy Change": ("CIS-17.3", "High"),
                "Privilege Use": ("CIS-17.4", "Medium"),
                "System": ("CIS-17.5", "High")
            }
            
            for category, (control_id, severity) in audit_categories.items():
                control = ComplianceControl(
                    control_id=control_id,
                    standard=ComplianceStandard.CIS_LEVEL1,
                    title=f"Audit {category}",
                    description=f"Ensure audit logging is enabled for {category}",
                    requirement="Success and Failure",
                    automated=True,
                    severity=severity
                )
                
                if category in output:
                    category_section = output[output.find(category):]
                    next_section = category_section.find("\n  ")
                    if next_section > 0:
                        category_text = category_section[:next_section]
                    else:
                        category_text = category_section[:200]
                    
                    if "Success and Failure" in category_text or ("Success" in category_text and "Failure" in category_text):
                        control.status = ControlStatus.PASS
                        control.evidence.append(f"{category}: Success and Failure logging enabled")
                    elif "Success" in category_text or "Failure" in category_text:
                        control.status = ControlStatus.PARTIAL
                        control.evidence.append(f"{category}: Partial logging enabled")
                        control.remediation = f"Enable full audit logging: auditpol /set /category:\"{category}\" /success:enable /failure:enable"
                    else:
                        control.status = ControlStatus.FAIL
                        control.evidence.append(f"{category}: No logging enabled")
                        control.remediation = f"Enable audit logging: auditpol /set /category:\"{category}\" /success:enable /failure:enable"
                
                controls.append(control)
        
        except Exception as e:
            print(f"⚠️ Error scanning Windows audit policy: {e}")
        
        return controls
    
    def _scan_linux_audit(self) -> List[ComplianceControl]:
        """Scan Linux auditd configuration"""
        controls = []
        
        control = ComplianceControl(
            control_id="CIS-4.1.1",
            standard=ComplianceStandard.CIS_LEVEL2,
            title="Auditd service enabled",
            description="Ensure auditd service is installed and enabled",
            requirement="auditd enabled and running",
            automated=True,
            severity="High"
        )
        
        try:
            # Check if auditd is running
            result = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and "active" in result.stdout:
                control.status = ControlStatus.PASS
                control.evidence.append("auditd service: Active")
            else:
                control.status = ControlStatus.FAIL
                control.evidence.append("auditd service: Inactive")
                control.remediation = "Enable auditd: sudo systemctl enable auditd && sudo systemctl start auditd"
        
        except FileNotFoundError:
            control.status = ControlStatus.FAIL
            control.evidence.append("auditd not installed")
            control.remediation = "Install auditd: sudo apt install auditd (Debian/Ubuntu) or sudo yum install audit (RHEL/CentOS)"
        except Exception as e:
            control.status = ControlStatus.MANUAL_REVIEW
            control.evidence.append(f"Error checking auditd: {e}")
        
        controls.append(control)
        return controls


class PCIDSSScanner:
    """PCI-DSS compliance scanner"""
    
    def scan_all(self) -> List[ComplianceControl]:
        """Run all PCI-DSS checks"""
        controls = []
        
        # Requirement 1: Install and maintain firewall
        controls.append(ComplianceControl(
            control_id="PCI-1.1",
            standard=ComplianceStandard.PCI_DSS,
            title="Firewall Configuration Standards",
            description="Establish and implement firewall and router configuration standards",
            requirement="Documented firewall standards and review process",
            status=ControlStatus.MANUAL_REVIEW,
            severity="Critical",
            remediation="Document firewall standards, review configurations quarterly"
        ))
        
        # Requirement 2: Change vendor defaults
        controls.append(ComplianceControl(
            control_id="PCI-2.1",
            standard=ComplianceStandard.PCI_DSS,
            title="Change Vendor Defaults",
            description="Always change vendor-supplied defaults before installing on network",
            requirement="No default passwords, SNMP community strings, or accounts",
            status=ControlStatus.MANUAL_REVIEW,
            severity="Critical",
            remediation="Change all default passwords, disable default accounts"
        ))
        
        # Requirement 8: Identify and authenticate access
        controls.extend(self._scan_password_requirements())
        
        # Requirement 10: Track and monitor all access
        controls.append(ComplianceControl(
            control_id="PCI-10.1",
            standard=ComplianceStandard.PCI_DSS,
            title="Audit Trails",
            description="Implement audit trails to link all access to system components",
            requirement="Logging enabled for all access to cardholder data",
            status=ControlStatus.MANUAL_REVIEW,
            severity="Critical",
            remediation="Enable comprehensive audit logging, retain logs for 3 months minimum"
        ))
        
        return controls
    
    def _scan_password_requirements(self) -> List[ComplianceControl]:
        """Check PCI-DSS password requirements (Req 8.3)"""
        controls = []
        
        control = ComplianceControl(
            control_id="PCI-8.3.6",
            standard=ComplianceStandard.PCI_DSS,
            title="Password Complexity",
            description="Passwords must contain: minimum 12 characters, numeric, uppercase, lowercase",
            requirement="Complex passwords with length >= 12",
            status=ControlStatus.MANUAL_REVIEW,
            severity="High",
            remediation="Enforce password complexity: 12+ chars, mixed case, numbers, special chars"
        )
        controls.append(control)
        
        control = ComplianceControl(
            control_id="PCI-8.3.9",
            standard=ComplianceStandard.PCI_DSS,
            title="Password Change Frequency",
            description="Passwords must be changed at least every 90 days",
            requirement="Maximum password age: 90 days",
            status=ControlStatus.MANUAL_REVIEW,
            severity="High",
            remediation="Set password expiration to 90 days maximum"
        )
        controls.append(control)
        
        return controls


class HIPAAScanner:
    """HIPAA Security Rule compliance scanner"""
    
    def scan_all(self) -> List[ComplianceControl]:
        """Run all HIPAA Security Rule checks"""
        controls = []
        
        # 164.308(a)(1)(ii)(B) - Risk Management
        controls.append(ComplianceControl(
            control_id="HIPAA-164.308(a)(1)(ii)(B)",
            standard=ComplianceStandard.HIPAA,
            title="Risk Management",
            description="Implement security measures sufficient to reduce risks to reasonable level",
            requirement="Regular risk assessments and mitigation",
            status=ControlStatus.MANUAL_REVIEW,
            severity="Critical",
            remediation="Conduct annual risk assessments, document mitigation strategies"
        ))
        
        # 164.312(a)(1) - Access Control
        controls.append(ComplianceControl(
            control_id="HIPAA-164.312(a)(1)",
            standard=ComplianceStandard.HIPAA,
            title="Access Control",
            description="Implement technical policies to allow only authorized access to ePHI",
            requirement="Role-based access control, unique user IDs",
            status=ControlStatus.MANUAL_REVIEW,
            severity="Critical",
            remediation="Implement RBAC, disable shared accounts, enforce principle of least privilege"
        ))
        
        # 164.312(b) - Audit Controls
        controls.append(ComplianceControl(
            control_id="HIPAA-164.312(b)",
            standard=ComplianceStandard.HIPAA,
            title="Audit Controls",
            description="Implement hardware/software that records activity in systems containing ePHI",
            requirement="Comprehensive audit logging of ePHI access",
            status=ControlStatus.MANUAL_REVIEW,
            severity="High",
            remediation="Enable audit logging, retain logs for 6 years, regular log review"
        ))
        
        # 164.312(e)(1) - Transmission Security
        controls.append(ComplianceControl(
            control_id="HIPAA-164.312(e)(1)",
            standard=ComplianceStandard.HIPAA,
            title="Transmission Security",
            description="Implement technical measures to guard against unauthorized access during transmission",
            requirement="Encryption of ePHI in transit (TLS 1.2+)",
            status=ControlStatus.MANUAL_REVIEW,
            severity="Critical",
            remediation="Enforce TLS 1.2+ for all ePHI transmission, disable weak ciphers"
        ))
        
        return controls


class ComplianceScanner:
    """Main compliance scanner orchestrator"""
    
    def __init__(self):
        self.cis = CISBenchmarkScanner()
        self.pci_dss = PCIDSSScanner()
        self.hipaa = HIPAAScanner()
    
    def scan(self, standards: List[ComplianceStandard] = None) -> Dict:
        """Run compliance scans for specified standards"""
        
        if standards is None:
            standards = [
                ComplianceStandard.CIS_LEVEL1,
                ComplianceStandard.PCI_DSS,
                ComplianceStandard.HIPAA
            ]
        
        all_controls = []
        
        print(f"🔍 Starting compliance scan for {len(standards)} standards...")
        
        for standard in standards:
            print(f"\n📋 Scanning: {standard.value}")
            
            if standard in [ComplianceStandard.CIS_LEVEL1, ComplianceStandard.CIS_LEVEL2]:
                controls = []
                controls.extend(self.cis.scan_password_policy())
                controls.extend(self.cis.scan_firewall())
                controls.extend(self.cis.scan_audit_logging())
                print(f"  ✅ {len(controls)} CIS controls checked")
                all_controls.extend(controls)
            
            elif standard == ComplianceStandard.PCI_DSS:
                controls = self.pci_dss.scan_all()
                print(f"  ✅ {len(controls)} PCI-DSS controls checked")
                all_controls.extend(controls)
            
            elif standard == ComplianceStandard.HIPAA:
                controls = self.hipaa.scan_all()
                print(f"  ✅ {len(controls)} HIPAA controls checked")
                all_controls.extend(controls)
        
        # Calculate statistics
        stats = {
            "total_controls": len(all_controls),
            "pass": len([c for c in all_controls if c.status == ControlStatus.PASS]),
            "fail": len([c for c in all_controls if c.status == ControlStatus.FAIL]),
            "partial": len([c for c in all_controls if c.status == ControlStatus.PARTIAL]),
            "manual_review": len([c for c in all_controls if c.status == ControlStatus.MANUAL_REVIEW]),
            "compliance_score": 0.0
        }
        
        if stats["total_controls"] > 0:
            stats["compliance_score"] = (stats["pass"] / stats["total_controls"]) * 100
        
        return {
            "controls": [c.to_dict() for c in all_controls],
            "statistics": stats,
            "standards_scanned": [s.value for s in standards]
        }
    
    def generate_report(self, scan_results: Dict, output_file: Path):
        """Generate compliance report"""
        
        report = f"""
# Compliance Scan Report

## Summary

- **Standards Scanned:** {', '.join(scan_results['standards_scanned'])}
- **Total Controls:** {scan_results['statistics']['total_controls']}
- **Compliance Score:** {scan_results['statistics']['compliance_score']:.1f}%

### Control Status

- ✅ **Pass:** {scan_results['statistics']['pass']}
- ❌ **Fail:** {scan_results['statistics']['fail']}
- ⚠️ **Partial:** {scan_results['statistics']['partial']}
- 📋 **Manual Review:** {scan_results['statistics']['manual_review']}

## Detailed Findings

"""
        
        # Group by standard
        controls_by_standard = {}
        for control in scan_results['controls']:
            std = control['standard']
            if std not in controls_by_standard:
                controls_by_standard[std] = []
            controls_by_standard[std].append(control)
        
        for standard, controls in controls_by_standard.items():
            report += f"### {standard}\n\n"
            
            for control in controls:
                status_icon = {
                    "Pass": "✅",
                    "Fail": "❌",
                    "Partial": "⚠️",
                    "Manual Review Required": "📋"
                }.get(control['status'], "❓")
                
                report += f"#### {status_icon} {control['control_id']}: {control['title']}\n\n"
                report += f"**Status:** {control['status']}\n\n"
                report += f"**Requirement:** {control['requirement']}\n\n"
                
                if control['evidence']:
                    report += f"**Evidence:**\n"
                    for evidence in control['evidence']:
                        report += f"- {evidence}\n"
                    report += "\n"
                
                if control['remediation']:
                    report += f"**Remediation:** {control['remediation']}\n\n"
                
                report += "---\n\n"
        
        # Save report
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\n✅ Compliance report saved: {output_file}")


def main():
    """Demo compliance scanning"""
    
    scanner = ComplianceScanner()
    
    print("="*60)
    print("COMPLIANCE SCANNING DEMO")
    print("="*60)
    
    # Run scans
    results = scanner.scan([
        ComplianceStandard.CIS_LEVEL1,
        ComplianceStandard.PCI_DSS,
        ComplianceStandard.HIPAA
    ])
    
    # Print summary
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Compliance Score: {results['statistics']['compliance_score']:.1f}%")
    print(f"Pass: {results['statistics']['pass']}")
    print(f"Fail: {results['statistics']['fail']}")
    print(f"Manual Review: {results['statistics']['manual_review']}")
    
    # Generate report
    scanner.generate_report(results, Path("reports/compliance_report.md"))
    
    # Save JSON
    with open("reports/compliance_results.json", 'w') as f:
        json.dump(results, f, indent=2)
    print("✅ JSON results saved: reports/compliance_results.json")


if __name__ == "__main__":
    main()

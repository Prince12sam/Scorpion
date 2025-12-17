#!/usr/bin/env python3
"""
Advanced Reporting Engine
Generate professional security assessment reports with executive summaries,
technical details, charts, compliance mapping, and remediation tracking.
"""

import json
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import base64


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class ComplianceStandard(Enum):
    """Compliance standards"""
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    ISO_27001 = "ISO 27001"
    SOC2 = "SOC 2"
    NIST_CSF = "NIST CSF"
    GDPR = "GDPR"
    FEDRAMP = "FedRAMP"
    CIS = "CIS Benchmarks"


@dataclass
class Vulnerability:
    """Vulnerability finding"""
    id: str
    title: str
    severity: SeverityLevel
    cvss_score: float
    description: str
    affected_asset: str
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    exploitable: bool = False
    exploit_available: bool = False
    status: str = "Open"  # Open, In Progress, Fixed, Accepted Risk
    compliance_mapping: Dict[str, List[str]] = field(default_factory=dict)
    discovered_date: datetime.datetime = field(default_factory=datetime.datetime.now)
    fixed_date: Optional[datetime.datetime] = None
    
    def cvss_rating(self) -> str:
        """Get CVSS rating from score"""
        if self.cvss_score >= 9.0:
            return "Critical"
        elif self.cvss_score >= 7.0:
            return "High"
        elif self.cvss_score >= 4.0:
            return "Medium"
        elif self.cvss_score >= 0.1:
            return "Low"
        else:
            return "None"


@dataclass
class AssetInfo:
    """Asset information"""
    hostname: str
    ip_address: str
    os: str = "Unknown"
    services: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0
    criticality: str = "Medium"  # Low, Medium, High, Critical


@dataclass
class ScanMetadata:
    """Scan metadata"""
    scan_id: str
    scan_name: str
    target: str
    start_time: datetime.datetime
    end_time: datetime.datetime
    scanner: str = "Scorpion Security Scanner"
    scanner_version: str = "2.0.2"
    operator: str = "Security Team"
    
    def duration(self) -> str:
        """Calculate scan duration"""
        delta = self.end_time - self.start_time
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60
        seconds = delta.seconds % 60
        return f"{hours}h {minutes}m {seconds}s"


class ReportGenerator:
    """Advanced report generator with multiple formats"""
    
    def __init__(self):
        self.matplotlib_available = False
        self.reportlab_available = False
        
        # Try importing optional dependencies
        try:
            import matplotlib
            matplotlib.use('Agg')  # Non-interactive backend
            import matplotlib.pyplot as plt
            self.plt = plt
            self.matplotlib_available = True
        except ImportError:
            pass
        
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            self.reportlab_available = True
            self.reportlab_modules = {
                'letter': letter,
                'A4': A4,
                'SimpleDocTemplate': SimpleDocTemplate,
                'Paragraph': Paragraph,
                'Spacer': Spacer,
                'Table': Table,
                'TableStyle': TableStyle,
                'PageBreak': PageBreak,
                'Image': Image,
                'getSampleStyleSheet': getSampleStyleSheet,
                'ParagraphStyle': ParagraphStyle,
                'inch': inch,
                'colors': colors
            }
        except ImportError:
            pass
        
        print(f"📊 Report Generator initialized:")
        print(f"  ├─ Charts (matplotlib): {'✅' if self.matplotlib_available else '❌ (install: pip install matplotlib)'}")
        print(f"  └─ PDF Export (reportlab): {'✅' if self.reportlab_available else '❌ (install: pip install reportlab)'}")
    
    def generate_executive_summary(self, vulnerabilities: List[Vulnerability],
                                   assets: List[AssetInfo],
                                   metadata: ScanMetadata) -> str:
        """Generate executive summary (non-technical)"""
        
        # Count by severity
        severity_counts = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 0,
            SeverityLevel.MEDIUM: 0,
            SeverityLevel.LOW: 0,
            SeverityLevel.INFO: 0
        }
        
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        # Calculate overall risk
        risk_score = (
            severity_counts[SeverityLevel.CRITICAL] * 10 +
            severity_counts[SeverityLevel.HIGH] * 5 +
            severity_counts[SeverityLevel.MEDIUM] * 2 +
            severity_counts[SeverityLevel.LOW] * 1
        )
        
        if risk_score > 50:
            risk_level = "CRITICAL"
        elif risk_score > 20:
            risk_level = "HIGH"
        elif risk_score > 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        summary = f"""
# Executive Summary

## Assessment Overview

**Organization:** {metadata.target}
**Assessment Date:** {metadata.start_time.strftime('%B %d, %Y')}
**Assessment Duration:** {metadata.duration()}
**Assessed By:** {metadata.operator}

## Key Findings

This security assessment identified **{len(vulnerabilities)} vulnerabilities** across **{len(assets)} assets**.

### Risk Distribution

- **Critical:** {severity_counts[SeverityLevel.CRITICAL]} vulnerabilities
- **High:** {severity_counts[SeverityLevel.HIGH]} vulnerabilities
- **Medium:** {severity_counts[SeverityLevel.MEDIUM]} vulnerabilities
- **Low:** {severity_counts[SeverityLevel.LOW]} vulnerabilities
- **Informational:** {severity_counts[SeverityLevel.INFO]} findings

### Overall Risk Rating: **{risk_level}**

## Top Concerns

"""
        
        # List top 5 critical/high vulnerabilities
        critical_high = [v for v in vulnerabilities if v.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        critical_high.sort(key=lambda v: v.cvss_score, reverse=True)
        
        for i, vuln in enumerate(critical_high[:5], 1):
            summary += f"{i}. **{vuln.title}** ({vuln.severity.value}) - CVSS {vuln.cvss_score}\n"
            summary += f"   - Affected Asset: {vuln.affected_asset}\n"
            if vuln.exploitable:
                summary += f"   - ⚠️ **EXPLOITABLE** - Immediate action required\n"
            summary += f"\n"
        
        summary += """
## Business Impact

"""
        
        if severity_counts[SeverityLevel.CRITICAL] > 0:
            summary += f"- **{severity_counts[SeverityLevel.CRITICAL]} critical vulnerabilities** pose immediate risk to business operations, data confidentiality, and regulatory compliance.\n"
        
        if severity_counts[SeverityLevel.HIGH] > 0:
            summary += f"- **{severity_counts[SeverityLevel.HIGH]} high-severity issues** could lead to unauthorized access, data breaches, or service disruption.\n"
        
        summary += """
## Recommendations

1. **Immediate Actions** (0-7 days):
   - Address all Critical vulnerabilities
   - Implement network segmentation for vulnerable systems
   - Enable logging and monitoring

2. **Short-term Actions** (1-4 weeks):
   - Patch all High-severity vulnerabilities
   - Conduct security awareness training
   - Review access controls

3. **Long-term Actions** (1-3 months):
   - Address Medium/Low vulnerabilities
   - Implement continuous security monitoring
   - Establish vulnerability management program

## Compliance Impact

"""
        
        # Check compliance violations
        compliance_issues = {}
        for vuln in vulnerabilities:
            for standard, controls in vuln.compliance_mapping.items():
                if standard not in compliance_issues:
                    compliance_issues[standard] = 0
                compliance_issues[standard] += 1
        
        if compliance_issues:
            summary += "The identified vulnerabilities may impact compliance with:\n\n"
            for standard, count in compliance_issues.items():
                summary += f"- **{standard}**: {count} findings\n"
        else:
            summary += "No specific compliance violations identified.\n"
        
        return summary
    
    def generate_technical_report(self, vulnerabilities: List[Vulnerability],
                                  assets: List[AssetInfo],
                                  metadata: ScanMetadata) -> str:
        """Generate detailed technical report"""
        
        report = f"""
# Technical Security Assessment Report

## Scan Information

- **Scan ID:** {metadata.scan_id}
- **Target:** {metadata.target}
- **Start Time:** {metadata.start_time.strftime('%Y-%m-%d %H:%M:%S')}
- **End Time:** {metadata.end_time.strftime('%Y-%m-%d %H:%M:%S')}
- **Duration:** {metadata.duration()}
- **Scanner:** {metadata.scanner} v{metadata.scanner_version}

## Asset Inventory

"""
        
        for asset in assets:
            report += f"### {asset.hostname} ({asset.ip_address})\n\n"
            report += f"- **Operating System:** {asset.os}\n"
            report += f"- **Criticality:** {asset.criticality}\n"
            report += f"- **Risk Score:** {asset.risk_score:.1f}/10\n"
            
            if asset.services:
                report += f"- **Services:**\n"
                for service in asset.services[:10]:  # Top 10 services
                    port = service.get('port', '?')
                    name = service.get('name', 'unknown')
                    report += f"  - Port {port}: {name}\n"
            
            report += "\n"
        
        report += "## Vulnerability Findings\n\n"
        
        # Group by severity
        for severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]:
            vulns = [v for v in vulnerabilities if v.severity == severity]
            
            if not vulns:
                continue
            
            report += f"### {severity.value} Severity ({len(vulns)} findings)\n\n"
            
            for vuln in vulns:
                report += f"#### {vuln.id}: {vuln.title}\n\n"
                report += f"**Severity:** {vuln.severity.value} (CVSS {vuln.cvss_score})\n\n"
                report += f"**Affected Asset:** {vuln.affected_asset}\n\n"
                
                if vuln.cve_ids:
                    report += f"**CVE IDs:** {', '.join(vuln.cve_ids)}\n\n"
                
                if vuln.cwe_ids:
                    report += f"**CWE IDs:** {', '.join(vuln.cwe_ids)}\n\n"
                
                report += f"**Description:**\n{vuln.description}\n\n"
                
                if vuln.exploitable:
                    report += "⚠️ **This vulnerability is exploitable!**\n\n"
                
                if vuln.exploit_available:
                    report += "⚠️ **Public exploit code is available.**\n\n"
                
                report += f"**Remediation:**\n{vuln.remediation}\n\n"
                
                if vuln.references:
                    report += "**References:**\n"
                    for ref in vuln.references:
                        report += f"- {ref}\n"
                    report += "\n"
                
                if vuln.compliance_mapping:
                    report += "**Compliance Impact:**\n"
                    for standard, controls in vuln.compliance_mapping.items():
                        report += f"- {standard}: {', '.join(controls)}\n"
                    report += "\n"
                
                report += "---\n\n"
        
        return report
    
    def generate_json_report(self, vulnerabilities: List[Vulnerability],
                            assets: List[AssetInfo],
                            metadata: ScanMetadata) -> Dict:
        """Generate JSON report"""
        
        return {
            "metadata": {
                "scan_id": metadata.scan_id,
                "scan_name": metadata.scan_name,
                "target": metadata.target,
                "start_time": metadata.start_time.isoformat(),
                "end_time": metadata.end_time.isoformat(),
                "duration": metadata.duration(),
                "scanner": metadata.scanner,
                "scanner_version": metadata.scanner_version,
                "operator": metadata.operator
            },
            "assets": [
                {
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "os": asset.os,
                    "services": asset.services,
                    "risk_score": asset.risk_score,
                    "criticality": asset.criticality
                }
                for asset in assets
            ],
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "title": vuln.title,
                    "severity": vuln.severity.value,
                    "cvss_score": vuln.cvss_score,
                    "cvss_rating": vuln.cvss_rating(),
                    "description": vuln.description,
                    "affected_asset": vuln.affected_asset,
                    "cve_ids": vuln.cve_ids,
                    "cwe_ids": vuln.cwe_ids,
                    "remediation": vuln.remediation,
                    "references": vuln.references,
                    "exploitable": vuln.exploitable,
                    "exploit_available": vuln.exploit_available,
                    "status": vuln.status,
                    "compliance_mapping": vuln.compliance_mapping,
                    "discovered_date": vuln.discovered_date.isoformat(),
                    "fixed_date": vuln.fixed_date.isoformat() if vuln.fixed_date else None
                }
                for vuln in vulnerabilities
            ],
            "statistics": {
                "total_assets": len(assets),
                "total_vulnerabilities": len(vulnerabilities),
                "by_severity": {
                    "critical": len([v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
                    "high": len([v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]),
                    "medium": len([v for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
                    "low": len([v for v in vulnerabilities if v.severity == SeverityLevel.LOW]),
                    "info": len([v for v in vulnerabilities if v.severity == SeverityLevel.INFO])
                },
                "exploitable_count": len([v for v in vulnerabilities if v.exploitable]),
                "with_exploits": len([v for v in vulnerabilities if v.exploit_available])
            }
        }
    
    def generate_charts(self, vulnerabilities: List[Vulnerability],
                       output_dir: Path) -> Dict[str, Path]:
        """Generate charts for report"""
        if not self.matplotlib_available:
            print("⚠️ matplotlib not installed. Install: pip install matplotlib")
            return {}
        
        output_dir.mkdir(parents=True, exist_ok=True)
        charts = {}
        
        # Severity distribution pie chart
        severity_counts = {
            'Critical': len([v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
            'High': len([v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]),
            'Medium': len([v for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
            'Low': len([v for v in vulnerabilities if v.severity == SeverityLevel.LOW]),
            'Info': len([v for v in vulnerabilities if v.severity == SeverityLevel.INFO])
        }
        
        # Remove zero counts
        severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        if severity_counts:
            self.plt.figure(figsize=(10, 6))
            colors_map = {
                'Critical': '#d32f2f',
                'High': '#f57c00',
                'Medium': '#fbc02d',
                'Low': '#388e3c',
                'Info': '#1976d2'
            }
            colors_list = [colors_map[k] for k in severity_counts.keys()]
            
            self.plt.pie(severity_counts.values(), labels=severity_counts.keys(),
                        autopct='%1.1f%%', colors=colors_list, startangle=90)
            self.plt.title('Vulnerability Distribution by Severity', fontsize=16, fontweight='bold')
            
            chart_file = output_dir / 'severity_distribution.png'
            self.plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            self.plt.close()
            charts['severity_distribution'] = chart_file
        
        # CVSS score distribution
        if vulnerabilities:
            self.plt.figure(figsize=(12, 6))
            cvss_scores = [v.cvss_score for v in vulnerabilities]
            
            self.plt.hist(cvss_scores, bins=20, color='#1976d2', edgecolor='black', alpha=0.7)
            self.plt.xlabel('CVSS Score', fontsize=12)
            self.plt.ylabel('Number of Vulnerabilities', fontsize=12)
            self.plt.title('CVSS Score Distribution', fontsize=16, fontweight='bold')
            self.plt.grid(axis='y', alpha=0.3)
            
            chart_file = output_dir / 'cvss_distribution.png'
            self.plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            self.plt.close()
            charts['cvss_distribution'] = chart_file
        
        # Vulnerability trends (if historical data available)
        # This would require multiple scans to be tracked over time
        
        return charts
    
    def generate_risk_heatmap(self, assets: List[AssetInfo],
                             vulnerabilities: List[Vulnerability],
                             output_dir: Path) -> Optional[Path]:
        """Generate risk heatmap (Asset x Severity)"""
        if not self.matplotlib_available:
            return None
        
        import numpy as np
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create matrix: assets x severity levels
        severity_levels = ['Critical', 'High', 'Medium', 'Low']
        matrix = []
        asset_labels = []
        
        for asset in assets[:20]:  # Limit to 20 assets for readability
            asset_labels.append(asset.hostname[:30])
            row = []
            
            asset_vulns = [v for v in vulnerabilities if v.affected_asset == asset.hostname]
            
            for severity_name in severity_levels:
                severity = SeverityLevel[severity_name.upper()]
                count = len([v for v in asset_vulns if v.severity == severity])
                row.append(count)
            
            matrix.append(row)
        
        if not matrix:
            return None
        
        matrix = np.array(matrix)
        
        self.plt.figure(figsize=(12, max(8, len(asset_labels) * 0.3)))
        self.plt.imshow(matrix, cmap='YlOrRd', aspect='auto', interpolation='nearest')
        
        self.plt.xticks(range(len(severity_levels)), severity_levels)
        self.plt.yticks(range(len(asset_labels)), asset_labels, fontsize=8)
        
        self.plt.xlabel('Severity Level', fontsize=12)
        self.plt.ylabel('Assets', fontsize=12)
        self.plt.title('Risk Heatmap: Vulnerabilities by Asset', fontsize=16, fontweight='bold')
        
        # Add colorbar
        cbar = self.plt.colorbar()
        cbar.set_label('Number of Vulnerabilities', fontsize=10)
        
        # Add text annotations
        for i in range(len(asset_labels)):
            for j in range(len(severity_levels)):
                if matrix[i, j] > 0:
                    self.plt.text(j, i, str(matrix[i, j]),
                                ha='center', va='center',
                                color='white' if matrix[i, j] > matrix.max() * 0.5 else 'black',
                                fontsize=10, fontweight='bold')
        
        chart_file = output_dir / 'risk_heatmap.png'
        self.plt.savefig(chart_file, dpi=300, bbox_inches='tight')
        self.plt.close()
        
        return chart_file
    
    def generate_comparison_report(self, scan1_data: Dict, scan2_data: Dict) -> str:
        """Compare two scans and show changes"""
        
        report = f"""
# Vulnerability Comparison Report

## Scan Details

### Baseline Scan
- **Date:** {scan1_data['metadata']['start_time']}
- **Vulnerabilities:** {scan1_data['statistics']['total_vulnerabilities']}

### Current Scan
- **Date:** {scan2_data['metadata']['start_time']}
- **Vulnerabilities:** {scan2_data['statistics']['total_vulnerabilities']}

## Changes

"""
        
        # Calculate changes
        vuln1_ids = {v['id'] for v in scan1_data['vulnerabilities']}
        vuln2_ids = {v['id'] for v in scan2_data['vulnerabilities']}
        
        new_vulns = vuln2_ids - vuln1_ids
        fixed_vulns = vuln1_ids - vuln2_ids
        persistent_vulns = vuln1_ids & vuln2_ids
        
        report += f"- **New Vulnerabilities:** {len(new_vulns)}\n"
        report += f"- **Fixed Vulnerabilities:** {len(fixed_vulns)}\n"
        report += f"- **Persistent Vulnerabilities:** {len(persistent_vulns)}\n\n"
        
        if new_vulns:
            report += "### New Vulnerabilities\n\n"
            for vuln_id in new_vulns:
                vuln = next(v for v in scan2_data['vulnerabilities'] if v['id'] == vuln_id)
                report += f"- **{vuln['title']}** ({vuln['severity']}) - CVSS {vuln['cvss_score']}\n"
            report += "\n"
        
        if fixed_vulns:
            report += "### Fixed Vulnerabilities\n\n"
            for vuln_id in fixed_vulns:
                vuln = next(v for v in scan1_data['vulnerabilities'] if v['id'] == vuln_id)
                report += f"- **{vuln['title']}** ({vuln['severity']}) - CVSS {vuln['cvss_score']}\n"
            report += "\n"
        
        # Severity trend
        report += "### Severity Trend\n\n"
        report += "| Severity | Baseline | Current | Change |\n"
        report += "|----------|----------|---------|--------|\n"
        
        for severity in ['critical', 'high', 'medium', 'low']:
            count1 = scan1_data['statistics']['by_severity'][severity]
            count2 = scan2_data['statistics']['by_severity'][severity]
            change = count2 - count1
            change_str = f"+{change}" if change > 0 else str(change)
            report += f"| {severity.capitalize()} | {count1} | {count2} | {change_str} |\n"
        
        return report
    
    def save_report(self, content: str, output_file: Path, format: str = "markdown"):
        """Save report to file"""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        if format == "markdown":
            with open(output_file.with_suffix('.md'), 'w', encoding='utf-8') as f:
                f.write(content)
        elif format == "html":
            html = self._markdown_to_html(content)
            with open(output_file.with_suffix('.html'), 'w', encoding='utf-8') as f:
                f.write(html)
        elif format == "json":
            with open(output_file.with_suffix('.json'), 'w', encoding='utf-8') as f:
                json.dump(content, f, indent=2)
        
        print(f"✅ Report saved: {output_file}")
    
    def _markdown_to_html(self, markdown: str) -> str:
        """Convert markdown to HTML (basic conversion)"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #1976d2; border-bottom: 3px solid #1976d2; padding-bottom: 10px; }}
        h2 {{ color: #424242; border-bottom: 2px solid #e0e0e0; padding-bottom: 8px; margin-top: 30px; }}
        h3 {{ color: #616161; }}
        h4 {{ color: #757575; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; font-weight: bold; }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #1976d2;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f5f5f5;
        }}
        code {{
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        {self._convert_markdown_content(markdown)}
    </div>
</body>
</html>
"""
        return html
    
    def _convert_markdown_content(self, markdown: str) -> str:
        """Simple markdown to HTML conversion"""
        import re
        
        html = markdown
        
        # Headers
        html = re.sub(r'^#### (.*?)$', r'<h4>\1</h4>', html, flags=re.MULTILINE)
        html = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        
        # Bold
        html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
        
        # Lists
        html = re.sub(r'^\- (.*?)$', r'<li>\1</li>', html, flags=re.MULTILINE)
        html = re.sub(r'(<li>.*?</li>\n?)+', r'<ul>\g<0></ul>', html, flags=re.DOTALL)
        
        # Paragraphs
        lines = html.split('\n\n')
        html = '\n'.join([f'<p>{line}</p>' if not line.startswith('<') else line for line in lines])
        
        return html


def main():
    """Demo report generation"""
    
    # Create sample data
    metadata = ScanMetadata(
        scan_id="SCAN-2024-001",
        scan_name="Production Environment Assessment",
        target="example.com",
        start_time=datetime.datetime(2024, 1, 15, 9, 0, 0),
        end_time=datetime.datetime(2024, 1, 15, 17, 30, 0),
        operator="Security Team"
    )
    
    assets = [
        AssetInfo(
            hostname="web-server-01",
            ip_address="192.168.1.10",
            os="Ubuntu 20.04",
            services=[
                {"port": 80, "name": "http"},
                {"port": 443, "name": "https"},
                {"port": 22, "name": "ssh"}
            ],
            risk_score=7.5,
            criticality="High"
        ),
        AssetInfo(
            hostname="db-server-01",
            ip_address="192.168.1.20",
            os="RedHat 8",
            services=[
                {"port": 3306, "name": "mysql"},
                {"port": 22, "name": "ssh"}
            ],
            risk_score=8.2,
            criticality="Critical"
        )
    ]
    
    vulnerabilities = [
        Vulnerability(
            id="VULN-001",
            title="SQL Injection in Login Form",
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.8,
            description="The login form is vulnerable to SQL injection attacks, allowing attackers to bypass authentication and access sensitive data.",
            affected_asset="web-server-01",
            cve_ids=["CVE-2023-12345"],
            cwe_ids=["CWE-89"],
            remediation="Implement parameterized queries and input validation. Use prepared statements instead of string concatenation.",
            exploitable=True,
            exploit_available=True,
            compliance_mapping={
                "PCI-DSS": ["6.5.1"],
                "OWASP Top 10": ["A03:2021"]
            }
        ),
        Vulnerability(
            id="VULN-002",
            title="Outdated MySQL Version",
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            description="MySQL server is running version 5.6, which is end-of-life and contains known security vulnerabilities.",
            affected_asset="db-server-01",
            cve_ids=["CVE-2023-54321", "CVE-2023-54322"],
            remediation="Upgrade MySQL to version 8.0 or later. Test application compatibility before upgrading production systems.",
            exploitable=False,
            compliance_mapping={
                "PCI-DSS": ["6.2"],
                "HIPAA": ["164.308(a)(5)(ii)(B)"]
            }
        )
    ]
    
    # Generate reports
    generator = ReportGenerator()
    
    print("\n" + "="*60)
    print("GENERATING REPORTS")
    print("="*60)
    
    # Executive summary
    exec_summary = generator.generate_executive_summary(vulnerabilities, assets, metadata)
    generator.save_report(exec_summary, Path("reports/executive_summary.md"))
    
    # Technical report
    tech_report = generator.generate_technical_report(vulnerabilities, assets, metadata)
    generator.save_report(tech_report, Path("reports/technical_report.md"))
    
    # JSON report
    json_report = generator.generate_json_report(vulnerabilities, assets, metadata)
    generator.save_report(json_report, Path("reports/scan_results.json"), format="json")
    
    # Charts
    charts = generator.generate_charts(vulnerabilities, Path("reports/charts"))
    print(f"\n✅ Generated {len(charts)} charts")
    
    # Risk heatmap
    heatmap = generator.generate_risk_heatmap(assets, vulnerabilities, Path("reports/charts"))
    if heatmap:
        print(f"✅ Generated risk heatmap: {heatmap}")
    
    print("\n✅ All reports generated successfully!")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Advanced reporting utilities.

This module generates reports from *provided scan output* (metadata, assets,
vulnerabilities). It intentionally does not ship demo/mock scan data.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class ScanMetadata:
    scan_id: str
    scan_name: str
    target: str
    start_time: datetime.datetime
    end_time: datetime.datetime
    scanner: str = "scorpion"
    scanner_version: str = ""
    operator: str = ""

    def duration_seconds(self) -> float:
        return max(0.0, (self.end_time - self.start_time).total_seconds())


@dataclass
class AssetInfo:
    hostname: str
    ip_address: str = ""
    os: str = ""
    services: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    criticality: str = ""


@dataclass
class Vulnerability:
    id: str
    title: str
    severity: SeverityLevel
    cvss_score: float
    description: str
    affected_asset: str
    remediation: str
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploitable: bool = False
    exploit_available: bool = False
    status: str = "open"
    compliance_mapping: Dict[str, List[str]] = field(default_factory=dict)
    discovered_date: datetime.date = field(default_factory=lambda: datetime.date.today())
    fixed_date: Optional[datetime.date] = None

    def cvss_rating(self) -> str:
        score = float(self.cvss_score or 0.0)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "none"


class ReportGenerator:
    def __init__(self) -> None:
        try:
            import matplotlib.pyplot as plt  # type: ignore

            self._plt = plt
            self._matplotlib_available = True
        except Exception:
            self._plt = None
            self._matplotlib_available = False

    def generate_executive_summary(
        self,
        vulnerabilities: List[Vulnerability],
        assets: List[AssetInfo],
        metadata: ScanMetadata,
    ) -> str:
        by_sev = {
            "critical": len([v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
            "high": len([v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]),
            "medium": len([v for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
            "low": len([v for v in vulnerabilities if v.severity == SeverityLevel.LOW]),
            "info": len([v for v in vulnerabilities if v.severity == SeverityLevel.INFO]),
        }

        top_vulns = sorted(
            vulnerabilities,
            key=lambda v: (v.severity != SeverityLevel.CRITICAL, v.severity != SeverityLevel.HIGH, -(v.cvss_score or 0.0)),
        )[:10]

        lines = [
            "# Executive Summary",
            "",
            f"- Scan: {metadata.scan_name} ({metadata.scan_id})",
            f"- Target: {metadata.target}",
            f"- Duration: {metadata.duration_seconds():.0f}s",
            f"- Assets assessed: {len(assets)}",
            f"- Total findings: {len(vulnerabilities)}",
            "",
            "## Severity Breakdown",
            "",
            f"- Critical: {by_sev['critical']}",
            f"- High: {by_sev['high']}",
            f"- Medium: {by_sev['medium']}",
            f"- Low: {by_sev['low']}",
            f"- Info: {by_sev['info']}",
            "",
        ]

        if top_vulns:
            lines.append("## Top Findings")
            lines.append("")
            for v in top_vulns:
                lines.append(f"- {v.id}: {v.title} ({v.severity.value}, CVSS {v.cvss_score})")
            lines.append("")

        return "\n".join(lines)

    def generate_technical_report(
        self,
        vulnerabilities: List[Vulnerability],
        assets: List[AssetInfo],
        metadata: ScanMetadata,
    ) -> str:
        lines = [
            "# Technical Report",
            "",
            "## Scan Metadata",
            "",
            f"- Scan ID: {metadata.scan_id}",
            f"- Name: {metadata.scan_name}",
            f"- Target: {metadata.target}",
            f"- Start: {metadata.start_time.isoformat()}",
            f"- End: {metadata.end_time.isoformat()}",
            "",
            "## Assets",
            "",
        ]

        for asset in assets:
            lines.append(f"### {asset.hostname}")
            if asset.ip_address:
                lines.append(f"- IP: {asset.ip_address}")
            if asset.os:
                lines.append(f"- OS: {asset.os}")
            if asset.criticality:
                lines.append(f"- Criticality: {asset.criticality}")
            if asset.services:
                lines.append("- Services:")
                for svc in asset.services:
                    port = svc.get("port", "?")
                    name = svc.get("name", "unknown")
                    lines.append(f"  - {port}: {name}")
            lines.append("")

        lines.append("## Vulnerabilities")
        lines.append("")

        for sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]:
            sev_vulns = [v for v in vulnerabilities if v.severity == sev]
            if not sev_vulns:
                continue
            lines.append(f"### {sev.value} ({len(sev_vulns)})")
            lines.append("")
            for v in sev_vulns:
                lines.extend(
                    [
                        f"#### {v.id}: {v.title}",
                        "",
                        f"- CVSS: {v.cvss_score} ({v.cvss_rating()})",
                        f"- Affected asset: {v.affected_asset}",
                    ]
                )
                if v.cve_ids:
                    lines.append(f"- CVE: {', '.join(v.cve_ids)}")
                if v.cwe_ids:
                    lines.append(f"- CWE: {', '.join(v.cwe_ids)}")
                lines.append("")
                lines.append("**Description**")
                lines.append(v.description)
                lines.append("")
                lines.append("**Remediation**")
                lines.append(v.remediation)
                lines.append("")
                if v.references:
                    lines.append("**References**")
                    for ref in v.references:
                        lines.append(f"- {ref}")
                    lines.append("")
                if v.compliance_mapping:
                    lines.append("**Compliance Mapping**")
                    for standard, controls in v.compliance_mapping.items():
                        lines.append(f"- {standard}: {', '.join(controls)}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        return "\n".join(lines)

    def generate_json_report(
        self,
        vulnerabilities: List[Vulnerability],
        assets: List[AssetInfo],
        metadata: ScanMetadata,
    ) -> Dict[str, Any]:
        return {
            "metadata": {
                "scan_id": metadata.scan_id,
                "scan_name": metadata.scan_name,
                "target": metadata.target,
                "start_time": metadata.start_time.isoformat(),
                "end_time": metadata.end_time.isoformat(),
                "duration_seconds": metadata.duration_seconds(),
                "scanner": metadata.scanner,
                "scanner_version": metadata.scanner_version,
                "operator": metadata.operator,
            },
            "assets": [
                {
                    "hostname": a.hostname,
                    "ip_address": a.ip_address,
                    "os": a.os,
                    "services": a.services,
                    "risk_score": a.risk_score,
                    "criticality": a.criticality,
                }
                for a in assets
            ],
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "cvss_rating": v.cvss_rating(),
                    "description": v.description,
                    "affected_asset": v.affected_asset,
                    "cve_ids": v.cve_ids,
                    "cwe_ids": v.cwe_ids,
                    "remediation": v.remediation,
                    "references": v.references,
                    "exploitable": v.exploitable,
                    "exploit_available": v.exploit_available,
                    "status": v.status,
                    "compliance_mapping": v.compliance_mapping,
                    "discovered_date": v.discovered_date.isoformat(),
                    "fixed_date": v.fixed_date.isoformat() if v.fixed_date else None,
                }
                for v in vulnerabilities
            ],
        }

    def save_report(
        self,
        content: Union[str, Dict[str, Any]],
        output_file: Path,
        format: str = "markdown",
    ) -> Path:
        output_file.parent.mkdir(parents=True, exist_ok=True)

        fmt = (format or "markdown").lower()
        if fmt in {"md", "markdown"}:
            out = output_file.with_suffix(".md")
            if not isinstance(content, str):
                raise TypeError("Markdown output requires string content")
            out.write_text(content, encoding="utf-8")
            return out

        if fmt == "json":
            out = output_file.with_suffix(".json")
            out.write_text(json.dumps(content, indent=2, ensure_ascii=False), encoding="utf-8")
            return out

        raise ValueError(f"Unsupported format: {format}")


def main() -> None:
    raise SystemExit(
        "This module provides reporting utilities. Use the Scorpion CLI to generate reports from real scan output."
    )


if __name__ == "__main__":
    main()

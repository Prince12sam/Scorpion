from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .ssl_analyzer import analyze_ssl
from .web_owasp import web_owasp_passive
from .recon import recon


@dataclass
class ControlCheckResult:
    control_id: str
    name: str
    passed: bool
    severity: str
    evidence: str = ""
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class ControlValidationReport:
    target: str
    pack: str
    timestamp: str
    checks: List[ControlCheckResult]
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> Dict[str, Any]:
        passed = len([c for c in self.checks if c.passed])
        failed = len(self.checks) - passed
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for c in self.checks:
            if not c.passed:
                severities[c.severity] = severities.get(c.severity, 0) + 1
        return {
            "total": len(self.checks),
            "passed": passed,
            "failed": failed,
            "failed_by_severity": severities,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "pack": self.pack,
            "timestamp": self.timestamp,
            "summary": self.summary,
            "checks": [asdict(c) for c in self.checks],
            "raw": self.raw,
        }


def _normalize_host(host: str) -> str:
    return (host or "").strip().replace("https://", "").replace("http://", "").split("/")[0]


async def run_control_validation(host: str, pack: str = "web-basic") -> Dict[str, Any]:
    """Run safe control validation packs.

    Packs are passive and do not attempt exploitation; they validate observable controls
    like TLS config, headers, and basic OWASP passive hygiene.
    """

    target = _normalize_host(host)
    if not target:
        raise ValueError("host cannot be empty")

    ts = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    checks: List[ControlCheckResult] = []
    raw: Dict[str, Any] = {}

    pack_norm = (pack or "").strip().lower()
    if pack_norm not in {"web-basic", "tls-only", "headers-only", "recon-passive"}:
        raise ValueError("pack must be one of: web-basic, tls-only, headers-only, recon-passive")

    if pack_norm in {"web-basic", "tls-only"}:
        ssl_report = await analyze_ssl(target, 443)
        raw["ssl"] = ssl_report

        days_left = None
        cert = ssl_report.get("certificate") or {}
        if isinstance(cert, dict):
            days_left = cert.get("days_left")

        if isinstance(days_left, int):
            checks.append(
                ControlCheckResult(
                    control_id="TLS_CERT_EXPIRY",
                    name="TLS certificate not near expiry",
                    passed=days_left >= 30,
                    severity="medium",
                    evidence=f"days_left={days_left}",
                    remediation=["Renew/rotate certificate before expiry", "Automate renewals and monitoring"],
                )
            )

        tls = ssl_report.get("tls") or {}
        tls_version = tls.get("version") if isinstance(tls, dict) else None
        if tls_version:
            checks.append(
                ControlCheckResult(
                    control_id="TLS_MIN_VERSION",
                    name="No deprecated TLS versions",
                    passed=tls_version not in {"TLSv1", "TLSv1.1"},
                    severity="medium",
                    evidence=f"negotiated={tls_version}",
                    remediation=["Disable TLS 1.0/1.1; require TLS 1.2+", "Review cipher suites and protocol policy"],
                )
            )

        headers = (ssl_report.get("security_headers") or {})
        if isinstance(headers, dict):
            checks.append(
                ControlCheckResult(
                    control_id="HSTS",
                    name="HSTS enabled",
                    passed=bool(headers.get("hsts")),
                    severity="medium",
                    evidence="strict-transport-security present" if headers.get("hsts") else "missing strict-transport-security",
                    remediation=["Enable Strict-Transport-Security with a long max-age and includeSubDomains"],
                )
            )

    if pack_norm in {"web-basic", "headers-only"}:
        owasp = await web_owasp_passive(target)
        raw["web_owasp"] = owasp

        findings = owasp.get("findings") or []
        missing = {"Missing CSP", "Missing HSTS", "Missing X-Frame-Options", "Missing X-Content-Type-Options"}
        present_names = {f.get("name") for f in findings if isinstance(f, dict)}

        checks.append(
            ControlCheckResult(
                control_id="SEC_HEADERS_BASELINE",
                name="Baseline security headers present",
                passed=len(missing - present_names) == 0,
                severity="medium",
                evidence=f"missing={sorted(list(missing - present_names))}",
                remediation=[
                    "Add CSP, HSTS, X-Frame-Options (or frame-ancestors), and X-Content-Type-Options",
                    "Verify headers on all routes and error responses",
                ],
            )
        )

        checks.append(
            ControlCheckResult(
                control_id="CORS_SAFE",
                name="CORS not overly permissive",
                passed="Overly broad CORS with credentials" not in present_names,
                severity="high",
                evidence="no wildcard-with-credentials pattern detected" if "Overly broad CORS with credentials" not in present_names else "wildcard with credentials detected",
                remediation=["Avoid ACAO=* with credentials; scope origins to trusted allowlist"],
            )
        )

    if pack_norm in {"web-basic", "recon-passive"}:
        recon_report = await recon(target)
        raw["recon"] = recon_report

        waf_hint = False
        try:
            waf_hint = bool(recon_report.get("http", {}).get("waf_hint"))
        except Exception:
            waf_hint = False

        checks.append(
            ControlCheckResult(
                control_id="WAF_CDN_AWARENESS",
                name="WAF/CDN hint surfaced",
                passed=True,
                severity="info",
                evidence="waf_hint=true" if waf_hint else "waf_hint=false",
                remediation=["If WAF/CDN present, coordinate allowlisting and tune rate limits to avoid false positives"],
            )
        )

    report = ControlValidationReport(target=target, pack=pack_norm, timestamp=ts, checks=checks, raw=raw)
    return report.to_dict()


def run_control_validation_sync(host: str, pack: str = "web-basic") -> Dict[str, Any]:
    return asyncio.run(run_control_validation(host, pack))

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class FindingKey:
    name: str
    severity: str
    location: str


def _safe_str(v: Any) -> str:
    return "" if v is None else str(v)


def _extract_location(finding: Dict[str, Any]) -> str:
    for k in ("location", "path", "file", "endpoint", "url", "target"):
        v = finding.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict):
            endpoint = v.get("endpoint") or v.get("path")
            if isinstance(endpoint, str) and endpoint.strip():
                return endpoint.strip()
    return ""


def _finding_key(finding: Dict[str, Any]) -> FindingKey:
    name = _safe_str(finding.get("name") or finding.get("type") or finding.get("rule") or finding.get("id"))
    severity = _safe_str(finding.get("severity") or finding.get("level") or "info").lower()
    location = _extract_location(finding)
    return FindingKey(name=name, severity=severity, location=location)


def _walk_findings(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "findings" and isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        yield item
            else:
                yield from _walk_findings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_findings(item)


def _collect_finding_map(report: Dict[str, Any]) -> Dict[FindingKey, Dict[str, Any]]:
    out: Dict[FindingKey, Dict[str, Any]] = {}
    for f in _walk_findings(report):
        k = _finding_key(f)
        # Keep first occurrence for stability
        if k not in out:
            out[k] = f
    return out


def _diff_metrics(baseline: Dict[str, Any], current: Dict[str, Any]) -> List[Dict[str, Any]]:
    b = baseline.get("metrics")
    c = current.get("metrics")
    if not isinstance(b, dict) or not isinstance(c, dict):
        return []
    changes: List[Dict[str, Any]] = []
    keys = set(b.keys()) | set(c.keys())
    for k in sorted(keys):
        if b.get(k) != c.get(k):
            changes.append({"key": k, "baseline": b.get(k), "current": c.get(k)})
    return changes


def diff_reports(baseline_report: Dict[str, Any], current_report: Dict[str, Any]) -> Dict[str, Any]:
    baseline_map = _collect_finding_map(baseline_report)
    current_map = _collect_finding_map(current_report)

    baseline_keys = set(baseline_map.keys())
    current_keys = set(current_map.keys())

    added = [current_map[k] for k in sorted(current_keys - baseline_keys, key=lambda x: (x.severity, x.name, x.location))]
    removed = [baseline_map[k] for k in sorted(baseline_keys - current_keys, key=lambda x: (x.severity, x.name, x.location))]

    metric_changes = _diff_metrics(baseline_report, current_report)

    return {
        "summary": {
            "added_findings": len(added),
            "removed_findings": len(removed),
            "metric_changes": len(metric_changes),
            "baseline_findings": len(baseline_keys),
            "current_findings": len(current_keys),
        },
        "added_findings": added,
        "removed_findings": removed,
        "metric_changes": metric_changes,
    }


def diff_reports_from_files(baseline_path: str, current_path: str) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    b_path = Path(baseline_path)
    c_path = Path(current_path)

    baseline_report = json.loads(b_path.read_text(encoding="utf-8"))
    current_report = json.loads(c_path.read_text(encoding="utf-8"))

    return baseline_report, current_report, diff_reports(baseline_report, current_report)

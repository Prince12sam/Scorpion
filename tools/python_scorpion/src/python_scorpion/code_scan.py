from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class CodeScanFinding:
    tool: str
    severity: str
    title: str
    description: str
    recommendation: str
    file: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    rule_id: Optional[str] = None
    references: Optional[List[str]] = None


def _iter_python_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() == ".py":
            yield root
        return

    for path in root.rglob("*.py"):
        parts_lower = {p.lower() for p in path.parts}
        if any(
            skip in parts_lower
            for skip in {
                ".venv",
                "venv",
                "__pycache__",
                "site-packages",
                "node_modules",
                ".git",
                "dist",
                "build",
            }
        ):
            continue
        yield path


_OPENAPI_CANDIDATE_SUFFIXES = {".yml", ".yaml", ".json"}


def _iter_openapi_spec_files(root: Path) -> Iterable[Path]:
    """Yield likely OpenAPI/Swagger/AsyncAPI spec files.

    This is a best-effort heuristic to avoid running Spectral on every YAML/JSON.
    """
    scan_root = root if root.is_dir() else root.parent
    for path in scan_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _OPENAPI_CANDIDATE_SUFFIXES:
            continue
        parts_lower = {p.lower() for p in path.parts}
        if any(skip in parts_lower for skip in _DEFAULT_EXCLUDE_DIRS):
            continue
        try:
            # Avoid huge files.
            if path.stat().st_size > 2_000_000:
                continue
            head = path.read_text(encoding="utf-8", errors="replace")[:200_000]
        except Exception:
            continue

        # Common markers.
        if any(m in head for m in ("openapi:", "swagger:", '"openapi"', '"swagger"', "asyncapi:")):
            yield path


_DEFAULT_EXCLUDE_DIRS = {
    ".venv",
    "venv",
    "__pycache__",
    "site-packages",
    "node_modules",
    ".git",
    "dist",
    "build",
}


def _severity_normalize(value: str) -> str:
    v = (value or "").strip().lower()
    if v in {"critical", "high", "medium", "low", "info"}:
        return v
    if v in {"warn", "warning"}:
        return "medium"
    if v in {"error"}:
        return "high"
    return "info"


class _PythonAstScanner(ast.NodeVisitor):
    def __init__(self, file_path: Path, source: str):
        self.file_path = file_path
        self.source = source
        self.findings: List[CodeScanFinding] = []

    def _add(
        self,
        *,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
        node: Optional[ast.AST] = None,
        rule_id: Optional[str] = None,
        references: Optional[List[str]] = None,
    ):
        line = getattr(node, "lineno", None)
        col = getattr(node, "col_offset", None)
        self.findings.append(
            CodeScanFinding(
                tool="builtin",
                severity=_severity_normalize(severity),
                title=title,
                description=description,
                recommendation=recommendation,
                file=str(self.file_path),
                line=line,
                column=col,
                rule_id=rule_id,
                references=references,
            )
        )

    def visit_Call(self, node: ast.Call):
        fn_name = None
        if isinstance(node.func, ast.Name):
            fn_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            fn_name = node.func.attr

        # Dangerous builtins
        if fn_name in {"eval", "exec"}:
            self._add(
                severity="high",
                title=f"Use of {fn_name}()",
                description=f"Calling {fn_name}() can execute attacker-controlled code if inputs are not strictly controlled.",
                recommendation="Avoid eval/exec. Use safe parsing/dispatch; validate inputs; prefer literal_eval for basic literals.",
                node=node,
                rule_id=f"PY-{fn_name.upper()}",
                references=["https://docs.python.org/3/library/ast.html#ast.literal_eval"],
            )

        # pickle.loads / pickle.load
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "pickle" and node.func.attr in {"loads", "load"}:
                self._add(
                    severity="high",
                    title="Unsafe deserialization (pickle)",
                    description="pickle can execute arbitrary code during deserialization when given untrusted input.",
                    recommendation="Never unpickle untrusted data. Use a safe format (JSON) or signed/verified payloads.",
                    node=node,
                    rule_id="PY-PICKLE",
                    references=["https://docs.python.org/3/library/pickle.html"],
                )

        # yaml.load without SafeLoader
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id in {"yaml", "ruamel"} and node.func.attr == "load":
                has_loader = False
                for kw in node.keywords:
                    if kw.arg in {"Loader", "loader"}:
                        has_loader = True
                        break
                if not has_loader:
                    self._add(
                        severity="high",
                        title="Potential unsafe YAML load",
                        description="yaml.load() without an explicit safe loader can construct arbitrary Python objects.",
                        recommendation="Use yaml.safe_load() (or SafeLoader) for untrusted YAML.",
                        node=node,
                        rule_id="PY-YAML-LOAD",
                        references=["https://pyyaml.org/wiki/PyYAMLDocumentation"],
                    )

        # subprocess with shell=True
        if fn_name in {"Popen", "call", "run", "check_call", "check_output"}:
            is_subprocess = isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
            if is_subprocess:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self._add(
                            severity="high",
                            title="subprocess with shell=True",
                            description="Using shell=True increases risk of command injection when command contains untrusted input.",
                            recommendation="Avoid shell=True. Pass args as a list; validate/escape inputs; use shlex.quote only as last resort.",
                            node=node,
                            rule_id="PY-SUBPROCESS-SHELL",
                            references=["https://docs.python.org/3/library/subprocess.html#security-considerations"],
                        )

        # Weak hashes (md5/sha1)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib" and node.func.attr in {"md5", "sha1"}:
                self._add(
                    severity="medium",
                    title=f"Weak hash function: hashlib.{node.func.attr}()",
                    description="MD5/SHA1 are considered weak for security uses (collision attacks).",
                    recommendation="Use SHA-256+ for integrity, and use dedicated password hashing (bcrypt/scrypt/argon2) for passwords.",
                    node=node,
                    rule_id="PY-WEAK-HASH",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
                )

        # requests(..., verify=False)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "requests" and node.func.attr in {"get", "post", "put", "delete", "head", "request", "patch"}:
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        self._add(
                            severity="high",
                            title="TLS verification disabled (requests verify=False)",
                            description="Disabling certificate verification enables MITM attacks and breaks transport security.",
                            recommendation="Remove verify=False and fix cert chain properly; if needed, pass a CA bundle instead of disabling verification.",
                            node=node,
                            rule_id="PY-TLS-NOVERIFY",
                            references=["https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification"],
                        )

        # ssl._create_unverified_context
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "ssl" and node.func.attr == "_create_unverified_context":
                self._add(
                    severity="high",
                    title="TLS verification disabled (ssl._create_unverified_context)",
                    description="Creating an unverified SSL context disables certificate validation.",
                    recommendation="Use the default verified context and install/configure trusted CAs. Avoid _create_unverified_context in production.",
                    node=node,
                    rule_id="PY-SSL-UNVERIFIED",
                )

        self.generic_visit(node)


_SECRET_REGEXES: List[Tuple[str, re.Pattern[str], str]] = [
    (
        "PY-SECRET-AWS",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Possible AWS Access Key ID. Remove secrets from source; rotate keys; use env vars / secret manager.",
    ),
    (
        "PY-SECRET-GITHUB",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "Possible GitHub personal access token. Revoke/rotate and move to secrets storage.",
    ),
    (
        "PY-SECRET-GENERIC",
        re.compile(r"(?i)(api_key|apikey|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        "Possible hardcoded secret. Move to env vars/secret manager; rotate if exposed.",
    ),
]


def _scan_secrets_text(file_path: Path, text: str) -> List[CodeScanFinding]:
    findings: List[CodeScanFinding] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        for rule_id, rx, recommendation in _SECRET_REGEXES:
            if rx.search(line):
                findings.append(
                    CodeScanFinding(
                        tool="builtin",
                        severity="high" if rule_id != "PY-SECRET-GENERIC" else "medium",
                        title="Possible hardcoded secret",
                        description="A pattern matched a likely credential/secret in source code.",
                        recommendation=recommendation,
                        file=str(file_path),
                        line=idx,
                        column=None,
                        rule_id=rule_id,
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
                        ],
                    )
                )
    return findings


def scan_python_builtin(root: Path) -> List[CodeScanFinding]:
    findings: List[CodeScanFinding] = []
    for py_file in _iter_python_files(root):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        findings.extend(_scan_secrets_text(py_file, source))

        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        scanner = _PythonAstScanner(py_file, source)
        scanner.visit(tree)
        findings.extend(scanner.findings)

    return findings


def _run_subprocess_json(cmd: List[str], cwd: Optional[Path] = None, timeout_s: int = 180) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except Exception as e:
        return None, str(e)

    if proc.returncode not in (0, 1, 2):
        return None, proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}"

    out = (proc.stdout or "").strip()
    if not out:
        return None, proc.stderr.strip() or "No output"

    try:
        return json.loads(out), None
    except Exception:
        return None, "Failed to parse JSON output"


def _run_subprocess_json_any(cmd: List[str], cwd: Optional[Path] = None, timeout_s: int = 180) -> Tuple[Optional[Any], Optional[str]]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except Exception as e:
        return None, str(e)

    if proc.returncode not in (0, 1, 2):
        return None, proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}"

    out = (proc.stdout or "").strip()
    if not out:
        return None, proc.stderr.strip() or "No output"

    try:
        return json.loads(out), None
    except Exception:
        return None, "Failed to parse JSON output"


def scan_with_bandit(root: Path, python_exe: str) -> Tuple[List[CodeScanFinding], Optional[str]]:
    # Prefer running via module for venv consistency
    cmd = [python_exe, "-m", "bandit", "-r", str(root), "-f", "json"]
    data, err = _run_subprocess_json(cmd, cwd=root if root.is_dir() else root.parent)
    if err or not data:
        return [], err

    findings: List[CodeScanFinding] = []
    for item in data.get("results", []) or []:
        findings.append(
            CodeScanFinding(
                tool="bandit",
                severity=_severity_normalize(item.get("issue_severity", "info")),
                title=item.get("issue_text", "Bandit finding"),
                description=item.get("issue_text", ""),
                recommendation=item.get("issue_text", "Review and remediate the finding."),
                file=item.get("filename"),
                line=item.get("line_number"),
                column=item.get("col_offset"),
                rule_id=item.get("test_id"),
                references=[item.get("more_info")] if item.get("more_info") else None,
            )
        )
    return findings, None


def scan_with_snyk_code(root: Path) -> Tuple[List[CodeScanFinding], Optional[str]]:
    snyk = shutil.which("snyk")
    if not snyk:
        return [], "snyk CLI not found"

    # Snyk may require auth; caller can decide to enable.
    cmd = [snyk, "code", "test", "--json", "--path", str(root)]
    data, err = _run_subprocess_json(cmd, cwd=root if root.is_dir() else root.parent, timeout_s=600)
    if err or not data:
        return [], err

    findings: List[CodeScanFinding] = []
    for result in data.get("runs", []) or []:
        tool_info = ((result.get("tool") or {}).get("driver") or {}).get("name") or "snyk"
        for issue in (result.get("results") or []):
            rule_id = (issue.get("ruleId") or issue.get("rule", {}) or {}).get("id")
            level = (issue.get("level") or "info").lower()
            msg = ((issue.get("message") or {}).get("text") if isinstance(issue.get("message"), dict) else issue.get("message"))
            locs = issue.get("locations") or []
            file_path = None
            line = None
            col = None
            if locs:
                phys = (locs[0].get("physicalLocation") or {})
                art = (phys.get("artifactLocation") or {})
                file_path = art.get("uri")
                region = (phys.get("region") or {})
                line = region.get("startLine")
                col = region.get("startColumn")

            findings.append(
                CodeScanFinding(
                    tool=tool_info,
                    severity=_severity_normalize(level),
                    title=msg or "Snyk Code finding",
                    description=msg or "",
                    recommendation="Review the finding and apply the suggested fix in Snyk output.",
                    file=file_path,
                    line=line,
                    column=col,
                    rule_id=rule_id,
                    references=None,
                )
            )

    return findings, None


def scan_with_pip_audit(root: Path, python_exe: str) -> Tuple[List[CodeScanFinding], Optional[str]]:
    # Prefer requirements.txt if present; otherwise audit current environment.
    req = None
    for candidate in [
        root / "requirements.txt",
        root / "requirements.in",
    ]:
        if candidate.exists() and candidate.is_file():
            req = candidate
            break

    cmd = [python_exe, "-m", "pip_audit", "-f", "json"]
    if req:
        cmd.extend(["-r", str(req)])

    data, err = _run_subprocess_json(cmd, cwd=root if root.is_dir() else root.parent, timeout_s=600)
    if err or data is None:
        return [], err

    findings: List[CodeScanFinding] = []
    # pip-audit JSON is typically a list of dependency entries.
    if isinstance(data, list):
        for dep in data:
            if not isinstance(dep, dict):
                continue
            name = dep.get("name")
            version = dep.get("version")
            vulns = dep.get("vulns") or []
            for v in vulns:
                vuln_id = v.get("id") or v.get("aliases", [None])[0]
                fix_versions = v.get("fix_versions") or []
                rec = "Upgrade to a fixed version" + (f" (e.g. {fix_versions[0]})" if fix_versions else "")
                findings.append(
                    CodeScanFinding(
                        tool="pip-audit",
                        severity="high",
                        title=f"Vulnerable dependency: {name} {version}",
                        description=(v.get("description") or "Dependency vulnerability reported by pip-audit."),
                        recommendation=rec,
                        file=str(req) if req else None,
                        line=None,
                        column=None,
                        rule_id=vuln_id,
                        references=[v.get("url")] if v.get("url") else None,
                    )
                )

    return findings, None


def scan_with_semgrep(
    root: Path,
    *,
    configs: Optional[List[str]] = None,
    timeout_s: int = 900,
) -> Tuple[List[CodeScanFinding], Optional[str]]:
    semgrep = shutil.which("semgrep")
    if not semgrep:
        return [], "semgrep CLI not found"

    scan_root = root if root.is_dir() else root.parent
    cfgs = configs or ["p/security-audit", "p/owasp-top-ten"]

    cmd: List[str] = [semgrep, "scan", "--json", "--quiet", "--disable-version-check"]
    for c in cfgs:
        cmd.extend(["--config", c])
    for d in sorted(_DEFAULT_EXCLUDE_DIRS):
        cmd.extend(["--exclude", d])
    cmd.append(str(root))

    data, err = _run_subprocess_json_any(cmd, cwd=scan_root, timeout_s=timeout_s)
    if err or not isinstance(data, dict):
        return [], err

    results = data.get("results") or []
    if not isinstance(results, list):
        return [], None

    findings: List[CodeScanFinding] = []
    for r in results:
        if not isinstance(r, dict):
            continue

        check_id = r.get("check_id")
        path = r.get("path")
        start = r.get("start") or {}
        extra = r.get("extra") or {}

        severity = extra.get("severity") or "info"
        message = extra.get("message") or (extra.get("metadata") or {}).get("shortDescription") or check_id or "Semgrep finding"
        fix = extra.get("fix")

        recommendation = "Review the finding and refactor to a safe pattern (validate inputs, avoid dangerous APIs)."
        if isinstance(fix, str) and fix.strip():
            recommendation = f"Suggested fix: {fix.strip()}"

        refs: Optional[List[str]] = None
        meta = extra.get("metadata") or {}
        if isinstance(meta, dict):
            links = meta.get("references") or meta.get("reference")
            if isinstance(links, list):
                refs = [str(x) for x in links if x]
            elif isinstance(links, str) and links:
                refs = [links]

        findings.append(
            CodeScanFinding(
                tool="semgrep",
                severity=_severity_normalize(str(severity)),
                title=str(message),
                description=str(message),
                recommendation=recommendation,
                file=str(path) if path else None,
                line=start.get("line"),
                column=start.get("col"),
                rule_id=str(check_id) if check_id else None,
                references=refs,
            )
        )

    return findings, None


def scan_with_gitleaks(root: Path, *, timeout_s: int = 900) -> Tuple[List[CodeScanFinding], Optional[str]]:
    gitleaks = shutil.which("gitleaks")
    if not gitleaks:
        return [], "gitleaks CLI not found"

    scan_root = root if root.is_dir() else root.parent
    fd, report_path = tempfile.mkstemp(prefix="scorpion-gitleaks-", suffix=".json")
    os.close(fd)
    try:
        cmd = [
            gitleaks,
            "detect",
            "--no-git",
            "--source",
            str(scan_root),
            "--report-format",
            "json",
            "--report-path",
            report_path,
            "--redact",
        ]
        proc = subprocess.run(
            cmd,
            cwd=str(scan_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        if proc.returncode not in (0, 1):
            return [], (proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}")

        try:
            raw = Path(report_path).read_text(encoding="utf-8", errors="replace").strip()
        except Exception as e:
            return [], str(e)

        if not raw:
            return [], None

        try:
            data = json.loads(raw)
        except Exception:
            return [], "Failed to parse gitleaks JSON report"

        if not isinstance(data, list):
            return [], None

        findings: List[CodeScanFinding] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            rule_id = item.get("RuleID") or item.get("Rule")
            desc = item.get("Description") or "Secret detected"
            file_path = item.get("File")
            line = item.get("StartLine")
            col = item.get("StartColumn")

            findings.append(
                CodeScanFinding(
                    tool="gitleaks",
                    severity="high",
                    title="Potential secret in source",
                    description=str(desc),
                    recommendation=(
                        "Remove the secret from source control, rotate/revoke it, and store it in a secret manager/env vars. "
                        "Also purge it from git history if it was committed."
                    ),
                    file=str(file_path) if file_path else None,
                    line=int(line) if isinstance(line, int) else None,
                    column=int(col) if isinstance(col, int) else None,
                    rule_id=str(rule_id) if rule_id else None,
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
                )
            )
        return findings, None
    finally:
        try:
            Path(report_path).unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass


def scan_with_npm_audit(root: Path, *, timeout_s: int = 600) -> Tuple[List[CodeScanFinding], Optional[str]]:
    npm = shutil.which("npm")
    if not npm:
        return [], "npm not found"

    scan_root = root if root.is_dir() else root.parent
    package_json = scan_root / "package.json"
    if not package_json.exists():
        return [], "package.json not found (npm audit skipped)"

    cmd = [npm, "audit", "--json"]
    data, err = _run_subprocess_json_any(cmd, cwd=scan_root, timeout_s=timeout_s)
    if err:
        return [], err
    if not isinstance(data, dict):
        return [], None

    findings: List[CodeScanFinding] = []

    vulns = data.get("vulnerabilities")
    if isinstance(vulns, dict):
        for pkg, info in vulns.items():
            if not isinstance(info, dict):
                continue
            severity = info.get("severity") or "info"
            via = info.get("via") or []
            if not via:
                continue
            for v in via:
                if isinstance(v, str):
                    title = v
                    rule_id = None
                    description = v
                    url = None
                elif isinstance(v, dict):
                    title = v.get("title") or v.get("name") or f"Vulnerability in {pkg}"
                    rule_id = v.get("source") or v.get("id")
                    description = v.get("title") or v.get("url") or "Dependency vulnerability"
                    url = v.get("url")
                else:
                    continue

                findings.append(
                    CodeScanFinding(
                        tool="npm-audit",
                        severity=_severity_normalize(str(severity)),
                        title=str(title),
                        description=str(description),
                        recommendation="Upgrade the dependency to a non-vulnerable version (use `npm audit fix` cautiously and review changes).",
                        file=str(package_json),
                        line=None,
                        column=None,
                        rule_id=str(rule_id) if rule_id else None,
                        references=[url] if url else None,
                    )
                )
        return findings, None

    advisories = data.get("advisories")
    if isinstance(advisories, dict):
        for _, adv in advisories.items():
            if not isinstance(adv, dict):
                continue
            severity = adv.get("severity") or "info"
            module_name = adv.get("module_name")
            title = adv.get("title") or f"Vulnerability in {module_name}"
            url = adv.get("url")
            findings.append(
                CodeScanFinding(
                    tool="npm-audit",
                    severity=_severity_normalize(str(severity)),
                    title=str(title),
                    description=str(adv.get("overview") or title),
                    recommendation="Upgrade the dependency to a fixed version and re-run npm audit.",
                    file=str(package_json),
                    line=None,
                    column=None,
                    rule_id=str(
                        (adv.get("cves", [None])[0] if isinstance(adv.get("cves"), list) and adv.get("cves") else adv.get("id"))
                    )
                    if (adv.get("id") or adv.get("cves"))
                    else None,
                    references=[url] if url else None,
                )
            )

    return findings, None


def scan_with_osv_scanner(root: Path, *, timeout_s: int = 900) -> Tuple[List[CodeScanFinding], Optional[str]]:
    osv = shutil.which("osv-scanner") or shutil.which("osv-scanner.exe")
    if not osv:
        return [], "osv-scanner not found"

    scan_root = root if root.is_dir() else root.parent

    # Best-effort JSON output. osv-scanner behavior varies by version.
    # Common flags: --format json, --recursive/-r
    cmd = [osv, "--format", "json", "--recursive", str(scan_root)]
    data, err = _run_subprocess_json_any(cmd, cwd=scan_root, timeout_s=timeout_s)
    if err:
        # Try fallback flag (-r) for older versions.
        cmd_fallback = [osv, "--format", "json", "-r", str(scan_root)]
        data, err = _run_subprocess_json_any(cmd_fallback, cwd=scan_root, timeout_s=timeout_s)
        if err:
            return [], err

    if not isinstance(data, dict):
        return [], None

    findings: List[CodeScanFinding] = []

    results = data.get("results")
    if not isinstance(results, list):
        return [], None

    for r in results:
        if not isinstance(r, dict):
            continue
        source = r.get("source") or {}
        src_path = None
        if isinstance(source, dict):
            src_path = source.get("path")

        packages = r.get("packages") or []
        if not isinstance(packages, list):
            continue
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            pkg_name = pkg.get("package") or pkg.get("name")
            pkg_version = pkg.get("version")
            vulns = pkg.get("vulnerabilities") or []
            if not isinstance(vulns, list):
                continue
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("id")
                summary = v.get("summary") or v.get("details") or "Dependency vulnerability reported by OSV"
                refs = []
                for ref in (v.get("references") or []):
                    if isinstance(ref, dict) and ref.get("url"):
                        refs.append(str(ref.get("url")))
                refs_out = refs or None
                findings.append(
                    CodeScanFinding(
                        tool="osv-scanner",
                        severity="high",
                        title=f"Vulnerable dependency: {pkg_name} {pkg_version}" if pkg_name else "Vulnerable dependency",
                        description=str(summary),
                        recommendation="Upgrade to a fixed version and re-run the scan. If no fix exists, consider mitigations or dependency replacement.",
                        file=str(src_path) if src_path else None,
                        line=None,
                        column=None,
                        rule_id=str(vuln_id) if vuln_id else None,
                        references=refs_out,
                    )
                )

    return findings, None


def scan_with_trivy_fs(root: Path, *, timeout_s: int = 900) -> Tuple[List[CodeScanFinding], Optional[str]]:
    trivy = shutil.which("trivy") or shutil.which("trivy.exe")
    if not trivy:
        return [], "trivy not found"

    scan_root = root if root.is_dir() else root.parent
    cmd = [trivy, "fs", "--format", "json", "--quiet", str(scan_root)]
    data, err = _run_subprocess_json_any(cmd, cwd=scan_root, timeout_s=timeout_s)
    if err:
        return [], err
    if not isinstance(data, dict):
        return [], None

    findings: List[CodeScanFinding] = []
    results = data.get("Results")
    if not isinstance(results, list):
        return [], None

    for r in results:
        if not isinstance(r, dict):
            continue
        target = r.get("Target")

        vulns = r.get("Vulnerabilities") or []
        if isinstance(vulns, list):
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                vid = v.get("VulnerabilityID")
                pkg = v.get("PkgName")
                installed = v.get("InstalledVersion")
                fixed = v.get("FixedVersion")
                sev = v.get("Severity") or "info"
                title = v.get("Title") or f"{vid} in {pkg}" if vid and pkg else "Dependency vulnerability"
                desc = v.get("Description") or title
                refs = v.get("References")
                rec = "Upgrade to a fixed version" + (f" (e.g. {fixed})" if fixed else "")
                findings.append(
                    CodeScanFinding(
                        tool="trivy",
                        severity=_severity_normalize(str(sev)),
                        title=str(title),
                        description=str(desc),
                        recommendation=rec,
                        file=str(target) if target else None,
                        line=None,
                        column=None,
                        rule_id=str(vid) if vid else None,
                        references=[str(x) for x in refs if x] if isinstance(refs, list) else None,
                    )
                )

        misconfigs = r.get("Misconfigurations") or []
        if isinstance(misconfigs, list):
            for m in misconfigs:
                if not isinstance(m, dict):
                    continue
                mid = m.get("ID")
                title = m.get("Title") or m.get("Description") or "Misconfiguration"
                sev = m.get("Severity") or "info"
                primary_url = m.get("PrimaryURL")
                msg = m.get("Message") or m.get("Cause") or title
                rec = m.get("Resolution") or "Apply the recommended configuration hardening and re-scan."
                findings.append(
                    CodeScanFinding(
                        tool="trivy",
                        severity=_severity_normalize(str(sev)),
                        title=str(title),
                        description=str(msg),
                        recommendation=str(rec),
                        file=str(target) if target else None,
                        line=None,
                        column=None,
                        rule_id=str(mid) if mid else None,
                        references=[str(primary_url)] if primary_url else None,
                    )
                )

    return findings, None


def scan_with_spectral(
    root: Path,
    *,
    ruleset: Optional[str] = None,
    timeout_s: int = 600,
) -> Tuple[List[CodeScanFinding], Optional[str]]:
    spectral = shutil.which("spectral")
    if not spectral:
        return [], "spectral CLI not found"

    spec_files = list(_iter_openapi_spec_files(root))
    if not spec_files:
        return [], "No OpenAPI/Swagger/AsyncAPI spec files found (Spectral skipped)"

    scan_root = root if root.is_dir() else root.parent

    cmd: List[str] = [spectral, "lint"]
    if ruleset:
        cmd.extend(["--ruleset", ruleset])
    cmd.extend(["-f", "json"])
    cmd.extend([str(p) for p in spec_files])

    data, err = _run_subprocess_json_any(cmd, cwd=scan_root, timeout_s=timeout_s)
    if err:
        return [], err

    # Spectral typically returns a list of results.
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        results_any: Any = data.get("results")
    else:
        results_any = data

    if not isinstance(results_any, list):
        return [], None

    sev_map = {
        0: "high",  # error
        1: "medium",  # warn
        2: "low",  # info
        3: "info",  # hint
    }

    findings: List[CodeScanFinding] = []
    for item in results_any:
        if not isinstance(item, dict):
            continue

        code = item.get("code")
        message = item.get("message") or "Spectral issue"
        src = item.get("source")
        path = item.get("path")  # JSON pointer within spec
        rng = item.get("range") or {}
        start = (rng.get("start") or {}) if isinstance(rng, dict) else {}
        # Spectral ranges are typically 0-based.
        line0 = start.get("line")
        col0 = start.get("character")

        severity_num = item.get("severity")
        severity = sev_map.get(int(severity_num), "info") if isinstance(severity_num, int) else "info"

        title = str(message)
        if path:
            title = f"{title} ({path})"

        findings.append(
            CodeScanFinding(
                tool="spectral",
                severity=_severity_normalize(str(severity)),
                title=title,
                description=str(message),
                recommendation=(
                    "Fix the OpenAPI/AsyncAPI specification issue and re-lint. "
                    "Prefer aligning with OpenAPI best practices and keeping schemas/response codes consistent."
                ),
                file=str(src) if src else None,
                line=int(line0) + 1 if isinstance(line0, int) else None,
                column=int(col0) if isinstance(col0, int) else None,
                rule_id=str(code) if code else None,
                references=["https://meta.stoplight.io/docs/spectral"],
            )
        )

    return findings, None


def scan_with_checkov(
    root: Path,
    *,
    frameworks: Optional[List[str]] = None,
    timeout_s: int = 900,
) -> Tuple[List[CodeScanFinding], Optional[str]]:
    """Run Checkov locally for IaC misconfig scanning (Terraform/K8s/etc).

    This is a defensive, local filesystem scan; it does not probe external targets.
    """
    checkov = shutil.which("checkov")
    if not checkov:
        return [], "checkov CLI not found"

    scan_root = root if root.is_dir() else root.parent
    cmd: List[str] = [checkov, "-d", str(scan_root), "-o", "json", "--quiet"]
    if frameworks:
        # Comma-separated list expected by Checkov.
        fw = ",".join([f.strip() for f in frameworks if f and f.strip()])
        if fw:
            cmd.extend(["--framework", fw])

    data, err = _run_subprocess_json_any(cmd, cwd=scan_root, timeout_s=timeout_s)
    if err:
        return [], err
    if not isinstance(data, dict):
        return [], None

    results = data.get("results") or {}
    failed = None
    if isinstance(results, dict):
        failed = results.get("failed_checks")
    if failed is None:
        # Some versions may return a top-level list; best-effort.
        failed = data.get("failed_checks")

    if not isinstance(failed, list):
        return [], None

    findings: List[CodeScanFinding] = []
    for item in failed:
        if not isinstance(item, dict):
            continue

        check_id = item.get("check_id")
        check_name = item.get("check_name") or "IaC misconfiguration"
        file_path = item.get("file_path")
        guideline = item.get("guideline")
        line_range = item.get("file_line_range")

        line = None
        if isinstance(line_range, list) and line_range:
            start = line_range[0]
            if isinstance(start, int) and start > 0:
                line = start

        sev_raw = item.get("severity") or item.get("Severity")
        severity = _severity_normalize(str(sev_raw)) if isinstance(sev_raw, str) else "medium"

        findings.append(
            CodeScanFinding(
                tool="checkov",
                severity=severity,
                title=str(check_name),
                description=str(item.get("description") or check_name),
                recommendation="Apply the recommended IaC hardening for this check and re-run Checkov.",
                file=str(file_path) if file_path else None,
                line=line,
                column=None,
                rule_id=str(check_id) if check_id else None,
                references=[str(guideline)] if guideline else None,
            )
        )

    return findings, None


def build_sarif_report(*, target_root: Path, findings: List[CodeScanFinding]) -> Dict[str, Any]:
    # SARIF 2.1.0 minimal, compatible with GitHub Code Scanning.
    def _to_uri(file_path: Optional[str]) -> Optional[str]:
        if not file_path:
            return None
        try:
            p = Path(file_path)
            # Try to make path relative to target_root when possible.
            rel = p.resolve().relative_to(target_root)
            return rel.as_posix()
        except Exception:
            return str(file_path).replace("\\", "/")

    rules_by_key: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_key = (f.rule_id or f.title or "FINDING").strip()
        if rule_key not in rules_by_key:
            rules_by_key[rule_key] = {
                "id": rule_key,
                "name": rule_key,
                "shortDescription": {"text": f.title or rule_key},
                "fullDescription": {"text": f.description or f.title or rule_key},
                "help": {"text": f.recommendation or ""},
                "properties": {
                    "tags": ["security"],
                    "precision": "medium",
                    "security-severity": "8.0" if _severity_normalize(f.severity) in {"critical", "high"} else "5.0",
                },
            }

        level = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }.get(_severity_normalize(f.severity), "note")

        location = None
        uri = _to_uri(f.file)
        if uri:
            region: Dict[str, Any] = {}
            if isinstance(f.line, int) and f.line > 0:
                region["startLine"] = f.line
            if isinstance(f.column, int) and f.column >= 0:
                region["startColumn"] = f.column + 1
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": region if region else None,
                }
            }
            if location["physicalLocation"].get("region") is None:
                location["physicalLocation"].pop("region", None)

        res: Dict[str, Any] = {
            "ruleId": rule_key,
            "level": level,
            "message": {"text": f.title or rule_key},
        }
        if location:
            res["locations"] = [location]
        results.append(res)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scorpion-code-scan",
                        "informationUri": "https://github.com/Prince12sam/Scorpion",
                        "rules": list(rules_by_key.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def build_code_scan_report(
    *,
    target_path: str,
    python_exe: str,
    enable_bandit: bool,
    enable_pip_audit: bool,
    enable_snyk: bool,
    enable_semgrep: bool = False,
    semgrep_configs: Optional[List[str]] = None,
    enable_gitleaks: bool = False,
    enable_npm_audit: bool = False,
    enable_osv_scanner: bool = False,
    enable_trivy: bool = False,
    enable_spectral: bool = False,
    spectral_ruleset: Optional[str] = None,
    enable_checkov: bool = False,
    checkov_frameworks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    root = Path(target_path).resolve()
    findings: List[CodeScanFinding] = []
    notes: List[str] = []

    findings.extend(scan_python_builtin(root))

    if enable_bandit:
        bandit_findings, bandit_err = scan_with_bandit(root, python_exe=python_exe)
        if bandit_err:
            notes.append(f"Bandit unavailable/failed: {bandit_err}. Install with: pip install bandit")
        findings.extend(bandit_findings)

    if enable_pip_audit:
        pa_findings, pa_err = scan_with_pip_audit(root, python_exe=python_exe)
        if pa_err:
            notes.append(f"pip-audit unavailable/failed: {pa_err}. Install with: pip install pip-audit")
        findings.extend(pa_findings)

    if enable_snyk:
        snyk_findings, snyk_err = scan_with_snyk_code(root)
        if snyk_err:
            notes.append(f"Snyk Code unavailable/failed: {snyk_err}. Install/auth Snyk CLI to enable.")
        findings.extend(snyk_findings)

    if enable_semgrep:
        sg_findings, sg_err = scan_with_semgrep(root, configs=semgrep_configs)
        if sg_err:
            notes.append(
                f"Semgrep unavailable/failed: {sg_err}. Install with: pip install semgrep (or see https://semgrep.dev)"
            )
        findings.extend(sg_findings)

    if enable_gitleaks:
        gl_findings, gl_err = scan_with_gitleaks(root)
        if gl_err:
            notes.append(f"Gitleaks unavailable/failed: {gl_err}. Install from: https://github.com/gitleaks/gitleaks")
        findings.extend(gl_findings)

    if enable_npm_audit:
        na_findings, na_err = scan_with_npm_audit(root)
        if na_err and "skipped" not in na_err.lower():
            notes.append(f"npm audit unavailable/failed: {na_err}.")
        findings.extend(na_findings)

    if enable_osv_scanner:
        osv_findings, osv_err = scan_with_osv_scanner(root)
        if osv_err:
            notes.append(
                f"OSV-Scanner unavailable/failed: {osv_err}. Install from: https://google.github.io/osv-scanner/"
            )
        findings.extend(osv_findings)

    if enable_trivy:
        trivy_findings, trivy_err = scan_with_trivy_fs(root)
        if trivy_err:
            notes.append(f"Trivy unavailable/failed: {trivy_err}. Install from: https://aquasecurity.github.io/trivy/")
        findings.extend(trivy_findings)

    if enable_spectral:
        sp_findings, sp_err = scan_with_spectral(root, ruleset=spectral_ruleset)
        if sp_err:
            notes.append(
                f"Spectral unavailable/failed: {sp_err}. Install from: https://github.com/stoplightio/spectral (CLI: @stoplight/spectral-cli)"
            )
        findings.extend(sp_findings)

    if enable_checkov:
        ck_findings, ck_err = scan_with_checkov(root, frameworks=checkov_frameworks)
        if ck_err:
            notes.append(
                f"Checkov unavailable/failed: {ck_err}. Install with: pip install checkov (or see https://www.checkov.io)"
            )
        findings.extend(ck_findings)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = _severity_normalize(f.severity)
        counts[sev] = counts.get(sev, 0) + 1

    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings_sorted = sorted(
        findings,
        key=lambda f: (
            -sev_rank.get(_severity_normalize(f.severity), 0),
            str(f.file or ""),
            int(f.line or 0),
            str(f.tool or ""),
            str(f.rule_id or ""),
        ),
    )

    return {
        "target_path": str(root),
        "summary": {
            "total_findings": len(findings_sorted),
            "by_severity": counts,
            "tools": sorted({f.tool for f in findings_sorted} | {"builtin"}),
        },
        "notes": notes,
        "findings": [asdict(f) for f in findings_sorted],
    }

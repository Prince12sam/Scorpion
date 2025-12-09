import json
from typing import Any, Dict, List


def _h(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _section(title: str, content_html: str) -> str:
    return f"""
    <section>
      <h2>{_h(title)}</h2>
      {content_html}
    </section>
    """


def _table(headers, rows) -> str:
    thead = "".join(f"<th>{_h(h)}</th>" for h in headers)
    trs = []
    for r in rows:
        tds = "".join(f"<td>{_h(str(c))}</td>" for c in r)
        trs.append(f"<tr>{tds}</tr>")
    return f"<table><thead><tr>{thead}</tr></thead><tbody>{''.join(trs)}</tbody></table>"


def _render_scan(scan: Dict[str, Any]) -> str:
    results = scan.get("results", [])
    rows = [(r.get("port"), r.get("state"), r.get("reason", "")) for r in results]
    return _table(["Port", "State", "Reason"], rows)


def _render_ssl(ssl: Dict[str, Any]) -> str:
    cert = ssl.get("certificate") or {}
    tls = ssl.get("tls") or {}
    headers = ssl.get("security_headers") or {}
    parts = [
        f"<p><b>Severity:</b> {_h(str(ssl.get('severity')))}</p>",
        f"<p><b>Version:</b> {_h(str(tls.get('version')))} | <b>Cipher:</b> {_h(str(tls.get('cipher')))}</p>",
        f"<p><b>Cert:</b> {_h(str(cert.get('subject')))} | <b>Issuer:</b> {_h(str(cert.get('issuer')))} | <b>Expires:</b> {_h(str(cert.get('expires')))}</p>",
        f"<p><b>HSTS:</b> {_h(str(headers.get('hsts')))} | <b>Insecure fetch:</b> {_h(str(headers.get('insecure_fetch')))}</p>",
    ]
    if ssl.get("remediation"):
        rem = "".join(f"<li>{_h(x)}</li>" for x in ssl["remediation"])
        parts.append(f"<ul class='remediation'>{rem}</ul>")
    return "\n".join(parts)


def _render_takeover(tk: Dict[str, Any]) -> str:
    dns = tk.get("dns", {})
    http = tk.get("http", {})
    parts = [
        f"<p><b>Vulnerable:</b> {_h(str(tk.get('vulnerable')))} | <b>Service:</b> {_h(str(dns.get('service')))} | <b>CNAME:</b> {_h(str(dns.get('cname')))}</p>",
        f"<p><b>HTTP Status:</b> {_h(str(http.get('status_code')))}</p>",
    ]
    if tk.get("remediation"):
        rem = "".join(f"<li>{_h(x)}</li>" for x in tk["remediation"]) 
        parts.append(f"<ul class='remediation'>{rem}</ul>")
    return "\n".join(parts)


def _render_api(api: Dict[str, Any]) -> str:
    findings = api.get("findings", [])
    rows = [(f.get("type"), f.get("severity"), f.get("location")) for f in findings]
    return _table(["Type", "Severity", "Location"], rows)


def _render_recon(rc: Dict[str, Any]) -> str:
    dns = rc.get("dns", {})
    http = rc.get("http", {})
    rows = []
    for rtype, vals in dns.items():
        rows.append((f"DNS {rtype}", ", ".join(vals)))
    rows.append(("HTTP Status", http.get("status_code")))
    rows.append(("Server", http.get("server")))
    return _table(["Key", "Value"], rows)


def _render_dirb(dirb: Dict[str, Any]) -> str:
    results = dirb.get("results", [])
    pruned = [(r.get("status"), r.get("url"), r.get("length")) for r in results[:500]]
    return _table(["Status", "URL", "Length"], pruned)


def _render_tech(tech: Dict[str, Any]) -> str:
    det = tech.get("detected", [])
    rows = [(d.get("name"), d.get("evidence")) for d in det]
    return _table(["Technology", "Evidence"], rows)


def _render_crawl(crawl: Dict[str, Any]) -> str:
    rows = []
    for r in (crawl.get("results", []) or [])[:200]:
        issues = ", ".join(
            sorted({f.get("name") for f in r.get("findings", []) if f.get("type") in ("secret", "header_missing", "cors_overly_permissive") and f.get("name")})
        )
        rows.append((r.get("status"), r.get("title") or "-", r.get("url"), issues or "-"))
    tbl = _table(["Status", "Title", "URL", "Findings"], rows)
    summ = crawl.get("summary", {})
    smry_rows = [(k, v) for k, v in (summ.get("secret_counts") or {}).items()]
    smry_rows += [(f"Header Missing: {k}", v) for k, v in (summ.get("header_missing") or {}).items()]
    smry_rows += [("CORS *", summ.get("cors_overly_permissive", 0))]
    smry = _table(["Issue", "Count"], smry_rows) if smry_rows else ""
    return smry + tbl


def _render_cloud(cloud: Dict[str, Any]) -> str:
    rows_r = []
    for r in cloud.get("results", []) or []:
        rows_r.append([r.get("provider"), r.get("name"), ", ".join([str(s) for s in (r.get("status") or [])])])
    tbl_r = _table(["Provider", "Name", "HTTP Statuses"], rows_r) if rows_r else "<p>No provider responses.</p>"
    rows_f = []
    for f in cloud.get("findings", []) or []:
        rows_f.append([f.get("provider"), f.get("impact"), f.get("severity"), ", ".join(f.get("endpoints") or [])])
    tbl_f = _table(["Provider", "Impact", "Severity", "Endpoints"], rows_f) if rows_f else "<p>No cloud exposures detected.</p>"
    return tbl_f + tbl_r


def _render_k8s(k8s: Dict[str, Any]) -> str:
    rows_r = []
    for r in k8s.get("results", []) or []:
        rows_r.append([r.get("endpoint"), r.get("status")])
    tbl_r = _table(["Endpoint", "Status"], rows_r)
    rows_f = []
    for f in k8s.get("findings", []) or []:
        rows_f.append([f.get("type"), f.get("impact"), f.get("severity"), f.get("location")])
    tbl_f = _table(["Type", "Impact", "Severity", "Location"], rows_f) if rows_f else "<p>No K8s exposures detected.</p>"
    return tbl_f + tbl_r


def _render_container(container: Dict[str, Any]) -> str:
    rows_r = []
    for r in container.get("results", []) or []:
        rows_r.append([r.get("url"), r.get("status")])
    tbl_r = _table(["URL", "Status"], rows_r)
    rows_f = []
    for f in container.get("findings", []) or []:
        rows_f.append([f.get("type"), f.get("impact"), f.get("severity"), f.get("remediation")])
    tbl_f = _table(["Type", "Impact", "Severity", "Remediation"], rows_f) if rows_f else "<p>No container registry exposures detected.</p>"
    return tbl_f + tbl_r


def generate_html_report(data: Dict[str, Any]) -> str:
    target = data.get("target", "")
    ts = data.get("timestamp", "")
    profile = data.get("profile", "")
    mode = data.get("mode", "")
    summary = data.get("summary", {})

    head = f"""
    <header>
      <h1>Scorpion Report</h1>
    <p><b>Target:</b> {_h(str(target))} &nbsp; | &nbsp; <b>Profile:</b> {_h(str(profile))} &nbsp; | &nbsp; <b>Mode:</b> {_h(str(mode))} &nbsp; | &nbsp; <b>Time:</b> {_h(str(ts))}</p>
      <p><b>Open ports:</b> {_h(str(summary.get('open_ports')))} &nbsp; | &nbsp; <b>SSL severity:</b> {_h(str(summary.get('ssl_severity')))} &nbsp; | &nbsp; <b>Takeover vulnerable:</b> {_h(str(summary.get('takeover_vulnerable')))}</p>
    </header>
    """

    # Optional charts
    def _counts_by_severity(findings):
        counts: Dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _svg_bar_chart(title: str, mapping: Dict[str, int]) -> str:
        if not mapping:
            return ""
        labels = list(mapping.keys())
        values = [mapping[k] for k in labels]
        max_v = max(values) if values else 0
        if max_v == 0:
            max_v = 1
        width = 480
        height = 160
        padding = 24
        bar_w = (width - 2 * padding) / max(len(values), 1)
        # simple color palette
        palette = ["#4caf50", "#ff9800", "#f44336", "#2196f3", "#9c27b0", "#607d8b"]
        rects = []
        texts = []
        for i, (lab, val) in enumerate(zip(labels, values)):
            x = padding + i * bar_w
            h = int((height - 2 * padding) * (val / max_v))
            y = height - padding - h
            color = palette[i % len(palette)]
            rects.append(f"<rect x='{x:.1f}' y='{y}' width='{bar_w-6:.1f}' height='{h}' fill='{color}' rx='3' />")
            texts.append(f"<text x='{x + bar_w/2:.1f}' y='{height - padding + 14}' text-anchor='middle' font-size='11' fill='#aab7c2'>{_h(lab)}</text>")
            texts.append(f"<text x='{x + bar_w/2:.1f}' y='{y - 4}' text-anchor='middle' font-size='11' fill='#d5e2ea'>{val}</text>")
        title_el = f"<text x='{width/2}' y='16' text-anchor='middle' font-size='13' fill='#d5e2ea'>{_h(title)}</text>"
        axis = f"<line x1='{padding}' y1='{height - padding}' x2='{width - padding}' y2='{height - padding}' stroke='#2a3239'/>"
        svg = f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='{_h(title)}'>{title_el}{axis}{''.join(rects)}{''.join(texts)}</svg>"
        return svg

    sections = []
    if data.get("scan"):
        sections.append(_section("Port Scan", _render_scan(data["scan"])))
    if data.get("ssl"):
        sections.append(_section("SSL/TLS", _render_ssl(data["ssl"])))
    if data.get("takeover"):
        sections.append(_section("Subdomain Takeover", _render_takeover(data["takeover"])))
    if data.get("api"):
        sections.append(_section("API Findings", _render_api(data["api"])))
    if data.get("recon"):
        sections.append(_section("Recon", _render_recon(data["recon"])))
    if data.get("dirbust"):
        sections.append(_section("Dirbusting", _render_dirb(data["dirbust"])))
    if data.get("tech"):
        sections.append(_section("Technology", _render_tech(data["tech"])))
    if data.get("crawl"):
        sections.append(_section("Crawl", _render_crawl(data["crawl"])))
    if data.get("web_owasp"):
        # Render web OWASP passive findings
        def _render_web_owasp(w: Dict[str, Any]) -> str:
            rows_f = []
            for f in w.get("findings", []) or []:
                rows_f.append([f.get("name"), f.get("severity"), f.get("impact"), f.get("remediation")])
            tbl_f = _table(["Name", "Severity", "Impact", "Remediation"], rows_f) if rows_f else "<p>No OWASP passive findings.</p>"
            return tbl_f
        sections.append(_section("Web OWASP (Passive)", _render_web_owasp(data["web_owasp"])))
    if data.get("cloud"):
        sections.append(_section("Cloud Storage", _render_cloud(data["cloud"])))
    if data.get("k8s"):
        sections.append(_section("Kubernetes", _render_k8s(data["k8s"])))
    if data.get("container"):
        sections.append(_section("Container Registry", _render_container(data["container"])))

    # Charts assembly (placed after header, before sections)
    charts_html = ""
    try:
        api_counts = _counts_by_severity(data.get("api", {}).get("findings", [])) if data.get("api") else {}
        dirb_status = data.get("dirbust", {}).get("summary", {}).get("by_status", {}) if data.get("dirbust") else {}
        crawl_secret = data.get("crawl", {}).get("summary", {}).get("secret_counts", {}) if data.get("crawl") else {}
        # convert keys to human-friendly ordering for status chart
        if dirb_status:
            ordered = dict(sorted(((k, dirb_status[k]) for k in dirb_status), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 9999))
        else:
            ordered = {}
        charts = []
        if api_counts:
            charts.append(_svg_bar_chart("API Findings by Severity", api_counts))
        if ordered:
            charts.append(_svg_bar_chart("Dirbusting Results by Status", ordered))
        if crawl_secret:
            charts.append(_svg_bar_chart("Secrets Found (Crawl)", crawl_secret))
        if charts:
            charts_html = f"<section><h2>Charts</h2>{''.join(charts)}</section>"
    except Exception:
        charts_html = ""

    css = """
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.4;margin:0;padding:0;background:#0b0f12;color:#e8eef1}
    header{padding:16px 24px;background:#11161a;border-bottom:1px solid #1d252b}
    h1{margin:0 0 6px 0;font-weight:700;font-size:20px}
    h2{margin:24px 0 10px 0;font-size:18px;border-bottom:1px solid #1d252b;padding-bottom:6px}
    section{padding:0 24px}
    table{width:100%;border-collapse:collapse;margin:8px 0 18px 0}
    th,td{border-bottom:1px solid #222a31;padding:6px 8px;text-align:left;font-size:14px}
    thead th{position:sticky;top:0;background:#12181d}
    ul.remediation{margin:8px 0 0 16px}
    a{color:#77c1ff}
    """

    html = f"""
    <!doctype html>
    <html lang='en'>
      <meta charset='utf-8'>
      <meta name='viewport' content='width=device-width, initial-scale=1'>
      <title>Scorpion Report - {_h(str(target))}</title>
      <style>{css}</style>
            <body>
                {head}
                {charts_html}
                {''.join(sections)}
      </body>
    </html>
    """
    return html


def _collect_findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    # API findings
    for f in data.get("api", {}).get("findings", []) or []:
        findings.append({
            "source": "api",
            "type": f.get("type"),
            "severity": str(f.get("severity", "info")).lower(),
            "location": f.get("location"),
        })
    # SSL severity
    if data.get("ssl"):
        sev = str(data["ssl"].get("severity", "info")).lower()
        if sev != "info":
            findings.append({
                "source": "ssl",
                "type": "ssl_configuration",
                "severity": sev,
                "location": data["ssl"].get("location", {}).get("endpoint"),
            })
    # Takeover vulnerable
    if data.get("takeover", {}).get("vulnerable"):
        findings.append({
            "source": "takeover",
            "type": "subdomain_takeover",
            "severity": "high",
            "location": data["takeover"].get("location", {}).get("dns_record"),
        })
    # Cloud/K8s/Container findings
    for f in (data.get("cloud", {}).get("findings", []) or []):
        findings.append({
            "source": "cloud",
            "type": f.get("provider"),
            "severity": str(f.get("severity", "info")).lower(),
            "location": ", ".join(f.get("endpoints") or []),
        })
    for f in (data.get("k8s", {}).get("findings", []) or []):
        findings.append({
            "source": "k8s",
            "type": f.get("type"),
            "severity": str(f.get("severity", "info")).lower(),
            "location": f.get("location"),
        })
    for f in (data.get("container", {}).get("findings", []) or []):
        findings.append({
            "source": "container",
            "type": f.get("type"),
            "severity": str(f.get("severity", "info")).lower(),
            "location": f.get("type"),
        })
    return findings


def generate_summary_html_report(data: Dict[str, Any]) -> str:
    target = data.get("target", "")
    ts = data.get("timestamp", "")
    profile = data.get("profile", "")
    mode = data.get("mode", "")
    summary = data.get("summary", {})

    findings = _collect_findings(data)
    # Show non-info only by default
    actionable = [f for f in findings if f.get("severity") != "info"]
    if not actionable:
        actionable = findings  # fall back to all if nothing actionable

    # Dirb highlights (only interesting statuses)
    dirb_rows: List[List[Any]] = []
    for r in (data.get("dirbust", {}).get("results", []) or [])[:200]:
        s = int(r.get("status") or 0)
        if s in (200, 204, 301, 302, 401, 403):
            dirb_rows.append([s, r.get("url"), r.get("length")])

    # Build minimal HTML
    css = """
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0b0f12;color:#e8eef1;margin:0}
    header{padding:16px 24px;background:#11161a;border-bottom:1px solid #1d252b}
    h1{margin:0 0 6px 0;font-weight:700;font-size:20px}
    h2{margin:20px 24px 10px}
    section{padding:0 24px}
    table{width:100%;border-collapse:collapse;margin:8px 0 18px 0}
    th,td{border-bottom:1px solid #222a31;padding:6px 8px;text-align:left;font-size:14px}
    .pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px}
    .sev-high{background:#f44336;color:#fff}.sev-medium{background:#ff9800;color:#000}.sev-low{background:#4caf50;color:#fff}.sev-info{background:#607d8b;color:#fff}
    """

    # Findings table
    def sev_pill(sev: str) -> str:
        cls = f"sev-{sev}"
        return f"<span class='pill {cls}'>{_h(sev)}</span>"

    rows = []
    for f in actionable[:200]:
        rows.append([f.get("source"), f.get("type"), sev_pill(str(f.get("severity"))), f.get("location") or "-"])

    findings_html = _table(["Source", "Type", "Severity", "Location"], rows)
    dirb_html = _table(["Status", "URL", "Length"], dirb_rows) if dirb_rows else "<p>No interesting directories found.</p>"

    head = f"""
    <header>
      <h1>Scorpion Summary</h1>
    <p><b>Target:</b> {_h(str(target))} &nbsp; | &nbsp; <b>Profile:</b> {_h(str(profile))} &nbsp; | &nbsp; <b>Mode:</b> {_h(str(mode))} &nbsp; | &nbsp; <b>Time:</b> {_h(str(ts))}</p>
      <p><b>Open ports:</b> {_h(str(summary.get('open_ports')))} &nbsp; | &nbsp; <b>SSL severity:</b> {_h(str(summary.get('ssl_severity')))} &nbsp; | &nbsp; <b>Takeover vulnerable:</b> {_h(str(summary.get('takeover_vulnerable')))}</p>
    </header>
    """

    html = f"""
    <!doctype html>
    <html lang='en'>
      <meta charset='utf-8'>
      <meta name='viewport' content='width=device-width, initial-scale=1'>
      <title>Scorpion Summary - {_h(str(target))}</title>
      <style>{css}</style>
      <body>
        {head}
        <section>
          <h2>Actionable Findings</h2>
          {findings_html}
        </section>
        <section>
          <h2>Dirbusting (Highlights)</h2>
          {dirb_html}
        </section>
      </body>
    </html>
    """
    return html

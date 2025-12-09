import asyncio
import json
import sys
from typing import List, Optional, cast
import os
import datetime

import typer
import rich
from rich.console import Console
from rich.panel import Panel
from rich import box
PILImage = None  # Optional, if Pillow is installed
console = Console()
from rich.console import Console
from rich.table import Table
from rich import box

from .scanner import async_port_scan, async_udp_scan, async_syn_scan
from .ssl_analyzer import analyze_ssl
from .takeover import takeover_scan
from .api import api_probe
from .recon import recon
from .dirbuster import dirbust_scan
from .tech import detect_tech
from .reporter import generate_html_report, generate_summary_html_report
from .crawler import crawl as web_crawl
from .cloud import cloud_audit
from .k8s import k8s_audit
from .container_sec import container_audit
from .web_owasp import web_owasp_passive

# Remove subtitle under banner by not setting a global help description
app = typer.Typer()

@app.callback(invoke_without_command=True)
def _banner_callback(
    ctx: typer.Context,
    no_banner: bool = typer.Option(False, "--no-banner", is_flag=True, help="Suppress startup banner"),
    version: bool = typer.Option(False, "--version", is_flag=True, help="Show version and exit"),
):
    """"""
    # Only show banner when no subcommand is invoked and banner not suppressed
    if version:
        try:
            import importlib.metadata as _md
            v = _md.version("python-scorpion")
        except Exception:
            v = "unknown"
        typer.echo(v)
        raise typer.Exit()
    if ctx.invoked_subcommand is not None or no_banner:
        return
    img_paths = [
        "public/scorpion.png",
        "public/scorpion.jpg",
        "public/scorpion-banner.png",
    ]
    img_path = None
    for p in img_paths:
        try:
            import os
            if os.path.exists(p):
                img_path = p
                break
        except Exception:
            pass

    # If an image path exists, show a panel referencing it (no external deps required)
    # Note: Print the ASCII banner first, then show image reference below it if present

    ascii_banner = (
        "\n"
        "╔══════════════════════════════════════════════════════════════════════╗\n"
        "║   ███████╗ ██████╗ ██████╗ ██████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗   ║\n"
        "║   ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║██╔═══██╗████╗  ██║   ║\n"
        "║   ███████╗██║     ██║   ██║██████╔╝██████╔╝██║██║   ██║██╔██╗ ██║   ║\n"
        "║   ╚════██║██║     ██║   ██║██╔══██╗██╔═══╝ ██║██║   ██║██║╚██╗██║   ║\n"
        "║   ███████║╚██████╗╚██████╔╝██║  ██║██║     ██║╚██████╔╝██║ ╚████║   ║\n"
        "║   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ║\n"
        "║                                                                      ║\n"
        "║         Scorpion — Security Testing & Threat-Hunting CLI            ║\n"
        "╚══════════════════════════════════════════════════════════════════════╝\n"
    )
    console.print(ascii_banner, style="green")
    if img_path:
        console.print(Panel.fit(f"Scorpion Banner Image: {img_path}", title="Scorpion", border_style="green"))
    # Show CLI help beneath the banner on root invocation
    try:
        # Print help without a descriptive subtitle (already removed at app init)
        typer.echo(ctx.get_help())
    except Exception:
        pass
    # Getting Started quick tips under the help on initial launch
    quickstart = (
        "Quick Start:\n"
        "- Scan ports: scorpion scan <host> --ports 1-1024 --output results/scan_<host>.json\n"
        "- SSL analyze: scorpion ssl-analyze <host> --output results/ssl_<host>.json\n"
        "- Takeover: scorpion takeover <host> --output results/takeover_<host>.json\n"
        "- API test: scorpion api-test <url> --output results/api_<host>.json\n"
        "- Recon: scorpion recon-cmd <host> --output results/recon_<host>.json\n"
        "- Tip: suppress banner in scripts with --no-banner"
    )
    console.print(Panel.fit(quickstart, title="Getting Started", border_style="cyan", box=box.ROUNDED))
console = Console()

@app.command()
def scan(
    host: Optional[str] = typer.Argument(None, help="Target host (positional)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Alias for host (supports -t)"),
    ports: str = "1-1024",
    concurrency: int = typer.Option(200, "--concurrency", "-C", help="Concurrent probes"),
    timeout: float = typer.Option(1.0, "--timeout", "-T", help="Timeout seconds per probe"),
    retries: int = typer.Option(0, "--retries", "-R", help="Retries on timeouts (reserved)"),
    udp: bool = typer.Option(False, "--udp", "-U", help="Enable UDP scanning (best-effort)"),
    udp_ports: Optional[str] = typer.Option(None, "--udp-ports", "-u", help="UDP ports range/list; default top ports if omitted"),
    only_open: bool = typer.Option(False, "--only-open", "-O", help="Show only open ports in output"),
    raw: bool = typer.Option(False, "--raw", help="Show raw banner only; do not infer service names"),
    no_write: bool = typer.Option(False, "--no-write", help="Do not send probe bytes; connect-and-read only"),
    fast: bool = typer.Option(False, "--fast", help="Preset: --timeout 2.0 --retries 1 --concurrency 60 --only-open"),
    web: bool = typer.Option(False, "--web", help="Preset: ports 80,443,8080 and only-open"),
    infra: bool = typer.Option(False, "--infra", help="Preset: common infra ports and only-open"),
    syn: bool = typer.Option(False, "--syn", help="Attempt TCP SYN scan (requires admin/raw sockets or scapy)"),
    syn_rate: float = typer.Option(0.0, "--rate-limit", help="Limit SYN probes per second (0 = unlimited)"),
    syn_iface: str = typer.Option("", "--iface", help="Network interface name for SYN scan (Scapy)"),
    list_ifaces: bool = typer.Option(False, "--list-ifaces", help="List available interfaces for SYN scan and exit"),
    output: Optional[str] = None,
):
    """Async TCP (and optional UDP) port scan: ranges (1-1024) or lists (80,443)."""
    async def run():
        tgt = target or host
        # If user requested interface listing, show and exit
        if list_ifaces:
            try:
                from scapy.all import get_if_list
                ifaces = get_if_list()
            except Exception:
                ifaces = []
            table = Table(title="Available Interfaces", box=box.MINIMAL)
            table.add_column("Name", style="cyan")
            for i in ifaces:
                table.add_row(i)
            if not ifaces:
                console.print("No interfaces found or Scapy not installed.", style="yellow")
                console.print("Install Scapy: pip install scapy", style="yellow")
            else:
                console.print(table)
            raise typer.Exit()
        if not tgt:
            console.print("Provide a host (positional) or --target", style="red")
            raise typer.Exit(code=2)
        # apply presets
        timeout_local = timeout
        retries_local = retries
        concurrency_local = concurrency
        only_open_local = only_open
        ports_local = ports

        if fast:
            timeout_local = 2.0
            retries_local = 1
            concurrency_local = 60
            only_open_local = True
        if web:
            ports_local = "80,443,8080"
            only_open_local = True
        if infra:
            ports_local = "22,25,53,80,110,143,443,3389,5432,3306"
            only_open_local = True

        # parse ports
        targets: List[int] = []
        udp_targets: List[int] = []
        results: List[dict] = []
        results_udp: List[dict] = []
        if "," in ports_local:
            targets = [int(p.strip()) for p in ports_local.split(",")]
        elif "-" in ports_local:
            start, end = ports_local.split("-")
            targets = list(range(int(start), int(end) + 1))
        else:
            targets = [int(ports_local)]

        if udp:
            if udp_ports:
                if "," in udp_ports:
                    udp_targets = [int(p.strip()) for p in udp_ports.split(",")]
                elif "-" in udp_ports:
                    us, ue = udp_ports.split("-")
                    udp_targets = list(range(int(us), int(ue) + 1))
                else:
                    udp_targets = [int(udp_ports)]
            else:
                # default top UDP ports
                udp_targets = [53, 123, 161, 500, 137, 138, 67, 68, 69, 1900]

        if syn:
            try:
                results = await async_syn_scan(tgt, targets, concurrency=concurrency_local, timeout=timeout_local, rate_limit=syn_rate, iface=syn_iface)
            except PermissionError:
                console.print("SYN scan requires admin privileges (Windows).", style="red")
                console.print("Tip: open an elevated PowerShell and retry, or run without --syn.", style="yellow")
                raise typer.Exit(code=2)
            except Exception as e:
                # Likely scapy missing
                if "scapy_not_installed" in str(e):
                    console.print("Install Scapy to use --syn: pip install scapy", style="yellow")
                else:
                    console.print(f"SYN scan error: {e}", style="red")
                raise typer.Exit(code=2)
        else:
            results = await async_port_scan(tgt, targets, concurrency=concurrency_local, timeout=timeout_local, no_write=no_write)
        if udp and udp_targets:
            results_udp = await async_udp_scan(tgt, udp_targets, concurrency=concurrency_local, timeout=timeout_local)
        if output:
            payload = {"target": tgt, "ports": targets, "results": results}
            if results_udp:
                payload.update({"udp_ports": udp_targets, "udp_results": results_udp})
            with open(output, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            console.print(f"Saved: {output}")
        # output table
        table = Table(title=f"Port Scan: {tgt}", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Port", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Banner/Reason", style="magenta")
        # basic port->service map as fallback
        port_map = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",443:"https",465:"smtps",587:"smtp",993:"imaps",995:"pop3s",3306:"mysql",3389:"rdp",6379:"redis",27017:"mongodb",5432:"postgres",8080:"http"}
        rows = [r for r in results if (r["state"]=="open" or not only_open_local)]
        for r in rows:
            rsn = r.get("reason", "")
            svc = "" if raw else port_map.get(r["port"], "")
            table.add_row(str(r["port"]), r["state"], svc, rsn)
        console.print(table)
        open_ports = [r['port'] for r in results if r['state']=='open']
        console.print(f"Open ports: {open_ports}")

        if results_udp:
            table_u = Table(title=f"UDP Scan: {tgt}", box=box.MINIMAL_DOUBLE_HEAD)
            table_u.add_column("Port", style="cyan")
            table_u.add_column("State", style="green")
            table_u.add_column("Service", style="yellow")
            table_u.add_column("Banner/Reason", style="magenta")
            rows_u = [r for r in results_udp if (r["state"]=="open" or not only_open_local)]
            for r in rows_u:
                rsn = r.get("reason", "")
                svc = "" if raw else port_map.get(r["port"], "")
                table_u.add_row(str(r["port"]), r["state"], svc, rsn)
            console.print(table_u)
            open_udp = [r['port'] for r in results_udp if r['state']=='open']
            console.print(f"Open UDP ports: {open_udp}")

    asyncio.run(run())

@app.command()
def ssl_analyze(
    host: Optional[str] = typer.Argument(None, help="Target host (positional)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Alias for host (supports -t)"),
    port: int = typer.Option(443, "--port", "-p", help="TLS port"),
    output: Optional[str] = None,
    timeout: float = typer.Option(5.0, "--timeout", "-T", help="Timeout seconds"),
):
    """Analyze TLS/SSL configuration: cert expiry, protocols, ciphers, headers."""
    tgt = target or host
    if not tgt:
        console.print("Provide a host (positional) or --target/-t", style="red")
        raise typer.Exit(code=2)
    report = asyncio.run(analyze_ssl(tgt, port))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")

@app.command()
def takeover(host: str, output: Optional[str] = None, timeout: float = 5.0):
    """Scan for potential subdomain takeover based on CNAME and provider fingerprints."""
    report = asyncio.run(takeover_scan(host))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")

@app.command()
def api_test(host: str, output: Optional[str] = None, bursts: int = 20):
    """Basic API probe: Swagger discovery and simple rate-limit pulses."""
    report = asyncio.run(api_probe(host))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")

@app.command()
def recon_cmd(
    host: Optional[str] = typer.Argument(None, help="Target host (positional)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Alias for host (supports -t)"),
    output: Optional[str] = None,
):
    """Reconnaissance: DNS records, HTTP headers, server/CDN/WAF hints, WHOIS."""
    tgt = target or host
    if not tgt:
        console.print("Provide a host (positional) or --target/-t", style="red")
        raise typer.Exit(code=2)
    report = asyncio.run(recon(tgt))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")

@app.command("recon")
def recon_alias(host: Optional[str] = None, output: Optional[str] = None, target: Optional[str] = None):
    """Alias for recon (compat with legacy Node CLI)."""
    recon_cmd(host=host, target=target, output=output)

@app.command()
def dirbust(host: str, wordlist: Optional[str] = None, concurrency: int = 50, https: bool = True, output: Optional[str] = None):
    """Directory and file discovery with a built-in curated wordlist."""
    report = asyncio.run(dirbust_scan(host, wordlist_path=wordlist, concurrency=concurrency, https=https))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")

@app.command()
def tech(host: str, output: Optional[str] = None):
    """Detect technologies via headers and HTML fingerprints."""
    report = asyncio.run(detect_tech(host))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")

@app.command()
def crawl(host: str, start: Optional[str] = typer.Option(None, "--start", help="Start URL, defaults to https://<host>"), max_pages: int = 30, concurrency: int = 8, output: Optional[str] = None):
    """Lightweight web crawler: same-host pages, secrets scan, CSP/CORS checks."""
    report = asyncio.run(web_crawl(host, start=start, max_pages=max_pages, concurrency=concurrency))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")

@app.command()
def cloud(
    name: str = typer.Argument(..., help="Bucket/account name to check across providers"),
    providers: Optional[str] = typer.Option("aws,azure,gcp", "--providers", help="Comma-separated providers (aws,azure,gcp)"),
    output: Optional[str] = None,
):
    """Audit common cloud storage endpoints for public listing exposure."""
    pv = [p.strip() for p in (providers or "").split(",") if p.strip()]
    report = asyncio.run(cloud_audit(name, pv))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")
@app.command()
def k8s(
    api_base: str = typer.Argument(..., help="Kubernetes API base URL, e.g., https://host:6443"),
    insecure: bool = typer.Option(False, "--insecure", help="Allow insecure TLS (skip certificate verification)"),
    output: Optional[str] = None,
):
    """Audit common unauthenticated Kubernetes API/kubelet endpoints (safe probes)."""
    report = asyncio.run(k8s_audit(api_base, verify_cert=(not insecure)))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")
@app.command()
def container(
    registry: str = typer.Argument(..., help="Container registry host (e.g., registry.example.com)"),
    output: Optional[str] = None,
):
    """Audit container registries for anonymous catalog/API exposure (Docker/Harbor)."""
    report = asyncio.run(container_audit(registry))
    console.print_json(data=report)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"Saved: {output}")

@app.command()
def report(
    suite: Optional[str] = typer.Option(None, "--suite", help="Path to combined suite JSON"),
    output: str = typer.Option("report.html", "--output", help="Output HTML file path"),
    summary: bool = typer.Option(False, "--summary", help="Generate concise findings-only report"),
):
    """Generate an HTML report from a suite JSON file."""
    if not suite:
        console.print("--suite is required", style="red")
        raise typer.Exit(code=2)
    try:
        with open(suite, "r", encoding="utf-8") as f:
            data = json.load(f)
        html = generate_summary_html_report(data) if summary else generate_html_report(data)
        with open(output, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"Saved: {output}")
    except Exception as e:
        console.print(f"Failed to generate report: {e}", style="red")
        raise typer.Exit(code=1)

@app.command()
def suite(
    host: Optional[str] = typer.Argument(None, help="Target host (positional)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Alias for host (supports -t)"),
    ports: str = "1-1024",
    concurrency: int = 200,
    timeout: float = 1.0,
    bursts: int = 20,
    profile: str = typer.Option("full", "--profile", help="Scan profile: web|api|infra|full"),
    output_dir: str = typer.Option("results", "--output-dir", help="Directory to store JSON outputs"),
    cloud_name: Optional[str] = typer.Option(None, "--cloud-name", help="Cloud bucket/account name to audit (aws/azure/gcp)"),
    k8s_api: Optional[str] = typer.Option(None, "--k8s-api", help="K8s API base URL to audit"),
    registry: Optional[str] = typer.Option(None, "--registry", help="Container registry host to audit"),
    mode: str = typer.Option("passive", "--mode", help="Testing mode: passive|active", case_sensitive=False),
    safe_mode: bool = typer.Option(True, "--safe-mode", help="Enable strict caps on active tests"),
    max_requests: int = typer.Option(200, "--max-requests", help="Global cap on active requests"),
    rate_limit: int = typer.Option(10, "--rate-limit", help="Approx requests per second cap for active tests"),
    udp: bool = typer.Option(False, "--udp", help="Include UDP scan of top ports"),
    udp_ports: Optional[str] = typer.Option(None, "--udp-ports", help="UDP ports range/list; defaults to top ports"),
):
    """Run a combined suite: scan, ssl, takeover, api, recon, with unified outputs."""

    async def run_all():
        tgt = target or host
        if not tgt:
            console.print("Provide a host (positional) or --target/-t", style="red")
            raise typer.Exit(code=2)
        # Prepare ports
        targets: List[int] = []
        if "," in ports:
            targets = [int(p.strip()) for p in ports.split(",")]
        elif "-" in ports:
            start, end = ports.split("-")
            targets = list(range(int(start), int(end) + 1))
        else:
            targets = [int(ports)]

        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        tasks = []
        include_scan = profile in ("infra", "full", "web")
        include_ssl = profile in ("web", "full")
        include_takeover = profile in ("web", "full")
        include_api = profile in ("api", "full", "web")
        include_recon = profile in ("infra", "web", "api", "full")
        include_dirbust = profile in ("web", "full")
        include_tech = profile in ("web", "infra", "full")
        include_crawl = profile in ("web", "full")
        include_web_owasp = profile in ("web", "full")
        include_cloud = bool(cloud_name)
        include_k8s = bool(k8s_api)
        include_container = bool(registry)

        # Launch tasks
        scan_task = None
        if include_scan:
            scan_task = asyncio.create_task(async_port_scan(tgt, targets, concurrency=concurrency, timeout=timeout))
        udp_targets: List[int] = []
        udp_task = None
        if include_scan and udp:
            if udp_ports:
                if "," in udp_ports:
                    udp_targets = [int(p.strip()) for p in udp_ports.split(",")]
                elif "-" in udp_ports:
                    us, ue = udp_ports.split("-")
                    udp_targets = list(range(int(us), int(ue) + 1))
                else:
                    udp_targets = [int(udp_ports)]
            else:
                udp_targets = [53, 123, 161, 500, 137, 138, 67, 68, 69, 1900]
            udp_task = asyncio.create_task(async_udp_scan(tgt, udp_targets, concurrency=concurrency, timeout=timeout))
        ssl_task = asyncio.create_task(analyze_ssl(tgt)) if include_ssl else None
        takeover_task = asyncio.create_task(takeover_scan(tgt)) if include_takeover else None
        api_task = asyncio.create_task(api_probe(tgt)) if include_api else None
        recon_task = asyncio.create_task(recon(tgt)) if include_recon else None
        dirb_task = asyncio.create_task(dirbust_scan(tgt)) if include_dirbust else None
        tech_task = asyncio.create_task(detect_tech(tgt)) if include_tech else None
        # Normalize mode before task creation to avoid unbound reference
        mode_norm = (mode or "passive").lower()
        crawl_task = asyncio.create_task(web_crawl(tgt, max_pages=30, concurrency=8)) if include_crawl else None
        web_owasp_task = asyncio.create_task(web_owasp_passive(tgt)) if include_web_owasp and mode_norm == "passive" else None
        cloud_task = asyncio.create_task(cloud_audit(cast(str, cloud_name))) if include_cloud else None
        k8s_task = asyncio.create_task(k8s_audit(cast(str, k8s_api))) if include_k8s else None
        container_task = asyncio.create_task(container_audit(cast(str, registry))) if include_container else None

        # Gather
        if mode_norm not in ("passive", "active"):
            console.print("--mode must be 'passive' or 'active'", style="red")
            raise typer.Exit(code=2)

        results: dict = {
            "target": tgt,
            "timestamp": ts,
            "profile": profile,
            "mode": mode_norm,
            "controls": {
                "safe_mode": safe_mode,
                "max_requests": max_requests,
                "rate_limit": rate_limit,
            },
        }
        if scan_task:
            scan_results = await scan_task
            results["scan"] = {"ports": targets, "results": scan_results}
            if udp_task:
                udp_results = await udp_task
                results["scan"].update({"udp_ports": udp_targets, "udp_results": udp_results})
            with open(os.path.join(output_dir, f"scan_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                payload = {"target": host, "ports": targets, "results": scan_results}
                if udp_task:
                    payload.update({"udp_ports": udp_targets, "udp_results": results["scan"].get("udp_results", [])})
                json.dump(payload, f, indent=2)
        if ssl_task:
            ssl_report = await ssl_task
            results["ssl"] = ssl_report
            with open(os.path.join(output_dir, f"ssl_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(ssl_report, f, indent=2)
        if takeover_task:
            takeover_report = await takeover_task
            results["takeover"] = takeover_report
            with open(os.path.join(output_dir, f"takeover_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(takeover_report, f, indent=2)
        if api_task:
            api_report = await api_task
            results["api"] = api_report
            with open(os.path.join(output_dir, f"api_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(api_report, f, indent=2)
        if recon_task:
            recon_report = await recon_task
            results["recon"] = recon_report
            with open(os.path.join(output_dir, f"recon_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(recon_report, f, indent=2)
        if dirb_task:
            dirb_report = await dirb_task
            results["dirbust"] = dirb_report
            with open(os.path.join(output_dir, f"dirbust_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(dirb_report, f, indent=2)
        if tech_task:
            tech_report = await tech_task
            results["tech"] = tech_report
            with open(os.path.join(output_dir, f"tech_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(tech_report, f, indent=2)
        if crawl_task:
            crawl_report = await crawl_task
            results["crawl"] = crawl_report
            with open(os.path.join(output_dir, f"crawl_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(crawl_report, f, indent=2)
        if web_owasp_task:
            web_owasp_report = await web_owasp_task
            results["web_owasp"] = web_owasp_report
            with open(os.path.join(output_dir, f"web_owasp_{tgt}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(web_owasp_report, f, indent=2)
        if cloud_task:
            cloud_report = await cloud_task
            results["cloud"] = cloud_report
            with open(os.path.join(output_dir, f"cloud_{(cloud_name or host)}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(cloud_report, f, indent=2)
        if k8s_task:
            k8s_report = await k8s_task
            results["k8s"] = k8s_report
            with open(os.path.join(output_dir, f"k8s_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(k8s_report, f, indent=2)
        if container_task:
            container_report = await container_task
            results["container"] = container_report
            with open(os.path.join(output_dir, f"container_{(registry or host)}_{ts}.json"), "w", encoding="utf-8") as f:
                json.dump(container_report, f, indent=2)

        # Derive a compact summary
        summary = {
            "open_ports": [r["port"] for r in results.get("scan", {}).get("results", []) if r.get("state") == "open"],
            "open_udp_ports": [r["port"] for r in results.get("scan", {}).get("udp_results", []) if r.get("state") == "open"],
            "ssl_severity": results.get("ssl", {}).get("severity"),
            "takeover_vulnerable": results.get("takeover", {}).get("vulnerable"),
            "api_findings": len(results.get("api", {}).get("findings", [])) if results.get("api") else None,
            "recon_waf_hint": any(f.get("type") == "waf_or_cdn_hint" for f in results.get("recon", {}).get("findings", [])) if results.get("recon") else None,
            "cloud_findings": len(results.get("cloud", {}).get("findings", [])) if results.get("cloud") else None,
            "k8s_findings": len(results.get("k8s", {}).get("findings", [])) if results.get("k8s") else None,
            "container_findings": len(results.get("container", {}).get("findings", [])) if results.get("container") else None,
        }
        results["summary"] = summary

        # Save combined
        combined_path = os.path.join(output_dir, f"suite_{tgt}_{ts}.json")
        with open(combined_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        console.print(f"Saved suite results: {combined_path}")

        # Print concise human summary
        console.print(Panel.fit(
            f"Target: {tgt}\nProfile: {profile} | Mode: {mode_norm}\nOpen ports: {summary['open_ports']}\nOpen UDP ports: {summary.get('open_udp_ports')}\nSSL severity: {summary['ssl_severity']}\nTakeover vulnerable: {summary['takeover_vulnerable']}\nWAF/CDN hint: {summary['recon_waf_hint']}\nCloud findings: {summary['cloud_findings']} | K8s findings: {summary['k8s_findings']} | Container findings: {summary['container_findings']}",
            title="Suite Summary",
            border_style="green",
        ))

    asyncio.run(run_all())

@app.command("threat-intel")
def threat_intel_deprecated():
    """Deprecated: use external threat intel tools; not provided in Python CLI."""
    console.print("`threat-intel` is deprecated in the Python CLI. Use the web/API suite, recon, and external TI sources (e.g., VirusTotal, AbuseIPDB) as needed.", style="yellow")

@app.command("enterprise-scan")
def enterprise_scan_migrate():
    """Deprecated: use `suite` with cloud/k8s/container for enterprise coverage."""
    tip = (
        "enterprise-scan (Node) has been replaced. Use:\n"
        "  scorpion suite <target> --profile full --output-dir results [--cloud-name <name>] [--k8s-api <url>] [--registry <host>]\n"
        "Run per-target and aggregate reports as needed."
    )
    console.print(tip, style="yellow")

if __name__ == "__main__":
    app()

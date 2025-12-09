# Python Scorpion (Heavy-weight)

A Python-based, high-concurrency variant of the Scorpion security toolkit.

## Features
- Async TCP port scanner (fast, concurrent)
- TLS/SSL analyzer (cert expiry, cipher, TLS version, HSTS)
- Subdomain takeover checks
- API probe (Swagger/GraphQL/JWT/IDOR/Rate-limit pulse)
- Recon (DNS, headers, WHOIS)
- NEW: Dirbust (built-in curated wordlist; wildcard filtering)
- NEW: Tech fingerprinting (server/framework/CDN/WAF)
- Orchestrated `suite` runs with profile selection and combined JSON

## Install (Windows PowerShell)

```powershell
# From repo root
cd "c:\Users\prince.sam_dubizzle\Downloads\open_project\tools\python_scorpion"

# Create venv
python -m venv .venv; .\.venv\Scripts\Activate.ps1

# Install requirements
pip install -U pip; pip install typer rich httpx dnspython cryptography

# Editable install
pip install -e .

# Verify CLI
scorpion --help
```

## Packaging (Single Binary)

Build a one-file binary for easy distribution on Windows or Linux.

Windows (PowerShell):

```powershell
cd tools/python_scorpion
pip install -r requirements-dev.txt
./build-windows.ps1
# Binary: tools/python_scorpion/dist/scorpion.exe
```

Linux (bash):

```bash
cd tools/python_scorpion
pip install -r requirements-dev.txt
bash build-linux.sh
# Binary: tools/python_scorpion/dist/scorpion
```

## Usage

```powershell
# Port scan 1-1024 with concurrency 300
scorpion scan dubizzle.com --ports 1-1024 --concurrency 300 --timeout 1.0

# Include UDP top ports (best-effort)
scorpion scan dubizzle.com --ports 1-1024 --udp --udp-ports 53,123,161,500,137,138,67,68,69,1900

# TLS/SSL analysis and save report
scorpion ssl-analyze google.com --port 443 --output ssl_google.json

# Dirbusting (built-in wordlist)
scorpion dirbust example.com --concurrency 50 --output results/dirb_example.json

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

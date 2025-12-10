# 🚀 AI Pentesting Agent - Quick Start Card

## Installation
```bash
cd tools/python_scorpion && pip install -e .
export SCORPION_AI_API_KEY='your-api-key'
```

## Primary Goals (10 Options)

| Goal | Description | Risk Level |
|------|-------------|------------|
| `comprehensive_assessment` | Full security audit | Medium |
| `gain_shell_access` ⭐ | Get shell on target | **HIGH** |
| `web_exploitation` | Web app vulnerabilities | Medium |
| `vulnerability_discovery` ⭐ | Find all vulns | Medium |
| `infrastructure_assessment` ⭐ | Servers/cloud/K8s | Medium |
| `privilege_escalation` | Gain elevated access | High |
| `data_access` | Discover sensitive data | Medium |
| `network_mapping` | Network recon | Low |
| `cloud_security_audit` ⭐ | Cloud testing | Medium |
| `api_security_testing` ⭐ | API-focused | Medium |

## Common Commands

### Web Testing (Safe)
```bash
scorpion ai-pentest -t webapp.com --primary-goal web_exploitation
```

### Gain Shell (Requires Authorization)
```bash
scorpion ai-pentest -t target.com --primary-goal gain_shell_access --risk-tolerance high
```

### Infrastructure Scan
```bash
scorpion ai-pentest -t 10.0.0.1 --primary-goal infrastructure_assessment --time-limit 180
```

### Cloud Audit
```bash
scorpion ai-pentest -t company-bucket --primary-goal cloud_security_audit
```

### Full Pentest (Supervised)
```bash
scorpion ai-pentest -t target.com \
  --primary-goal comprehensive_assessment \
  --risk-tolerance high \
  --autonomy supervised \
  --learning-mode
```

## Configuration Options

### Risk Tolerance
- `low` = Passive scanning only
- `medium` = Active scanning (default)
- `high` = Full exploitation ⚠️

### Autonomy
- `supervised` = Ask before every action
- `semi-autonomous` = Ask before high-risk (default)
- `fully-autonomous` = No prompts

### Stealth
- `low` = Fast, noisy
- `moderate` = Balanced (default)
- `high` = Slow, stealthy

## Available Tools (15+)

**Recon:** recon, tech_detect, os_fingerprint, crawler, dirbuster
**Scan:** port_scan, udp_scan, syn_scan, advanced_scan, ssl_analyze
**Vuln:** web_pentest, api_test, fuzzer, nuclei, takeover_scan, cloud_audit, k8s_audit, container_audit
**Exploit:** bruteforce, payload_generate, exploit_vuln

## Help & Documentation

```bash
scorpion ai-pentest --help
cat AI_AGENT_ENHANCED_GUIDE.md    # Complete guide (5,000+ lines)
cat AI_PENTESTING_QUICKREF.md      # Quick reference
```

## ⚠️ Legal Warning

**ONLY** test systems you own or have **explicit written authorization** to test.

Unauthorized testing = Criminal prosecution

## Cost (OpenAI GPT-4)

- Quick scan (30 min): $0.20-$0.50
- Web pentest (90 min): $0.80-$1.50
- Full assessment (180 min): $1.50-$3.00

**Tip:** Use `gpt-3.5-turbo` for 80% cost reduction

## Support

- GitHub: https://github.com/Prince12sam/Scorpion
- Docs: AI_AGENT_ENHANCED_GUIDE.md
- Issues: Report bugs on GitHub

---

**Status:** ✅ Production Ready
**Version:** 2.1.0 (Enhanced)
**Unique Feature:** AI-Powered Exploitation
**Last Updated:** December 10, 2025

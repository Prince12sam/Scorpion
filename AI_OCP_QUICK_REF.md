# AI Pentesting Agent - OCP Tactical Reference

## Setup
```bash
cd tools/python_scorpion && pip install -e .
export SCORPION_AI_API_KEY='sk-...'  # OpenAI/Anthropic key
```

## Mission Profiles

| Profile | Kill Chain Focus | Authorization Level |
|---------|------------------|---------------------|
| `comprehensive_assessment` | Full attack surface mapping | Medium |
| `gain_shell_access` | Initial access → shell | **HIGH** |
| `web_exploitation` | OWASP Top 10, auth bypass | Medium |
| `vulnerability_discovery` | CVE hunting, misconfig detection | Medium |
| `infrastructure_assessment` | Network pentest, lateral movement | Medium-High |
| `privilege_escalation` | Post-ex privilege vectors | High |
| `data_access` | Sensitive data exposure | Medium |
| `network_mapping` | Asset discovery, topology | Low |
| `cloud_security_audit` | Cloud IAM/resource abuse | Medium |
| `api_security_testing` | API injection, broken auth | Medium |

## Tactical Execution

### Initial Access (Web Target)
```bash
scorpion ai-pentest -t webapp.target.corp \
  --primary-goal gain_shell_access \
  --risk-tolerance high \
  --autonomy fully-autonomous \
  --stealth-level moderate
```

### Network Penetration (Internal)
```bash
scorpion ai-pentest -t 10.50.0.0/24 \
  --primary-goal infrastructure_assessment \
  --risk-tolerance high \
  --stealth-level low \
  --time-limit 180
```

### External Recon → Exploit
```bash
scorpion ai-pentest -t target.corp \
  --primary-goal comprehensive_assessment \
  --risk-tolerance high \
  --autonomy semi-autonomous
```

### Cloud Environment Assessment
```bash
scorpion ai-pentest -t company-infra \
  --primary-goal cloud_security_audit \
  --risk-tolerance medium
```

### Supervised Engagement (Client-Present)
```bash
scorpion ai-pentest -t target.corp \
  --autonomy supervised \
  --learning-mode \
  --risk-tolerance medium
```

## Operational Parameters

### Risk Tolerance
- `low` = Recon only, no authentication attempts
- `medium` = Active scanning, PoC exploits (default)
- `high` = Full exploitation, shell access

### Autonomy
- `supervised` = Operator approval per action
- `semi-autonomous` = Auto low/medium, ask for high-risk (default)
- `fully-autonomous` = Autonomous kill chain execution

### Stealth (IDS Evasion)
- `low` = Fast, noisy (internal/lab)
- `moderate` = Balanced (default)
- `high` = Slow, evasive (monitored production)

## Integrated Arsenal

**Recon:** recon, tech_detect, os_fingerprint, crawler, dirbuster
**Network:** port_scan, udp_scan, syn_scan, advanced_scan, ssl_analyze
**Exploitation:** web_pentest, api_test, fuzzer, nuclei, cloud_audit, k8s_audit, container_audit
**Post-Ex:** bruteforce, payload_generate, exploit_vuln

## Command Reference

```bash
# Full help
scorpion ai-pentest --help

# Quick web test
scorpion ai-pentest -t webapp.com --primary-goal web_exploitation

# Gain shell (requires explicit auth)
scorpion ai-pentest -t target.com --primary-goal gain_shell_access --risk-tolerance high

# Infrastructure scan
scorpion ai-pentest -t 192.168.1.0/24 --primary-goal infrastructure_assessment --time-limit 120
```

## Cost (OpenAI GPT-4)
- 30min engagement: ~$0.30
- 90min web pentest: ~$1.00  
- 180min full scope: ~$2.00

**Optimization:** Use `--model gpt-3.5-turbo` for 80% cost reduction

## Authorization

⚠️ **HIGH risk requires signed RoE with exploitation clause**

Only test assets with:
- Written contract/authorization
- Defined scope (CIDR/domains)
- Emergency contacts
- Cleanup procedures

Unauthorized = CFAA violation (20yr max sentence)

---

**OCP Level:** Professional Penetration Tester
**Status:** Production Ready
**Version:** 2.1.0 (Enhanced)

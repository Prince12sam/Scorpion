# Scorpion Decoy Scanning Guide

**IDS/IPS Evasion through IP Spoofing**

## Overview

Decoy scanning is an advanced evasion technique that obscures your real IP address by sending scan packets from multiple spoofed source IPs. This makes it extremely difficult for Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) to identify the actual attacker among the noise.

### How It Works

When decoy scanning is enabled, Scorpion:
1. Generates multiple decoy IP addresses (random, subnet-based, or manual)
2. Sends scan packets from each decoy IP to the target
3. Mixes your real IP among the decoys at a random or specified position
4. Makes it nearly impossible for defenders to distinguish real from fake sources

### Key Benefits

- **IDS/IPS Evasion**: Overwhelm signature-based detection with false positives
- **Attribution Obfuscation**: Hide your real IP among decoys
- **Log Pollution**: Fill target logs with decoy IPs, making forensics difficult
- **Firewall Bypass**: Some firewalls only track limited source IPs

---

## ⚠️ LEGAL WARNING

**Decoy scanning is ONLY legal when:**
- You own the target system
- You have explicit written authorization from the system owner
- You are conducting authorized penetration testing with proper scope documentation

**Unauthorized use is illegal and may result in:**
- Criminal charges under computer fraud and abuse laws (CFAA, Computer Misuse Act, etc.)
- Civil lawsuits for damages
- Professional sanctions and loss of security certifications

**IP spoofing can constitute:**
- Identity fraud (pretending to be someone else)
- Network abuse (sending packets with false source IPs)
- Additional charges beyond unauthorized access

**Always ensure you have proper authorization before using decoy scanning.**

---

## Requirements

### Administrator/Root Privileges

Decoy scanning **requires** root (Linux/macOS) privileges because it:
- Creates raw sockets for packet crafting
- Sets IP_HDRINCL socket option to control IP headers
- Crafts packets with spoofed source IPs

**Windows:**
```powershell
# Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"
scorpion scan target.com --syn --decoy RND:5
```

**Linux:**
```bash
# Run with sudo
sudo scorpion scan target.com --syn --decoy RND:5

# Or run as root
su -
scorpion scan target.com --syn --decoy RND:5
```

### Dependencies

- **Scapy**: Required for advanced scans (SYN/FIN/XMAS/NULL/ACK)
- **Python 3.10+**: For asyncio and dataclasses
- **Raw socket support**: Enabled by default on most systems

Install Scapy:
```bash
pip install scapy
```

### Compatible Scan Types

Decoy scanning works with **advanced scan types only**:
- `--syn` (TCP SYN scan)
- `--fin` (TCP FIN scan)
- `--xmas` (TCP XMAS scan)
- `--null` (TCP NULL scan)
- `--ack` (TCP ACK scan)

Regular TCP connect scans do not support decoy scanning.

---

## Quick Start

### 1. Random Decoys (Recommended)

Generate 5 random decoy IPs, mixing your real IP randomly among them:

```bash
scorpion scan target.com --syn --decoy RND:5
```

**Output:**
```
=== Decoy Scanning Enabled ===
Decoy Mode: random
Sending decoy packets (syn scan)...

✓ Decoy Scan Complete
  Decoys Used: 6 IPs (5 decoys + you)
  Real IP Position: 3 of 6
  Packets Sent: 6144
  Success Rate: 98.2%

Decoy IPs (showing first 5):
  1. 203.45.67.89
  2. 198.51.100.42
  3. 192.0.2.15 [YOU]
  4. 172.217.14.238
  5. 151.101.193.69
```

### 2. More Decoys for Better Obfuscation

Use 10 decoys for even more noise:

```bash
scorpion scan target.com --syn --decoy RND:10
```

### 3. Manual Decoy List

Specify exact decoy IPs (useful for targeting specific subnets):

```bash
# Manual decoys with real IP in random position
scorpion scan target.com --syn --decoy 10.0.0.1,10.0.0.2,10.0.0.3,ME,10.0.0.5

# Real IP at specific position (ME marker)
scorpion scan target.com --syn --decoy 192.168.1.10,ME,192.168.1.20,192.168.1.30
```

**Note:** `ME` marks where your real IP appears in the decoy list. If omitted, your IP is inserted at a random position.

### 4. Real IP Only (Comparison Test)

Test without decoys to compare results:

```bash
scorpion scan target.com --syn --decoy ME
```

---

## Command Reference

### Decoy Option Formats

| Format | Description | Example |
|--------|-------------|---------|
| `RND:count` | Generate `count` random decoy IPs | `RND:5`, `RND:10`, `RND:20` |
| `ME` | Only use real IP (no decoys) | `ME` |
| `IP1,IP2,ME` | Manual decoy list with real IP position | `10.0.0.1,ME,10.0.0.3` |
| `IP1,IP2,IP3` | Manual list, real IP random position | `10.0.0.1,10.0.0.2,10.0.0.3` |

### Full Command Syntax

```bash
scorpion scan <target> [scan_type] --decoy <decoy_option> [other_options]
```

**Parameters:**
- `<target>`: Target hostname or IP address
- `[scan_type]`: One of `--syn`, `--fin`, `--xmas`, `--null`, `--ack` (REQUIRED)
- `<decoy_option>`: Decoy format (see table above)
- `[other_options]`: Standard scan options (ports, timing, output, etc.)

---

## Detailed Examples

### Example 1: SYN Scan with Random Decoys

```bash
scorpion scan 192.168.1.100 --syn --decoy RND:8 --ports 1-1000 --output scan_decoy.json
```

**What happens:**
1. Generates 8 random decoy IPs (avoiding reserved ranges)
2. Inserts your real IP at a random position (e.g., position 4 of 9)
3. Sends SYN packets from all 9 IPs to ports 1-1000
4. Total packets: 9 IPs × 1000 ports = 9000 packets
5. Saves results including decoy information to `scan_decoy.json`

**Use case:** Standard penetration test with IDS evasion

### Example 2: FIN Scan with Subnet Decoys

```bash
# Manual subnet decoys (same /24 as target)
scorpion scan 10.0.1.50 --fin --decoy 10.0.1.10,10.0.1.20,ME,10.0.1.40,10.0.1.60
```

**What happens:**
1. Uses 4 decoy IPs from target's subnet (10.0.1.0/24)
2. Your real IP is explicitly at position 3
3. Sends FIN packets (stealthier than SYN)
4. Decoys appear to be from same network (more realistic)

**Use case:** Internal network penetration test where you want decoys to look local

### Example 3: XMAS Scan with Aggressive Timing

```bash
scorpion scan evil-corp.com --xmas --decoy RND:15 -T aggressive
```

**What happens:**
1. Generates 15 random decoys (16 total IPs including you)
2. XMAS scan (FIN+PSH+URG flags) - very stealthy
3. Aggressive timing (T4): 1.5s timeout, 100 concurrent
4. Sends 16× traffic volume to overwhelm IDS

**Use case:** Testing IDS thresholds and detection capabilities

### Example 4: NULL Scan with Slow Timing

```bash
scorpion scan target.example.com --null --decoy RND:5 -T sneaky
```

**What happens:**
1. NULL scan (no TCP flags) - extremely stealthy
2. Sneaky timing (T1): 15s timeout, 5 concurrent
3. Very slow scan rate (1 probe per 5 seconds)
4. 6 IPs sending very slow traffic = hard to correlate

**Use case:** Evading time-based IDS detection and rate limiting

### Example 5: ACK Scan for Firewall Detection

```bash
scorpion scan firewall.target.com --ack --decoy 203.0.113.5,203.0.113.10,ME,203.0.113.20
```

**What happens:**
1. ACK scan detects firewall rules (RST = unfiltered, nothing = filtered)
2. Manual decoys from public IP range (203.0.113.0/24)
3. Tests if firewall treats different source IPs differently

**Use case:** Firewall rule enumeration with source IP obfuscation

### Example 6: Full Scan with All Options

```bash
scorpion scan 192.168.50.100 \
  --syn \
  --decoy RND:10 \
  --ports 1-65535 \
  --concurrency 300 \
  --timeout 2.0 \
  --os-detect \
  --output full_scan_decoy.json
```

**What happens:**
1. Full port range scan (1-65535)
2. 11 total IPs (10 decoys + you)
3. 11 × 65535 = 720,885 packets sent
4. OS fingerprinting on open ports
5. High concurrency for speed

**Use case:** Comprehensive penetration test with maximum obfuscation

---

## Advanced Use Cases

### 1. Red Team Operations

**Scenario:** Simulating advanced persistent threat (APT) with decoys from multiple countries

```bash
# Use VPN/proxy for real IP, decoys from various geolocation
scorpion scan target-corp.com --syn --decoy RND:20 -T polite
```

**Technique:**
- 20 decoys generate massive log volume
- Polite timing avoids triggering rate-based detection
- Security team must analyze 21 potential attackers
- Real IP hidden in noise

**Detection Difficulty:** ⭐⭐⭐⭐⭐ (Extremely Hard)

### 2. IDS Signature Testing

**Scenario:** Testing if IDS can correlate multi-source scans

```bash
# Same scan from different source IPs
scorpion scan ids-test.lab --syn --decoy RND:5 --ports 22,80,443
scorpion scan ids-test.lab --fin --decoy RND:5 --ports 22,80,443
scorpion scan ids-test.lab --xmas --decoy RND:5 --ports 22,80,443
```

**Test:** Does IDS recognize this as a single attack campaign or treat as unrelated?

### 3. Firewall Rule Mapping

**Scenario:** Determine if firewall allows certain source IPs

```bash
# Test with manual decoys including known-good IPs
scorpion scan firewall.corp --ack --decoy 10.10.0.5,ME,10.10.0.50,192.168.1.1
```

**Technique:**
- `10.10.0.5`: Internal admin IP (might be whitelisted)
- `ME`: Your real IP
- `10.10.0.50`: Random internal IP
- `192.168.1.1`: Common gateway IP

**Goal:** Identify source-based firewall rules

### 4. Distributed Scan Simulation

**Scenario:** Simulate botnet-style distributed scanning

```bash
# Multiple scans with different random decoys
for i in {1..5}; do
  scorpion scan target.com --syn --decoy RND:8 --ports $((1000*i))-$((1000*(i+1))) &
done
wait
```

**Effect:**
- 5 parallel scans with different decoy sets
- Total: 40+ source IPs in logs
- Appears like distributed botnet attack

**Detection Difficulty:** ⭐⭐⭐⭐⭐ (Extremely Hard)

### 5. Log Capacity Testing

**Scenario:** Test if target logs can handle high volume

```bash
# Massive decoy count
scorpion scan log-test.lab --syn --decoy RND:50 --ports 1-10000
```

**Calculation:**
- 51 IPs × 10,000 ports = 510,000 log entries
- Tests log storage, SIEM performance
- May cause log rotation, losing forensic data

---

## Evasion Techniques

### Technique 1: Random Decoy Count

**Problem:** Consistent decoy count creates fingerprint

**Solution:** Vary decoy count across scans

```bash
# Scan 1: 5 decoys
scorpion scan target.com --syn --decoy RND:5 --ports 1-1000

# Scan 2: 12 decoys
scorpion scan target.com --syn --decoy RND:12 --ports 1001-2000

# Scan 3: 8 decoys
scorpion scan target.com --syn --decoy RND:8 --ports 2001-3000
```

### Technique 2: Timing Variation

**Problem:** Consistent timing patterns are detectable

**Solution:** Combine decoys with varied timing templates

```bash
# Slow scan with few decoys
scorpion scan target.com --syn --decoy RND:3 -T sneaky --ports 80,443

# Fast scan with many decoys
scorpion scan target.com --syn --decoy RND:15 -T aggressive --ports 1-10000
```

### Technique 3: Scan Type Diversity

**Problem:** Same scan type from all decoys is suspicious

**Solution:** Use different scan types in sequence (manual coordination)

```bash
# Different scan types appear as different attackers
scorpion scan target.com --syn --decoy RND:5 --ports 1-1000
sleep 300  # 5 minute delay
scorpion scan target.com --fin --decoy RND:7 --ports 1001-2000
sleep 600  # 10 minute delay
scorpion scan target.com --xmas --decoy RND:4 --ports 2001-3000
```

### Technique 4: Geographically Realistic Decoys

**Problem:** Random IPs may include geographically suspicious combinations

**Solution:** Use manual decoys from realistic locations

```bash
# Decoys from same country/region as target
# Target in US, decoys from US IP blocks
scorpion scan us-target.com --syn --decoy 203.0.113.10,ME,198.51.100.25,192.0.2.50
```

---

## Detection and Defense

### For Blue Team / Defenders

**How to Detect Decoy Scanning:**

1. **Statistical Analysis**
   - Look for correlated scans from multiple IPs in short time window
   - Same ports, same timing, different sources = likely decoy scan
   
2. **Decoy IP Verification**
   - Check if source IPs have reverse DNS records
   - Ping/traceroute to decoy IPs (may not respond)
   - Verify source IPs against geolocation (unrealistic combinations)

3. **Packet Analysis**
   - Decoy packets may have identical TTL patterns (same original source)
   - Sequence numbers may follow similar patterns
   - IP ID fields may increment predictably

4. **Behavioral Analysis**
   - Real attackers rarely scan from 10+ different IPs simultaneously
   - Decoy scans often have unrealistic source IP diversity (different continents)

5. **Network Forensics**
   - Upstream router logs may reveal real source IP
   - ISP cooperation can identify actual attacker
   - Decoy IPs often don't establish full TCP connections

**Defense Strategies:**

1. **Rate Limiting by Subnet**: Block entire subnets showing suspicious patterns
2. **Stateful Firewalls**: Track full TCP handshakes (decoys usually can't complete)
3. **Automated Blocking**: Use fail2ban-style tools to auto-block scanning IPs
4. **Honeypots**: Decoy scans will trigger honeypots, revealing attack patterns
5. **SIEM Correlation**: Advanced SIEM can correlate multi-source attacks

**Example IDS Rule (Snort-style):**
```
alert tcp any any -> $HOME_NET any (msg:"Possible Decoy Scan Detected"; \
  threshold: type threshold, track by_dst, count 5, seconds 10; \
  sid:1000001;)
```

---

## Troubleshooting

### Issue 1: Permission Denied

**Error:**
```
[red]Decoy scanning requires root (Linux/macOS) privileges[/red]
```

**Solutions:**

**Linux/macOS:**
```bash
# Option 1: Use sudo
sudo scorpion scan target.com --syn --decoy RND:5

# Option 2: Switch to root
su -
scorpion scan target.com --syn --decoy RND:5

# Option 3: Give Python raw socket capability (permanent)
sudo setcap cap_net_raw+ep $(which python3)
scorpion scan target.com --syn --decoy RND:5  # No sudo needed
```

### Issue 2: Decoy Scan Requires Advanced Scan Type

**Error:**
```
ERROR: Decoy scanning requires an advanced scan type (--syn, --fin, --xmas, --null, or --ack)
Tip: Use --syn --decoy RND:5 for decoy scanning
```

**Solution:**
```bash
# Wrong (no scan type)
scorpion scan target.com --decoy RND:5

# Correct (with scan type)
scorpion scan target.com --syn --decoy RND:5
```

### Issue 3: Low Success Rate

**Output:**
```
Packets Sent: 5000
Success Rate: 45.2%
```

**Causes:**
1. **Network congestion**: Too many packets too fast
2. **Firewall blocking**: Source IPs being blocked
3. **Rate limiting**: Target implementing rate limits

**Solutions:**
```bash
# Reduce concurrency
scorpion scan target.com --syn --decoy RND:5 --concurrency 50

# Use slower timing
scorpion scan target.com --syn --decoy RND:5 -T polite

# Reduce decoy count
scorpion scan target.com --syn --decoy RND:3
```

### Issue 4: Scapy Not Installed

**Error:**
```
Ensure Scapy is installed: pip install scapy
```

**Solution:**
```bash
# Install Scapy
pip install scapy

# Or if using pipx
pipx inject python-scorpion scapy

# Verify installation
python -c "import scapy; print(scapy.__version__)"
```

### Issue 5: No Decoys Generated

**Error:**
```
Failed to generate unique random IP after maximum attempts
```

**Causes:**
- Too many decoys requested
- IP exclusion list too large
- Random number generator issue

**Solutions:**
```bash
# Reduce decoy count
scorpion scan target.com --syn --decoy RND:5  # Instead of RND:50

# Use manual decoys
scorpion scan target.com --syn --decoy 10.0.0.1,10.0.0.2,ME
```

---

## Comparison: Decoy vs. Normal Scanning

| Aspect | Normal Scan | Decoy Scan (RND:5) | Decoy Scan (RND:20) |
|--------|-------------|-------------------|---------------------|
| **Source IPs** | 1 (you) | 6 (5 decoys + you) | 21 (20 decoys + you) |
| **Packets Sent** | 1,000 | 6,000 | 21,000 |
| **IDS Detection** | Easy ⭐ | Moderate ⭐⭐⭐ | Hard ⭐⭐⭐⭐⭐ |
| **Log Entries** | 1,000 | 6,000 | 21,000 |
| **Attribution** | Trivial | Difficult | Very Difficult |
| **Scan Time** | Fast | 6× longer | 21× longer |
| **Requires Root** | No | Yes | Yes |
| **Resource Usage** | Low | Moderate | High |

---

## Best Practices

### 1. Authorization First
✅ Always get written authorization before decoy scanning
✅ Document scope including decoy scanning in penetration test agreement
✅ Inform client that scan will generate high log volume
❌ Never use decoy scanning without explicit permission

### 2. Start Small
✅ Begin with `RND:3` or `RND:5` for testing
✅ Gradually increase decoy count based on results
✅ Monitor scan success rate
❌ Don't start with `RND:50` on first attempt

### 3. Combine with Other Techniques
✅ Use decoys with timing templates (`-T sneaky`, `-T polite`)
✅ Combine with fragmentation (when available)
✅ Vary scan types across different decoy scans
❌ Don't rely on decoys alone for evasion

### 4. Respect Resources
✅ Use slower timing for large decoy counts
✅ Monitor network bandwidth usage
✅ Consider target's log capacity
❌ Don't launch massive decoy scans against small targets

### 5. Document Everything
✅ Save all scan results with `--output scan.json`
✅ Document decoy IPs used in penetration test report
✅ Record timestamps of all decoy scans
❌ Don't perform decoy scans without logging

---

## Python API

### Basic Usage

```python
import asyncio
from python_scorpion.decoy_scanner import (
    DecoyScanner, 
    parse_decoy_option, 
    DecoyConfig, 
    DecoyMode
)

async def main():
    # Create scanner
    scanner = DecoyScanner()
    
    # Parse decoy option (nmap-style)
    config = parse_decoy_option("RND:5", "192.168.1.100")
    
    # Perform decoy scan
    results = await scanner.perform_decoy_scan(
        target_ip="192.168.1.100",
        ports=[80, 443, 8080],
        config=config,
        scan_type="syn"
    )
    
    # Print results
    print(f"Decoys used: {results['decoys_used']}")
    print(f"Real IP: {results['real_ip']}")
    print(f"Packets sent: {results['total_packets_sent']}")
    print(f"Success rate: {results['success_rate']:.1f}%")
    
    # Clean up
    scanner.close()

asyncio.run(main())
```

### Manual Configuration

```python
from python_scorpion.decoy_scanner import DecoyConfig, DecoyMode

# Random decoys
config = DecoyConfig(
    enabled=True,
    mode=DecoyMode.RANDOM,
    count=10,
    real_ip_position=None  # Random position
)

# Manual decoys
config = DecoyConfig(
    enabled=True,
    mode=DecoyMode.MANUAL,
    decoy_ips=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
    real_ip_position=1  # Second position
)
```

### Advanced: Custom Decoy Generator

```python
from python_scorpion.decoy_scanner import DecoyGenerator

generator = DecoyGenerator()

# Generate random IP (avoiding reserved ranges)
decoy_ip = generator.generate_random_ip(exclude=["192.168.1.1"])
print(f"Random decoy: {decoy_ip}")

# Generate subnet-based decoys
subnet_decoys = generator.generate_subnet_ips(
    target_ip="192.168.1.100",
    count=5,
    exclude=["192.168.1.1", "192.168.1.100"]
)
print(f"Subnet decoys: {subnet_decoys}")

# Generate full decoy list with real IP
decoy_list = generator.generate_decoy_list(
    config=config,
    target_ip="192.168.1.100",
    real_ip="192.168.1.50"
)
print(f"Full list: {decoy_list}")
```

---

## References

### Related Nmap Options

Scorpion's decoy scanning is modeled after nmap's `-D` option:

```bash
# Nmap syntax
nmap -D RND:10 target.com

# Scorpion equivalent
scorpion scan target.com --syn --decoy RND:10
```

**Nmap Documentation:**
- https://nmap.org/book/man-bypass-firewalls-ids.html
- https://nmap.org/book/man-host-discovery.html (see -D option)

### Research Papers

1. **"Techniques for Evading Network Intrusion Detection Systems"** (Ptacek & Newsham, 1998)
   - Classic paper on IDS evasion including decoy techniques

2. **"Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection"** (Secure Networks, 1998)
   - Covers IP spoofing and decoy scanning methodology

3. **"A Survey of Intrusion Detection Evasion Techniques"** (IEEE, 2005)
   - Modern IDS evasion strategies including decoy scanning

### Tools with Similar Capabilities

- **Nmap**: Original implementation of decoy scanning (`-D` option)
- **Hping3**: Can send packets with spoofed sources
- **Scapy**: Python library for custom packet crafting (used by Scorpion)
- **Masscan**: Fast scanner with source IP spoofing capabilities

### Legal Resources

- **SANS Institute**: "Penetration Testing Authorization Forms"
  - https://www.sans.org/blog/penetration-testing-authorization-forms/
  
- **NIST SP 800-115**: "Technical Guide to Information Security Testing"
  - Guidelines for authorized security testing

- **PTES (Penetration Testing Execution Standard)**
  - Industry standard for penetration testing methodology
  - http://www.pentest-standard.org/

---

## Frequently Asked Questions (FAQ)

### Q1: Is decoy scanning illegal?

**A:** Decoy scanning is legal **only** with proper authorization. Without permission, it's illegal under computer fraud and abuse laws in most countries. IP spoofing can add additional charges like identity fraud.

### Q2: Can decoy scanning completely hide my identity?

**A:** No. Decoys make attribution much harder, but determined forensics can still identify you through:
- Upstream router logs
- ISP cooperation
- Packet timing analysis
- Behavioral fingerprinting

### Q3: How many decoys should I use?

**A:** For most pentests:
- **Testing IDS**: 5-10 decoys (RND:5 to RND:10)
- **Red Team Ops**: 10-20 decoys (RND:10 to RND:20)
- **Quick Scan**: 3-5 decoys (RND:3 to RND:5)

More decoys = better obfuscation but slower scans and more resource usage.

### Q4: Do decoy packets reach the target?

**A:** Yes, decoy packets are real packets sent from spoofed source IPs. They actually reach the target and generate log entries. However, response packets go to the decoy IPs (not you), so decoys can't complete TCP handshakes.

### Q5: Can firewalls block decoy scanning?

**A:** Yes, firewalls can:
- Rate-limit per source IP (reduces decoy effectiveness)
- Block source IP ranges (blocks some decoys)
- Require full TCP handshake (decoys can't complete)
- Use stateful inspection (identifies spoofed IPs)

### Q6: Does decoy scanning work on cloud targets (AWS, Azure, GCP)?

**A:** Partially. Cloud providers often implement:
- Source IP validation (may drop spoofed packets)
- DDoS protection (rate-limiting)
- Network security groups (block most traffic)

Decoys may be less effective against cloud infrastructure.

### Q7: Can I use decoy scanning with regular TCP connect scans?

**A:** No. Decoy scanning requires raw packet crafting (advanced scans: SYN/FIN/XMAS/NULL/ACK). Regular TCP connect scans use OS TCP stack, which doesn't allow source IP spoofing.

### Q8: What's the difference between decoy scanning and using a VPN?

**A:**
- **VPN**: Changes your real IP to VPN server IP (single source)
- **Decoy Scan**: Sends packets from multiple spoofed IPs (multi-source)

VPN provides consistent attribution to VPN IP. Decoys create confusion with many IPs.

### Q9: Can I combine decoy scanning with other evasion techniques?

**A:** Yes! Combine with:
- Timing templates (`-T sneaky`)
- Packet fragmentation (when available)
- Slow scan rates
- Varied scan types

### Q10: Does Scorpion's decoy scanning match nmap's implementation?

**A:** Yes, Scorpion implements nmap-compatible decoy scanning:
- Same `-D` option syntax
- Same decoy formats (RND:count, ME, manual lists)
- Similar packet crafting approach
- Comparable evasion effectiveness

---

## Summary

Decoy scanning is a powerful IDS/IPS evasion technique that:

✅ Obscures your real IP among multiple decoys
✅ Makes attribution extremely difficult
✅ Overwhelms signature-based IDS detection
✅ Pollutes target logs with decoy IPs

❌ Requires administrator/root privileges
❌ Only works with advanced scan types
❌ Slower than regular scanning (N× decoys = N× packets)
❌ **ILLEGAL without proper authorization**

**Use responsibly and legally!**

---

## Quick Reference Card

```bash
# Basic decoy scan
scorpion scan target.com --syn --decoy RND:5

# More decoys
scorpion scan target.com --syn --decoy RND:10

# Manual decoys
scorpion scan target.com --syn --decoy 10.0.0.1,ME,10.0.0.3

# With timing
scorpion scan target.com --syn --decoy RND:5 -T sneaky

# Full options
scorpion scan target.com --syn --decoy RND:8 --ports 1-1000 -T polite --output scan.json
```

**Remember:** Always get authorization first! 🔒

---

*Last Updated: December 2025*  
*Scorpion Version: 0.1.0+*  
*Author: Scorpion Security Team*

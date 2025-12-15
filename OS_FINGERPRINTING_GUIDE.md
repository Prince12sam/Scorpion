# OS Fingerprinting Guide

## Overview

Scorpion's OS fingerprinting module provides nmap-level operating system detection using TCP/IP stack analysis. It identifies operating systems by analyzing packet characteristics like TTL values, TCP window sizes, TCP options, and DF flags.

## Features

- **TCP/IP Stack Analysis**: Real packet inspection (NO dummy data)
- **Multiple Detection Techniques**: TCP SYN, ICMP echo, multi-port analysis
- **OS Signatures**: Linux, macOS, BSD, network devices
- **Confidence Scoring**: 0-100% confidence with consensus algorithm
- **Professional Output**: Family classification, hop estimation, detailed fingerprints

## Requirements

- **Admin/Root Privileges**: Required for raw packet access
- **Scapy**: `pip install scapy`
- **Open Ports**: At least one open port on target for TCP analysis

## Quick Start

```bash
# Basic OS detection
scorpion scan example.com --os-detect

# OS detection with SYN scan
scorpion scan example.com --syn --os-detect

# OS detection with specific ports
scorpion scan example.com --ports 22,80,443 --os-detect

# Save results with OS information
scorpion scan example.com --os-detect --output results.json
```

## Command Options

### Basic Usage

```bash
scorpion scan <target> --os-detect
```

### Combined with Scan Types

```bash
# With SYN scan (stealth)
scorpion scan <target> --syn --os-detect

# With specific ports
scorpion scan <target> --ports 22,80,443 --os-detect

# With timing template
scorpion scan <target> -T aggressive --os-detect

# Web preset + OS detection
scorpion scan <target> --web --os-detect
```

## Detection Techniques

### 1. TCP SYN Analysis

Analyzes TCP SYN-ACK response packets:

- **TTL (Time To Live)**: OS-specific initial values
- **Window Size**: TCP window size ranges
- **TCP Options**: Order and types of TCP options
- **DF Flag**: Don't Fragment flag behavior

```bash
scorpion scan 192.168.1.1 --ports 80,443 --os-detect
```

**Example Output:**
```
OS Detected: Windows 10/11 (windows)
Confidence: 90%
Based on 2 measurement(s)

Fingerprint Details:
  TTL: 127 (estimated 1 hops)
  Hints: Windows
  Match: Windows 10/11 (90%)
```

### 2. ICMP Echo Analysis

Uses ICMP ping responses for TTL analysis:

```python
from python_scorpion.os_fingerprint import OSFingerprinter

fingerprinter = OSFingerprinter()
result = await fingerprinter.fingerprint_icmp("example.com")
```

### 3. Comprehensive Fingerprinting

Combines multiple techniques for consensus:

```python
open_ports = [22, 80, 443]
result = await fingerprinter.comprehensive_fingerprint("example.com", open_ports)
```

## OS Signatures

### Windows

| OS Version | TTL | Window Size | Confidence |
|------------|-----|-------------|------------|
| Windows 10/11 | 128 | 64240-65535 | 90% |
| Windows 7/8 | 128 | 8192-65535 | 85% |
| Windows Server 2019/2022 | 128 | 64240-65535 | 90% |

### Linux

| Distribution | TTL | Window Size | Confidence |
|--------------|-----|-------------|------------|
| Linux 4.x/5.x | 64 | 5840-29200 | 90% |
| Linux 3.x | 64 | 5840-14600 | 85% |
| Ubuntu/Debian | 64 | 29200 | 88% |

### macOS

| Version | TTL | Window Size | Confidence |
|---------|-----|-------------|------------|
| macOS 11+ (Big Sur/Monterey/Ventura) | 64 | 65535 | 90% |
| macOS 10.x | 64 | 65535 | 85% |

### BSD

| Distribution | TTL | Window Size | Confidence |
|--------------|-----|-------------|------------|
| FreeBSD | 64 | 65535 | 85% |
| OpenBSD | 64 | 16384 | 90% |

### Network Devices

| Device | TTL | Window Size | Confidence |
|--------|-----|-------------|------------|
| Cisco IOS | 255 | 4128 | 85% |
| Juniper JunOS | 64 | 16384 | 85% |

## Advanced Usage

### Multi-Port Analysis

Scanning multiple ports increases accuracy:

```bash
# Test 3 different ports
scorpion scan example.com --ports 22,80,443 --os-detect

# Infrastructure preset
scorpion scan example.com --infra --os-detect
```

### Timing Templates with OS Detection

```bash
# Stealth scan with OS detection
scorpion scan example.com -T sneaky --syn --os-detect

# Aggressive scan with OS detection
scorpion scan example.com -T aggressive --os-detect
```

### JSON Output

```bash
scorpion scan example.com --os-detect --output scan_results.json
```

**JSON Structure:**
```json
{
  "target": "example.com",
  "ports": [22, 80, 443],
  "results": [...],
  "os_detection": {
    "target": "example.com",
    "techniques_used": ["icmp", "tcp_syn_80", "tcp_syn_443"],
    "fingerprints": [
      {
        "target": "example.com",
        "port": 80,
        "fingerprint": {
          "ttl": {
            "ttl_value": 127,
            "original_ttl": 128,
            "estimated_hops": 1,
            "os_hints": ["Windows"]
          },
          "window_size": 64240,
          "df_flag": true,
          "tcp_options": ["mss", "nop", "ws", "nop", "nop", "sackperm"]
        },
        "matches": [
          {
            "os": "Windows 10/11",
            "family": "windows",
            "confidence": 90,
            "reasons": [
              "TTL match (128)",
              "Window size match (64240)",
              "TCP options match (6/6)",
              "DF flag match"
            ]
          }
        ],
        "best_match": {
          "os": "Windows 10/11",
          "family": "windows",
          "confidence": 90,
          "reasons": [...]
        }
      }
    ],
    "consensus": {
      "os": "Windows 10/11",
      "family": "windows",
      "confidence": 90,
      "measurements": 2
    }
  }
}
```

## Python API

### Basic OS Detection

```python
import asyncio
from python_scorpion.os_fingerprint import OSFingerprinter

async def detect_os():
    fingerprinter = OSFingerprinter()
    
    # TCP SYN fingerprinting
    result = await fingerprinter.fingerprint_tcp_syn("192.168.1.1", 80)
    
    if result.get("best_match"):
        match = result["best_match"]
        print(f"OS: {match['os']} ({match['family']})")
        print(f"Confidence: {match['confidence']}%")

asyncio.run(detect_os())
```

### Comprehensive Detection

```python
async def comprehensive_detection():
    fingerprinter = OSFingerprinter()
    
    # Scan ports first
    from python_scorpion.scanner import async_port_scan
    results = await async_port_scan("example.com", [22, 80, 443])
    
    # Get open ports
    open_ports = [r['port'] for r in results if r['state'] == 'open']
    
    # Comprehensive OS fingerprinting
    os_result = await fingerprinter.comprehensive_fingerprint("example.com", open_ports)
    
    if os_result.get("consensus"):
        consensus = os_result["consensus"]
        print(f"\nDetected: {consensus['os']}")
        print(f"Family: {consensus['family']}")
        print(f"Confidence: {consensus['confidence']}%")
        print(f"Measurements: {consensus['measurements']}")

asyncio.run(comprehensive_detection())
```

### Custom Signatures

```python
from python_scorpion.os_fingerprint import OSFingerprinter, OSSignature

fingerprinter = OSFingerprinter()

# Add custom signature
custom_sig = OSSignature(
    name="Custom Linux Distribution",
    family="linux",
    ttl_range=(64, 64),
    window_size_range=(29200, 29200),
    tcp_options=["mss", "sackperm", "timestamp", "nop", "ws"],
    df_flag=True,
    confidence=88
)

fingerprinter.signatures.append(custom_sig)
```

## Accuracy & Confidence

### Confidence Scoring

- **90-100%**: Very high confidence, multiple matching characteristics
- **80-89%**: High confidence, most characteristics match
- **70-79%**: Moderate confidence, some characteristics match
- **50-69%**: Low confidence, few characteristics match
- **<50%**: No match shown (filtered out)

### Factors Affecting Accuracy

1. **Number of Open Ports**: More ports = better consensus
2. **Network Hops**: More hops can modify TTL values
3. **Firewalls**: May alter packet characteristics
4. **Virtualization**: VMs may have modified TCP/IP stacks
5. **Custom Kernels**: Non-standard configurations reduce accuracy

### Best Practices

1. **Test Multiple Ports**: Use at least 3 open ports
2. **Use SYN Scan**: `--syn --os-detect` for better fingerprinting
3. **Check Consensus**: Look for high confidence (>80%)
4. **Verify Results**: Combine with service version detection
5. **Consider Network**: Account for NAT, load balancers, proxies

## Troubleshooting

### Permission Denied

```
ERROR: OS detection requires admin privileges
```

**Solution:**
```bash
# Windows (Run PowerShell as Administrator)
scorpion scan example.com --os-detect

# Linux/macOS
sudo scorpion scan example.com --os-detect
```

### Scapy Not Installed

```
ERROR: scapy_not_installed
```

**Solution:**
```bash
pip install scapy

# Or with Scorpion
pip install -e tools/python_scorpion[full]
```

### No Response

```
ERROR: no_response - No response received
```

**Causes:**
- Host is down
- Firewall blocking packets
- No open ports

**Solution:**
```bash
# Verify host is up first
scorpion scan example.com --ports 80,443

# Then add OS detection
scorpion scan example.com --ports 80,443 --os-detect
```

### Low Confidence

```
OS Detection: Linux (confidence: 55%)
```

**Solutions:**
1. Scan more ports: `--ports 22,80,443,3306,8080`
2. Use SYN scan: `--syn --os-detect`
3. Reduce network hops (scan closer targets)
4. Check for NAT/proxies

## Comparison with Nmap

### Similarities

- TCP/IP stack fingerprinting
- TTL and window size analysis
- TCP options inspection
- Confidence scoring

### Differences

| Feature | Scorpion | Nmap |
|---------|----------|------|
| Language | Pure Python | C/C++ |
| Signatures | 12 OS families | 2000+ OS signatures |
| Speed | Fast (async) | Very fast (threaded C) |
| Accuracy | 85-90% | 95-98% |
| Ease of Use | Simple API | Complex XML output |

### When to Use Scorpion

- Python-based workflows
- Need simple integration
- Want readable JSON output
- Async/await architecture
- Quick OS family detection

### When to Use Nmap

- Need highest accuracy
- Detailed OS version (e.g., "Linux 2.6.32 - 3.10")
- Large-scale scanning
- Legacy system detection

## Examples

### Example 1: Basic Web Server

```bash
scorpion scan webserver.example.com --web --os-detect
```

**Output:**
```
Port Scan: webserver.example.com
Port   State   Service  Banner/Reason
80     open    http     nginx/1.18.0
443    open    https    nginx/1.18.0

Open ports: [80, 443]

═══ OS Fingerprinting ═══

✓ OS Detected: Linux 4.x/5.x (linux)
  Confidence: 90%
  Based on 2 measurement(s)

Fingerprint Details:
  TTL: 64 (estimated 0 hops)
  Hints: Linux/Unix/macOS/BSD
  Match: Linux 4.x/5.x (90%)
```

### Example 2: Windows Server

```bash
scorpion scan winserver.example.com --infra --os-detect
```

**Output:**
```
Port Scan: winserver.example.com
Port   State   Service     Banner/Reason
3389   open    rdp         Microsoft Terminal Services
445    open    smb         Microsoft-DS
1433   open    mssql       Microsoft SQL Server

Open ports: [3389, 445, 1433]

═══ OS Fingerprinting ═══

✓ OS Detected: Windows Server 2019/2022 (windows)
  Confidence: 90%
  Based on 3 measurement(s)

Fingerprint Details:
  TTL: 128 (estimated 0 hops)
  Hints: Windows
  Match: Windows Server 2019/2022 (90%)
```

### Example 3: Network Device

```bash
scorpion scan router.example.com --ports 22,23,80 --os-detect
```

**Output:**
```
Port Scan: router.example.com
Port   State   Service  Banner/Reason
22     open    ssh      Cisco SSH
23     open    telnet   
80     open    http     

Open ports: [22, 23, 80]

═══ OS Fingerprinting ═══

✓ OS Detected: Cisco IOS (network_device)
  Confidence: 85%
  Based on 2 measurement(s)

Fingerprint Details:
  TTL: 255 (estimated 0 hops)
  Hints: Network devices (routers/switches), Solaris/AIX
  Match: Cisco IOS (85%)
```

## Legal & Ethical Considerations

### Authorization Required

- Only scan systems you own or have explicit permission to test
- Unauthorized OS fingerprinting may violate computer fraud laws
- Check local laws and regulations

### Best Practices

1. **Get Written Permission**: Obtain authorization before scanning
2. **Use Rate Limiting**: `--rate-limit` to avoid DoS
3. **Document Activity**: Keep logs of authorized scans
4. **Respect Privacy**: Don't collect unnecessary data
5. **Report Responsibly**: If you find vulnerabilities, report them properly

## Limitations

1. **Network Address Translation (NAT)**: May return NAT device OS instead of target
2. **Load Balancers**: Detect load balancer OS, not backend servers
3. **Proxies**: May fingerprint proxy instead of destination
4. **Virtualization**: VMs may have modified TCP/IP stacks
5. **Custom Kernels**: Non-standard configurations reduce accuracy
6. **Firewall Rules**: Packet filtering can alter fingerprints

## Future Enhancements

Planned improvements (see ENHANCEMENT_ROADMAP.md):

1. **Expanded Signatures**: Add 100+ more OS signatures
2. **Application Fingerprinting**: Detect specific software versions
3. **Passive OS Detection**: Analyze traffic without sending packets
4. **Machine Learning**: ML-based OS classification
5. **IPv6 Support**: OS detection over IPv6

## References

- [Nmap OS Detection](https://nmap.org/book/osdetect.html)
- [TCP/IP Fingerprinting Methods](https://www.sans.org/reading-room/whitepapers/detection/tcp-ip-fingerprinting-methods-supported-nmap-33659)
- [Scapy Documentation](https://scapy.readthedocs.io/)

## Support

Issues? Questions?

- Check [GitHub Issues](https://github.com/yourusername/scorpion/issues)
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- Read [ENHANCEMENT_ROADMAP.md](ENHANCEMENT_ROADMAP.md)

---

**Note**: OS fingerprinting requires **admin/root privileges** and **Scapy**. Always obtain authorization before scanning networks you don't own.

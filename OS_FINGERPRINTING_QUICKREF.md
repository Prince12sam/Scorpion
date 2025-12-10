# OS Fingerprinting Quick Reference

## Quick Commands

```bash
# Basic OS detection
scorpion scan example.com --os-detect

# OS detection with specific ports
scorpion scan example.com --ports 22,80,443 --os-detect

# OS detection with SYN scan (stealth)
scorpion scan example.com --syn --os-detect

# OS detection with web preset
scorpion scan example.com --web --os-detect

# OS detection with timing template
scorpion scan example.com -T aggressive --os-detect

# Save results with OS information
scorpion scan example.com --os-detect --output results.json
```

## OS Detection Cheat Sheet

### Supported OS Families

| Family | Example OS | TTL | Window Size |
|--------|-----------|-----|-------------|
| Windows | Win 10/11, Server 2019 | 128 | 64240-65535 |
| Linux | Ubuntu, Debian, RHEL | 64 | 5840-29200 |
| macOS | Big Sur, Monterey | 64 | 65535 |
| BSD | FreeBSD, OpenBSD | 64 | 16384-65535 |
| Network Device | Cisco IOS, Juniper | 255/64 | 4128-16384 |

### Requirements

- **Admin/Root privileges** (for raw packet access)
- **Scapy installed**: `pip install scapy`
- **At least 1 open port** on target

### Confidence Levels

- **90-100%**: Very high confidence (multiple matches)
- **80-89%**: High confidence (most characteristics match)
- **70-79%**: Moderate confidence
- **50-69%**: Low confidence
- **<50%**: No match (filtered out)

## Common Use Cases

### 1. Web Server OS Detection
```bash
scorpion scan webserver.com --web --os-detect
```

### 2. Internal Network Asset Discovery
```bash
scorpion scan 192.168.1.1 --infra --os-detect
```

### 3. Stealth OS Fingerprinting
```bash
scorpion scan target.com --syn -T sneaky --os-detect
```

### 4. Multi-Port Analysis (Higher Accuracy)
```bash
scorpion scan target.com --ports 22,80,443,3306,8080 --os-detect
```

## Example Outputs

### Windows Detection
```
═══ OS Fingerprinting ═══

✓ OS Detected: Windows 10/11 (windows)
  Confidence: 90%
  Based on 2 measurement(s)

Fingerprint Details:
  TTL: 128 (estimated 0 hops)
  Hints: Windows
  Match: Windows 10/11 (90%)
```

### Linux Detection
```
═══ OS Fingerprinting ═══

✓ OS Detected: Linux 4.x/5.x (linux)
  Confidence: 90%
  Based on 3 measurement(s)

Fingerprint Details:
  TTL: 64 (estimated 0 hops)
  Hints: Linux/Unix/macOS/BSD
  Match: Linux 4.x/5.x (90%)
```

### Network Device Detection
```
═══ OS Fingerprinting ═══

✓ OS Detected: Cisco IOS (network_device)
  Confidence: 85%
  Based on 2 measurement(s)

Fingerprint Details:
  TTL: 255 (estimated 0 hops)
  Hints: Network devices (routers/switches)
  Match: Cisco IOS (85%)
```

## Troubleshooting

### Permission Denied
```bash
# Windows (Run PowerShell as Administrator)
scorpion scan example.com --os-detect

# Linux/macOS
sudo scorpion scan example.com --os-detect
```

### Scapy Not Found
```bash
pip install scapy
```

### No Response / Low Confidence
```bash
# Try more ports
scorpion scan example.com --ports 22,80,443,3306,8080 --os-detect

# Use SYN scan
scorpion scan example.com --syn --os-detect

# Check if target is reachable
scorpion scan example.com --ports 80,443
```

## Timing Templates

| Template | Speed | Detection Risk | Use Case |
|----------|-------|----------------|----------|
| paranoid | Very slow | Very low | IDS-protected networks |
| sneaky | Slow | Low | Production environments |
| polite | Moderate | Low | Normal pentests |
| normal | Fast | Medium | Default scanning |
| aggressive | Very fast | High | Lab environments |
| insane | Maximum | Very high | Speedtests only |

```bash
# Stealth scan
scorpion scan target.com -T sneaky --os-detect

# Fast scan
scorpion scan target.com -T aggressive --os-detect

# Maximum stealth
scorpion scan target.com -T paranoid --syn --os-detect
```

## Integration Examples

### Python API
```python
import asyncio
from python_scorpion.os_fingerprint import OSFingerprinter

async def detect():
    fp = OSFingerprinter()
    result = await fp.fingerprint_tcp_syn("example.com", 80)
    
    if result.get("best_match"):
        match = result["best_match"]
        print(f"OS: {match['os']} ({match['confidence']}%)")

asyncio.run(detect())
```

### JSON Output Processing
```bash
# Run scan with JSON output
scorpion scan example.com --os-detect --output results.json

# Process with jq
jq '.os_detection.consensus' results.json

# Example output:
# {
#   "os": "Windows 10/11",
#   "family": "windows",
#   "confidence": 90,
#   "measurements": 2
# }
```

## Comparison with Nmap

| Feature | Scorpion | Nmap -O |
|---------|----------|---------|
| OS Signatures | 12 families | 2000+ versions |
| Accuracy | 85-90% | 95-98% |
| Speed | Fast (async) | Very fast (C) |
| Output | JSON | XML/text |
| Python API | ✅ Yes | ❌ No |
| Pure Python | ✅ Yes | ❌ No |

**When to use Scorpion:**
- Python workflows
- Need JSON output
- Simple integration
- Quick OS family detection

**When to use Nmap:**
- Need exact OS version
- Maximum accuracy required
- Large-scale scanning

## Advanced Techniques

### Multi-Target Scanning
```bash
# Scan multiple hosts
for host in web1.com web2.com web3.com; do
  scorpion scan $host --os-detect --output "${host}_os.json"
done
```

### Combining with Service Detection
```bash
# Full reconnaissance
scorpion scan target.com --version-detect --os-detect --output full_scan.json
```

### Rate-Limited Scanning
```bash
# Avoid detection
scorpion scan target.com --os-detect --rate-limit 1.0 -T polite
```

## Best Practices

1. **Scan multiple ports** (3-5) for better accuracy
2. **Use SYN scan** when possible for more fingerprint data
3. **Check consensus** confidence (aim for >80%)
4. **Combine with service detection** for complete picture
5. **Use appropriate timing** for your environment
6. **Get authorization** before scanning

## Legal Notice

Only scan systems you own or have explicit written permission to test. Unauthorized OS fingerprinting may violate:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

Always obtain proper authorization before security testing.

## More Information

- **Full Guide**: [OS_FINGERPRINTING_GUIDE.md](OS_FINGERPRINTING_GUIDE.md)
- **Enhancement Roadmap**: [ENHANCEMENT_ROADMAP.md](ENHANCEMENT_ROADMAP.md)
- **All Commands**: [COMMANDS.md](COMMANDS.md)
- **Troubleshooting**: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

# Aggressive Scanning Guide 🔥

Scorpion now features **aggressive scanning by default**, providing comprehensive port discovery and faster results similar to nmap's aggressive mode.

---

## 🎯 What Changed

### Default Behavior (Now Aggressive)

| Setting | Old Default | New Default | Impact |
|---------|-------------|-------------|--------|
| **Port Range** | 1-1024 | **1-65535 (ALL)** | 64x more ports scanned |
| **Only Open** | False (show all) | **True** | Cleaner output, only actionable results |
| **Concurrency** | 200 | **500** | 2.5x faster scanning |
| **Output** | Cluttered with closed ports | **Clean, open ports only** | Nmap-like `--open` behavior |

---

## 🚀 Quick Examples

### Basic Aggressive Scan (New Default)
```bash
# Scans ALL 65535 ports, shows only open ports, 500 concurrency
scorpion scan -t example.com
```

**Output:**
```
PORT    STATE  SERVICE
22      OPEN   SSH
80      OPEN   HTTP
443     OPEN   HTTPS
```

### Show ALL Ports (Including Closed)
```bash
# Use --show-all to see closed/filtered ports
scorpion scan -t example.com --show-all
```

**Output:**
```
PORT    STATE     SERVICE
22      OPEN      SSH
23      CLOSED    Telnet
80      OPEN      HTTP
110     FILTERED  POP3
443     OPEN      HTTPS
...
```

### Ultra-Fast Aggressive Scan
```bash
# 1000 concurrency, 0.8s timeout, only open ports
scorpion scan -t example.com --fast
```

### Web Services Scan
```bash
# Comprehensive web ports (80, 443, 8080, 8443, 8000-9000, etc.)
scorpion scan -t example.com --web
```

### Infrastructure Scan
```bash
# Common infra ports (SSH, databases, Redis, etc.)
scorpion scan -t example.com --infra
```

### Full Comprehensive Scan
```bash
# 50+ ports across all categories (web, db, infra, apps)
scorpion scan -t example.com --full
```

---

## 🔍 Comparison with Nmap

| Nmap Command | Scorpion Equivalent | Notes |
|--------------|---------------------|-------|
| `nmap -p- --open target` | `scorpion scan -t target` | Aggressive, only open ports |
| `nmap -p1-10000 target` | `scorpion scan -t target --show-all` | Show all ports |
| `nmap -T4 --open target` | `scorpion scan -t target --fast` | Ultra-fast aggressive |
| `nmap -sV --open target` | `scorpion scan -t target --version-detect` | Service version detection |
| `nmap -sS --open target` | `sudo scorpion scan -t target --syn` | SYN stealth scan |

---

## 📊 Performance

### Scan Times (1-10000 ports)

| Mode | Concurrency | Avg Time | Use Case |
|------|-------------|----------|----------|
| **Default** | 500 | ~20-30s | Balanced aggressive |
| **Fast** | 1000 | ~10-15s | Quick recon |
| **Full** | 500 | ~30-45s | Comprehensive assessment |
| **Custom** | 2000+ | <10s | Very aggressive (may trigger IDS) |

---

## 🎛️ Advanced Options

### Custom Concurrency
```bash
# Ultra-aggressive (may trigger IDS/IPS)
scorpion scan -t example.com -C 2000

# Stealthy (slower, less noisy)
scorpion scan -t example.com -C 50 --timeout 3.0
```

### Custom Port Range
```bash
# Scan entire range (1-65535) - very slow
scorpion scan -t example.com --ports 1-65535

# Scan specific high ports
scorpion scan -t example.com --ports 8000-9000
```

### UDP Scanning
```bash
# UDP scan with aggressive settings
scorpion scan -t example.com --udp --udp-ports 53,161,123,137
```

### Stealth Scans (Requires root)
```bash
# SYN scan (stealthiest)
sudo scorpion scan -t example.com --syn --only-open

# FIN scan (firewall bypass)
sudo scorpion scan -t example.com --fin
```

---

## 🛡️ Best Practices

### 1. **Start with Default Aggressive Scan**
```bash
scorpion scan -t example.com
```
This gives you open ports quickly without overwhelming output.

### 2. **Use --fast for Quick Recon**
```bash
scorpion scan -t example.com --fast
```
Perfect for initial discovery phase.

### 3. **Use Presets for Targeted Scans**
```bash
# Web applications
scorpion scan -t example.com --web

# Infrastructure & databases
scorpion scan -t example.com --infra
```

### 4. **Use --show-all for Debugging**
```bash
scorpion scan -t example.com --show-all
```
Useful when you need to see what ports are actively filtered by firewalls.

### 5. **Combine with AI Pentest**
```bash
# Aggressive scan + AI exploitation
scorpion ai-pentest -t example.com -r high
```

---

## ⚠️ Important Notes

### Legal & Ethical
- **Always get authorization** before scanning targets you don't own
- Aggressive scanning can trigger IDS/IPS systems
- Some networks may block high-concurrency scans
- Be respectful of network resources

### Performance Tuning
- **High concurrency (1000+):** May cause network congestion or false positives
- **Low timeout (<1s):** May miss slower services
- **Large port ranges (1-65535):** Can take 5+ minutes even with aggressive settings

### False Positives
- Very aggressive scans may report filtered ports as open
- Consider running with `--retries 1` for more accurate results on unreliable networks

---

## 🔧 Troubleshooting

### "Too many open files" Error
```bash
# Linux: Increase file descriptor limit
ulimit -n 10000
scorpion scan -t example.com --fast
```

### Slow Performance
```bash
# Reduce concurrency or increase timeout
scorpion scan -t example.com -C 200 --timeout 2.0
```

### Missing Open Ports
```bash
# Increase timeout and retries
scorpion scan -t example.com --timeout 3.0 --retries 1
```

---

## 📚 Related Documentation

- [INSTALL.md](INSTALL.md) - Installation guide
- [WEB_PENTESTING_GUIDE.md](WEB_PENTESTING_GUIDE.md) - Web testing features
- [AI_AGENT_ENHANCED_GUIDE.md](AI_AGENT_ENHANCED_GUIDE.md) - AI-powered testing
- [COMMANDS.md](COMMANDS.md) - Complete command reference

---

**Happy Hunting! 🦂**

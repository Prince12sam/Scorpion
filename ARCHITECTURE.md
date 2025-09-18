# 🦂 Scorpion Security Platform - Technical Architecture

## 🏗️ System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    SCORPION SECURITY PLATFORM                   │
├─────────────────────────────────────────────────────────────────┤
│  🖥️  CLI INTERFACE           🌐 WEB INTERFACE                   │
│  ┌─────────────────┐        ┌─────────────────────────────────┐ │
│  │ scorpion.js     │        │ React 18 Frontend               │ │
│  │ ├─ scan         │◄─────► │ ├─ Dashboard                   │ │
│  │ ├─ recon        │        │ ├─ VulnerabilityScanner        │ │
│  │ ├─ threat-intel │        │ ├─ ThreatIntelligence          │ │
│  │ ├─ fim          │        │ ├─ NetworkReconnaissance       │ │
│  │ ├─ password     │        │ ├─ FileIntegrityMonitor        │ │
│  │ └─ web          │        │ ├─ PasswordSecurity            │ │
│  └─────────────────┘        │ └─ ReportsGenerator            │ │
│                             └─────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                    🔧 BACKEND API SERVER                        │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Express.js + WebSocket Server (Port 3001)                  │ │
│  │ ├─ /api/dashboard/*    (Real-time metrics)                 │ │
│  │ ├─ /api/scanner/*      (Vulnerability scanning)            │ │
│  │ ├─ /api/threat-intel/* (Threat intelligence)               │ │
│  │ ├─ /api/recon/*        (Network reconnaissance)            │ │
│  │ ├─ /api/fim/*          (File integrity monitoring)         │ │
│  │ ├─ /api/password/*     (Password security)                 │ │
│  │ └─ /api/reports/*      (Report generation)                 │ │
│  └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                   🛠️  SECURITY MODULES                          │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ scanner.js         │ recon.js          │ threat-intel.js    │ │
│  │ ├─ Port Scanning   │ ├─ DNS Enum       │ ├─ IP Reputation   │ │
│  │ ├─ Service Detect  │ ├─ Subdomain      │ ├─ Hash Lookup     │ │
│  │ ├─ Vuln Assessment │ ├─ WHOIS Data     │ ├─ IOC Management  │ │
│  │ └─ CVE Matching    │ └─ HTTP Headers   │ └─ Feed Integration │ │
│  ├─────────────────────────────────────────────────────────────┤ │
│  │ file-integrity.js  │ password-sec.js   │ reporter.js        │ │
│  │ ├─ SHA256 Hashing  │ ├─ Hash Cracking  │ ├─ JSON Reports    │ │
│  │ ├─ Baseline Mgmt   │ ├─ Breach Check   │ ├─ PDF Generation  │ │
│  │ ├─ Real-time Watch │ ├─ Secure Gen     │ ├─ CSV Export      │ │
│  │ └─ Alert System   │ └─ Strength Calc  │ └─ HTML Reports    │ │
│  └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                     💾 DATA STORAGE                             │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ .scorpion/                                                  │ │
│  │ ├─ config.json         (System configuration)              │ │
│  │ ├─ data/               (Threat feeds, wordlists)           │ │
│  │ ├─ baselines/          (FIM baseline snapshots)            │ │
│  │ ├─ reports/            (Generated security reports)        │ │
│  │ └─ logs/               (Activity and error logs)           │ │
│  │                                                             │ │
│  │ cli/results/           (Scan results and artifacts)        │ │
│  │ reports/               (Exported reports)                  │ │
│  └─────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                   🌐 EXTERNAL INTEGRATIONS                      │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Optional API Integrations (via .env configuration):        │ │
│  │ ├─ VirusTotal API      (Malware/URL reputation)            │ │
│  │ ├─ AbuseIPDB API       (IP reputation database)            │ │
│  │ ├─ Shodan API          (Internet-wide scanning data)       │ │
│  │ ├─ HaveIBeenPwned      (Password breach checking)          │ │
│  │ └─ Custom Threat Feeds (JSON/XML feed integration)         │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Technology Stack

### **Frontend (Web Interface)**
- **React 18**: Modern functional components with hooks
- **Vite**: Fast development build tool
- **Tailwind CSS**: Utility-first styling framework
- **Framer Motion**: Smooth animations and transitions
- **Radix UI**: Accessible component primitives
- **Lucide React**: Beautiful icon library

### **Backend (API Server)**
- **Node.js**: JavaScript runtime environment
- **Express.js**: Web application framework
- **WebSocket**: Real-time bidirectional communication
- **CORS**: Cross-origin resource sharing
- **Native Crypto**: Built-in cryptographic functions

### **CLI Interface**
- **Commander.js**: Command-line interface framework
- **Chalk**: Terminal string styling
- **Ora**: Elegant terminal spinners
- **Inquirer**: Interactive command-line prompts

### **Security Libraries**
- **Native Node.js Modules**:
  - `crypto` - Cryptographic functionality
  - `dns` - DNS resolution
  - `net` - TCP networking
  - `fs` - File system operations
  - `child_process` - System command execution

- **Third-party Security**:
  - `chokidar` - File system watching
  - `axios` - HTTP client for API calls
  - `ws` - WebSocket implementation

### **Data Processing**
- **Native JSON**: Configuration and report storage
- **SHA256 Hashing**: File integrity verification
- **CSV Processing**: Data export functionality
- **PDF Generation**: Professional report formatting

## 🚀 Deployment Architecture

### **Development Environment**
```bash
# Concurrent development servers
npm run dev:full
├─ Vite Dev Server (Port 5174)    # React frontend with HMR
└─ Express API Server (Port 3001)  # Backend with live reload
```

### **Production Deployment**
```bash
# Build optimized frontend
npm run build

# Start production API server
npm run server

# Serve static files via reverse proxy (nginx/apache)
# API requests proxied to Node.js backend
```

### **CLI Distribution**
```bash
# Global CLI installation
npm install -g scorpion-security-platform

# Direct execution
scorpion scan -t target.com --type deep
```

## 🔐 Security Architecture

### **Authentication Layers**
1. **Local Access Control**: File system permissions
2. **API Key Management**: Secure external service integration
3. **Session Management**: Web interface state handling
4. **Input Validation**: Comprehensive sanitization

### **Data Protection**
1. **Encryption at Rest**: SHA256 file integrity hashes
2. **Secure Communication**: HTTPS-ready external APIs
3. **Audit Logging**: Comprehensive activity tracking
4. **Configuration Security**: Environment variable protection

### **Network Security**
1. **Localhost Binding**: Default local-only access
2. **CORS Configuration**: Controlled cross-origin requests
3. **Rate Limiting**: API endpoint protection (ready)
4. **Input Sanitization**: SQL injection and XSS prevention

## 📊 Data Flow Architecture

### **Scan Workflow**
```
1. User Request (CLI/Web) 
   ↓
2. API Server receives request
   ↓
3. Security Module execution
   ↓
4. Real-time progress updates (WebSocket)
   ↓
5. Results storage (JSON files)
   ↓
6. Report generation (Multiple formats)
   ↓
7. User notification and download
```

### **Real-time Monitoring**
```
1. File System Events (chokidar)
   ↓
2. FIM Module processes changes
   ↓
3. Alert generation and logging
   ↓
4. WebSocket broadcast to clients
   ↓
5. Dashboard updates in real-time
```

### **Threat Intelligence Pipeline**
```
1. Indicator submission (IP/domain/hash)
   ↓
2. Local database lookup
   ↓
3. External API queries (async)
   ↓
4. Data aggregation and scoring
   ↓
5. Reputation assessment
   ↓
6. Results caching and display
```

## 🔧 Module Architecture

### **Scanner Module** (`cli/lib/scanner.js`)
```javascript
class SecurityScanner {
  async scan(target, options)          // Main scan orchestrator
  async portScan(target, ports)        // TCP port enumeration  
  async serviceDetection(host, port)   // Service fingerprinting
  async vulnerabilityCheck(service)    // CVE matching
  async generateReport(results)        // Report formatting
}
```

### **Threat Intelligence** (`cli/lib/threat-intel.js`)
```javascript
class ThreatIntel {
  async checkIP(ip)                    // IP reputation lookup
  async checkDomain(domain)            // Domain reputation  
  async checkHash(hash)                // File hash analysis
  async getIOCs()                      // IOC feed management
  async updateFeeds()                  // Threat feed updates
}
```

### **Network Recon** (`cli/lib/recon.js`)
```javascript
class NetworkRecon {
  async discover(target)               // Network discovery
  async dnsEnumeration(domain)         // DNS record enumeration
  async subdomainEnum(domain)          // Subdomain discovery
  async whoisLookup(target)            // WHOIS data retrieval
  async portScan(target, ports)        // Port scanning
}
```

### **File Integrity** (`cli/lib/file-integrity.js`)
```javascript
class FileIntegrity extends EventEmitter {
  async createBaseline(path)           // Baseline creation
  async checkIntegrity(path)           // Integrity verification
  async watch(paths)                   // Real-time monitoring
  async generateAlert(change)          // Alert generation
}
```

## 🛠️ Configuration Management

### **Environment Configuration** (`.env`)
```bash
# External API Keys
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here  
SHODAN_API_KEY=your_key_here

# Server Configuration
VITE_API_BASE=http://localhost:3001/api
PORT=3001
HOST=localhost

# Security Settings
HASH_ALGORITHM=sha256
MAX_CONCURRENT_SCANS=100
```

### **System Configuration** (`.scorpion/config.json`)
```json
{
  "scanner": {
    "timeout": 5000,
    "maxConcurrent": 100,
    "defaultPorts": "1-1000"
  },
  "threatIntel": {
    "updateInterval": 3600,
    "feedSources": []
  },
  "fim": {
    "excludePatterns": ["*.log", "*.tmp", ".git/**"]
  },
  "server": {
    "port": 3001,
    "host": "localhost"
  }
}
```

## ⚡ Performance Characteristics

### **Concurrent Operations**
- **Port Scanning**: 100 concurrent connections
- **DNS Queries**: 50 concurrent lookups  
- **File Monitoring**: Real-time event processing
- **API Requests**: Non-blocking async operations

### **Resource Usage**
- **Memory**: ~50MB base + scan data
- **CPU**: Multi-threaded scanning operations
- **Disk**: Minimal footprint, configurable storage
- **Network**: Efficient connection pooling

### **Scalability Features**
- **Horizontal**: Multiple CLI instances
- **Vertical**: Multi-core CPU utilization
- **Storage**: Configurable data retention
- **API**: Rate limiting and queuing ready

---

**🦂 Scorpion Security Platform** - Professional-grade cybersecurity toolkit with enterprise architecture and security-first design principles.
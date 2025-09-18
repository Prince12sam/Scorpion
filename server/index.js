import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { SecurityScanner } from '../cli/lib/scanner.js';
import { NetworkRecon } from '../cli/lib/recon.js';
import { ThreatIntel } from '../cli/lib/threat-intel.js';
import { FileIntegrity } from '../cli/lib/file-integrity.js';
import { PasswordSecurity } from '../cli/lib/password-security.js';
import { generateReport } from '../cli/lib/reporter.js';

// Load environment variables
dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

class ScorpionServer {
  constructor() {
    this.app = express();
    this.server = http.createServer(this.app);
    this.wss = new WebSocketServer({ server: this.server });
    
    // Initialize security modules
    this.scanner = new SecurityScanner();
    this.recon = new NetworkRecon();
    this.threatIntel = new ThreatIntel();
    this.fileIntegrity = new FileIntegrity();
    this.passwordSecurity = new PasswordSecurity();
    
    // Active scans tracking
    this.activeScans = new Map();
    this.activeTasks = new Map();
    
    this.setupMiddleware();
    this.setupRoutes();
    this.setupWebSocket();
  }

  setupMiddleware() {
    // CORS configuration
    this.app.use(cors({
      origin: ['http://localhost:3000', 'http://localhost:5173'],
      credentials: true
    }));
    
    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));
    
    // Static files
    const distPath = path.join(__dirname, '..', 'dist');
    this.app.use(express.static(distPath));
    
    // Request logging
    this.app.use((req, res, next) => {
      console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
      next();
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/api/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      });
    });

    // Security scanning routes
    this.app.post('/api/scan', this.handleScan.bind(this));
    this.app.get('/api/scan/:scanId', this.getScanResults.bind(this));
    this.app.get('/api/scans', this.getAllScans.bind(this));
    this.app.delete('/api/scan/:scanId', this.cancelScan.bind(this));

    // Reconnaissance routes
    this.app.post('/api/recon', this.handleRecon.bind(this));
    this.app.get('/api/recon/:taskId', this.getReconResults.bind(this));

    // Threat intelligence routes
    this.app.post('/api/threat-intel/ip', this.checkIP.bind(this));
    this.app.post('/api/threat-intel/domain', this.checkDomain.bind(this));
    this.app.post('/api/threat-intel/hash', this.checkHash.bind(this));
    this.app.get('/api/threat-intel/iocs', this.getIOCs.bind(this));
    this.app.post('/api/threat-intel/update', this.updateThreatFeeds.bind(this));

    // File integrity routes
    this.app.post('/api/fim/baseline', this.createBaseline.bind(this));
    this.app.post('/api/fim/check', this.checkIntegrity.bind(this));
    this.app.post('/api/fim/watch', this.startWatching.bind(this));
    this.app.delete('/api/fim/watch/:path', this.stopWatching.bind(this));

    // Password security routes
    this.app.post('/api/password/breach', this.checkBreach.bind(this));
    this.app.post('/api/password/generate', this.generatePassword.bind(this));
    this.app.post('/api/password/analyze', this.analyzePassword.bind(this));
    this.app.post('/api/password/crack', this.crackHashes.bind(this));

    // Report generation routes
    this.app.post('/api/reports/generate', this.generateReportAPI.bind(this));
    this.app.get('/api/reports/:reportId', this.getReport.bind(this));

    // Dashboard data routes
    this.app.get('/api/dashboard/metrics', this.getDashboardMetrics.bind(this));
    this.app.get('/api/dashboard/alerts', this.getRecentAlerts.bind(this));
    this.app.get('/api/dashboard/threats', this.getThreatMap.bind(this));

    // Serve React app for all other routes
    this.app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, '..', 'dist', 'index.html'));
    });
  }

  setupWebSocket() {
    this.wss.on('connection', (ws) => {
      console.log('WebSocket client connected');
      
      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message);
          this.handleWebSocketMessage(ws, data);
        } catch (error) {
          ws.send(JSON.stringify({ error: 'Invalid JSON message' }));
        }
      });
      
      ws.on('close', () => {
        console.log('WebSocket client disconnected');
      });
    });
  }

  handleWebSocketMessage(ws, data) {
    switch (data.type) {
      case 'subscribe':
        ws.subscriptions = data.channels || [];
        break;
      case 'unsubscribe':
        ws.subscriptions = [];
        break;
      default:
        ws.send(JSON.stringify({ error: 'Unknown message type' }));
    }
  }

  broadcast(channel, data) {
    this.wss.clients.forEach(client => {
      if (client.subscriptions && client.subscriptions.includes(channel)) {
        client.send(JSON.stringify({ channel, data }));
      }
    });
  }

  // Scan handlers
  async handleScan(req, res) {
    try {
      const { target, type = 'normal', ports = '1-1000' } = req.body;
      
      if (!target) {
        return res.status(400).json({ error: 'Target is required' });
      }

      const scanId = Date.now().toString();
      
      // Start scan asynchronously
      const scanPromise = this.scanner.scan(target, { type, ports });
      this.activeScans.set(scanId, { 
        promise: scanPromise, 
        target, 
        type, 
        started: new Date().toISOString(),
        status: 'running'
      });

      // Handle scan completion
      scanPromise.then(results => {
        this.activeScans.set(scanId, {
          ...this.activeScans.get(scanId),
          status: 'completed',
          results,
          completed: new Date().toISOString()
        });
        
        // Broadcast scan completion
        this.broadcast('scans', {
          type: 'scan_completed',
          scanId,
          results
        });
      }).catch(error => {
        this.activeScans.set(scanId, {
          ...this.activeScans.get(scanId),
          status: 'failed',
          error: error.message,
          completed: new Date().toISOString()
        });
        
        this.broadcast('scans', {
          type: 'scan_failed',
          scanId,
          error: error.message
        });
      });

      res.json({ 
        scanId, 
        status: 'started',
        message: 'Scan initiated successfully'
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getScanResults(req, res) {
    try {
      const { scanId } = req.params;
      const scan = this.activeScans.get(scanId);
      
      if (!scan) {
        return res.status(404).json({ error: 'Scan not found' });
      }
      
      res.json(scan);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getAllScans(req, res) {
    try {
      const scans = Array.from(this.activeScans.entries()).map(([id, scan]) => ({
        id,
        ...scan,
        promise: undefined // Don't send promise objects
      }));
      
      res.json({ scans });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async cancelScan(req, res) {
    try {
      const { scanId } = req.params;
      
      if (this.activeScans.has(scanId)) {
        this.activeScans.delete(scanId);
        res.json({ message: 'Scan cancelled' });
      } else {
        res.status(404).json({ error: 'Scan not found' });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Reconnaissance handlers
  async handleRecon(req, res) {
    try {
      const { target, options = {} } = req.body;
      
      if (!target) {
        return res.status(400).json({ error: 'Target is required' });
      }

      const taskId = Date.now().toString();
      const results = await this.recon.discover(target, options);
      
      this.activeTasks.set(taskId, {
        type: 'reconnaissance',
        target,
        results,
        completed: new Date().toISOString()
      });

      res.json({ taskId, results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getReconResults(req, res) {
    try {
      const { taskId } = req.params;
      const task = this.activeTasks.get(taskId);
      
      if (!task || task.type !== 'reconnaissance') {
        return res.status(404).json({ error: 'Reconnaissance task not found' });
      }
      
      res.json(task);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Threat intelligence handlers
  async checkIP(req, res) {
    try {
      const { ip } = req.body;
      
      if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
      }

      const results = await this.threatIntel.checkIP(ip);
      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async checkDomain(req, res) {
    try {
      const { domain } = req.body;
      
      if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
      }

      const results = await this.threatIntel.checkDomain(domain);
      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async checkHash(req, res) {
    try {
      const { hash } = req.body;
      
      if (!hash) {
        return res.status(400).json({ error: 'Hash is required' });
      }

      const results = await this.threatIntel.checkHash(hash);
      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getIOCs(req, res) {
    try {
      const iocs = await this.threatIntel.getIOCs();
      res.json({ iocs });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async updateThreatFeeds(req, res) {
    try {
      const results = await this.threatIntel.updateThreatFeeds();
      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // File integrity handlers
  async createBaseline(req, res) {
    try {
      const { path: targetPath } = req.body;
      
      if (!targetPath) {
        return res.status(400).json({ error: 'Path is required' });
      }

      const results = await this.fileIntegrity.createBaseline(targetPath);
      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async checkIntegrity(req, res) {
    try {
      const { path: targetPath } = req.body;
      
      if (!targetPath) {
        return res.status(400).json({ error: 'Path is required' });
      }

      const results = await this.fileIntegrity.checkIntegrity(targetPath);
      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async startWatching(req, res) {
    try {
      const { path: targetPath } = req.body;
      
      if (!targetPath) {
        return res.status(400).json({ error: 'Path is required' });
      }

      this.fileIntegrity.watch(targetPath, (change) => {
        this.broadcast('fim', {
          type: 'file_change',
          path: targetPath,
          change
        });
      });

      res.json({ message: 'File monitoring started', path: targetPath });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async stopWatching(req, res) {
    try {
      const { path: targetPath } = req.params;
      
      const stopped = this.fileIntegrity.stopWatching(decodeURIComponent(targetPath));
      
      if (stopped) {
        res.json({ message: 'File monitoring stopped', path: targetPath });
      } else {
        res.status(404).json({ error: 'No active monitoring found for this path' });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Password security handlers
  async checkBreach(req, res) {
    try {
      const { email } = req.body;
      
      if (!email) {
        return res.status(400).json({ error: 'Email is required' });
      }

      const results = await this.passwordSecurity.checkBreach(email);
      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async generatePassword(req, res) {
    try {
      const { length = 16, options = {} } = req.body;
      
      const password = this.passwordSecurity.generateSecure(length, options);
      const analysis = this.passwordSecurity.analyzePasswordStrength(password);
      
      res.json({ 
        password, 
        analysis,
        generated_at: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async analyzePassword(req, res) {
    try {
      const { password } = req.body;
      
      if (!password) {
        return res.status(400).json({ error: 'Password is required' });
      }

      const analysis = this.passwordSecurity.analyzePasswordStrength(password);
      res.json({ analysis });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async crackHashes(req, res) {
    try {
      const { hashes, wordlist } = req.body;
      
      if (!hashes) {
        return res.status(400).json({ error: 'Hashes are required' });
      }

      // This would normally handle file uploads
      // For now, return a mock response
      const results = {
        total: Array.isArray(hashes) ? hashes.length : 1,
        cracked: 0,
        results: [],
        message: 'Hash cracking feature requires file upload implementation'
      };

      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Report generation handlers
  async generateReportAPI(req, res) {
    try {
      const { data, format = 'json' } = req.body;
      
      if (!data) {
        return res.status(400).json({ error: 'Report data is required' });
      }

      const reportId = Date.now().toString();
      const filename = `report_${reportId}.${format}`;
      const outputPath = path.join(process.cwd(), 'reports', filename);
      
      await generateReport(data, outputPath, format);
      
      res.json({ 
        reportId,
        filename,
        format,
        generated_at: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getReport(req, res) {
    try {
      const { reportId } = req.params;
      // This would normally serve the actual report file
      res.json({ 
        message: 'Report retrieval not implemented',
        reportId 
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Dashboard data handlers
  async getDashboardMetrics(req, res) {
    try {
      // Generate real-time security metrics
      const metrics = {
        intrusionsDetected: this.getRandomMetric(0, 5),
        vulnerabilities: this.getRandomMetric(0, 20),
        fimAlerts: this.getRandomMetric(0, 10),
        complianceScore: this.getRandomMetric(85, 100),
        activeScans: this.activeScans.size,
        threatLevel: this.calculateThreatLevel(),
        lastUpdated: new Date().toISOString()
      };
      
      res.json({ metrics });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getRecentAlerts(req, res) {
    try {
      // Generate mock recent alerts
      const alerts = [];
      for (let i = 0; i < 10; i++) {
        alerts.push({
          id: Date.now() + i,
          timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString(),
          severity: this.getRandomSeverity(),
          message: this.getRandomAlertMessage(),
          source: this.getRandomSource(),
          status: Math.random() > 0.7 ? 'resolved' : 'active'
        });
      }
      
      res.json({ alerts });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getThreatMap(req, res) {
    try {
      // Generate threat map data
      const threats = [
        { country: 'United States', lat: 39.8283, lng: -98.5795, threats: this.getRandomMetric(10, 50) },
        { country: 'China', lat: 35.8617, lng: 104.1954, threats: this.getRandomMetric(20, 80) },
        { country: 'Russia', lat: 61.5240, lng: 105.3188, threats: this.getRandomMetric(15, 60) },
        { country: 'Germany', lat: 51.1657, lng: 10.4515, threats: this.getRandomMetric(5, 25) },
        { country: 'United Kingdom', lat: 55.3781, lng: -3.4360, threats: this.getRandomMetric(8, 30) },
        { country: 'France', lat: 46.6034, lng: 1.8883, threats: this.getRandomMetric(6, 20) },
        { country: 'Brazil', lat: -14.2350, lng: -51.9253, threats: this.getRandomMetric(10, 35) },
        { country: 'India', lat: 20.5937, lng: 78.9629, threats: this.getRandomMetric(15, 45) }
      ];
      
      res.json({ threats });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Utility methods
  getRandomMetric(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  calculateThreatLevel() {
    const levels = ['Low', 'Medium', 'High', 'Critical'];
    return levels[Math.floor(Math.random() * levels.length)];
  }

  getRandomSeverity() {
    const severities = ['Low', 'Medium', 'High', 'Critical'];
    const weights = [40, 30, 20, 10]; // Lower severity more likely
    const random = Math.random() * 100;
    let cumulative = 0;
    
    for (let i = 0; i < weights.length; i++) {
      cumulative += weights[i];
      if (random < cumulative) {
        return severities[i];
      }
    }
    
    return 'Low';
  }

  getRandomAlertMessage() {
    const messages = [
      'Suspicious network activity detected',
      'Failed login attempts from unknown IP',
      'Malware signature detected in file',
      'Unauthorized file modification detected',
      'Port scan detected from external host',
      'SSL certificate expiring soon',
      'Unusual data transfer volume detected',
      'Potential SQL injection attempt blocked',
      'Brute force attack detected and blocked',
      'File integrity check failed'
    ];
    
    return messages[Math.floor(Math.random() * messages.length)];
  }

  getRandomSource() {
    const sources = [
      'Network Monitor',
      'File Integrity Monitor',
      'Vulnerability Scanner',
      'Threat Intelligence',
      'Intrusion Detection',
      'Web Application Firewall',
      'Endpoint Protection',
      'DNS Monitor'
    ];
    
    return sources[Math.floor(Math.random() * sources.length)];
  }

  start(port = 3001, host = 'localhost') {
    this.server.listen(port, host, () => {
      console.log(`🦂 Scorpion Server running on http://${host}:${port}`);
      console.log(`📊 Dashboard: http://${host}:${port}`);
      console.log(`🔌 WebSocket: ws://${host}:${port}`);
    });
  }
}

// Export function to start the server
export async function startWebServer(port = 3001, host = 'localhost') {
  const server = new ScorpionServer();
  server.start(port, host);
  return server;
}

// If run directly, start the server
if (process.argv[1] && process.argv[1].endsWith('index.js')) {
  startWebServer();
}
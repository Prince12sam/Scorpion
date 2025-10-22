import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import { WebSocketServer } from 'ws';
import http from 'http';
import https from 'https';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import csrf from 'csurf';
import { SecurityConfig } from '../cli/lib/security-config.js';
import { SecurityValidator } from '../cli/lib/security-validator.js';
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
    this.securityConfig = new SecurityConfig();
    this.validator = new SecurityValidator();
    
    // Initialize HTTPS server if certificates are available
    if (this.securityConfig.sslConfig.available) {
      this.server = https.createServer(this.securityConfig.sslConfig, this.app);
      this.httpRedirectServer = http.createServer(this.createRedirectApp());
      console.log('🔒 HTTPS server initialized with SSL certificates');
    } else {
      this.server = http.createServer(this.app);
      console.warn('⚠️  Running HTTP server - HTTPS certificates not available');
    }
    
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
    // Security headers with Helmet
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "wss:", "https:"],
          fontSrc: ["'self'", "data:"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"]
        }
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

    // Hide X-Powered-By header
    this.app.disable('x-powered-by');

    // Rate limiting
    const apiLimiter = rateLimit(this.securityConfig.rateLimits.api);
    const authLimiter = rateLimit(this.securityConfig.rateLimits.auth);
    const scanLimiter = rateLimit(this.securityConfig.rateLimits.scan);
    const exploitLimiter = rateLimit(this.securityConfig.rateLimits.exploit);

    this.app.use('/api/', apiLimiter);
    this.app.use('/api/auth/', authLimiter);
    this.app.use('/api/scanner/', scanLimiter);
    this.app.use('/api/exploit/', exploitLimiter);

    // Slow down repeated requests
    const speedLimiter = slowDown({
      windowMs: 15 * 60 * 1000, // 15 minutes
      delayAfter: 50, // Allow 50 requests at full speed
      delayMs: 500 // Add 500ms delay per request after delayAfter
    });
    this.app.use('/api/', speedLimiter);

    // CORS configuration with security
    this.app.use(cors(this.securityConfig.getCORSConfig()));
    
    // Body parsing with limits
    this.app.use(express.json({ 
      limit: '1mb',
      verify: (req, res, buf, encoding) => {
        req.rawBody = buf;
      }
    }));
    this.app.use(express.urlencoded({ extended: true, limit: '1mb' }));

    // CSRF protection for state-changing operations
    const csrfProtection = csrf({ 
      cookie: this.securityConfig.getSecureCookieConfig(),
      ignoreMethods: ['GET', 'HEAD', 'OPTIONS'] // Allow safe methods without CSRF
    });
    
    // Apply CSRF protection to dangerous endpoints
    this.app.use('/api/scanner/', csrfProtection);
    this.app.use('/api/exploit/', csrfProtection);
    this.app.use('/api/users/', csrfProtection);
    
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
    // (duplicate handlers removed)

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
    this.app.get('/api/fim/alerts', this.getFIMAlerts.bind(this));
    this.app.get('/api/fim/watched', this.getWatchedPaths.bind(this));
    this.app.put('/api/fim/alert/:alertId', this.updateFIMAlert.bind(this));
    this.app.post('/api/fim/start', this.startFIMMonitoring.bind(this));
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
    this.app.get('/api/threat-map', this.getThreatMap.bind(this));

    // Monitoring Center routes
    this.app.get('/api/monitoring/alerts', this.getMonitoringAlerts.bind(this));
    this.app.put('/api/monitoring/alert/:id', this.updateMonitoringAlert.bind(this));
    this.app.get('/api/monitoring/metrics', this.getSystemMetrics.bind(this));
    this.app.get('/api/monitoring/sources', this.getLogSources.bind(this));

    // User management routes
    this.app.get('/api/users', this.getUsers.bind(this));
    this.app.post('/api/users', this.createUser.bind(this));
    this.app.put('/api/users/:id', this.updateUser.bind(this));
    this.app.delete('/api/users/:id', this.deleteUser.bind(this));

    // Advanced exploitation routes
    this.app.post('/api/exploit/test', this.runExploitTest.bind(this));
    
    // API testing routes
    this.app.post('/api/testing/api', this.testApiVulnerabilities.bind(this));
    
    // Network discovery routes
    this.app.post('/api/discovery/network', this.performNetworkDiscovery.bind(this));
    
    // Brute force routes
    this.app.post('/api/bruteforce/attack', this.performBruteForceAttack.bind(this));
    
    // System health routes
    this.app.get('/api/health/system', this.getSystemHealth.bind(this));
    this.app.get('/api/system/health', this.getSystemHealthData.bind(this));
    
  // (removed duplicate report/threat-intel/FIM routes)
    
    // Compliance routes
    this.app.post('/api/compliance/assess', this.runComplianceAssessment.bind(this));
    this.app.post('/api/compliance/export', this.exportComplianceReport.bind(this));
    
    // Settings routes
    this.app.post('/api/settings', this.saveSettings.bind(this));
    this.app.get('/api/settings', this.getSettings.bind(this));

    // CSRF token endpoint
    this.app.get('/api/csrf-token', (req, res) => {
      res.json({ csrfToken: req.csrfToken() });
    });

    // Serve React app for all other routes
    this.app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, '..', 'dist', 'index.html'));
    });
  }

  /**
   * Create HTTP to HTTPS redirect app
   */
  createRedirectApp() {
    const redirectApp = express();
    redirectApp.all('*', (req, res) => {
      const httpsPort = process.env.HTTPS_PORT || 3443;
      res.redirect(301, `https://${req.hostname}:${httpsPort}${req.url}`);
    });
    return redirectApp;
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
      const { target, type = 'normal', ports = '1-1000', stealth = false, stealthLevel = 'medium' } = req.body;
      
      if (!target) {
        return res.status(400).json({ error: 'Target is required' });
      }

      // Validate and sanitize the target
      let validatedTarget;
      try {
        validatedTarget = await this.validator.validateTarget(target, {
          allowPrivateNetworks: type === 'internal' // Allow private networks for internal scans
        });
      } catch (error) {
        return res.status(400).json({ 
          error: 'Invalid target', 
          details: error.message,
          code: 'INVALID_TARGET'
        });
      }

      // Validate ports if provided
      let validatedPorts = '1-1000';
      if (ports) {
        try {
          validatedPorts = this.validator.validatePorts(ports);
        } catch (error) {
          return res.status(400).json({ 
            error: 'Invalid port specification', 
            details: error.message,
            code: 'INVALID_PORTS' 
          });
        }
      }

      const scanId = Date.now().toString();
      
      const scanOptions = {
        type,
        ports: validatedPorts,
        stealth: stealth === true || stealth === 'true',
        stealthLevel: ['low', 'medium', 'high', 'ninja'].includes(stealthLevel) ? stealthLevel : 'medium',
        allowPrivateNetworks: type === 'internal'
      };

      console.log(`🎯 Initiating ${stealth ? 'STEALTH' : 'STANDARD'} scan against ${validatedTarget.sanitized}`);
      
      // Start scan asynchronously
      const scanPromise = this.scanner.scan(validatedTarget.sanitized, scanOptions);
      this.activeScans.set(scanId, { 
        promise: scanPromise, 
        target: validatedTarget.sanitized, 
        resolvedIP: validatedTarget.resolvedIP,
        type, 
        stealth: scanOptions.stealth,
        stealthLevel: scanOptions.stealthLevel,
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

  async getFIMAlerts(req, res) {
    try {
      const alerts = await this.fileIntegrity.getAlerts();
      res.json({ alerts: alerts.alerts || [], totalAlerts: alerts.totalAlerts || 0 });
    } catch (error) {
      console.error('Error getting FIM alerts:', error);
      res.status(500).json({ error: error.message });
    }
  }

  async getWatchedPaths(req, res) {
    try {
      const watchedPaths = await this.fileIntegrity.getWatchedPaths();
      res.json({ paths: watchedPaths || [] });
    } catch (error) {
      console.error('Error getting watched paths:', error);
      res.status(500).json({ error: error.message });
    }
  }

  async updateFIMAlert(req, res) {
    try {
      const { alertId } = req.params;
      const { status } = req.body;
      
      // For now, just acknowledge the update
      res.json({ 
        message: 'Alert updated successfully',
        alertId,
        status,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error updating FIM alert:', error);
      res.status(500).json({ error: error.message });
    }
  }

  async startFIMMonitoring(req, res) {
    try {
      // Start general FIM monitoring
      res.json({ 
        message: 'File Integrity Monitoring started',
        status: 'active',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error starting FIM monitoring:', error);
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
      // Get real security metrics from modules
      const [fimData, threatData, scanData] = await Promise.allSettled([
        this.fileIntegrity.getAlerts(),
        this.threatIntel.getThreatStats(),
        this.scanner.getLatestScanResults()
      ]);

      // Process File Integrity Monitoring data
      const fimAlerts = fimData.status === 'fulfilled' ? 
        (fimData.value?.alerts?.length || 0) : 0;
      
      // Process Threat Intelligence data  
      const threatStats = threatData.status === 'fulfilled' ? threatData.value : {};
      const intrusionsDetected = threatStats.maliciousIPs?.length || 0;
      
      // Process Vulnerability Scanner data
      const scanResults = scanData.status === 'fulfilled' ? scanData.value : {};
      const vulnerabilities = scanResults.vulnerabilities?.length || 0;

      // Calculate compliance score based on real factors
      const complianceScore = this.calculateComplianceScore({
        fimAlerts,
        vulnerabilities,
        intrusionsDetected
      });

      const metrics = {
        intrusionsDetected,
        vulnerabilities,
        fimAlerts,
        complianceScore,
        activeScans: this.activeScans.size,
        threatLevel: this.calculateThreatLevel(),
        systemHealth: this.getSystemHealthData(),
        lastScan: scanResults.timestamp || null,
        lastUpdated: new Date().toISOString()
      };
      
      res.json({ metrics });
    } catch (error) {
      console.error('Error getting dashboard metrics:', error);
      res.status(500).json({ error: error.message });
    }
  }

  async getRecentAlerts(req, res) {
    try {
      const alerts = [];
      
      // Get real alerts from different security modules
      const [fimAlerts, threatAlerts, scanAlerts] = await Promise.allSettled([
        this.fileIntegrity.getAlerts(),
        this.threatIntel.getThreatStats(),
        this.scanner.getLatestScanResults()
      ]);

      // Process File Integrity alerts
      if (fimAlerts.status === 'fulfilled' && fimAlerts.value.alerts) {
        fimAlerts.value.alerts.forEach(alert => {
          alerts.push({
            id: alert.id || Date.now(),
            timestamp: alert.timestamp,
            severity: alert.severity || 'medium',
            message: alert.details || alert.message,
            source: 'File Integrity Monitor',
            status: 'active',
            type: 'file_integrity'
          });
        });
      }

      // Process Threat Intelligence alerts
      if (threatAlerts.status === 'fulfilled') {
        const stats = threatAlerts.value;
        if (stats.maliciousIPs && stats.maliciousIPs.length > 0) {
          alerts.push({
            id: Date.now() + 1,
            timestamp: new Date().toISOString(),
            severity: 'high',
            message: `${stats.maliciousIPs.length} malicious IPs detected in threat feeds`,
            source: 'Threat Intelligence',
            status: 'active',
            type: 'threat_intel'
          });
        }
      }

      // Process Vulnerability Scan alerts
      if (scanAlerts.status === 'fulfilled' && scanAlerts.value.vulnerabilities) {
        const vulns = scanAlerts.value.vulnerabilities;
        const criticalVulns = vulns.filter(v => v.severity === 'critical');
        
        if (criticalVulns.length > 0) {
          alerts.push({
            id: Date.now() + 2,
            timestamp: scanAlerts.value.timestamp || new Date().toISOString(),
            severity: 'critical',
            message: `${criticalVulns.length} critical vulnerabilities found in latest scan`,
            source: 'Vulnerability Scanner',
            status: 'active',
            type: 'vulnerability'
          });
        }
      }

      // Sort by timestamp (newest first)
      alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      
      res.json({ 
        alerts: alerts.slice(0, 20), // Limit to 20 most recent
        totalAlerts: alerts.length
      });
    } catch (error) {
      console.error('Error getting recent alerts:', error);
      res.status(500).json({ error: error.message });
    }
  }

  async getThreatMap(req, res) {
    try {
      // Get real threat intelligence data
      const threatStats = await this.threatIntel.getThreatStats();
      const threats = [];

      // Process malicious IPs with geolocation
      const ipPromises = threatStats.maliciousIPs.slice(0, 10).map(async (ip) => {
        try {
          // In production, you'd use a real geolocation API
          const geoData = this.getIPGeolocation(ip);
          return {
            ip,
            country: geoData.country,
            lat: geoData.lat,
            lng: geoData.lng,
            threats: 1,
            type: 'malicious_ip',
            severity: 'high'
          };
        } catch (error) {
          return null;
        }
      });

      const ipThreats = (await Promise.all(ipPromises)).filter(t => t !== null);
      threats.push(...ipThreats);

      // Add known threat hotspots based on threat intelligence
      const knownHotspots = [
        { country: 'China', lat: 35.8617, lng: 104.1954, threats: threatStats.maliciousIPs.filter(ip => ip.startsWith('59.')).length },
        { country: 'Russia', lat: 61.5240, lng: 105.3188, threats: threatStats.maliciousIPs.filter(ip => ip.startsWith('185.')).length },
        { country: 'United States', lat: 39.8283, lng: -98.5795, threats: threatStats.maliciousIPs.filter(ip => ip.startsWith('162.')).length },
        { country: 'Brazil', lat: -14.2350, lng: -51.9253, threats: threatStats.maliciousIPs.filter(ip => ip.startsWith('177.')).length }
      ].filter(h => h.threats > 0);

      threats.push(...knownHotspots);
      
      res.json({ 
        threats,
        totalThreats: threats.reduce((sum, t) => sum + t.threats, 0),
        lastUpdated: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error getting threat map:', error);
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

  calculateComplianceScore({ fimAlerts, vulnerabilities, intrusionsDetected }) {
    // Start with perfect score and deduct based on security issues
    let score = 100;
    
    // Deduct points for active issues
    score -= Math.min(fimAlerts * 5, 25); // Max 25 points for FIM alerts
    score -= Math.min(vulnerabilities * 2, 30); // Max 30 points for vulnerabilities
    score -= Math.min(intrusionsDetected * 8, 40); // Max 40 points for intrusions
    
    // Ensure minimum score of 0
    return Math.max(score, 0);
  }

  getSystemHealth() {
    // Calculate system health based on various factors
    const memUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    return {
      memory: {
        used: Math.round(memUsage.heapUsed / 1024 / 1024), // MB
        total: Math.round(memUsage.heapTotal / 1024 / 1024), // MB
        percentage: Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100)
      },
      uptime: Math.round(uptime), // seconds
      activeConnections: this.wss.clients.size,
      status: 'healthy'
    };
  }

  async getMonitoringAlerts(req, res) {
    try {
      const alerts = [
        {
          id: 1,
          title: 'Suspicious Login Activity',
          severity: 'high',
          status: 'active',
          timestamp: new Date().toISOString(),
          source: 'Authentication Service',
          description: 'Multiple failed login attempts detected from IP 192.168.1.100'
        },
        {
          id: 2,
          title: 'High CPU Usage',
          severity: 'medium',
          status: 'monitoring',
          timestamp: new Date().toISOString(),
          source: 'System Monitor',
          description: 'CPU usage above 85% for 5 minutes'
        },
        {
          id: 3,
          title: 'Disk Space Low',
          severity: 'medium',
          status: 'active',
          timestamp: new Date().toISOString(),
          source: 'System Monitor',
          description: 'Available disk space below 15%'
        }
      ];
      res.json({ alerts });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async updateMonitoringAlert(req, res) {
    try {
      const { id } = req.params;
      const { status } = req.body;
      
      // In a real implementation, update the alert in the database
      res.json({ 
        success: true, 
        message: `Alert ${id} ${status} successfully`,
        alertId: id,
        newStatus: status
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getSystemMetrics(req, res) {
    try {
      const os = await import('os');
      const cpus = os.cpus();
      const totalMem = os.totalmem();
      const freeMem = os.freemem();

      // CPU usage estimation (simple average over cores)
      const cpuLoad = cpus.reduce((acc, cpu) => {
        const times = cpu.times;
        const idle = times.idle;
        const total = Object.values(times).reduce((a, b) => a + b, 0);
        return acc + (1 - idle / total);
      }, 0) / cpus.length;

      const metrics = {
        cpu: Math.round(cpuLoad * 100),
        memory: Math.round(((totalMem - freeMem) / totalMem) * 100),
        disk: null, // not trivial cross-platform; leave null instead of dummy
        network: null, // requires sampling; leave null instead of dummy
        uptime: os.uptime(),
        timestamp: new Date().toISOString()
      };
      res.json({ metrics });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getLogSources(req, res) {
    try {
      const sources = [
        { id: 1, name: 'Web Server Logs', type: 'server', status: 'connected', events: 1240 },
        { id: 2, name: 'Database Logs', type: 'server', status: 'connected', events: 856 },
        { id: 3, name: 'Cloud Storage', type: 'cloud', status: 'connected', events: 432 },
        { id: 4, name: 'DNS Logs', type: 'public', status: 'connected', events: 2100 }
      ];
      res.json({ sources });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // User management methods
  async getUsers(req, res) {
    try {
      // In a real app, this would query a database
      // For now, return empty array since we removed dummy data
      const users = [];
      res.json({ users });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async createUser(req, res) {
    try {
      const { username, email, role } = req.body;
      
      if (!username || !email || !role) {
        return res.status(400).json({ error: 'Username, email, and role are required' });
      }

      // In a real app, this would save to database
      const newUser = {
        id: Date.now().toString(),
        username,
        email,
        role,
        status: 'active',
        lastLogin: new Date().toISOString(),
        created: new Date().toISOString()
      };

      res.status(201).json({ user: newUser });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async updateUser(req, res) {
    try {
      const { id } = req.params;
      const updates = req.body;

      // In a real app, this would update the database
      res.json({ 
        message: 'User updated successfully',
        userId: id,
        updates 
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async deleteUser(req, res) {
    try {
      const { id } = req.params;

      // In a real app, this would delete from database
      res.json({ 
        message: 'User deleted successfully',
        userId: id 
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Advanced exploitation methods
  async runExploitTest(req, res) {
    try {
      const { target, mode, timestamp } = req.body;
      
      // Simulate exploit testing
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const result = {
        target,
        mode,
        timestamp,
        success: Math.random() > 0.7,
        vulnerabilities: [
          'SQL Injection detected in login form',
          'XSS vulnerability in search parameter',
          'Weak session management'
        ].slice(0, Math.floor(Math.random() * 3) + 1)
      };

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async testApiVulnerabilities(req, res) {
    try {
      const { target, testType, timestamp } = req.body;
      
      // Simulate API testing
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      const endpoints = [
        { method: 'GET', path: '/api/users', status: 'secure', response_code: 200, response_time: 45 },
        { method: 'POST', path: '/api/login', status: 'vulnerable', response_code: 200, response_time: 120 },
        { method: 'GET', path: '/api/admin', status: 'warning', response_code: 403, response_time: 30 },
        { method: 'PUT', path: '/api/users/:id', status: 'secure', response_code: 401, response_time: 25 }
      ];
      
      const vulnerabilities = [
        { severity: 'HIGH', description: 'Authentication bypass in /api/login endpoint' },
        { severity: 'MEDIUM', description: 'Information disclosure in error messages' }
      ].slice(0, Math.floor(Math.random() * 2) + 1);

      const result = {
        target,
        testType,
        timestamp,
        endpoints,
        vulnerabilities
      };

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async performNetworkDiscovery(req, res) {
    try {
      const { range, scanType, timestamp } = req.body;
      
      // Simulate network discovery
      await new Promise(resolve => setTimeout(resolve, 4000));
      
      const hosts = [
        {
          ip: '192.168.1.1',
          status: 'online',
          hostname: 'router.local',
          mac: '00:11:22:33:44:55',
          os: 'Linux',
          services: [
            { name: 'http', port: 80 },
            { name: 'https', port: 443 },
            { name: 'ssh', port: 22 }
          ]
        },
        {
          ip: '192.168.1.100',
          status: 'online',
          hostname: 'workstation-01',
          mac: 'AA:BB:CC:DD:EE:FF',
          os: 'Windows 10',
          services: [
            { name: 'smb', port: 445 },
            { name: 'rdp', port: 3389 }
          ]
        }
      ].slice(0, Math.floor(Math.random() * 5) + 2);

      const result = {
        range,
        scanType,
        timestamp,
        hosts
      };

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async performBruteForceAttack(req, res) {
    try {
      const { target, port, service, username, maxAttempts, timestamp } = req.body;
      
      // Simulate brute force attack
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      const attempts_made = Math.floor(Math.random() * maxAttempts) + 1;
      const successful_logins = Math.random() > 0.8 ? [
        { username, password: 'admin123' }
      ] : [];
      
      const result = {
        target,
        port,
        service,
        username,
        timestamp,
        attempts_made,
        successful_logins,
        locked_accounts: [],
        rate_limiting_detected: Math.random() > 0.7
      };

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  getSystemHealthData() {
    // Simulate system health data
    return {
      overall_status: 'healthy',
      uptime: '5d 12h 34m',
      load_average: '1.2',
      active_connections: Math.floor(Math.random() * 50) + 10,
      security_alerts: Math.floor(Math.random() * 5),
      cpu_usage: Math.floor(Math.random() * 80) + '%',
      memory_usage: Math.floor(Math.random() * 70) + '%',
      disk_usage: Math.floor(Math.random() * 60) + '%',
      network_io: Math.floor(Math.random() * 100) + ' MB/s',
      cpu_cores: '8',
      total_memory: '16 GB',
      available_space: '500 GB',
      network_speed: '1 Gbps',
      services: [
        { name: 'Web Server', status: 'healthy', port: 80 },
        { name: 'Database', status: 'healthy', port: 3306 },
        { name: 'SSH Service', status: 'healthy', port: 22 },
        { name: 'FTP Service', status: 'warning', port: 21 }
      ]
    };
  }

  async getSystemHealth(req, res) {
    try {
      const healthData = this.getSystemHealthData();
      res.json(healthData);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getSystemHealthData(req, res) {
    try {
      const os = await import('os');
      
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      
      const health = {
        cpu: Math.round(os.loadavg()[0] * 10), // Approximation
        memory: Math.round((usedMem / totalMem) * 100),
        disk: Math.round(Math.random() * 30 + 20), // Simulated disk usage
        uptime: Math.round(os.uptime()),
        status: 'healthy'
      };
      
      if (res) {
        res.json(health);
      } else {
        return health;
      }
    } catch (error) {
      if (res) {
        res.status(500).json({ error: error.message });
      } else {
        throw error;
      }
    }
  }

  // duplicate quick report and updateThreatIntelligence handlers removed

  getIPGeolocation(ip) {
    // Simple geolocation based on IP prefixes
    // In production, use a real geolocation service
    const geoMap = {
      '185.': { country: 'Russia', lat: 61.5240, lng: 105.3188 },
      '59.': { country: 'China', lat: 35.8617, lng: 104.1954 },
      '162.': { country: 'United States', lat: 39.8283, lng: -98.5795 },
      '177.': { country: 'Brazil', lat: -14.2350, lng: -51.9253 },
      '198.': { country: 'United States', lat: 39.8283, lng: -98.5795 },
      '203.': { country: 'Australia', lat: -25.2744, lng: 133.7751 }
    };

    for (const [prefix, geo] of Object.entries(geoMap)) {
      if (ip.startsWith(prefix)) {
        return geo;
      }
    }

    // Default location for unknown IPs
    return { country: 'Unknown', lat: 0, lng: 0 };
  }

  // File Integrity Monitor methods
  async getWatchedFiles(req, res) {
    try {
      const paths = await this.fileIntegrity.getWatchedPaths();
      res.json({ paths });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async addWatchedFile(req, res) {
    try {
      const { path } = req.body;
      
      if (!path) {
        return res.status(400).json({ error: 'File path is required' });
      }
      
      // In a real implementation, this would register a path with FileIntegrity.watch
      res.json({ success: true, message: 'Path registered for monitoring request received', path });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async removeWatchedFile(req, res) {
    try {
      const { path } = req.body;
      
      if (!path) {
        return res.status(400).json({ error: 'File path is required' });
      }
      
      // Simulate removing file from monitoring
      res.json({ success: true, message: `${path} removed from monitoring` });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async toggleFileMonitoring(req, res) {
    try {
      const { action } = req.body;
      
      // Simulate starting/stopping file monitoring
      res.json({ 
        success: true, 
        status: action === 'start' ? 'monitoring' : 'stopped',
        message: `File monitoring ${action}ed successfully`
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async runIntegrityCheck(req, res) {
    try {
      // Simulate integrity check
      const results = {
        filesChecked: Math.floor(Math.random() * 100) + 50,
        changesDetected: Math.floor(Math.random() * 5),
        errors: Math.floor(Math.random() * 2),
        duration: Math.floor(Math.random() * 30) + 10
      };
      
      res.json({ success: true, results });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Compliance methods
  async runComplianceAssessment(req, res) {
    try {
      const { framework } = req.body;
      
      if (!framework) {
        return res.status(400).json({ error: 'Framework is required' });
      }
      
      // Simulate compliance assessment
      const overallScore = Math.floor(Math.random() * 30) + 70; // 70-100%
      
      res.json({
        success: true,
        framework,
        overallScore,
        assessmentDate: new Date().toISOString(),
        controlsEvaluated: Math.floor(Math.random() * 20) + 10
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async exportComplianceReport(req, res) {
    try {
      const { framework } = req.body;
      
      if (!framework) {
        return res.status(400).json({ error: 'Framework is required' });
      }
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `compliance_${framework}_${timestamp}.pdf`;
      
      res.json({
        success: true,
        filename,
        framework,
        exportDate: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Settings methods
  async saveSettings(req, res) {
    try {
      const settings = req.body;
      
      // In a real implementation, save to database
      // For now, just acknowledge the save
      res.json({
        success: true,
        message: 'Settings saved successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getSettings(req, res) {
    try {
      // In a real implementation, fetch from database
      // For now, return default settings
      const defaultSettings = {
        notifications: {
          email: true,
          push: false,
          criticalAlertsOnly: true,
          threatAlerts: true,
          scanComplete: true,
          systemHealth: false
        },
        security: {
          twoFactorAuth: true,
          sessionTimeout: 30,
          ipWhitelist: '192.168.1.1/24, 10.0.0.0/8',
          maxLoginAttempts: 5,
          passwordExpiry: 90,
          apiRateLimit: 1000
        },
        theme: 'dark'
      };
      
      res.json({ settings: defaultSettings });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  start(port = 3001, host = 'localhost') {
    // Validate security environment
    this.securityConfig.validateSecurityEnvironment();

    if (this.securityConfig.sslConfig.available) {
      // Start HTTPS server
      const httpsPort = process.env.HTTPS_PORT || 3443;
      this.server.listen(httpsPort, host, () => {
        console.log(`🔒 ${chalk.green('Scorpion HTTPS Server')} running on https://${host}:${httpsPort}`);
        console.log(`📊 ${chalk.cyan('Secure Dashboard')}: https://${host}:${httpsPort}`);
        console.log(`🔌 ${chalk.blue('Secure WebSocket')}: wss://${host}:${httpsPort}`);
        console.log(`🛡️  ${chalk.yellow('Security Features')}: HTTPS, CSRF, Rate Limiting, Input Validation`);
        
        if (this.securityConfig.sslConfig.selfSigned) {
          console.log(`⚠️  ${chalk.yellow('Self-signed certificate in use - not suitable for production')}`);
        }
      });

      // Start HTTP redirect server
      if (this.httpRedirectServer) {
        const httpPort = process.env.HTTP_PORT || 3001;
        this.httpRedirectServer.listen(httpPort, host, () => {
          console.log(`🔄 ${chalk.gray('HTTP Redirect Server')} running on http://${host}:${httpPort} → HTTPS`);
        });
      }
    } else {
      // Fallback to HTTP (development only)
      this.server.listen(port, host, () => {
        console.log(`⚠️  ${chalk.yellow('Scorpion HTTP Server')} running on http://${host}:${port}`);
        console.log(`📊 Dashboard: http://${host}:${port}`);
        console.log(`🔌 WebSocket: ws://${host}:${port}`);
        console.log(`🚨 ${chalk.red('WARNING: Running without HTTPS - not secure for production')}`);
      });
    }
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
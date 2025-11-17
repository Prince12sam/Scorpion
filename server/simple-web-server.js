import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { WebSocketServer } from 'ws';
import rateLimit from 'express-rate-limit';
import cluster from 'cluster';
import os from 'os';
import csrf from 'csrf';
import crypto from 'crypto';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

class ScorpionWebServer {
  constructor() {
    this.app = express();
    this.server = http.createServer(this.app);
    this.wss = new WebSocketServer({ server: this.server });
    this.csrfProtection = new csrf();
    this.setupMiddleware();
    this.setupRoutes();
    this.setupWebSocket();
  }

  setupMiddleware() {
    // Enable gzip compression
    this.app.use(compression({
      filter: (req, res) => {
        if (req.headers['x-no-compression']) {
          return false;
        }
        return compression.filter(req, res);
      },
      level: 6,
      threshold: 1024
    }));

    // Rate limiting
    const authLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // limit each IP to 5 requests per windowMs for auth
      message: { error: 'Too many authentication attempts, please try again later.' },
      standardHeaders: true,
      legacyHeaders: false,
    });

    const apiLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs for API
      message: { error: 'Too many API requests, please try again later.' },
      standardHeaders: true,
      legacyHeaders: false,
    });

    this.app.use('/api/auth/', authLimiter);
    this.app.use('/api/', apiLimiter);

    // Enhanced security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "ws:", "wss:", "https:"],
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
    
    this.app.use(cors({
      origin: process.env.NODE_ENV === 'production' 
        ? ['https://your-domain.com', 'http://localhost:3001'] 
        : ['http://localhost:3001', 'http://localhost:5173', 'http://127.0.0.1:3001'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token']
    }));

    // CSRF protection middleware
    this.app.use((req, res, next) => {
      if (req.method === 'GET' && req.path === '/api/csrf-token') {
        // Generate CSRF token
        const secret = crypto.randomBytes(18).toString('base64');
        const token = this.csrfProtection.create(secret);
        req.session = req.session || {};
        req.session.csrfSecret = secret;
        res.json({ csrfToken: token });
        return;
      }
      
      if (['POST', 'PUT', 'DELETE'].includes(req.method) && req.path.startsWith('/api/') && req.path !== '/api/auth/login') {
        const token = req.get('X-CSRF-Token') || req.body._csrf;
        const secret = req.session?.csrfSecret;
        
        if (!token || !secret || !this.csrfProtection.verify(secret, token)) {
          console.log(`🛡️  CSRF protection blocked request to ${req.path}`);
          return res.status(403).json({ error: 'Invalid CSRF token' });
        }
      }
      next();
    });

    // Disable X-Powered-By header for security
    this.app.disable('x-powered-by');
    
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));
    
    // Request logging
    this.app.use((req, res, next) => {
      console.log(`📡 ${new Date().toISOString()} - ${req.method} ${req.path}`);
      next();
    });
    
    // Static files with caching
    const distPath = path.join(__dirname, '..', 'dist');
    this.app.use(express.static(distPath, {
      maxAge: process.env.NODE_ENV === 'production' ? '1y' : '0',
      etag: true,
      lastModified: true,
      cacheControl: true,
      setHeaders: (res, path) => {
        // Set cache headers for different file types
        if (path.endsWith('.html')) {
          res.setHeader('Cache-Control', 'no-cache');
        } else if (path.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
      }
    }));
  }

  setupRoutes() {
    // Health check
    this.app.get('/api/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '2.0.0'
      });
    });

    // Authentication routes
    this.app.post('/api/auth/login', (req, res) => {
      console.log('🔐 Login request received:', req.body);
      const { username, password } = req.body;
      
      if (!username || !password) {
        console.log('❌ Missing credentials');
        return res.status(400).json({ error: 'Username and password are required' });
      }

      // Simple authentication check (admin/admin for demo)
      if (username === 'admin' && password === 'admin') {
        console.log('✅ Login successful for admin');
        const token = 'scorpion-jwt-token-' + Date.now();
        res.json({
          success: true,
          tokens: {
            accessToken: token,
            refreshToken: token + '-refresh'
          },
          user: {
            id: 1,
            username: 'admin',
            role: 'administrator',
            email: 'admin@scorpion.local'
          },
          message: 'Login successful'
        });
      } else {
        console.log('❌ Invalid credentials:', username);
        res.status(401).json({ 
          error: 'Invalid credentials',
          message: 'Please check your username and password'
        });
      }
    });

    this.app.post('/api/auth/register', (req, res) => {
      const { username, email, password } = req.body;
      
      if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required' });
      }

      // Simple registration (always successful for demo)
      const token = 'scorpion-jwt-token-' + Date.now();
      res.status(201).json({
        success: true,
        token,
        user: {
          id: Date.now(),
          username,
          email,
          role: 'user'
        },
        message: 'Registration successful'
      });
    });

    this.app.post('/api/auth/logout', (req, res) => {
      res.json({
        success: true,
        message: 'Logout successful'
      });
    });

    // Test endpoint for debugging authentication
    this.app.get('/api/auth/test', (req, res) => {
      res.json({
        message: 'Authentication test endpoint',
        timestamp: new Date().toISOString(),
        headers: req.headers
      });
    });

    this.app.get('/api/auth/verify', (req, res) => {
      console.log('🔍 Token verification request received');
      console.log('Headers:', req.headers.authorization);
      
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ No valid authorization header');
        return res.status(401).json({ 
          error: 'No valid token provided',
          details: 'Authorization header missing or invalid format'
        });
      }

      const token = authHeader.substring(7);
      console.log('🎫 Token received:', token.substring(0, 20) + '...');
      
      if (token.startsWith('scorpion-jwt-token-')) {
        console.log('✅ Token verification successful');
        res.json({
          valid: true,
          user: {
            id: 1,
            username: 'admin',
            role: 'administrator',
            email: 'admin@scorpion.local'
          }
        });
      } else {
        console.log('❌ Invalid token format:', token.substring(0, 20));
        res.status(401).json({ 
          error: 'Invalid token',
          details: 'Token does not match expected format'
        });
      }
    });

    // Dashboard metrics
    this.app.get('/api/dashboard/metrics', (req, res) => {
      res.json({
        metrics: {
          securityMetrics: {
            intrusionsDetected: 0,
            vulnerabilities: 0,
            fimAlerts: 0,
            complianceScore: 100
          }
        }
      });
    });

    // Simple scan endpoint
    this.app.post('/api/scan', async (req, res) => {
      const { target, type = 'quick', ports = '80,443' } = req.body;
      
      if (!target) {
        return res.status(400).json({ error: 'Target is required' });
      }

      // Simulate scan results
      const scanId = Date.now().toString();
      
      setTimeout(() => {
        res.json({
          scanId,
          target,
          status: 'completed',
          results: {
            openPorts: [
              { port: 80, status: 'open', service: 'HTTP' },
              { port: 443, status: 'open', service: 'HTTPS' }
            ],
            vulnerabilities: [],
            riskScore: 'LOW'
          }
        });
      }, 2000);
    });

    // Additional API endpoints for all dashboard tabs
    
    // Vulnerability Scanner endpoints
    this.app.post('/api/scanner/scan', async (req, res) => {
      const { target, scanType = 'normal' } = req.body;
      if (!target) return res.status(400).json({ error: 'Target required' });
      
      res.json({
        scanId: Date.now().toString(),
        target,
        scanType,
        status: 'scanning',
        progress: 0,
        estimatedTime: '5 minutes'
      });
    });

    // Reconnaissance & Discovery endpoints
    this.app.post('/api/recon/discover', async (req, res) => {
      const { target, depth = 'normal' } = req.body;
      if (!target) return res.status(400).json({ error: 'Target required' });
      
      res.json({
        target,
        depth,
        status: 'completed',
        discovered: {
          subdomains: ['www.example.com', 'api.example.com'],
          openPorts: [80, 443, 22],
          services: ['nginx', 'ssh'],
          technologies: ['React', 'Node.js']
        }
      });
    });

    // Monitoring endpoints
    this.app.get('/api/monitoring/alerts', (req, res) => {
      res.json({
        alerts: [
          { id: 1, severity: 'high', message: 'Suspicious login detected', timestamp: new Date().toISOString() },
          { id: 2, severity: 'medium', message: 'Port scan detected', timestamp: new Date().toISOString() }
        ],
        total: 2
      });
    });

    this.app.get('/api/system/health', (req, res) => {
      res.json({
        status: 'healthy',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        services: {
          database: 'healthy',
          scanner: 'healthy',
          monitor: 'healthy'
        }
      });
    });

    // File Integrity Monitor endpoints
    this.app.get('/api/fim/status', (req, res) => {
      res.json({
        status: 'active',
        watchedFiles: 1250,
        recentChanges: 5,
        lastScan: new Date().toISOString()
      });
    });

    this.app.post('/api/fim/scan', (req, res) => {
      res.json({
        scanId: Date.now().toString(),
        status: 'scanning',
        filesScanned: 0,
        changesDetected: 0
      });
    });

    // Threat Hunting endpoints
    this.app.get('/api/threat-hunting', (req, res) => {
      res.json({
        activeThreat: null,
        indicators: [],
        lastHunt: new Date().toISOString(),
        threatsFound: 0
      });
    });

    // Password Security endpoints
    this.app.post('/api/password/analyze', (req, res) => {
      const { password } = req.body;
      if (!password) return res.status(400).json({ error: 'Password required' });
      
      res.json({
        password: '[REDACTED]',
        strength: 'strong',
        score: 85,
        recommendations: ['Consider adding symbols', 'Increase length to 16+ characters'],
        breached: false
      });
    });

    // Advanced Exploitation endpoints
    this.app.get('/api/exploitation', (req, res) => {
      res.json({
        availableExploits: 150,
        activeTargets: 0,
        successRate: '85%',
        lastUpdate: new Date().toISOString()
      });
    });

    // API Testing endpoints
    this.app.get('/api/api-testing', (req, res) => {
      res.json({
        testsRun: 0,
        vulnerabilitiesFound: 0,
        endpoints: [],
        lastTest: null
      });
    });

    // Network Discovery endpoints
    this.app.get('/api/network-discovery', (req, res) => {
      res.json({
        discoveredHosts: 0,
        activeScans: 0,
        lastDiscovery: new Date().toISOString(),
        networkMap: []
      });
    });

    // Brute Force Tools endpoints
    this.app.get('/api/brute-force', (req, res) => {
      res.json({
        activeAttacks: 0,
        successfulCracks: 0,
        wordlists: ['common.txt', 'rockyou.txt'],
        lastAttempt: null
      });
    });

    // Reports endpoints
    this.app.get('/api/reports', (req, res) => {
      res.json({
        totalReports: 25,
        recentReports: [
          { id: 1, name: 'Security Assessment', date: new Date().toISOString(), type: 'PDF' },
          { id: 2, name: 'Vulnerability Report', date: new Date().toISOString(), type: 'HTML' }
        ]
      });
    });

    // Compliance endpoints
    this.app.get('/api/compliance', (req, res) => {
      res.json({
        overallScore: 92,
        frameworks: {
          'ISO 27001': 95,
          'NIST': 88,
          'SOC 2': 94
        },
        failedChecks: 3,
        lastAssessment: new Date().toISOString()
      });
    });

    // Threat Intelligence endpoints
    this.app.get('/api/intelligence', (req, res) => {
      res.json({
        activeThreat: null,
        feedsActive: 5,
        lastUpdate: new Date().toISOString(),
        iocs: 1250
      });
    });

    this.app.get('/api/threat-intel/iocs', (req, res) => {
      res.json({
        iocs: [
          { type: 'ip', value: '192.168.1.100', threat: 'malware', confidence: 'high' },
          { type: 'domain', value: 'malicious.com', threat: 'phishing', confidence: 'medium' }
        ],
        total: 2
      });
    });

    this.app.get('/api/threat-feeds/status', (req, res) => {
      res.json({
        feeds: [
          { name: 'AlienVault OTX', status: 'active', lastUpdate: new Date().toISOString() },
          { name: 'VirusTotal', status: 'active', lastUpdate: new Date().toISOString() }
        ]
      });
    });

    this.app.get('/api/threat-map/live', (req, res) => {
      res.json({
        threats: [
          { lat: 40.7128, lng: -74.0060, type: 'malware', severity: 'high' },
          { lat: 51.5074, lng: -0.1278, type: 'ddos', severity: 'medium' }
        ],
        lastUpdate: new Date().toISOString()
      });
    });

    this.app.post('/api/threat-intel/lookup', (req, res) => {
      const { indicator } = req.body;
      res.json({
        indicator,
        found: true,
        threat: 'suspicious',
        confidence: 'medium',
        sources: ['VirusTotal', 'AbuseIPDB']
      });
    });

    // Investigation Tools endpoints
    this.app.get('/api/investigation', (req, res) => {
      res.json({
        activeInvestigations: 2,
        tools: ['OSINT', 'Digital Forensics', 'Network Analysis'],
        recentFindings: [
          { type: 'email', value: 'suspicious@example.com', risk: 'medium' }
        ]
      });
    });

    // User Management endpoints
    this.app.get('/api/users', (req, res) => {
      res.json({
        users: [
          { id: 1, username: 'admin', role: 'administrator', lastLogin: new Date().toISOString() },
          { id: 2, username: 'analyst', role: 'analyst', lastLogin: new Date().toISOString() }
        ],
        total: 2
      });
    });

    // Settings endpoints
    this.app.get('/api/settings', (req, res) => {
      res.json({
        general: {
          theme: 'dark',
          language: 'en',
          notifications: true
        },
        security: {
          twoFactor: false,
          sessionTimeout: 3600,
          passwordPolicy: 'strong'
        }
      });
    });

    // Threat Map endpoint for real-time data
    this.app.get('/api/threat-map', (req, res) => {
      res.json({
        threats: [
          { lat: 40.7128, lng: -74.0060, type: 'malware', severity: 'high', timestamp: new Date().toISOString() },
          { lat: 51.5074, lng: -0.1278, type: 'ddos', severity: 'medium', timestamp: new Date().toISOString() },
          { lat: 35.6762, lng: 139.6503, type: 'botnet', severity: 'low', timestamp: new Date().toISOString() }
        ],
        stats: {
          totalThreats: 3,
          highSeverity: 1,
          mediumSeverity: 1,
          lowSeverity: 1
        },
        lastUpdate: new Date().toISOString()
      });
    });

    // Reports endpoint
    this.app.post('/api/reports/generate', (req, res) => {
      const report = {
        id: Date.now(),
        type: req.body.type || 'security',
        format: req.body.format || 'pdf',
        timestamp: new Date().toISOString(),
        status: 'completed'
      };
      
      res.json(report);
    });

    // Catch-all route for SPA
    this.app.get('*', (req, res) => {
      const indexPath = path.join(__dirname, '..', 'dist', 'index.html');
      res.sendFile(indexPath);
    });
  }

  setupWebSocket() {
    this.wss.on('connection', (ws) => {
      console.log('🔌 New WebSocket connection');
      
      ws.send(JSON.stringify({
        type: 'connection',
        message: 'Connected to Scorpion Security Platform'
      }));

      ws.on('message', (data) => {
        try {
          const message = JSON.parse(data);
          console.log('📨 WebSocket message:', message);
          
          // Echo back for now
          ws.send(JSON.stringify({
            type: 'response',
            data: message
          }));
        } catch (error) {
          console.error('WebSocket error:', error);
        }
      });

      ws.on('close', () => {
        console.log('🔌 WebSocket connection closed');
      });
    });
  }

  start(port = 3001, host = '127.0.0.1') {
    this.server.listen(port, host, () => {
      console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  🦂 SCORPION SECURITY PLATFORM - WEB INTERFACE ACTIVE 🦂     ║
╚═══════════════════════════════════════════════════════════════╝

🌐 Dashboard URL: http://${host}:${port}
🔌 WebSocket: ws://${host}:${port}
📊 Status: READY FOR SECURITY OPERATIONS
🛡️  Security Features: Rate Limiting, CORS, Security Headers
⚡ Performance: Optimized for Real-time Operations

🎯 Access your security dashboard at: http://${host}:${port}
      `);
    });

    this.server.on('error', (error) => {
      console.error('❌ Server error:', error);
      process.exit(1);
    });
  }
}

// Clustering for production performance
function startWithClustering() {
  const numCPUs = os.cpus().length;
  const workers = process.env.NODE_ENV === 'production' ? Math.min(numCPUs, 4) : 1;

  if (cluster.isPrimary && workers > 1) {
    console.log(`🚀 Starting ${workers} worker processes...`);
    
    // Fork workers
    for (let i = 0; i < workers; i++) {
      cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
      console.log(`⚠️  Worker ${worker.process.pid} died. Restarting...`);
      cluster.fork();
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('📴 Shutting down cluster...');
      for (const id in cluster.workers) {
        cluster.workers[id].kill();
      }
    });
  } else {
    // Worker process
    const server = new ScorpionWebServer();
    const port = process.env.PORT || 3001;
    const host = process.env.HOST || '127.0.0.1';
    server.start(port, host);
  }
}

// Start server if run directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startWithClustering();
}

export { ScorpionWebServer };
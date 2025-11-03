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

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

class ScorpionWebServer {
  constructor() {
    this.app = express();
    this.server = http.createServer(this.app);
    this.wss = new WebSocketServer({ server: this.server });
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
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));
    
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
# 🔒 **SECURITY HARDENING IMPLEMENTATION GUIDE**
## **Critical Fixes for Production Deployment**

This guide provides step-by-step implementation for all critical security issues identified in the production readiness assessment.

---

## 🚨 **IMMEDIATE SECURITY FIXES**

### **1. Authentication & Authorization System**

#### Install Required Dependencies
```bash
npm install jsonwebtoken bcryptjs express-validator helmet express-rate-limit
```

#### JWT Authentication Middleware
```javascript
// server/middleware/auth.js
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secure-secret-key';

export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

export const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};
```

#### Login System
```javascript
// server/routes/auth.js
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const router = express.Router();

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Find user (replace with database query)
    const user = await getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

export default router;
```

### **2. Input Validation & Sanitization**

```javascript
// server/middleware/validation.js
import { body, param, query, validationResult } from 'express-validator';

export const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: errors.array() 
    });
  }
  next();
};

// API endpoint validators
export const validateScanRequest = [
  body('target').isURL().normalizeEmail(),
  body('scanType').isIn(['quick', 'normal', 'deep', 'custom']),
  body('ports').optional().isArray(),
  validateRequest
];

export const validateFileIntegrity = [
  body('filePath').isString().trim().escape(),
  body('checksum').matches(/^[a-f0-9]{64}$/i), // SHA256 hash
  validateRequest
];

export const validateUserManagement = [
  body('name').isString().trim().isLength({ min: 2, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('role').isIn(['Admin', 'User', 'Guest']),
  validateRequest
];
```

### **3. Security Headers with Helmet**

```javascript
// server/middleware/security.js
import helmet from 'helmet';

export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Remove unsafe-inline in production
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]) ,
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Adjust based on requirements
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});
```

### **4. Rate Limiting**

```javascript
// server/middleware/rateLimiter.js
import rateLimit from 'express-rate-limit';

export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // requests per windowMs
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 login attempts per 15 minutes
  message: { error: 'Too many login attempts, please try again later.' },
  skipSuccessfulRequests: true,
});

export const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 scans per minute
  message: { error: 'Scan rate limit exceeded.' },
});
```

### **5. Environment Configuration**

```bash
# .env.production
NODE_ENV=production
PORT=3001

# Security
JWT_SECRET=your-super-secure-jwt-secret-minimum-32-characters
SESSION_SECRET=your-session-secret-key

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/scorpion
REDIS_URL=redis://localhost:6379

# API Keys (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Logging
LOG_LEVEL=info
LOG_FILE=logs/scorpion.log
```

---

## 🗄️ **DATABASE INTEGRATION**

### **PostgreSQL Setup with Prisma**

#### Install Dependencies
```bash
npm install prisma @prisma/client
npx prisma init
```

#### Database Schema
```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id          Int      @id @default(autoincrement())
  username    String   @unique
  email       String   @unique
  passwordHash String
  role        String   @default("User")
  status      String   @default("Active")
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
}

model WatchedFile {
  id          Int      @id @default(autoincrement())
  path        String   @unique
  checksum    String
  status      String   @default("ok")
  lastChecked DateTime @default(now())
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
}

model ScanResult {
  id            Int      @id @default(autoincrement())
  target        String
  scanType      String
  status        String
  vulnerabilities Json?
  createdAt     DateTime @default(now())
  completedAt   DateTime?
}
```

#### Database Client
```javascript
// server/lib/database.js
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export default prisma;

// Graceful shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect();
});
```

---

## 🔧 **UPDATED SERVER IMPLEMENTATION**

```javascript
// server/secure-server.js
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { WebSocketServer } from 'ws';
import http from 'http';
import dotenv from 'dotenv';

// Security middleware
import { securityHeaders } from './middleware/security.js';
import { generalLimiter, authLimiter, scanLimiter } from './middleware/rateLimiter.js';
import { authenticateToken, authorizeRole } from './middleware/auth.js';

// Routes
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import scanRoutes from './routes/scan.js';

dotenv.config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Security middleware
app.use(securityHeaders);
app.use(generalLimiter);

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// Public routes
app.use('/api/auth', authLimiter, authRoutes);
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    version: process.env.npm_package_version,
    uptime: process.uptime(),
    timestamp: new Date().toISOString() 
  });
});

// Protected routes
app.use('/api/users', authenticateToken, authorizeRole(['Admin']), userRoutes);
app.use('/api/scan', authenticateToken, scanLimiter, scanRoutes);

// File Integrity Monitor - requires authentication
app.get('/api/fim/watched', authenticateToken, async (req, res) => {
  try {
    const files = await prisma.watchedFile.findMany();
    res.json({ files });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch watched files' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Error:', error);
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : error.message 
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

const PORT = process.env.PORT || 3001;

server.listen(PORT, () => {
  console.log(`🦂 Scorpion Security Platform (Secure) running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
});

export default app;
```

---

## 🚀 **PRODUCTION DEPLOYMENT**

### **Docker Configuration**

#### Dockerfile
```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY . .

# Build the application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S scorpion -u 1001

# Change ownership
RUN chown -R scorpion:nodejs /app
USER scorpion

EXPOSE 3001

CMD ["npm", "start"]
```

#### Docker Compose
```yaml
# docker-compose.production.yml
version: '3.8'

services:
  database:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: scorpion
      POSTGRES_USER: scorpion
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - scorpion_network

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    networks:
      - scorpion_network

  scorpion-api:
    build: .
    environment:
      NODE_ENV: production
      DATABASE_URL: postgresql://scorpion:${DB_PASSWORD}@database:5432/scorpion
      REDIS_URL: redis://redis:6379
      JWT_SECRET: ${JWT_SECRET}
    depends_on:
      - database
      - redis
    networks:
      - scorpion_network
    ports:
      - "3001:3001"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - scorpion-api
    networks:
      - scorpion_network

volumes:
  postgres_data:
  redis_data:

networks:
  scorpion_network:
    driver: bridge
```

### **Nginx Configuration**
```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream scorpion_api {
        server scorpion-api:3001;
    }

    server {
        listen 80;
        server_name yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name yourdomain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

        location /api/ {
            proxy_pass http://scorpion_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location / {
            root /usr/share/nginx/html;
            try_files $uri $uri/ /index.html;
        }
    }
}
```

---

## 📊 **MONITORING & LOGGING**

### **Application Monitoring**
```javascript
// server/middleware/monitoring.js
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

export default logger;
```

### **Health Checks**
```javascript
// server/routes/health.js
import express from 'express';
import prisma from '../lib/database.js';

const router = express.Router();

router.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.env.npm_package_version
  };

  try {
    // Database health check
    await prisma.$queryRaw`SELECT 1`;
    health.database = 'connected';
  } catch (error) {
    health.database = 'disconnected';
    health.status = 'degraded';
  }

  const statusCode = health.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(health);
});

export default router;
```

---

## ✅ **IMPLEMENTATION CHECKLIST**

### **Phase 1: Critical Security (Required)**
- [ ] Install security dependencies (`jsonwebtoken`, `bcryptjs`, `helmet`, etc.)
- [ ] Implement JWT authentication system
- [ ] Add input validation middleware
- [ ] Configure security headers with Helmet
- [ ] Set up rate limiting
- [ ] Create production environment variables
- [ ] Update CORS configuration for production domains

### **Phase 2: Database Integration**
- [ ] Set up PostgreSQL database
- [ ] Install and configure Prisma ORM
- [ ] Create database schema and migrations
- [ ] Replace in-memory storage with database queries
- [ ] Implement connection pooling

### **Phase 3: Production Infrastructure**
- [ ] Create Docker containers and compose file
- [ ] Configure Nginx reverse proxy with SSL
- [ ] Set up monitoring and logging
- [ ] Implement health check endpoints
- [ ] Configure automated backups

### **Phase 4: Testing & Deployment**
- [ ] Security penetration testing
- [ ] Load testing and performance optimization
- [ ] Deploy to staging environment
- [ ] User acceptance testing
- [ ] Production deployment and monitoring

**This implementation guide provides all the code and configuration needed to secure your Scorpion Security Platform for production deployment.** 🦂🔒
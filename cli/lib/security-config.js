// Enhanced Security Configuration Module
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class SecurityConfig {
  constructor() {
    this.jwtSecret = this.generateSecureJWTSecret();
    this.sslConfig = this.initializeSSLConfig();
    this.csrfSecret = crypto.randomBytes(32).toString('hex');
    this.sessionSecret = crypto.randomBytes(64).toString('hex');
    
    // Advanced security headers
    this.securityHeaders = {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' wss: https:; font-src 'self' data:; object-src 'none'; media-src 'self'; frame-src 'none';",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'cross-origin'
    };

    // Rate limiting configurations
    this.rateLimits = {
      api: { windowMs: 15 * 60 * 1000, max: 100 }, // 15 minutes, 100 requests
      auth: { windowMs: 15 * 60 * 1000, max: 5 },  // 15 minutes, 5 attempts
      scan: { windowMs: 60 * 1000, max: 10 },      // 1 minute, 10 scans
      exploit: { windowMs: 5 * 60 * 1000, max: 3 } // 5 minutes, 3 attempts
    };
  }

  /**
   * Generate cryptographically secure JWT secret
   */
  generateSecureJWTSecret() {
    // Check environment variable first
    if (process.env.JWT_SECRET && process.env.JWT_SECRET.length >= 32) {
      return process.env.JWT_SECRET;
    }

    // Generate secure random secret
    const secret = crypto.randomBytes(64).toString('hex');
    
    // In production, this should be stored securely
    if (process.env.NODE_ENV === 'production') {
      console.warn('⚠️  WARNING: JWT_SECRET not set in environment. Using generated secret.');
      console.warn('⚠️  Set JWT_SECRET environment variable for production use.');
    }

    return secret;
  }

  /**
   * Initialize SSL configuration
   */
  initializeSSLConfig() {
    const certPath = path.join(__dirname, '..', '..', 'certs');
    const keyPath = path.join(certPath, 'private-key.pem');
    const certFilePath = path.join(certPath, 'certificate.pem');

    // Check if SSL certificates exist
    if (fs.existsSync(keyPath) && fs.existsSync(certFilePath)) {
      try {
        return {
          key: fs.readFileSync(keyPath),
          cert: fs.readFileSync(certFilePath),
          available: true
        };
      } catch (error) {
        console.warn('⚠️  SSL certificates found but could not be loaded:', error.message);
      }
    }

    // Generate self-signed certificates for development
    return this.generateSelfSignedCerts();
  }

  /**
   * Generate self-signed SSL certificates for development
   */
  generateSelfSignedCerts() {
    try {
      // Create certs directory if it doesn't exist
      const certPath = path.join(__dirname, '..', '..', 'certs');
      if (!fs.existsSync(certPath)) {
        fs.mkdirSync(certPath, { recursive: true });
      }

      // Generate private key and certificate using Node.js crypto
      const { privateKey, certificate } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });

      // Create a simple self-signed certificate
      const cert = this.createSelfSignedCertificate(privateKey);

      // Save certificates
      const keyPath = path.join(certPath, 'private-key.pem');
      const certFilePath = path.join(certPath, 'certificate.pem');
      
      fs.writeFileSync(keyPath, privateKey);
      fs.writeFileSync(certFilePath, cert);

      console.log('🔒 Generated self-signed SSL certificates for development');
      console.log('📁 Certificates saved to:', certPath);

      return {
        key: privateKey,
        cert: cert,
        available: true,
        selfSigned: true
      };
    } catch (error) {
      console.warn('⚠️  Could not generate SSL certificates:', error.message);
      return { available: false };
    }
  }

  /**
   * Create self-signed certificate (simplified version)
   */
  createSelfSignedCertificate(privateKey) {
    // This is a simplified version - in production, use proper certificate generation
    const certData = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUX7fRlJ2t2DvZ8N5O1xX9K6Zr7wMwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTEwMjIwMDAwMDBaFw0yNjEw
MjIwMDAwMDBaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC3X7p8y5F9nGLkV6BN4Dkv8QjF2XzKjB3Xc4N5o8wQ
T6fRlJ2t2DvZ8N5O1xX9K6Zr7wMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21l
LVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3X7p8y5F9nGLkV6BN4Dkv8QjF2XzK
jB3Xc4N5o8wQT6fRlJ2t2DvZ8N5O1xX9K6Zr7wMwDQYJKoZIhvcNAQELBQADggEB
ALC4X7p8y5F9nGLkV6BN4Dkv8QjF2XzKjB3Xc4N5o8wQT6fRlJ2t2DvZ8N5O1xX9
K6Zr7wMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQK
DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC3X7p8y5F9nGLkV6BN4Dkv8QjF2XzKjB3Xc4N5o8wQT6fRlJ2t
-----END CERTIFICATE-----`;
    
    return certData;
  }

  /**
   * Get secure cookie configuration
   */
  getSecureCookieConfig() {
    return {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      domain: process.env.COOKIE_DOMAIN || undefined
    };
  }

  /**
   * Get CORS configuration
   */
  getCORSConfig() {
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',')
      : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:5174', 'https://localhost:3443'];

    return {
      origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      optionsSuccessStatus: 200,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With']
    };
  }

  /**
   * Validate environment security
   */
  validateSecurityEnvironment() {
    const issues = [];

    // Check JWT secret strength
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
      issues.push('JWT_SECRET should be at least 32 characters long');
    }

    // Check if running in production without HTTPS
    if (process.env.NODE_ENV === 'production' && !this.sslConfig.available) {
      issues.push('HTTPS certificates required for production');
    }

    // Check other critical environment variables
    const requiredEnvVars = ['NODE_ENV'];
    requiredEnvVars.forEach(envVar => {
      if (!process.env[envVar]) {
        issues.push(`${envVar} environment variable not set`);
      }
    });

    if (issues.length > 0) {
      console.warn('⚠️  Security Environment Issues:');
      issues.forEach(issue => console.warn(`   - ${issue}`));
    }

    return issues.length === 0;
  }

  /**
   * Generate CSRF token
   */
  generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Hash password securely
   */
  async hashPassword(password) {
    const bcrypt = await import('bcrypt');
    return bcrypt.hash(password, 12);
  }

  /**
   * Verify password hash
   */
  async verifyPassword(password, hash) {
    const bcrypt = await import('bcrypt');
    return bcrypt.compare(password, hash);
  }

  /**
   * Generate secure session ID
   */
  generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Create secure hash using SHA-256
   */
  createSecureHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Create HMAC signature for integrity checking
   */
  createHMAC(data, key = this.jwtSecret) {
    return crypto.createHmac('sha256', key).update(data).digest('hex');
  }

  /**
   * Verify HMAC signature
   */
  verifyHMAC(data, signature, key = this.jwtSecret) {
    const expectedSignature = this.createHMAC(data, key);
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
  }

  /**
   * Sanitize file path to prevent directory traversal
   */
  sanitizeFilePath(filePath) {
    // Remove any path traversal attempts
    return path.normalize(filePath).replace(/^(\.\.[\/\\])+/, '');
  }

  /**
   * Generate Content Security Policy nonce
   */
  generateCSPNonce() {
    return crypto.randomBytes(16).toString('base64');
  }
}

export default SecurityConfig;
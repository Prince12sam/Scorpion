// Security Configuration Module for CLI
import crypto from 'crypto';

export class SecurityConfig {
  constructor() {
    this.csrfSecret = crypto.randomBytes(32).toString('hex');
    
    // Rate limiting configurations for CLI operations
    this.rateLimits = {
      scan: { windowMs: 60 * 1000, max: 10 },      // 1 minute, 10 scans
      exploit: { windowMs: 5 * 60 * 1000, max: 3 } // 5 minutes, 3 attempts
    };
  }

  /**
   * Generate CSRF token
   */
  generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
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
  createHMAC(data, key) {
    const hmacKey = key || this.csrfSecret;
    return crypto.createHmac('sha256', hmacKey).update(data).digest('hex');
  }

  /**
   * Verify HMAC signature
   */
  verifyHMAC(data, signature, key) {
    const hmacKey = key || this.csrfSecret;
    const expectedSignature = this.createHMAC(data, hmacKey);
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
  }

  /**
   * Generate Content Security Policy nonce
   */
  generateCSPNonce() {
    return crypto.randomBytes(16).toString('base64');
  }

  /**
   * Generate secure random bytes
   */
  generateRandomBytes(size = 32) {
    return crypto.randomBytes(size);
  }

  /**
   * Secure string comparison to prevent timing attacks
   */
  secureCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }
}

export default SecurityConfig;

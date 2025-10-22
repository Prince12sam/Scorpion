// Security Input Validation and Sanitization Module
import { URL } from 'url';
import net from 'net';
import dns from 'dns';
import { promisify } from 'util';

const dnsLookup = promisify(dns.lookup);

export class SecurityValidator {
  constructor() {
    // Blocked networks and hosts (prevent SSRF)
    this.blockedNetworks = [
      '127.0.0.0/8',    // Localhost
      '10.0.0.0/8',     // Private Class A
      '172.16.0.0/12',  // Private Class B
      '192.168.0.0/16', // Private Class C
      '169.254.0.0/16', // Link-local
      '224.0.0.0/4',    // Multicast
      '::1/128',        // IPv6 localhost
      'fc00::/7',       // IPv6 private
      'fe80::/10'       // IPv6 link-local
    ];
    
    this.blockedHosts = [
      'localhost', '127.0.0.1', '0.0.0.0', '::1',
      'metadata.google.internal', 'metadata.gce.internal',
      '169.254.169.254', // AWS/GCP metadata
      'metadata.aws.com'
    ];

    // Allowed protocols for scanning
    this.allowedProtocols = ['http:', 'https:'];
    
    // Enhanced validation patterns
    this.patterns = {
      ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
      domain: /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*/,
      port: /^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$/,
      portRange: /^(\d+)-(\d+)$|^\d+$/
    };
  }

  /**
   * Validate and sanitize target for scanning operations
   */
  async validateTarget(target, options = {}) {
    if (!target || typeof target !== 'string') {
      throw new Error('Invalid target: must be a non-empty string');
    }

    // Remove dangerous characters and normalize
    const sanitized = target.trim().toLowerCase();
    
    // Check for obvious injection attempts
    if (this.containsInjectionPatterns(sanitized)) {
      throw new Error('Target contains potentially malicious patterns');
    }

    // Validate format (IP or domain)
    let resolvedIP;
    if (this.patterns.ipv4.test(sanitized)) {
      resolvedIP = sanitized;
    } else if (this.patterns.domain.test(sanitized)) {
      try {
        const resolved = await dnsLookup(sanitized);
        resolvedIP = resolved.address;
      } catch (error) {
        throw new Error(`Cannot resolve target domain: ${error.message}`);
      }
    } else {
      throw new Error('Target must be a valid IP address or domain name');
    }

    // Check against blocked networks and hosts
    if (this.isBlockedTarget(sanitized, resolvedIP)) {
      throw new Error('Target is in blocked network range or hosts list');
    }

    // Additional security checks for scanning context
    if (options.allowPrivateNetworks !== true && this.isPrivateNetwork(resolvedIP)) {
      throw new Error('Private network scanning requires explicit permission');
    }

    return {
      original: target,
      sanitized: sanitized,
      resolvedIP: resolvedIP,
      validated: true
    };
  }

  /**
   * Validate URL for web application testing
   */
  async validateURL(urlString, options = {}) {
    if (!urlString || typeof urlString !== 'string') {
      throw new Error('Invalid URL: must be a non-empty string');
    }

    let url;
    try {
      url = new URL(urlString);
    } catch (error) {
      throw new Error(`Invalid URL format: ${error.message}`);
    }

    // Check protocol
    if (!this.allowedProtocols.includes(url.protocol)) {
      throw new Error(`Unsupported protocol: ${url.protocol}`);
    }

    // Validate hostname
    const targetValidation = await this.validateTarget(url.hostname, options);
    
    // Check for dangerous URL patterns
    if (this.containsDangerousURLPatterns(url)) {
      throw new Error('URL contains potentially dangerous patterns');
    }

    return {
      url: url,
      hostname: targetValidation.sanitized,
      resolvedIP: targetValidation.resolvedIP,
      validated: true
    };
  }

  /**
   * Validate port number or range
   */
  validatePorts(ports) {
    if (!ports || typeof ports !== 'string') {
      throw new Error('Invalid ports: must be a non-empty string');
    }

    const sanitized = ports.trim();
    
    if (!this.patterns.portRange.test(sanitized)) {
      throw new Error('Invalid port format: must be a number or range (e.g., 80 or 80-443)');
    }

    // Parse and validate range
    if (sanitized.includes('-')) {
      const [start, end] = sanitized.split('-').map(p => parseInt(p));
      if (start >= end || start < 1 || end > 65535) {
        throw new Error('Invalid port range: start must be less than end, within 1-65535');
      }
      if (end - start > 10000) {
        throw new Error('Port range too large: maximum 10,000 ports per scan');
      }
    } else {
      const port = parseInt(sanitized);
      if (port < 1 || port > 65535) {
        throw new Error('Invalid port: must be within 1-65535');
      }
    }

    return sanitized;
  }

  /**
   * Check for injection patterns
   */
  containsInjectionPatterns(input) {
    const dangerousPatterns = [
      // Command injection
      /[;&|`$(){}[\]]/,
      // SQL injection
      /['"`;-]{2,}|--|#/,
      // Script injection
      /<script|javascript:|vbscript:|data:/i,
      // Path traversal
      /\.\.|\/\.\.|\\\.\./, 
      // LDAP injection
      /[()&|*]/,
      // XML injection
      /<!|<\?xml/i
    ];

    return dangerousPatterns.some(pattern => pattern.test(input));
  }

  /**
   * Check for dangerous URL patterns
   */
  containsDangerousURLPatterns(url) {
    const dangerous = [
      // Internal services
      url.hostname.includes('metadata'),
      url.hostname.includes('consul'),
      url.hostname.includes('etcd'),
      // File protocols
      url.protocol === 'file:',
      url.protocol === 'ftp:',
      // Suspicious paths
      url.pathname.includes('..'),
      url.pathname.includes('admin'),
      url.pathname.includes('config')
    ];

    return dangerous.some(check => check === true);
  }

  /**
   * Check if target is blocked
   */
  isBlockedTarget(hostname, ip) {
    // Check hostname blocklist
    if (this.blockedHosts.includes(hostname)) {
      return true;
    }

    // Check IP against blocked networks
    return this.isInBlockedNetwork(ip);
  }

  /**
   * Check if IP is in blocked network ranges
   */
  isInBlockedNetwork(ip) {
    // Simple implementation - in production, use proper CIDR checking
    return this.blockedNetworks.some(network => {
      if (network.includes('/')) {
        const [netIP, bits] = network.split('/');
        return this.isIPInCIDR(ip, netIP, parseInt(bits));
      }
      return ip === network;
    });
  }

  /**
   * Check if IP is in private network
   */
  isPrivateNetwork(ip) {
    const privateRanges = [
      '10.0.0.0/8',
      '172.16.0.0/12', 
      '192.168.0.0/16'
    ];
    
    return privateRanges.some(range => {
      const [netIP, bits] = range.split('/');
      return this.isIPInCIDR(ip, netIP, parseInt(bits));
    });
  }

  /**
   * Simple CIDR check implementation
   */
  isIPInCIDR(ip, networkIP, prefixLength) {
    const ipParts = ip.split('.').map(Number);
    const netParts = networkIP.split('.').map(Number);
    
    const mask = (0xFFFFFFFF << (32 - prefixLength)) >>> 0;
    
    const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const netInt = (netParts[0] << 24) | (netParts[1] << 16) | (netParts[2] << 8) | netParts[3];
    
    return (ipInt & mask) === (netInt & mask);
  }

  /**
   * Sanitize user input for logging and display
   */
  sanitizeForOutput(input) {
    if (typeof input !== 'string') {
      return String(input);
    }
    
    return input
      .replace(/[<>&"']/g, char => ({
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&#x27;'
      }[char]))
      .substring(0, 1000); // Limit length
  }

  /**
   * Validate exploit payload for ethical testing
   */
  validateExploitPayload(payload, type) {
    if (!payload || typeof payload !== 'string') {
      throw new Error('Invalid payload: must be a non-empty string');
    }

    // Check payload length
    if (payload.length > 10000) {
      throw new Error('Payload too large: maximum 10,000 characters');
    }

    // Type-specific validation
    switch (type) {
      case 'sql':
        if (payload.includes('DROP TABLE') || payload.includes('DELETE FROM')) {
          throw new Error('Destructive SQL payloads not allowed');
        }
        break;
        
      case 'command':
        if (payload.includes('rm -rf') || payload.includes('format') || payload.includes('del /')) {
          throw new Error('Destructive command payloads not allowed');
        }
        break;
        
      case 'xss':
        // Allow XSS payloads but log them
        console.log(`XSS payload validated: ${this.sanitizeForOutput(payload)}`);
        break;
    }

    return payload;
  }

  /**
   * Rate limiting check for scan operations
   */
  checkRateLimit(identifier, maxRequests = 100, windowMs = 60000) {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    if (!this.rateLimitMap) {
      this.rateLimitMap = new Map();
    }
    
    const requests = this.rateLimitMap.get(identifier) || [];
    const validRequests = requests.filter(time => time > windowStart);
    
    if (validRequests.length >= maxRequests) {
      throw new Error(`Rate limit exceeded: ${maxRequests} requests per ${windowMs}ms`);
    }
    
    validRequests.push(now);
    this.rateLimitMap.set(identifier, validRequests);
    
    return true;
  }
}

export default SecurityValidator;
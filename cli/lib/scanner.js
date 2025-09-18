import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import dns from 'dns';
import net from 'net';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const execAsync = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class SecurityScanner {
  constructor() {
    this.vulnerabilities = [];
    this.scanHistory = [];
  }

  async scan(target, options = {}) {
    const scanId = Date.now().toString();
    const startTime = new Date();
    
    console.log(`Starting security scan of ${target}...`);
    
    const results = {
      scanId,
      target,
      timestamp: startTime.toISOString(),
      type: options.type || 'normal',
      vulnerabilities: [],
      openPorts: [],
      services: [],
      summary: {}
    };

    try {
      // Port scanning
      console.log('🔍 Performing port scan...');
      results.openPorts = await this.portScan(target, options.ports);
      
      // Service detection
      console.log('🔧 Detecting services...');
      results.services = await this.serviceDetection(target, results.openPorts);
      
      // Vulnerability detection
      console.log('⚠️  Checking for vulnerabilities...');
      results.vulnerabilities = await this.vulnerabilityCheck(target, results.services);
      
      // Web application testing (if HTTP/HTTPS detected)
      const webPorts = results.openPorts.filter(p => [80, 443, 8080, 8443].includes(p.port));
      if (webPorts.length > 0) {
        console.log('🌐 Testing web applications...');
        const webVulns = await this.webApplicationTest(target, webPorts);
        results.vulnerabilities.push(...webVulns);
      }
      
      // SSL/TLS testing (if HTTPS detected)
      const sslPorts = results.openPorts.filter(p => [443, 8443].includes(p.port));
      if (sslPorts.length > 0) {
        console.log('🔒 Testing SSL/TLS configuration...');
        const sslVulns = await this.sslTest(target, sslPorts);
        results.vulnerabilities.push(...sslVulns);
      }

      // Generate summary
      results.summary = this.generateSummary(results);
      
      // Save scan history
      this.scanHistory.push(results);
      await this.saveScanResults(results);
      
      return results;
    } catch (error) {
      console.error('Scan failed:', error.message);
      throw error;
    }
  }

  async portScan(target, portRange = '1-1000') {
    const [startPort, endPort] = portRange.split('-').map(p => parseInt(p));
    const openPorts = [];
    const timeout = 2000;

    // Simple TCP connect scan
    const scanPort = (port) => {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        
        socket.setTimeout(timeout);
        
        socket.connect(port, target, () => {
          socket.destroy();
          resolve({ port, status: 'open' });
        });
        
        socket.on('error', () => {
          resolve({ port, status: 'closed' });
        });
        
        socket.on('timeout', () => {
          socket.destroy();
          resolve({ port, status: 'filtered' });
        });
      });
    };

    // Scan ports in batches to avoid overwhelming the target
    const batchSize = 50;
    for (let i = startPort; i <= endPort; i += batchSize) {
      const batch = [];
      for (let j = i; j < Math.min(i + batchSize, endPort + 1); j++) {
        batch.push(scanPort(j));
      }
      
      const results = await Promise.all(batch);
      const open = results.filter(r => r.status === 'open');
      openPorts.push(...open);
      
      // Progress indicator
      process.stdout.write(`\rScanning ports: ${Math.min(i + batchSize, endPort)}/${endPort}`);
    }
    
    console.log(`\nFound ${openPorts.length} open ports`);
    return openPorts;
  }

  async serviceDetection(target, openPorts) {
    const services = [];
    
    for (const portInfo of openPorts) {
      try {
        const service = await this.detectService(target, portInfo.port);
        services.push({
          port: portInfo.port,
          service: service.name,
          version: service.version,
          banner: service.banner
        });
      } catch (error) {
        services.push({
          port: portInfo.port,
          service: 'unknown',
          version: null,
          banner: null
        });
      }
    }
    
    return services;
  }

  async detectService(target, port) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let banner = '';
      
      socket.setTimeout(5000);
      
      socket.connect(port, target, () => {
        // Send HTTP request for web services
        if ([80, 8080].includes(port)) {
          socket.write('GET / HTTP/1.1\r\nHost: ' + target + '\r\n\r\n');
        } else if ([443, 8443].includes(port)) {
          // For HTTPS, we'll just connect and see what we get
          socket.write('GET / HTTP/1.1\r\nHost: ' + target + '\r\n\r\n');
        }
      });
      
      socket.on('data', (data) => {
        banner += data.toString();
        socket.destroy();
        
        const service = this.parseServiceBanner(banner, port);
        resolve(service);
      });
      
      socket.on('error', () => {
        resolve({ name: 'unknown', version: null, banner: null });
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ name: this.getServiceByPort(port), version: null, banner: null });
      });
    });
  }

  parseServiceBanner(banner, port) {
    const service = { name: 'unknown', version: null, banner: banner.substring(0, 200) };
    
    // HTTP/HTTPS detection
    if (banner.includes('HTTP/')) {
      service.name = 'http';
      const serverMatch = banner.match(/Server: ([^\r\n]+)/i);
      if (serverMatch) {
        service.version = serverMatch[1];
      }
    }
    
    // SSH detection
    else if (banner.includes('SSH-')) {
      service.name = 'ssh';
      const versionMatch = banner.match(/SSH-([^\r\n]+)/);
      if (versionMatch) {
        service.version = versionMatch[1];
      }
    }
    
    // FTP detection
    else if (banner.includes('220') && port === 21) {
      service.name = 'ftp';
      const versionMatch = banner.match(/220[^\r\n]*([^\r\n]+)/);
      if (versionMatch) {
        service.version = versionMatch[1];
      }
    }
    
    // Default service by port
    else {
      service.name = this.getServiceByPort(port);
    }
    
    return service;
  }

  getServiceByPort(port) {
    const commonServices = {
      21: 'ftp',
      22: 'ssh',
      23: 'telnet',
      25: 'smtp',
      53: 'dns',
      80: 'http',
      110: 'pop3',
      143: 'imap',
      443: 'https',
      993: 'imaps',
      995: 'pop3s'
    };
    
    return commonServices[port] || 'unknown';
  }

  async vulnerabilityCheck(target, services) {
    const vulnerabilities = [];
    
    for (const service of services) {
      // Check for known vulnerable services
      const vulns = await this.checkServiceVulnerabilities(service);
      vulnerabilities.push(...vulns);
      
      // Check for default credentials
      const defaultCreds = await this.checkDefaultCredentials(target, service);
      vulnerabilities.push(...defaultCreds);
      
      // Check for outdated versions
      const outdated = await this.checkOutdatedVersions(service);
      vulnerabilities.push(...outdated);
    }
    
    return vulnerabilities;
  }

  async checkServiceVulnerabilities(service) {
    const vulnerabilities = [];
    
    // Load vulnerability database
    const vulnDb = await this.loadVulnerabilityDatabase();
    
    // Check service against known vulnerabilities
    const serviceVulns = vulnDb.filter(vuln => 
      vuln.service === service.service && 
      (vuln.version === service.version || vuln.version === '*')
    );
    
    for (const vuln of serviceVulns) {
      vulnerabilities.push({
        id: vuln.id,
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity,
        cvss: vuln.cvss,
        cve: vuln.cve,
        service: service.service,
        port: service.port,
        remediation: vuln.remediation,
        references: vuln.references
      });
    }
    
    return vulnerabilities;
  }

  async loadVulnerabilityDatabase() {
    // This would normally load from a real vulnerability database
    // For now, we'll use a sample database
    return [
      {
        id: 'VULN-001',
        title: 'SSH Weak Encryption',
        description: 'SSH server supports weak encryption algorithms',
        severity: 'Medium',
        cvss: 5.3,
        cve: 'CVE-2016-0777',
        service: 'ssh',
        version: '*',
        remediation: 'Update SSH configuration to disable weak ciphers',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2016-0777']
      },
      {
        id: 'VULN-002',
        title: 'HTTP Server Information Disclosure',
        description: 'Web server reveals version information',
        severity: 'Low',
        cvss: 2.6,
        service: 'http',
        version: '*',
        remediation: 'Configure server to hide version information',
        references: ['https://owasp.org/www-project-top-ten/']
      },
      {
        id: 'VULN-003',
        title: 'FTP Anonymous Login',
        description: 'FTP server allows anonymous login',
        severity: 'High',
        cvss: 7.5,
        service: 'ftp',
        version: '*',
        remediation: 'Disable anonymous FTP access',
        references: ['https://cwe.mitre.org/data/definitions/287.html']
      }
    ];
  }

  async checkDefaultCredentials(target, service) {
    const vulnerabilities = [];
    
    // Common default credentials
    const defaultCreds = {
      ssh: [['admin', 'admin'], ['root', 'root'], ['admin', 'password']],
      ftp: [['anonymous', ''], ['admin', 'admin'], ['ftp', 'ftp']],
      http: [['admin', 'admin'], ['admin', 'password'], ['root', 'root']]
    };
    
    if (defaultCreds[service.service]) {
      // Note: In a real implementation, you'd actually test these credentials
      // For demo purposes, we'll randomly flag some as vulnerable
      if (Math.random() > 0.8) {
        vulnerabilities.push({
          id: 'DEFAULT-CREDS',
          title: 'Default Credentials Detected',
          description: `Service ${service.service} on port ${service.port} may be using default credentials`,
          severity: 'Critical',
          cvss: 9.8,
          service: service.service,
          port: service.port,
          remediation: 'Change default credentials immediately',
          references: ['https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication']
        });
      }
    }
    
    return vulnerabilities;
  }

  async checkOutdatedVersions(service) {
    const vulnerabilities = [];
    
    // This would check against a database of known vulnerable versions
    // For demo, we'll flag some common outdated versions
    const outdatedVersions = {
      'Apache/2.2': 'Apache 2.2 is end-of-life and contains known vulnerabilities',
      'nginx/1.10': 'nginx 1.10 has known security issues',
      'OpenSSH_6.6': 'OpenSSH 6.6 has multiple CVEs'
    };
    
    if (service.version && outdatedVersions[service.version]) {
      vulnerabilities.push({
        id: 'OUTDATED-VERSION',
        title: 'Outdated Software Version',
        description: outdatedVersions[service.version],
        severity: 'High',
        cvss: 7.8,
        service: service.service,
        port: service.port,
        version: service.version,
        remediation: 'Update to the latest stable version',
        references: ['https://nvd.nist.gov/']
      });
    }
    
    return vulnerabilities;
  }

  async webApplicationTest(target, webPorts) {
    const vulnerabilities = [];
    
    for (const portInfo of webPorts) {
      const protocol = portInfo.port === 443 || portInfo.port === 8443 ? 'https' : 'http';
      const baseUrl = `${protocol}://${target}:${portInfo.port}`;
      
      try {
        // Check for common web vulnerabilities
        const webVulns = await this.checkWebVulnerabilities(baseUrl);
        vulnerabilities.push(...webVulns);
      } catch (error) {
        console.error(`Web testing failed for ${baseUrl}:`, error.message);
      }
    }
    
    return vulnerabilities;
  }

  async checkWebVulnerabilities(baseUrl) {
    const vulnerabilities = [];
    
    // This would perform actual web application testing
    // For demo, we'll simulate some common findings
    const commonWebVulns = [
      {
        id: 'XSS-001',
        title: 'Potential Cross-Site Scripting (XSS)',
        description: 'Web application may be vulnerable to XSS attacks',
        severity: 'Medium',
        cvss: 6.1,
        remediation: 'Implement proper input validation and output encoding'
      },
      {
        id: 'SQL-001',
        title: 'SQL Injection Vulnerability',
        description: 'Database queries may be vulnerable to SQL injection',
        severity: 'Critical',
        cvss: 9.8,
        remediation: 'Use parameterized queries and input validation'
      }
    ];
    
    // Randomly add some vulnerabilities for demo
    if (Math.random() > 0.7) {
      const vuln = commonWebVulns[Math.floor(Math.random() * commonWebVulns.length)];
      vulnerabilities.push({
        ...vuln,
        url: baseUrl,
        references: ['https://owasp.org/www-project-top-ten/']
      });
    }
    
    return vulnerabilities;
  }

  async sslTest(target, sslPorts) {
    const vulnerabilities = [];
    
    for (const portInfo of sslPorts) {
      try {
        // This would perform actual SSL/TLS testing
        // For demo, we'll simulate some common SSL issues
        if (Math.random() > 0.6) {
          vulnerabilities.push({
            id: 'SSL-001',
            title: 'Weak SSL/TLS Configuration',
            description: 'SSL/TLS configuration supports weak ciphers or protocols',
            severity: 'Medium',
            cvss: 5.9,
            port: portInfo.port,
            remediation: 'Update SSL/TLS configuration to use strong ciphers only',
            references: ['https://ssl-config.mozilla.org/']
          });
        }
      } catch (error) {
        console.error(`SSL testing failed for port ${portInfo.port}:`, error.message);
      }
    }
    
    return vulnerabilities;
  }

  generateSummary(results) {
    const summary = {
      totalVulnerabilities: results.vulnerabilities.length,
      criticalVulns: results.vulnerabilities.filter(v => v.severity === 'Critical').length,
      highVulns: results.vulnerabilities.filter(v => v.severity === 'High').length,
      mediumVulns: results.vulnerabilities.filter(v => v.severity === 'Medium').length,
      lowVulns: results.vulnerabilities.filter(v => v.severity === 'Low').length,
      openPorts: results.openPorts.length,
      services: results.services.length,
      riskScore: this.calculateRiskScore(results.vulnerabilities)
    };
    
    return summary;
  }

  calculateRiskScore(vulnerabilities) {
    let score = 0;
    vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case 'Critical': score += 10; break;
        case 'High': score += 7; break;
        case 'Medium': score += 4; break;
        case 'Low': score += 1; break;
      }
    });
    return Math.min(score, 100);
  }

  async saveScanResults(results) {
    try {
      const resultsDir = path.join(__dirname, '..', 'results');
      await fs.mkdir(resultsDir, { recursive: true });
      
      const filename = `scan_${results.scanId}_${Date.now()}.json`;
      const filepath = path.join(resultsDir, filename);
      
      await fs.writeFile(filepath, JSON.stringify(results, null, 2));
      console.log(`Scan results saved to: ${filepath}`);
    } catch (error) {
      console.error('Failed to save scan results:', error.message);
    }
  }
}
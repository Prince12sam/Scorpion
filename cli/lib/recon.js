import dns from 'dns';
import { promisify } from 'util';
import net from 'net';
import { spawn, exec } from 'child_process';
import axios from 'axios';

const dnsResolve = promisify(dns.resolve);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const execAsync = promisify(exec);

export class NetworkRecon {
  constructor() {
    this.results = {};
  }

  async discover(target, options = {}) {
    console.log(`Starting reconnaissance on ${target}...`);
    
    const results = {
      target,
      timestamp: new Date().toISOString(),
      dns: null,
      whois: null,
      ports: null,
      subdomains: null,
      geolocation: null,
      certificates: null,
      headers: null
    };

    try {
      // DNS enumeration
      if (options.dns !== false) {
        console.log('🔍 Performing DNS enumeration...');
        results.dns = await this.dnsEnumeration(target);
      }

      // WHOIS lookup
      if (options.whois) {
        console.log('📋 Performing WHOIS lookup...');
        results.whois = await this.whoisLookup(target);
      }

      // Port scanning
      if (options.ports) {
        console.log('🔌 Scanning ports...');
        results.ports = await this.portScan(target);
      }

      // Subdomain enumeration
      if (options.subdomain) {
        console.log('🌐 Enumerating subdomains...');
        results.subdomains = await this.subdomainEnumeration(target);
      }

      // Geolocation
      console.log('🌍 Getting geolocation data...');
      results.geolocation = await this.getGeolocation(target);

      // HTTP headers (if web service is running)
      console.log('📝 Analyzing HTTP headers...');
      results.headers = await this.getHttpHeaders(target);

      return results;
    } catch (error) {
      console.error('Reconnaissance failed:', error.message);
      throw error;
    }
  }

  async dnsEnumeration(target) {
    const dnsResults = {
      a: [],
      aaaa: [],
      mx: [],
      txt: [],
      ns: [],
      cname: []
    };

    try {
      // A records
      try {
        const aRecords = await dnsResolve4(target);
        dnsResults.a = aRecords.map(ip => ({ type: 'A', value: ip }));
      } catch (e) {
        // Ignore DNS resolution errors
      }

      // AAAA records
      try {
        const aaaaRecords = await dnsResolve6(target);
        dnsResults.aaaa = aaaaRecords.map(ip => ({ type: 'AAAA', value: ip }));
      } catch (e) {
        // Ignore DNS resolution errors
      }

      // MX records
      try {
        const mxRecords = await dnsResolveMx(target);
        dnsResults.mx = mxRecords.map(mx => ({ 
          type: 'MX', 
          value: mx.exchange, 
          priority: mx.priority 
        }));
      } catch (e) {
        // Ignore DNS resolution errors
      }

      // TXT records
      try {
        const txtRecords = await dnsResolveTxt(target);
        dnsResults.txt = txtRecords.flat().map(txt => ({ type: 'TXT', value: txt }));
      } catch (e) {
        // Ignore DNS resolution errors
      }

      // NS records
      try {
        const nsRecords = await dnsResolveNs(target);
        dnsResults.ns = nsRecords.map(ns => ({ type: 'NS', value: ns }));
      } catch (e) {
        // Ignore DNS resolution errors
      }

      // Flatten all records for easier consumption
      const allRecords = [
        ...dnsResults.a,
        ...dnsResults.aaaa,
        ...dnsResults.mx,
        ...dnsResults.txt,
        ...dnsResults.ns
      ];

      return allRecords;
    } catch (error) {
      console.error('DNS enumeration failed:', error.message);
      return [];
    }
  }

  async whoisLookup(target) {
    try {
      // Use a WHOIS API service or command line tool
      const response = await axios.get(`https://ipinfo.io/${target}/json`, {
        timeout: 10000
      });

      return {
        ip: response.data.ip,
        hostname: response.data.hostname,
        city: response.data.city,
        region: response.data.region,
        country: response.data.country,
        org: response.data.org,
        postal: response.data.postal,
        timezone: response.data.timezone,
        registrar: 'Unknown', // Would need domain WHOIS for this
        created: 'Unknown',   // Would need domain WHOIS for this
        expires: 'Unknown'    // Would need domain WHOIS for this
      };
    } catch (error) {
      console.error('WHOIS lookup failed:', error.message);
      
      // Fallback to basic IP info
      try {
        const basicInfo = await this.getBasicIpInfo(target);
        return basicInfo;
      } catch (fallbackError) {
        return {
          error: 'WHOIS lookup failed',
          message: error.message
        };
      }
    }
  }

  async getBasicIpInfo(target) {
    // Try to resolve the target to an IP
    try {
      const ips = await dnsResolve4(target);
      return {
        domain: target,
        ip: ips[0],
        registrar: 'Unknown',
        created: 'Unknown',
        expires: 'Unknown'
      };
    } catch (error) {
      // If it's already an IP
      if (net.isIP(target)) {
        return {
          ip: target,
          registrar: 'Unknown',
          created: 'Unknown',
          expires: 'Unknown'
        };
      }
      throw error;
    }
  }

  async portScan(target, portRange = '1-1000') {
    const [startPort, endPort] = portRange.split('-').map(p => parseInt(p));
    const openPorts = [];
    const timeout = 2000;

    const scanPort = (port) => {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        
        socket.setTimeout(timeout);
        
        socket.connect(port, target, () => {
          socket.destroy();
          resolve({ 
            port, 
            status: 'open',
            service: this.getServiceName(port)
          });
        });
        
        socket.on('error', () => {
          resolve(null);
        });
        
        socket.on('timeout', () => {
          socket.destroy();
          resolve(null);
        });
      });
    };

    // Scan common ports first
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443];
    const quickResults = await Promise.all(commonPorts.map(scanPort));
    openPorts.push(...quickResults.filter(r => r !== null));

    // Then scan the full range if requested
    if (endPort > 1000) {
      const batchSize = 50;
      for (let i = startPort; i <= endPort; i += batchSize) {
        if (commonPorts.includes(i)) continue; // Skip already scanned ports
        
        const batch = [];
        for (let j = i; j < Math.min(i + batchSize, endPort + 1); j++) {
          if (!commonPorts.includes(j)) {
            batch.push(scanPort(j));
          }
        }
        
        const results = await Promise.all(batch);
        const open = results.filter(r => r !== null);
        openPorts.push(...open);
        
        // Progress indicator
        process.stdout.write(`\rScanning: ${Math.min(i + batchSize, endPort)}/${endPort}`);
      }
    }
    
    console.log(`\nFound ${openPorts.length} open ports`);
    return openPorts;
  }

  getServiceName(port) {
    const services = {
      21: 'FTP',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      143: 'IMAP',
      443: 'HTTPS',
      993: 'IMAPS',
      995: 'POP3S',
      8080: 'HTTP-Alt',
      8443: 'HTTPS-Alt'
    };
    
    return services[port] || 'Unknown';
  }

  async subdomainEnumeration(target) {
    const subdomains = [];
    
    // Common subdomains to check
    const commonSubs = [
      'www', 'mail', 'ftp', 'admin', 'www2', 'ns1', 'ns2', 'dns1', 'dns2',
      'mx', 'blog', 'forum', 'shop', 'api', 'cdn', 'static', 'media',
      'dev', 'test', 'staging', 'beta', 'alpha', 'secure', 'vpn', 'remote'
    ];

    console.log(`Checking ${commonSubs.length} common subdomains...`);

    for (const sub of commonSubs) {
      const subdomain = `${sub}.${target}`;
      try {
        const ips = await dnsResolve4(subdomain);
        subdomains.push({
          subdomain,
          ips,
          status: 'active'
        });
        console.log(`✓ Found: ${subdomain} -> ${ips.join(', ')}`);
      } catch (error) {
        // Subdomain doesn't exist, ignore
      }
    }

    return subdomains;
  }

  async getGeolocation(target) {
    try {
      // First resolve domain to IP if needed
      let ip = target;
      if (!net.isIP(target)) {
        const ips = await dnsResolve4(target);
        ip = ips[0];
      }

      const response = await axios.get(`https://ipinfo.io/${ip}/json`, {
        timeout: 10000
      });

      return {
        ip: response.data.ip,
        city: response.data.city,
        region: response.data.region,
        country: response.data.country,
        loc: response.data.loc,
        org: response.data.org,
        postal: response.data.postal,
        timezone: response.data.timezone
      };
    } catch (error) {
      console.error('Geolocation lookup failed:', error.message);
      return null;
    }
  }

  async getHttpHeaders(target) {
    const headers = {};
    const ports = [80, 443, 8080, 8443];

    for (const port of ports) {
      try {
        const protocol = (port === 443 || port === 8443) ? 'https' : 'http';
        const url = `${protocol}://${target}:${port}`;
        
        const response = await axios.get(url, {
          timeout: 10000,
          maxRedirects: 0,
          validateStatus: () => true // Accept any status code
        });

        headers[port] = {
          status: response.status,
          headers: response.headers,
          server: response.headers.server || 'Unknown',
          powered_by: response.headers['x-powered-by'] || 'Unknown',
          security_headers: this.analyzeSecurityHeaders(response.headers)
        };

        console.log(`✓ HTTP headers retrieved for port ${port}`);
      } catch (error) {
        if (error.code !== 'ECONNREFUSED') {
          headers[port] = {
            error: error.message,
            status: 'unreachable'
          };
        }
      }
    }

    return headers;
  }

  analyzeSecurityHeaders(headers) {
    const securityHeaders = {
      'strict-transport-security': headers['strict-transport-security'] ? 'Present' : 'Missing',
      'content-security-policy': headers['content-security-policy'] ? 'Present' : 'Missing',
      'x-frame-options': headers['x-frame-options'] ? 'Present' : 'Missing',
      'x-content-type-options': headers['x-content-type-options'] ? 'Present' : 'Missing',
      'x-xss-protection': headers['x-xss-protection'] ? 'Present' : 'Missing',
      'referrer-policy': headers['referrer-policy'] ? 'Present' : 'Missing'
    };

    const score = Object.values(securityHeaders).filter(v => v === 'Present').length;
    securityHeaders.score = `${score}/6`;
    securityHeaders.grade = score >= 5 ? 'A' : score >= 3 ? 'B' : score >= 1 ? 'C' : 'F';

    return securityHeaders;
  }

  async traceroute(target) {
    try {
      // Simple traceroute implementation
      const hops = [];
      const maxHops = 30;
      
      for (let ttl = 1; ttl <= maxHops; ttl++) {
        try {
          // This is a simplified version - real traceroute would use ICMP/UDP
          const hop = await this.performHop(target, ttl);
          hops.push(hop);
          
          if (hop.reached_target) {
            break;
          }
        } catch (error) {
          hops.push({
            hop: ttl,
            ip: '*',
            hostname: '*',
            rtt: 'timeout'
          });
        }
      }
      
      return hops;
    } catch (error) {
      console.error('Traceroute failed:', error.message);
      return [];
    }
  }

  async performHop(target, ttl) {
    // This is a placeholder - real implementation would require raw sockets
    // For demo purposes, we'll simulate some hops
    const simulatedHops = [
      { ip: '192.168.1.1', hostname: 'router.local' },
      { ip: '10.0.0.1', hostname: 'isp-gateway' },
      { ip: '8.8.8.8', hostname: 'dns.google' }
    ];
    
    if (ttl <= simulatedHops.length) {
      return {
        hop: ttl,
        ...simulatedHops[ttl - 1],
        rtt: Math.random() * 100 + 10,
        reached_target: ttl === simulatedHops.length
      };
    }
    
    return {
      hop: ttl,
      ip: target,
      hostname: target,
      rtt: Math.random() * 100 + 50,
      reached_target: true
    };
  }

  async getCertificateInfo(target, port = 443) {
    try {
      // This would normally use OpenSSL or a TLS library
      // For demo, we'll return mock certificate data
      return {
        subject: `CN=${target}`,
        issuer: 'Let\'s Encrypt Authority X3',
        valid_from: '2023-01-01',
        valid_to: '2024-01-01',
        fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
        key_size: 2048,
        signature_algorithm: 'sha256WithRSAEncryption',
        extensions: {
          subject_alt_names: [`*.${target}`, target],
          key_usage: ['Digital Signature', 'Key Encipherment'],
          extended_key_usage: ['TLS Web Server Authentication']
        }
      };
    } catch (error) {
      console.error('Certificate info retrieval failed:', error.message);
      return null;
    }
  }
}
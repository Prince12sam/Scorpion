import axios from 'axios';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class ThreatIntel {
  constructor() {
    this.apiKeys = {
      virustotal: process.env.VIRUSTOTAL_API_KEY,
      abuseipdb: process.env.ABUSEIPDB_API_KEY,
      shodan: process.env.SHODAN_API_KEY
    };
    
    this.threatFeeds = [];
    this.iocDatabase = new Map();
    this.loadThreatFeeds();
  }

  async loadThreatFeeds() {
    try {
      // Load local threat intelligence feeds
      const feedsPath = path.join(__dirname, '..', 'data', 'threat-feeds.json');
      const feedsData = await fs.readFile(feedsPath, 'utf8');
      this.threatFeeds = JSON.parse(feedsData);
    } catch (error) {
      // Initialize with default feeds if file doesn't exist
      this.threatFeeds = await this.initializeDefaultFeeds();
      await this.saveThreatFeeds();
    }
  }

  async initializeDefaultFeeds() {
    return {
      malicious_ips: [
        '185.220.100.240',
        '185.220.100.241',
        '185.220.100.242',
        '198.96.155.3',
        '162.247.74.27'
      ],
      malicious_domains: [
        'malware-example.com',
        'phishing-site.net',
        'fake-bank.org',
        'suspicious-domain.info'
      ],
      malicious_hashes: [
        '5d41402abc4b2a76b9719d911017c592',
        'aec070645fe53ee3b3763059376134f0',
        '098f6bcd4621d373cade4e832627b4f6'
      ],
      apt_groups: [
        {
          name: 'APT28',
          aliases: ['Fancy Bear', 'Pawn Storm', 'Sofacy'],
          description: 'Russian military intelligence cyberespionage group',
          techniques: ['T1566.001', 'T1059.001', 'T1055'],
          indicators: ['watering hole attacks', 'spear phishing']
        },
        {
          name: 'APT29',
          aliases: ['Cozy Bear', 'The Dukes'],
          description: 'Russian foreign intelligence cyberespionage group',
          techniques: ['T1566.002', 'T1053.005', 'T1047'],
          indicators: ['supply chain attacks', 'PowerShell usage']
        }
      ],
      last_updated: new Date().toISOString()
    };
  }

  async checkIP(ip) {
    console.log(`Analyzing IP: ${ip}`);
    
    const analysis = {
      ip,
      timestamp: new Date().toISOString(),
      reputation: 'clean',
      threat_score: 0,
      sources: [],
      geolocation: null,
      asn_info: null,
      malware_families: [],
      threat_types: [],
      first_seen: null,
      last_seen: null
    };

    try {
      // Check local threat feeds first
      const localCheck = this.checkLocalThreatFeeds('ip', ip);
      if (localCheck.found) {
        analysis.reputation = 'malicious';
        analysis.threat_score = 85;
        analysis.sources.push('Local Threat Feed');
        analysis.threat_types = localCheck.types;
      }

      // Check with VirusTotal
      if (this.apiKeys.virustotal) {
        const vtResult = await this.checkVirusTotal('ip', ip);
        if (vtResult) {
          analysis.sources.push('VirusTotal');
          if (vtResult.malicious > 0) {
            analysis.reputation = 'malicious';
            analysis.threat_score = Math.max(analysis.threat_score, vtResult.score);
            if (vtResult.malware_families && Array.isArray(vtResult.malware_families)) {
              analysis.malware_families.push(...vtResult.malware_families);
            }
          }
        }
      }

      // Check with AbuseIPDB
      if (this.apiKeys.abuseipdb) {
        const abuseResult = await this.checkAbuseIPDB(ip);
        if (abuseResult) {
          analysis.sources.push('AbuseIPDB');
          if (abuseResult.abuse_confidence > 25) {
            analysis.reputation = 'suspicious';
            analysis.threat_score = Math.max(analysis.threat_score, abuseResult.abuse_confidence);
          }
        }
      }

      // Get geolocation info
      analysis.geolocation = await this.getIPGeolocation(ip);

      // Check Shodan for additional context
      if (this.apiKeys.shodan) {
        const shodanResult = await this.checkShodan(ip);
        if (shodanResult) {
          analysis.sources.push('Shodan');
          analysis.asn_info = shodanResult.asn_info;
        }
      }

      // Final threat assessment
      if (analysis.threat_score > 70) {
        analysis.reputation = 'malicious';
      } else if (analysis.threat_score > 30) {
        analysis.reputation = 'suspicious';
      }

      return analysis;
    } catch (error) {
      console.error('IP analysis failed:', error.message);
      return { ...analysis, error: error.message };
    }
  }

  async checkDomain(domain) {
    console.log(`Analyzing domain: ${domain}`);
    
    const analysis = {
      domain,
      timestamp: new Date().toISOString(),
      reputation: 'clean',
      threat_score: 0,
      sources: [],
      categories: [],
      subdomains: [],
      dns_records: [],
      whois_info: null,
      ssl_info: null,
      first_seen: null,
      last_seen: null
    };

    try {
      // Check local threat feeds
      const localCheck = this.checkLocalThreatFeeds('domain', domain);
      if (localCheck.found) {
        analysis.reputation = 'malicious';
        analysis.threat_score = 90;
        analysis.sources.push('Local Threat Feed');
        analysis.categories = localCheck.types;
      }

      // Check with VirusTotal
      if (this.apiKeys.virustotal) {
        const vtResult = await this.checkVirusTotal('domain', domain);
        if (vtResult) {
          analysis.sources.push('VirusTotal');
          if (vtResult.malicious > 0) {
            analysis.reputation = 'malicious';
            analysis.threat_score = Math.max(analysis.threat_score, vtResult.score);
            analysis.categories.push(...vtResult.categories);
          }
        }
      }

      // Check with Shodan (domain search)
      if (this.apiKeys.shodan) {
        try {
          const shodanResult = await this.checkShodan(domain);
          if (shodanResult) {
            analysis.sources.push('Shodan');
            analysis.network_data = shodanResult.network_data;
            
            // Assess threat based on exposed services
            if (shodanResult.network_data && shodanResult.network_data.open_ports) {
              const dangerousPorts = shodanResult.network_data.open_ports.filter(port => 
                [22, 23, 445, 1433, 3389, 5432].includes(port.port)
              );
              if (dangerousPorts.length > 0) {
                analysis.threat_score += 10;
                analysis.categories.push('exposed_services');
              }
            }

            // Check for vulnerabilities
            if (shodanResult.network_data && shodanResult.network_data.vulnerabilities && 
                shodanResult.network_data.vulnerabilities.length > 0) {
              analysis.threat_score += 25;
              analysis.reputation = 'suspicious';
              analysis.categories.push('known_vulnerabilities');
            }
          }
        } catch (error) {
          console.warn('Shodan domain check failed:', error.message);
        }
      }

      // Domain age and registration analysis
      const domainAge = await this.analyzeDomainAge(domain);
      if (domainAge && domainAge.days_old < 30) {
        analysis.threat_score += 20;
        analysis.categories.push('newly_registered');
      }

      // Suspicious domain patterns
      const suspiciousPatterns = this.analyzeSuspiciousPatterns(domain);
      if (suspiciousPatterns.length > 0) {
        analysis.threat_score += 15;
        analysis.categories.push(...suspiciousPatterns);
      }

      // Final assessment
      if (analysis.threat_score > 70) {
        analysis.reputation = 'malicious';
      } else if (analysis.threat_score > 30) {
        analysis.reputation = 'suspicious';
      }

      return analysis;
    } catch (error) {
      console.error('Domain analysis failed:', error.message);
      return { ...analysis, error: error.message };
    }
  }

  async checkHash(hash) {
    console.log(`Analyzing hash: ${hash}`);
    
    const analysis = {
      hash,
      hash_type: this.detectHashType(hash),
      timestamp: new Date().toISOString(),
      reputation: 'clean',
      threat_score: 0,
      sources: [],
      malware_families: [],
      file_names: [],
      file_types: [],
      first_seen: null,
      last_seen: null,
      yara_rules: []
    };

    try {
      // Check local threat feeds
      const localCheck = this.checkLocalThreatFeeds('hash', hash);
      if (localCheck.found) {
        analysis.reputation = 'malicious';
        analysis.threat_score = 95;
        analysis.sources.push('Local Threat Feed');
        analysis.malware_families = localCheck.families || [];
      }

      // Check with VirusTotal
      if (this.apiKeys.virustotal) {
        const vtResult = await this.checkVirusTotal('file', hash);
        if (vtResult) {
          analysis.sources.push('VirusTotal');
          if (vtResult.malicious > 0) {
            analysis.reputation = 'malicious';
            analysis.threat_score = Math.max(analysis.threat_score, vtResult.score);
            analysis.malware_families.push(...vtResult.malware_families);
            analysis.file_names.push(...vtResult.file_names);
          }
        }
      }

      return analysis;
    } catch (error) {
      console.error('Hash analysis failed:', error.message);
      return { ...analysis, error: error.message };
    }
  }

  checkLocalThreatFeeds(type, indicator) {
    const result = { found: false, types: [], families: [] };
    
    switch (type) {
      case 'ip':
        if (this.threatFeeds.malicious_ips?.includes(indicator)) {
          result.found = true;
          result.types = ['malicious_ip', 'botnet'];
        }
        break;
      case 'domain':
        if (this.threatFeeds.malicious_domains?.includes(indicator)) {
          result.found = true;
          result.types = ['malicious_domain', 'phishing'];
        }
        break;
      case 'hash':
        if (this.threatFeeds.malicious_hashes?.includes(indicator)) {
          result.found = true;
          result.types = ['malware'];
          result.families = ['Generic Malware'];
        }
        break;
    }
    
    return result;
  }

  async checkVirusTotal(type, indicator) {
    if (!this.apiKeys.virustotal) {
      console.log('⚠️  VirusTotal API key not configured');
      return null;
    }

    try {
      let url;
      let encodedIndicator;
      
      switch (type) {
        case 'ip':
          url = `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`;
          break;
        case 'domain':
          url = `https://www.virustotal.com/api/v3/domains/${indicator}`;
          break;
        case 'file':
          url = `https://www.virustotal.com/api/v3/files/${indicator}`;
          break;
        default:
          return null;
      }

      console.log(`🔍 Checking ${indicator} with VirusTotal...`);
      
      const response = await axios.get(url, {
        headers: {
          'x-apikey': this.apiKeys.virustotal,
          'User-Agent': 'Scorpion-Security-Platform/1.0'
        },
        timeout: 15000
      });
      
      if (response.data && response.data.data) {
        const attributes = response.data.data.attributes;
        const stats = attributes.last_analysis_stats || {};
        
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = Object.values(stats).reduce((sum, count) => sum + count, 0);
        
        const result = {
          malicious: malicious,
          suspicious: suspicious,
          total: total,
          score: total > 0 ? Math.round(((malicious + suspicious * 0.5) / total) * 100) : 0,
          reputation: malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean',
          categories: attributes.categories || [],
          tags: attributes.tags || [],
          first_seen: attributes.first_submission_date,
          last_seen: attributes.last_analysis_date
        };

        // Type-specific data extraction
        if (type === 'ip') {
          result.asn = attributes.asn;
          result.country = attributes.country;
          result.network = attributes.network;
        } else if (type === 'domain') {
          result.registrar = attributes.registrar;
          result.creation_date = attributes.creation_date;
        } else if (type === 'file') {
          result.file_type = attributes.type_description;
          result.size = attributes.size;
          result.names = attributes.names;
        }

        console.log(`✅ VirusTotal: ${malicious}/${total} engines flagged as malicious`);
        return result;
      }
      
      return null;
    } catch (error) {
      if (error.response?.status === 404) {
        console.log(`ℹ️  ${indicator} not found in VirusTotal database`);
        return { malicious: 0, total: 0, score: 0, reputation: 'unknown' };
      } else if (error.response?.status === 429) {
        console.log('⚠️  VirusTotal rate limit reached. Skipping check.');
        return null;
      } else {
        console.error('❌ VirusTotal check failed:', error.message);
        return null;
      }
    }
  }

  async checkAbuseIPDB(ip) {
    if (!this.apiKeys.abuseipdb) {
      return null;
    }

    try {
      const response = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
        headers: {
          'Key': this.apiKeys.abuseipdb,
          'Accept': 'application/json'
        },
        params: {
          ipAddress: ip,
          maxAgeInDays: 90,
          verbose: ''
        },
        timeout: 10000
      });

      return {
        abuse_confidence: response.data.data.abuseConfidencePercentage,
        country_code: response.data.data.countryCode,
        usage_type: response.data.data.usageType,
        isp: response.data.data.isp,
        total_reports: response.data.data.totalReports
      };
    } catch (error) {
      console.error('AbuseIPDB check failed:', error.message);
      return null;
    }
  }

  async checkShodan(ip) {
    if (!this.apiKeys.shodan) {
      console.log('⚠️  Shodan API key not configured');
      return null;
    }

    try {
      console.log(`🌐 Checking ${ip} with Shodan...`);
      
      const response = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
        params: {
          key: this.apiKeys.shodan
        },
        timeout: 15000,
        headers: {
          'User-Agent': 'Scorpion-Security-Platform/1.0'
        }
      });

      const data = response.data;
      
      const result = {
        asn_info: {
          asn: data.asn,
          org: data.org,
          isp: data.isp
        },
        location: {
          country: data.country_name,
          country_code: data.country_code,
          city: data.city,
          region: data.region_code,
          latitude: data.latitude,
          longitude: data.longitude
        },
        ports: data.ports || [],
        open_ports: data.ports?.length || 0,
        services: data.data?.map(service => ({
          port: service.port,
          protocol: service.transport,
          product: service.product,
          version: service.version,
          service: service._shodan?.module,
          banner: service.data?.substring(0, 200), // Truncate long banners
          timestamp: service.timestamp,
          ssl: service.ssl ? {
            version: service.ssl.version,
            cipher: service.ssl.cipher?.name,
            cert_serial: service.ssl.cert?.serial
          } : null
        })) || [],
        hostnames: data.hostnames || [],
        domains: data.domains || [],
        tags: data.tags || [],
        vulnerabilities: data.vulns ? Object.keys(data.vulns) : [],
        last_update: data.last_update,
        total_services: data.data?.length || 0
      };

      console.log(`✅ Shodan: Found ${result.open_ports} open ports, ${result.total_services} services`);
      if (result.vulnerabilities.length > 0) {
        console.log(`⚠️  Shodan: ${result.vulnerabilities.length} known vulnerabilities detected`);
      }
      
      return result;
    } catch (error) {
      if (error.response?.status === 404) {
        console.log(`ℹ️  ${ip} not found in Shodan database`);
        return { asn_info: null, services: [], ports: [], message: 'Host not found' };
      } else if (error.response?.status === 402) {
        console.log('⚠️  Shodan API quota exceeded. Using cached data if available.');
        return null;
      } else if (error.response?.status === 401) {
        console.log('❌ Shodan API authentication failed. Please check your API key.');
        return null;
      } else {
        console.error('❌ Shodan check failed:', error.message);
        return null;
      }
    }
  }

  async getIPGeolocation(ip) {
    try {
      const response = await axios.get(`https://ipinfo.io/${ip}/json`, {
        timeout: 10000
      });

      return {
        country: response.data.country,
        city: response.data.city,
        region: response.data.region,
        org: response.data.org,
        timezone: response.data.timezone
      };
    } catch (error) {
      return null;
    }
  }

  detectHashType(hash) {
    switch (hash.length) {
      case 32: return 'MD5';
      case 40: return 'SHA1';
      case 64: return 'SHA256';
      case 128: return 'SHA512';
      default: return 'Unknown';
    }
  }

  analyzeSuspiciousPatterns(domain) {
    const patterns = [];
    
    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'];
    if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
      patterns.push('suspicious_tld');
    }
    
    // Check for homograph attacks
    if (/[а-яё]/i.test(domain)) { // Cyrillic characters
      patterns.push('homograph_attack');
    }
    
    // Check for excessive subdomains
    if ((domain.match(/\./g) || []).length > 3) {
      patterns.push('excessive_subdomains');
    }
    
    // Check for suspicious keywords
    const suspiciousKeywords = ['bank', 'paypal', 'amazon', 'microsoft', 'google', 'apple', 'secure', 'login'];
    if (suspiciousKeywords.some(keyword => domain.toLowerCase().includes(keyword))) {
      patterns.push('brand_impersonation');
    }
    
    return patterns;
  }

  async analyzeDomainAge(domain) {
    try {
      // This would normally use a WHOIS service
      // For demo, we'll simulate domain age analysis
      const ages = [1, 5, 30, 90, 365, 1095]; // Days
      const randomAge = ages[Math.floor(Math.random() * ages.length)];
      
      return {
        domain,
        days_old: randomAge,
        registration_date: new Date(Date.now() - (randomAge * 24 * 60 * 60 * 1000)).toISOString()
      };
    } catch (error) {
      return null;
    }
  }

  async getIOCs() {
    console.log('Gathering current Indicators of Compromise...');
    
    const iocs = {
      timestamp: new Date().toISOString(),
      total_indicators: 0,
      ip_addresses: [],
      domains: [],
      file_hashes: [],
      urls: [],
      apt_groups: this.threatFeeds.apt_groups || []
    };

    // Aggregate IOCs from various sources
    iocs.ip_addresses = this.threatFeeds.malicious_ips || [];
    iocs.domains = this.threatFeeds.malicious_domains || [];
    iocs.file_hashes = this.threatFeeds.malicious_hashes || [];
    
    // Add some dynamic IOCs (would come from real threat feeds)
    const recentIOCs = await this.fetchRecentIOCs();
    iocs.ip_addresses.push(...recentIOCs.ips);
    iocs.domains.push(...recentIOCs.domains);
    iocs.file_hashes.push(...recentIOCs.hashes);
    
    iocs.total_indicators = iocs.ip_addresses.length + iocs.domains.length + iocs.file_hashes.length;
    
    return iocs;
  }

  async fetchRecentIOCs() {
    // This would fetch from real threat intelligence feeds
    // For demo, return some sample data
    return {
      ips: ['192.168.1.100', '10.0.0.5'],
      domains: ['recent-threat.com', 'new-phishing.net'],
      hashes: ['e3b0c44298fc1c149afbf4c8996fb924', '27d3b37f3b6e9f9d2c8a5b1e4f7c9d8e']
    };
  }

  async updateThreatFeeds() {
    console.log('Updating threat intelligence feeds...');
    
    try {
      // This would normally fetch from multiple threat intelligence sources
      const updates = await this.fetchThreatFeedUpdates();
      
      // Update local feeds
      this.threatFeeds.malicious_ips.push(...updates.new_ips);
      this.threatFeeds.malicious_domains.push(...updates.new_domains);
      this.threatFeeds.malicious_hashes.push(...updates.new_hashes);
      this.threatFeeds.last_updated = new Date().toISOString();
      
      // Remove duplicates
      this.threatFeeds.malicious_ips = [...new Set(this.threatFeeds.malicious_ips)];
      this.threatFeeds.malicious_domains = [...new Set(this.threatFeeds.malicious_domains)];
      this.threatFeeds.malicious_hashes = [...new Set(this.threatFeeds.malicious_hashes)];
      
      await this.saveThreatFeeds();
      
      console.log(`Updated feeds with ${updates.new_ips.length} IPs, ${updates.new_domains.length} domains, ${updates.new_hashes.length} hashes`);
      
      return {
        success: true,
        updated: new Date().toISOString(),
        new_indicators: updates.new_ips.length + updates.new_domains.length + updates.new_hashes.length
      };
    } catch (error) {
      console.error('Failed to update threat feeds:', error.message);
      throw error;
    }
  }

  async fetchThreatFeedUpdates() {
    // Simulate fetching updates from threat intelligence feeds
    return {
      new_ips: ['203.0.113.1', '198.51.100.2'],
      new_domains: ['malicious-new.com', 'phishing-update.org'],
      new_hashes: ['a1b2c3d4e5f6789012345678901234567890abcd', 'fedcba0987654321098765432109876543210fedcb']
    };
  }

  async getThreatStats() {
    try {
      const stats = {
        maliciousIPs: this.threatFeeds.malicious_ips || [],
        maliciousDomains: this.threatFeeds.malicious_domains || [],
        maliciousHashes: this.threatFeeds.malicious_hashes || [],
        aptGroups: this.threatFeeds.apt_groups || [],
        totalThreats: 0,
        lastUpdated: this.threatFeeds.last_updated || new Date().toISOString()
      };

      stats.totalThreats = stats.maliciousIPs.length + 
                          stats.maliciousDomains.length + 
                          stats.maliciousHashes.length;

      return stats;
    } catch (error) {
      console.error('Error getting threat stats:', error);
      return {
        maliciousIPs: [],
        maliciousDomains: [],
        maliciousHashes: [],
        aptGroups: [],
        totalThreats: 0,
        lastUpdated: new Date().toISOString()
      };
    }
  }

  async getIOCs() {
    try {
      const iocs = {
        indicators: [],
        categories: {
          malicious_ips: this.threatFeeds.malicious_ips || [],
          malicious_domains: this.threatFeeds.malicious_domains || [],
          malicious_hashes: this.threatFeeds.malicious_hashes || [],
          apt_groups: this.threatFeeds.apt_groups || []
        },
        summary: {
          totalIOCs: 0,
          newToday: 0,
          highConfidence: 0
        },
        lastUpdated: this.threatFeeds.last_updated || new Date().toISOString()
      };

      // Process IPs into IOC format
      iocs.categories.malicious_ips.forEach(ip => {
        iocs.indicators.push({
          type: 'ip',
          value: ip,
          confidence: 'high',
          description: 'Malicious IP address from threat feed',
          firstSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
          tags: ['malware', 'c2']
        });
      });

      // Process domains into IOC format
      iocs.categories.malicious_domains.forEach(domain => {
        iocs.indicators.push({
          type: 'domain',
          value: domain,
          confidence: 'high',
          description: 'Malicious domain from threat feed',
          firstSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
          tags: ['phishing', 'malware']
        });
      });

      // Process hashes into IOC format
      iocs.categories.malicious_hashes.forEach(hash => {
        iocs.indicators.push({
          type: 'hash',
          value: hash,
          confidence: 'high',
          description: 'Malicious file hash from threat feed',
          firstSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
          tags: ['malware']
        });
      });

      // Calculate summary stats
      iocs.summary.totalIOCs = iocs.indicators.length;
      iocs.summary.highConfidence = iocs.indicators.filter(i => i.confidence === 'high').length;
      iocs.summary.newToday = iocs.indicators.filter(i => {
        const today = new Date();
        const indicatorDate = new Date(i.firstSeen);
        return indicatorDate.toDateString() === today.toDateString();
      }).length;

      return iocs;
    } catch (error) {
      console.error('Error getting IOCs:', error);
      return {
        indicators: [],
        categories: { malicious_ips: [], malicious_domains: [], malicious_hashes: [], apt_groups: [] },
        summary: { totalIOCs: 0, newToday: 0, highConfidence: 0 },
        lastUpdated: new Date().toISOString()
      };
    }
  }

  async saveThreatFeeds() {
    try {
      const dataDir = path.join(__dirname, '..', 'data');
      await fs.mkdir(dataDir, { recursive: true });
      
      const feedsPath = path.join(dataDir, 'threat-feeds.json');
      await fs.writeFile(feedsPath, JSON.stringify(this.threatFeeds, null, 2));
    } catch (error) {
      console.error('Failed to save threat feeds:', error.message);
    }
  }
}
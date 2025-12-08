import dns from 'dns';
import { promisify } from 'util';
import axios from 'axios';
import chalk from 'chalk';

const resolveCname = promisify(dns.resolveCname);
const resolve4 = promisify(dns.resolve4);
const resolveMx = promisify(dns.resolveMx);

/**
 * Subdomain Takeover Detection Module
 * Tests for vulnerable DNS configurations pointing to unclaimed cloud resources
 */
export class SubdomainTakeover {
  constructor() {
    // Real fingerprints for detecting unclaimed services
    this.serviceFingerprints = {
      'amazonaws': {
        patterns: ['.s3.amazonaws.com', '.s3-website', '.elasticbeanstalk.com', '.cloudfront.net'],
        errorStrings: ['NoSuchBucket', 'Not Found', '404 Not Found'],
        vulnerable: true
      },
      'azure': {
        patterns: ['.azurewebsites.net', '.cloudapp.azure.com', '.trafficmanager.net', '.blob.core.windows.net'],
        errorStrings: ['404 Web Site not found', 'Error 404', 'not found'],
        vulnerable: true
      },
      'github': {
        patterns: ['.github.io'],
        errorStrings: ['There isn\'t a GitHub Pages site here', '404 Not Found'],
        vulnerable: true
      },
      'heroku': {
        patterns: ['.herokuapp.com'],
        errorStrings: ['no such app', 'No such app', 'Application Error'],
        vulnerable: true
      },
      'shopify': {
        patterns: ['.myshopify.com'],
        errorStrings: ['Sorry, this shop is currently unavailable', 'Only one step left'],
        vulnerable: true
      },
      'wordpress': {
        patterns: ['.wordpress.com'],
        errorStrings: ['Do you want to register'],
        vulnerable: true
      },
      'tumblr': {
        patterns: ['.tumblr.com'],
        errorStrings: ['There\'s nothing here', 'Whatever you were looking for doesn\'t currently exist'],
        vulnerable: true
      },
      'ghost': {
        patterns: ['.ghost.io'],
        errorStrings: ['The thing you were looking for is no longer here'],
        vulnerable: true
      },
      'bitbucket': {
        patterns: ['.bitbucket.io'],
        errorStrings: ['Repository not found'],
        vulnerable: true
      },
      'fastly': {
        patterns: ['.fastly.net'],
        errorStrings: ['Fastly error: unknown domain'],
        vulnerable: true
      },
      'pantheon': {
        patterns: ['.pantheonsite.io'],
        errorStrings: ['404 error unknown site'],
        vulnerable: true
      },
      'zendesk': {
        patterns: ['.zendesk.com'],
        errorStrings: ['Help Center Closed'],
        vulnerable: true
      },
      'surge': {
        patterns: ['.surge.sh'],
        errorStrings: ['project not found'],
        vulnerable: true
      },
      'cargo': {
        patterns: ['.cargocollective.com'],
        errorStrings: ['404 Not Found'],
        vulnerable: true
      },
      'statuspage': {
        patterns: ['.statuspage.io'],
        errorStrings: ['You are being', 'redirected'],
        vulnerable: true
      }
    };
  }

  /**
   * Check if domain has vulnerable CNAME configuration
   */
  async checkDomain(domain) {
    try {
      console.log(chalk.cyan(`[*] Checking domain: ${domain}`));
      
      // Resolve CNAME records
      const cnames = await this.resolveCNAME(domain);
      
      if (!cnames || cnames.length === 0) {
        return {
          domain,
          vulnerable: false,
          reason: 'No CNAME records found'
        };
      }

      // Check each CNAME
      const results = [];
      for (const cname of cnames) {
        const serviceCheck = await this.checkService(domain, cname);
        results.push(serviceCheck);
      }

      return {
        domain,
        cnames,
        checks: results,
        vulnerable: results.some(r => r.vulnerable)
      };

    } catch (error) {
      return {
        domain,
        vulnerable: false,
        error: error.message
      };
    }
  }

  /**
   * Resolve CNAME records for a domain
   */
  async resolveCNAME(domain) {
    try {
      const cnames = await resolveCname(domain);
      return cnames;
    } catch (error) {
      if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
        // Try resolving A record to see if domain exists
        try {
          await resolve4(domain);
          return null; // Domain exists but no CNAME
        } catch {
          return null; // Domain doesn't exist
        }
      }
      throw error;
    }
  }

  /**
   * Check if CNAME points to vulnerable service
   */
  async checkService(domain, cname) {
    console.log(chalk.gray(`  [>] Checking CNAME: ${cname}`));

    // Identify service from CNAME pattern
    const service = this.identifyService(cname);
    
    if (!service) {
      return {
        cname,
        service: 'unknown',
        vulnerable: false,
        reason: 'Unknown or non-vulnerable service'
      };
    }

    // Check if service endpoint is claimed
    const isVulnerable = await this.checkServiceAvailability(domain, cname, service);
    
    return {
      cname,
      service: service.name,
      vulnerable: isVulnerable.vulnerable,
      reason: isVulnerable.reason,
      evidence: isVulnerable.evidence
    };
  }

  /**
   * Identify service provider from CNAME
   */
  identifyService(cname) {
    for (const [name, config] of Object.entries(this.serviceFingerprints)) {
      for (const pattern of config.patterns) {
        if (cname.includes(pattern)) {
          return { name, ...config };
        }
      }
    }
    return null;
  }

  /**
   * Check if service endpoint is available (unclaimed)
   */
  async checkServiceAvailability(domain, cname, service) {
    try {
      // Try both HTTP and HTTPS
      const urls = [
        `https://${domain}`,
        `http://${domain}`
      ];

      for (const url of urls) {
        try {
          const response = await axios.get(url, {
            timeout: 10000,
            maxRedirects: 5,
            validateStatus: () => true, // Accept any status code
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          });

          // Check response body for service error messages
          const body = response.data.toString();
          
          for (const errorString of service.errorStrings) {
            if (body.includes(errorString)) {
              return {
                vulnerable: true,
                reason: `Service endpoint unclaimed - ${service.name}`,
                evidence: errorString
              };
            }
          }

          // Check status code
          if (response.status === 404 && service.name === 'amazonaws') {
            if (cname.includes('.s3.') || cname.includes('s3-website')) {
              return {
                vulnerable: true,
                reason: 'Unclaimed S3 bucket',
                evidence: '404 Not Found on S3 endpoint'
              };
            }
          }

        } catch (error) {
          // Connection errors might indicate unclaimed resource
          if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
            return {
              vulnerable: true,
              reason: `${service.name} endpoint not resolving`,
              evidence: error.code
            };
          }
        }
      }

      return {
        vulnerable: false,
        reason: 'Service endpoint appears claimed'
      };

    } catch (error) {
      return {
        vulnerable: false,
        reason: 'Unable to verify',
        error: error.message
      };
    }
  }

  /**
   * Scan multiple subdomains for takeover vulnerabilities
   */
  async scanSubdomains(domain, subdomains = null) {
    console.log(chalk.cyan.bold(`\n🔍 Subdomain Takeover Scanner\n`));
    console.log(chalk.gray(`Target: ${domain}\n`));

    // If no subdomains provided, use common patterns
    if (!subdomains) {
      subdomains = await this.enumerateCommonSubdomains(domain);
    }

    const results = [];
    const vulnerableSubdomains = [];

    for (const subdomain of subdomains) {
      const result = await this.checkDomain(subdomain);
      results.push(result);

      if (result.vulnerable) {
        vulnerableSubdomains.push(result);
        console.log(chalk.red.bold(`\n  [!] VULNERABILITY FOUND: Subdomain Takeover`));
        console.log(chalk.white(`      Subdomain: ${chalk.cyan(subdomain)}`));
        if (result.checks) {
          result.checks.forEach(check => {
            if (check.vulnerable) {
              console.log(chalk.yellow(`      Service: ${check.service}`));
              console.log(chalk.yellow(`      CNAME Points To: ${check.cname}`));
              console.log(chalk.yellow(`      Issue: ${check.reason}`));
              console.log(chalk.red(`\n      📍 LOCATION: DNS CNAME record for ${subdomain}`));
              console.log(chalk.cyan(`\n      💡 REMEDIATION:`));
              console.log(chalk.white(`         1. Claim the resource: ${check.cname}`));
              console.log(chalk.white(`         2. OR remove the CNAME DNS record for ${subdomain}`));
              console.log(chalk.white(`         3. Monitor for unauthorized content on ${subdomain}`));
            }
          });
        }
      }
    }

    // Summary
    console.log(chalk.cyan.bold(`\n📊 Scan Summary:`));
    console.log(chalk.white(`  Total subdomains checked: ${results.length}`));
    console.log(chalk.green(`  Safe: ${results.length - vulnerableSubdomains.length}`));
    console.log(chalk.red(`  Vulnerable: ${vulnerableSubdomains.length}`));

    if (vulnerableSubdomains.length > 0) {
      console.log(chalk.red.bold(`\n⚠️  WARNING: ${vulnerableSubdomains.length} subdomain(s) vulnerable to takeover!`));
    } else {
      console.log(chalk.green.bold(`\n✅ No subdomain takeover vulnerabilities detected`));
    }

    return {
      domain,
      totalChecked: results.length,
      vulnerable: vulnerableSubdomains.length,
      results: vulnerableSubdomains
    };
  }

  /**
   * Enumerate common subdomains and filter to only existing ones
   */
  async enumerateCommonSubdomains(domain) {
    const commonPrefixes = [
      'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
      'smtp', 'secure', 'vpn', 'admin', 'portal', 'api', 'dev', 'staging',
      'test', 'demo', 'app', 'cdn', 'static', 'assets', 'media', 'images',
      'ftp', 'cpanel', 'webdisk', 'docs', 'store', 'shop', 'beta', 'old'
    ];

    console.log(chalk.cyan(`[*] Discovering active subdomains for ${domain}...`));
    const activeSubdomains = [];

    // Check each subdomain to see if it actually exists
    for (const prefix of commonPrefixes) {
      const subdomain = `${prefix}.${domain}`;
      try {
        // Try DNS resolution first (faster)
        await resolve4(subdomain);
        activeSubdomains.push(subdomain);
        console.log(chalk.green(`  [✓] Found active subdomain: ${subdomain}`));
      } catch (error) {
        // If A record fails, try CNAME
        try {
          await resolveCname(subdomain);
          activeSubdomains.push(subdomain);
          console.log(chalk.green(`  [✓] Found subdomain with CNAME: ${subdomain}`));
        } catch {
          // Subdomain doesn't exist, skip it
          console.log(chalk.gray(`  [-] Not found: ${subdomain}`));
        }
      }
    }

    if (activeSubdomains.length === 0) {
      console.log(chalk.yellow(`\n  [!] No active subdomains found. Testing main domain only.`));
      return [domain];
    }

    console.log(chalk.cyan(`\n  [*] Found ${activeSubdomains.length} active subdomain(s)\n`));
    return activeSubdomains;
  }

  /**
   * Check specific service types
   */
  async checkAWSS3(domain) {
    console.log(chalk.cyan(`[*] Checking AWS S3 configuration for: ${domain}`));
    
    try {
      const cnames = await this.resolveCNAME(domain);
      
      if (!cnames) {
        return { vulnerable: false, reason: 'No CNAME records' };
      }

      for (const cname of cnames) {
        if (cname.includes('.s3.amazonaws.com') || cname.includes('s3-website')) {
          // Extract bucket name
          const bucketName = cname.split('.s3')[0];
          
          // Try to access the bucket
          const bucketUrl = `https://${bucketName}.s3.amazonaws.com`;
          
          try {
            const response = await axios.get(bucketUrl, {
              timeout: 5000,
              validateStatus: () => true
            });

            if (response.status === 404 || response.data.includes('NoSuchBucket')) {
              return {
                vulnerable: true,
                reason: 'Unclaimed S3 bucket',
                bucketName,
                cname
              };
            }
          } catch (error) {
            if (error.code === 'ENOTFOUND') {
              return {
                vulnerable: true,
                reason: 'S3 bucket does not exist',
                bucketName,
                cname
              };
            }
          }
        }
      }

      return { vulnerable: false, reason: 'S3 bucket appears claimed' };
    } catch (error) {
      return { vulnerable: false, error: error.message };
    }
  }

  /**
   * Check Azure services
   */
  async checkAzure(domain) {
    console.log(chalk.cyan(`[*] Checking Azure configuration for: ${domain}`));
    
    try {
      const cnames = await this.resolveCNAME(domain);
      
      if (!cnames) {
        return { vulnerable: false, reason: 'No CNAME records' };
      }

      for (const cname of cnames) {
        if (cname.includes('.azurewebsites.net') || 
            cname.includes('.cloudapp.azure.com') ||
            cname.includes('.trafficmanager.net')) {
          
          const url = `https://${domain}`;
          
          try {
            const response = await axios.get(url, {
              timeout: 5000,
              validateStatus: () => true
            });

            const body = response.data.toString();
            
            if (body.includes('404 Web Site not found') || 
                body.includes('Error 404')) {
              return {
                vulnerable: true,
                reason: 'Unclaimed Azure resource',
                cname
              };
            }
          } catch (error) {
            if (error.code === 'ENOTFOUND') {
              return {
                vulnerable: true,
                reason: 'Azure resource does not exist',
                cname
              };
            }
          }
        }
      }

      return { vulnerable: false, reason: 'Azure resource appears claimed' };
    } catch (error) {
      return { vulnerable: false, error: error.message };
    }
  }
}

export default SubdomainTakeover;

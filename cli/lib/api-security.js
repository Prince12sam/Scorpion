import axios from 'axios';
import chalk from 'chalk';
import { parse } from 'url';

/**
 * API Security Testing Module
 * Production-ready testing for REST APIs, GraphQL, OpenAPI/Swagger endpoints
 */
export class APISecurityTester {
  constructor() {
    this.commonApiPaths = [
      '/api', '/api/v1', '/api/v2', '/api/v3',
      '/rest', '/graphql', '/swagger', '/swagger.json',
      '/swagger-ui.html', '/api-docs', '/openapi.json',
      '/v1', '/v2', '/v3', '/.well-known'
    ];
    
    this.sensitivePaths = [
      '/admin', '/debug', '/test', '/dev', '/internal',
      '/private', '/config', '/backup', '/old', '/tmp'
    ];
  }

  /**
   * Comprehensive API security test
   */
  async testAPI(target, options = {}) {
    console.log(chalk.cyan.bold(`\n🔍 API Security Testing\n`));
    console.log(chalk.gray(`Target: ${target}\n`));

    const results = {
      target,
      timestamp: new Date().toISOString(),
      tests: {}
    };

    // 1. API Discovery
    if (options.discover !== false) {
      console.log(chalk.cyan('[*] API Endpoint Discovery...'));
      results.tests.discovery = await this.discoverAPI(target);
    }

    // 2. OpenAPI/Swagger Testing
    if (options.swagger !== false) {
      console.log(chalk.cyan('[*] Checking for OpenAPI/Swagger documentation...'));
      results.tests.swagger = await this.testSwagger(target);
    }

    // 3. GraphQL Testing
    if (options.graphql !== false) {
      console.log(chalk.cyan('[*] Testing GraphQL endpoints...'));
      results.tests.graphql = await this.testGraphQL(target);
    }

    // 4. Authentication Testing
    if (options.auth !== false) {
      console.log(chalk.cyan('[*] Testing authentication mechanisms...'));
      results.tests.authentication = await this.testAuthentication(target);
    }

    // 5. Authorization Testing
    if (options.authz !== false) {
      console.log(chalk.cyan('[*] Testing authorization/IDOR vulnerabilities...'));
      results.tests.authorization = await this.testAuthorization(target);
    }

    // 6. Rate Limiting
    if (options.rateLimit !== false) {
      console.log(chalk.cyan('[*] Testing rate limiting...'));
      results.tests.rateLimiting = await this.testRateLimiting(target);
    }

    // 7. Input Validation
    if (options.validation !== false) {
      console.log(chalk.cyan('[*] Testing input validation...'));
      results.tests.inputValidation = await this.testInputValidation(target);
    }

    // Print summary
    this.printSummary(results);
    
    return results;
  }

  /**
   * Discover API endpoints
   */
  async discoverAPI(baseUrl) {
    const discovered = {
      endpoints: [],
      swagger: null,
      graphql: null
    };

    for (const path of this.commonApiPaths) {
      try {
        const url = new URL(path, baseUrl).toString();
        const response = await axios.get(url, {
          timeout: 5000,
          validateStatus: () => true,
          headers: { 'User-Agent': 'Mozilla/5.0 API-Scanner' }
        });

        if (response.status === 200) {
          discovered.endpoints.push({
            path,
            status: response.status,
            contentType: response.headers['content-type']
          });
          
          console.log(chalk.green(`  [✓] Found: ${path} (${response.status})`));

          // Check if it's Swagger/OpenAPI
          if (path.includes('swagger') || path.includes('openapi')) {
            discovered.swagger = url;
          }
          
          // Check if it's GraphQL
          if (path.includes('graphql')) {
            discovered.graphql = url;
          }
        }
      } catch (error) {
        // Ignore connection errors
      }
    }

    return discovered;
  }

  /**
   * Test OpenAPI/Swagger endpoints
   */
  async testSwagger(baseUrl) {
    const swaggerPaths = [
      '/swagger.json',
      '/swagger.yaml',
      '/swagger-ui.html',
      '/api-docs',
      '/api-docs.json',
      '/openapi.json',
      '/openapi.yaml',
      '/v2/api-docs',
      '/v3/api-docs'
    ];

    const results = {
      found: false,
      exposed: false,
      endpoints: [],
      securitySchemes: [],
      vulnerabilities: []
    };

    for (const path of swaggerPaths) {
      try {
        const url = new URL(path, baseUrl).toString();
        const response = await axios.get(url, {
          timeout: 5000,
          validateStatus: () => true
        });

        if (response.status === 200) {
          results.found = true;
          results.exposed = true;
          
          console.log(chalk.yellow(`  [!] Exposed Swagger/OpenAPI: ${path}`));
          
          try {
            const spec = typeof response.data === 'string' 
              ? JSON.parse(response.data) 
              : response.data;

            // Parse OpenAPI spec
            if (spec.paths) {
              results.endpoints = Object.keys(spec.paths);
              console.log(chalk.gray(`      Discovered ${results.endpoints.length} endpoints`));
            }

            // Check security schemes
            if (spec.securityDefinitions || spec.components?.securitySchemes) {
              const schemes = spec.securityDefinitions || spec.components.securitySchemes;
              results.securitySchemes = Object.keys(schemes);
              console.log(chalk.gray(`      Security schemes: ${results.securitySchemes.join(', ')}`));
            }

            // Check for sensitive endpoints
            results.endpoints.forEach(endpoint => {
              if (this.isSensitiveEndpoint(endpoint)) {
                results.vulnerabilities.push({
                  type: 'sensitive_endpoint_exposed',
                  endpoint,
                  severity: 'medium',
                  location: url,
                  remediation: 'Restrict access to sensitive endpoints using authentication and authorization controls'
                });
              }
            });

          } catch (parseError) {
            // Not valid JSON/YAML
          }

          break; // Found one, stop searching
        }
      } catch (error) {
        // Continue checking other paths
      }
    }

    if (results.exposed) {
      console.log(chalk.red.bold(`\n  [!] MEDIUM RISK: API Documentation Publicly Exposed`));
      console.log(chalk.white(`      📍 Location: ${results.path}`));
      console.log(chalk.yellow(`      ⚠️  IMPACT: Attack surface disclosure, endpoint enumeration`));
      console.log(chalk.gray(`      📄 Format: ${results.format}`));
      console.log(chalk.cyan(`\n      💡 REMEDIATION:`));
      console.log(chalk.white(`         1. Remove Swagger/OpenAPI documentation from production`));
      console.log(chalk.white(`         2. Require authentication to access API docs`));
      console.log(chalk.white(`         3. Host documentation on separate internal domain`));
      console.log(chalk.white(`         4. Use environment variables to disable in production`));
    }

    return results;
  }

  /**
   * Test GraphQL endpoints
   */
  async testGraphQL(baseUrl) {
    const graphqlPaths = ['/graphql', '/api/graphql', '/v1/graphql', '/query'];
    
    const results = {
      found: false,
      introspectionEnabled: false,
      schema: null,
      vulnerabilities: []
    };

    for (const path of graphqlPaths) {
      try {
        const url = new URL(path, baseUrl).toString();
        
        // Test introspection query
        const introspectionQuery = {
          query: `{
            __schema {
              types {
                name
                fields {
                  name
                  type {
                    name
                  }
                }
              }
            }
          }`
        };

        const response = await axios.post(url, introspectionQuery, {
          timeout: 5000,
          validateStatus: () => true,
          headers: { 'Content-Type': 'application/json' }
        });

        if (response.status === 200 && response.data.data) {
          results.found = true;
          results.introspectionEnabled = true;
          
          console.log(chalk.red(`  [!] GraphQL Introspection Enabled: ${path}`));
          
          if (response.data.data.__schema) {
            results.schema = response.data.data.__schema;
            const typeCount = results.schema.types.length;
            console.log(chalk.gray(`      Discovered ${typeCount} types in schema`));
            
            results.vulnerabilities.push({
              type: 'graphql_introspection_enabled',
              path,
              severity: 'high',
              location: url,
              description: 'Introspection exposes entire GraphQL schema',
              remediation: 'Disable introspection in production: graphqlHTTP({ graphiql: false, introspection: false })'
            });
            
            console.log(chalk.red.bold(`\n  [!] HIGH RISK: GraphQL Introspection Enabled`));
            console.log(chalk.white(`      📍 Location: ${url}`));
            console.log(chalk.yellow(`      ⚠️  IMPACT: Full schema disclosure, attack surface mapping`));
            console.log(chalk.gray(`      🔍 Discovered: ${typeCount} types, queries, mutations`));
            console.log(chalk.cyan(`\n      💡 REMEDIATION:`));
            console.log(chalk.white(`         1. Disable introspection in production environment`));
            console.log(chalk.white(`         2. For Apollo: introspection: false in config`));
            console.log(chalk.white(`         3. For Express-GraphQL: introspection: false`));
            console.log(chalk.white(`         4. Allow introspection only for authenticated admins`));
          }
        }

        // Test for common GraphQL vulnerabilities
        await this.testGraphQLInjection(url, results);
        await this.testGraphQLBatching(url, results);

      } catch (error) {
        // Continue with next path
      }
    }

    return results;
  }

  /**
   * Test GraphQL injection vulnerabilities
   */
  async testGraphQLInjection(url, results) {
    const injectionPayloads = [
      { query: '{ __typename @skip(if: true) }' },
      { query: '{ user(id: "1\'") { name } }' },
      { query: '{ user(id: 1 OR 1=1) { name } }' }
    ];

    for (const payload of injectionPayloads) {
      try {
        const response = await axios.post(url, payload, {
          timeout: 5000,
          validateStatus: () => true,
          headers: { 'Content-Type': 'application/json' }
        });

        if (response.data && response.data.errors) {
          const errorMsg = JSON.stringify(response.data.errors);
          if (errorMsg.includes('SQL') || errorMsg.includes('syntax')) {
            results.vulnerabilities.push({
              type: 'graphql_injection',
              severity: 'critical',
              description: 'Possible SQL injection through GraphQL'
            });
            console.log(chalk.red(`  [!] Possible GraphQL injection vulnerability`));
          }
        }
      } catch (error) {
        // Continue testing
      }
    }
  }

  /**
   * Test GraphQL query batching abuse
   */
  async testGraphQLBatching(url, results) {
    const batchQuery = Array(100).fill({ query: '{ __typename }' });
    
    try {
      const start = Date.now();
      const response = await axios.post(url, batchQuery, {
        timeout: 10000,
        validateStatus: () => true,
        headers: { 'Content-Type': 'application/json' }
      });
      const duration = Date.now() - start;

      if (response.status === 200 && Array.isArray(response.data)) {
        results.vulnerabilities.push({
          type: 'graphql_batching_enabled',
          severity: 'medium',
          description: 'Query batching enabled - potential DoS vector',
          batchSize: 100,
          responseTime: duration
        });
        console.log(chalk.yellow(`  [!] GraphQL batching enabled (${duration}ms for 100 queries)`));
      }
    } catch (error) {
      // Batching not supported or blocked
    }
  }

  /**
   * Test authentication mechanisms
   */
  async testAuthentication(baseUrl) {
    const results = {
      methods: [],
      vulnerabilities: []
    };

    try {
      const url = new URL('/api', baseUrl).toString();
      const response = await axios.get(url, {
        timeout: 5000,
        validateStatus: () => true
      });

      // Check authentication headers
      const authHeader = response.headers['www-authenticate'];
      if (authHeader) {
        results.methods.push(authHeader);
        console.log(chalk.gray(`  [i] Authentication method: ${authHeader}`));
      }

      // Test for JWT token exposure
      const cookies = response.headers['set-cookie'] || [];
      for (const cookie of cookies) {
        if (cookie.includes('token') || cookie.includes('jwt')) {
          // Check if HttpOnly flag is set
          if (!cookie.includes('HttpOnly')) {
            results.vulnerabilities.push({
              type: 'jwt_cookie_no_httponly',
              severity: 'medium',
              location: `${baseUrl} Set-Cookie header`,
              description: 'JWT cookie missing HttpOnly flag',
              remediation: 'Set HttpOnly flag on JWT cookies: res.cookie("token", jwt, { httpOnly: true, secure: true })'
            });
            console.log(chalk.yellow.bold(`\n  [!] MEDIUM RISK: JWT Cookie Missing HttpOnly`));
            console.log(chalk.white(`      📍 Location: Set-Cookie header`));
            console.log(chalk.yellow(`      ⚠️  IMPACT: XSS can steal JWT tokens`));
            console.log(chalk.cyan(`      💡 FIX: res.cookie('token', jwt, { httpOnly: true })`));
          }
          
          // Check if Secure flag is set
          if (!cookie.includes('Secure')) {
            results.vulnerabilities.push({
              type: 'jwt_cookie_no_secure',
              severity: 'medium',
              location: `${baseUrl} Set-Cookie header`,
              description: 'JWT cookie missing Secure flag',
              remediation: 'Set Secure flag on JWT cookies to require HTTPS: res.cookie("token", jwt, { secure: true })'
            });
            console.log(chalk.yellow.bold(`\n  [!] MEDIUM RISK: JWT Cookie Missing Secure Flag`));
            console.log(chalk.white(`      📍 Location: Set-Cookie header`));
            console.log(chalk.yellow(`      ⚠️  IMPACT: Token can be intercepted over HTTP`));
            console.log(chalk.cyan(`      💡 FIX: res.cookie('token', jwt, { secure: true })`));
          }
        }
      }

      // Test for basic auth
      await this.testBasicAuth(baseUrl, results);
      
      // Test for weak JWT secrets
      await this.testWeakJWT(baseUrl, results);

    } catch (error) {
      results.error = error.message;
    }

    return results;
  }

  /**
   * Test for weak basic authentication
   */
  async testBasicAuth(baseUrl, results) {
    const weakCreds = [
      ['admin', 'admin'],
      ['admin', 'password'],
      ['root', 'root'],
      ['test', 'test']
    ];

    for (const [user, pass] of weakCreds) {
      try {
        const url = new URL('/api', baseUrl).toString();
        const auth = Buffer.from(`${user}:${pass}`).toString('base64');
        
        const response = await axios.get(url, {
          timeout: 3000,
          validateStatus: () => true,
          headers: { 'Authorization': `Basic ${auth}` }
        });

        if (response.status === 200) {
          results.vulnerabilities.push({
            type: 'weak_credentials',
            severity: 'critical',
            credentials: `${user}:${pass}`,
            location: `${baseUrl}/login`,
            remediation: 'Implement strong password policy, enforce MFA, disable default credentials'
          });
          console.log(chalk.red.bold(`\n  [!] CRITICAL VULNERABILITY: Weak Credentials`));
          console.log(chalk.white(`      Credentials: ${chalk.yellow(`${user}:${pass}`)}`));
          console.log(chalk.red(`      📍 LOCATION: ${baseUrl}/login`));
          console.log(chalk.cyan(`\n      💡 REMEDIATION:`));
          console.log(chalk.white(`         1. Disable default credentials immediately`));
          console.log(chalk.white(`         2. Enforce strong password policy (min 12 chars, complexity)`));
          console.log(chalk.white(`         3. Implement multi-factor authentication (MFA)`));
          console.log(chalk.white(`         4. Monitor for unauthorized access attempts`));
        }
      } catch (error) {
        // Continue testing
      }
    }
  }

  /**
   * Test for weak JWT implementation
   */
  async testWeakJWT(baseUrl, results) {
    // Common weak JWT secrets
    const weakSecrets = ['secret', 'password', '123456', 'jwt_secret'];
    
    // This would require actual JWT tokens from the API
    // For now, we'll just check for JWT endpoints
    const jwtEndpoints = ['/api/token', '/api/auth', '/api/login'];
    
    for (const endpoint of jwtEndpoints) {
      try {
        const url = new URL(endpoint, baseUrl).toString();
        const response = await axios.post(url, {}, {
          timeout: 3000,
          validateStatus: () => true
        });

        if (response.status === 401 || response.status === 403) {
          results.methods.push('JWT');
        }
      } catch (error) {
        // Continue
      }
    }
  }

  /**
   * Test for authorization/IDOR vulnerabilities
   */
  async testAuthorization(baseUrl) {
    const results = {
      tested: [],
      vulnerabilities: []
    };

    // Test sequential ID enumeration
    const endpoints = [
      '/api/user',
      '/api/users',
      '/api/account',
      '/api/profile'
    ];

    for (const endpoint of endpoints) {
      try {
        // Test with sequential IDs
        for (let id = 1; id <= 5; id++) {
          const url = new URL(`${endpoint}/${id}`, baseUrl).toString();
          const response = await axios.get(url, {
            timeout: 3000,
            validateStatus: () => true
          });

          if (response.status === 200) {
            results.tested.push({ endpoint: `${endpoint}/${id}`, accessible: true });
            
            // Check if different IDs return different data
            if (id === 1) {
              // Store first response for comparison
              results.firstResponse = response.data;
            } else if (results.firstResponse && 
                       JSON.stringify(response.data) !== JSON.stringify(results.firstResponse)) {
              results.vulnerabilities.push({
                type: 'idor_enumeration',
                severity: 'high',
                endpoint,
                description: 'Sequential ID enumeration possible - potential IDOR',
                location: `${endpoint}/:id`,
                remediation: 'Implement proper authorization checks, use UUIDs instead of sequential IDs'
              });
              console.log(chalk.red.bold(`\n  [!] HIGH RISK VULNERABILITY: IDOR (Insecure Direct Object Reference)`));
              console.log(chalk.white(`      Endpoint: ${chalk.cyan(`${endpoint}/:id`)}`));
              console.log(chalk.red(`      📍 LOCATION: API endpoint allows sequential ID enumeration`));
              console.log(chalk.yellow(`      ⚠️  IMPACT: Unauthorized access to other users' data`));
              console.log(chalk.cyan(`\n      💡 REMEDIATION:`));
              console.log(chalk.white(`         1. Implement authorization checks for each ID access`));
              console.log(chalk.white(`         2. Use UUIDs instead of sequential integers`));
              console.log(chalk.white(`         3. Validate user permissions before returning data`));
              console.log(chalk.white(`         4. Add rate limiting to prevent enumeration`));
              break;
            }
          }
        }
      } catch (error) {
        // Continue testing
      }
    }

    return results;
  }

  /**
   * Test rate limiting
   */
  async testRateLimiting(baseUrl) {
    const results = {
      rateLimited: false,
      requestsBeforeLimit: 0,
      vulnerabilities: []
    };

    try {
      const url = new URL('/api', baseUrl).toString();
      let requestCount = 0;
      const maxRequests = 100;

      console.log(chalk.gray(`  [i] Sending ${maxRequests} rapid requests...`));

      for (let i = 0; i < maxRequests; i++) {
        try {
          const response = await axios.get(url, {
            timeout: 2000,
            validateStatus: () => true
          });

          requestCount++;

          if (response.status === 429) {
            results.rateLimited = true;
            results.requestsBeforeLimit = requestCount;
            console.log(chalk.green(`  [✓] Rate limiting active after ${requestCount} requests`));
            break;
          }
        } catch (error) {
          break;
        }
      }

      if (!results.rateLimited) {
        results.vulnerabilities.push({
          type: 'no_rate_limiting',
          severity: 'medium',
          description: `No rate limiting detected (${requestCount} requests succeeded)`,
          requestsSucceeded: requestCount,
          location: `${baseUrl}/api`,
          remediation: 'Implement rate limiting middleware: Express: express-rate-limit, Nginx: limit_req_zone, API Gateway: throttling rules'
        });
        console.log(chalk.yellow.bold(`\n  [!] MEDIUM RISK: No Rate Limiting`));
        console.log(chalk.white(`      📍 Location: ${baseUrl}/api`));
        console.log(chalk.yellow(`      ⚠️  IMPACT: API abuse, DDoS, credential stuffing`));
        console.log(chalk.white(`      🧪 Tested: ${requestCount} consecutive requests succeeded`));
        console.log(chalk.cyan(`\n      💡 REMEDIATION:`));
        console.log(chalk.white(`         1. Implement rate limiting (e.g., 100 requests/hour/IP)`));
        console.log(chalk.white(`         2. Use middleware: express-rate-limit for Node.js`));
        console.log(chalk.white(`         3. Configure API Gateway throttling rules`));
        console.log(chalk.white(`         4. Monitor and alert on unusual traffic patterns`));
      }

    } catch (error) {
      results.error = error.message;
    }

    return results;
  }

  /**
   * Test input validation
   */
  async testInputValidation(baseUrl) {
    const results = {
      tested: [],
      vulnerabilities: []
    };

    const testPayloads = [
      { name: 'XSS', payload: '<script>alert(1)</script>' },
      { name: 'SQL Injection', payload: "' OR '1'='1" },
      { name: 'Command Injection', payload: '$(whoami)' },
      { name: 'Path Traversal', payload: '../../../etc/passwd' },
      { name: 'XXE', payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' }
    ];

    const endpoints = ['/api/search', '/api/query', '/api/user'];

    for (const endpoint of endpoints) {
      for (const test of testPayloads) {
        try {
          const url = new URL(`${endpoint}?q=${encodeURIComponent(test.payload)}`, baseUrl).toString();
          const response = await axios.get(url, {
            timeout: 3000,
            validateStatus: () => true
          });

          results.tested.push({ endpoint, test: test.name });

          // Check if payload is reflected without sanitization
          if (response.data && typeof response.data === 'string') {
            if (response.data.includes(test.payload)) {
              results.vulnerabilities.push({
                type: 'unsanitized_input',
                severity: 'high',
                test: test.name,
                endpoint,
                payload: test.payload,
                location: `${endpoint}?q=...`,
                description: `Input not sanitized - potential ${test.name}`,
                remediation: test.name === 'XSS' ? 
                  'Sanitize all user input. Use DOMPurify for XSS prevention, Content-Security-Policy headers' :
                  'Use parameterized queries/prepared statements. Never concatenate user input in SQL queries'
              });
              console.log(chalk.red.bold(`\n  [!] HIGH RISK: ${test.name} Vulnerability`));
              console.log(chalk.white(`      📍 Location: ${endpoint}?q=...`));
              console.log(chalk.yellow(`      ⚠️  IMPACT: ${test.name === 'XSS' ? 'Session hijacking, data theft' : 'Database breach, data loss'}`));
              console.log(chalk.gray(`      🧪 Payload: ${test.payload}`));
              console.log(chalk.cyan(`\n      💡 REMEDIATION:`));
              if (test.name === 'XSS') {
                console.log(chalk.white(`         1. Sanitize input using DOMPurify or similar`));
                console.log(chalk.white(`         2. Encode output: HTML entity encoding`));
                console.log(chalk.white(`         3. Set Content-Security-Policy headers`));
                console.log(chalk.white(`         4. Use template engines with auto-escaping`));
              } else if (test.name === 'SQL Injection') {
                console.log(chalk.white(`         1. Use parameterized queries (prepared statements)`));
                console.log(chalk.white(`         2. Use ORM frameworks (Sequelize, TypeORM)`));
                console.log(chalk.white(`         3. Never concatenate user input in SQL`));
                console.log(chalk.white(`         4. Apply least privilege database permissions`));
              } else {
                console.log(chalk.white(`         1. Validate and sanitize all user input`));
                console.log(chalk.white(`         2. Use allowlist validation patterns`));
                console.log(chalk.white(`         3. Implement input length limits`));
              }
            }
          }

        } catch (error) {
          // Continue testing
        }
      }
    }

    return results;
  }

  /**
   * Check if endpoint is sensitive
   */
  isSensitiveEndpoint(endpoint) {
    const sensitive = ['admin', 'internal', 'private', 'debug', 'test', 'password', 'token', 'key'];
    return sensitive.some(word => endpoint.toLowerCase().includes(word));
  }

  /**
   * Print test summary
   */
  printSummary(results) {
    console.log(chalk.cyan.bold(`\n📊 API Security Test Summary\n`));
    
    let totalVulnerabilities = 0;
    let critical = 0, high = 0, medium = 0;
    const allVulnerabilities = [];

    for (const [testName, testResults] of Object.entries(results.tests)) {
      if (testResults.vulnerabilities) {
        totalVulnerabilities += testResults.vulnerabilities.length;
        
        testResults.vulnerabilities.forEach(vuln => {
          if (vuln.severity === 'critical') critical++;
          else if (vuln.severity === 'high') high++;
          else if (vuln.severity === 'medium') medium++;
          allVulnerabilities.push({ ...vuln, test: testName });
        });
      }
    }

    console.log(chalk.white(`Total Vulnerabilities: ${totalVulnerabilities}`));
    if (critical > 0) console.log(chalk.red(`  Critical: ${critical}`));
    if (high > 0) console.log(chalk.red(`  High: ${high}`));
    if (medium > 0) console.log(chalk.yellow(`  Medium: ${medium}`));

    if (totalVulnerabilities === 0) {
      console.log(chalk.green.bold(`\n✅ No major API security issues detected`));
    } else {
      console.log(chalk.red.bold(`\n⚠️  ${totalVulnerabilities} API security issue(s) found!`));
      console.log(chalk.cyan.bold(`\n📋 Detailed Vulnerability Report:\n`));
      
      allVulnerabilities.forEach((vuln, index) => {
        const severityColor = vuln.severity === 'critical' ? chalk.red.bold :
                             vuln.severity === 'high' ? chalk.red :
                             chalk.yellow;
        
        console.log(severityColor(`${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.type || 'Unknown'}`));
        if (vuln.location) console.log(chalk.white(`   📍 Location: ${vuln.location}`));
        if (vuln.endpoint) console.log(chalk.white(`   🔗 Endpoint: ${vuln.endpoint}`));
        if (vuln.description) console.log(chalk.white(`   📝 Description: ${vuln.description}`));
        if (vuln.remediation) {
          console.log(chalk.cyan(`   💡 Fix: ${vuln.remediation}`));
        }
        console.log('');
      });
    }
  }
}

export default APISecurityTester;

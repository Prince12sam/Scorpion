// API Connection Test Suite
export class APIConnectionTester {
  constructor() {
    this.baseURL = 'http://localhost:3001/api';
    this.results = [];
  }

  async testEndpoint(method, endpoint, data = null, expectedFields = []) {
    const startTime = Date.now();
    try {
      const options = {
        method,
        headers: { 'Content-Type': 'application/json' }
      };
      
      if (data && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(data);
      }

      const response = await fetch(`${this.baseURL}${endpoint}`, options);
      const responseData = await response.json();
      const duration = Date.now() - startTime;

      const result = {
        endpoint,
        method,
        status: response.status,
        success: response.ok,
        duration,
        data: responseData,
        hasExpectedFields: expectedFields.length === 0 || expectedFields.every(field => 
          this.hasNestedProperty(responseData, field)
        )
      };

      this.results.push(result);
      return result;
    } catch (error) {
      const result = {
        endpoint,
        method,
        status: 0,
        success: false,
        duration: Date.now() - startTime,
        error: error.message
      };
      
      this.results.push(result);
      return result;
    }
  }

  hasNestedProperty(obj, path) {
    return path.split('.').reduce((current, key) => current && current[key], obj) !== undefined;
  }

  async runAllTests() {
    console.log('🔍 Starting API Connection Tests...\n');

    // Dashboard APIs
    await this.testEndpoint('GET', '/dashboard/metrics', null, ['metrics.intrusionsDetected', 'metrics.vulnerabilities']);
    
    // Monitoring APIs
    await this.testEndpoint('GET', '/monitoring/alerts', null, ['alerts']);
    await this.testEndpoint('GET', '/monitoring/metrics', null, ['metrics.cpu', 'metrics.memory']);
    
    // File Integrity APIs
    await this.testEndpoint('GET', '/fim/watched', null, ['watchedPaths']);
    await this.testEndpoint('POST', '/fim/add', { path: '/test/path' }, ['success']);
    await this.testEndpoint('POST', '/fim/check');
    
    // User Management APIs
    await this.testEndpoint('GET', '/users', null, ['users']);
    await this.testEndpoint('POST', '/users', { 
      name: 'Test User', 
      email: 'test@example.com', 
      role: 'Viewer' 
    });
    
    // Vulnerability Scanner APIs
    await this.testEndpoint('POST', '/scan', { 
      target: 'localhost', 
      ports: '80,443' 
    }, ['scanId']);
    
    // Compliance APIs
    await this.testEndpoint('POST', '/compliance/assess', { framework: 'owasp' });
    
    // Settings APIs
    await this.testEndpoint('GET', '/settings');
    await this.testEndpoint('POST', '/settings', { theme: 'dark' });
    
    // System Health APIs
    await this.testEndpoint('GET', '/system/health', null, ['cpu', 'memory', 'disk']);
    
    // Report Generation APIs
    await this.testEndpoint('POST', '/reports/generate', { type: 'quick' });
    
    // Threat Intelligence APIs
    await this.testEndpoint('POST', '/threat-intel/update');

    this.printResults();
    return this.results;
  }

  printResults() {
    console.log('\n📊 API Connection Test Results\n');
    console.log('=' * 60);

    const successful = this.results.filter(r => r.success);
    const failed = this.results.filter(r => !r.success);

    console.log(`✅ Successful: ${successful.length}/${this.results.length}`);
    console.log(`❌ Failed: ${failed.length}/${this.results.length}`);
    console.log(`⏱️  Average Response Time: ${Math.round(this.results.reduce((acc, r) => acc + r.duration, 0) / this.results.length)}ms\n`);

    // Successful endpoints
    if (successful.length > 0) {
      console.log('✅ WORKING ENDPOINTS:');
      successful.forEach(result => {
        console.log(`   ${result.method} ${result.endpoint} - ${result.status} (${result.duration}ms)`);
      });
      console.log('');
    }

    // Failed endpoints
    if (failed.length > 0) {
      console.log('❌ FAILED ENDPOINTS:');
      failed.forEach(result => {
        console.log(`   ${result.method} ${result.endpoint} - ${result.error || 'HTTP ' + result.status}`);
      });
      console.log('');
    }

    // Data validation results
    const validationIssues = this.results.filter(r => r.success && r.hasExpectedFields === false);
    if (validationIssues.length > 0) {
      console.log('⚠️  DATA VALIDATION ISSUES:');
      validationIssues.forEach(result => {
        console.log(`   ${result.method} ${result.endpoint} - Missing expected fields`);
      });
    }
  }

  getHealthScore() {
    const successRate = (this.results.filter(r => r.success).length / this.results.length) * 100;
    const avgResponseTime = this.results.reduce((acc, r) => acc + r.duration, 0) / this.results.length;
    
    let healthScore = successRate;
    
    // Penalize slow responses
    if (avgResponseTime > 1000) healthScore -= 10;
    else if (avgResponseTime > 500) healthScore -= 5;
    
    return Math.round(healthScore);
  }
}

// Export for use in browser console
window.APITester = APIConnectionTester;
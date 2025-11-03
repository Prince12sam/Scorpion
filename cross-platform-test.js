#!/usr/bin/env node

/**
 * Scorpion Cross-Platform Testing Suite
 * Tests all functionality across different operating systems
 */

import os from 'os';
import { execSync, spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

class CrossPlatformTester {
  constructor() {
    this.platform = os.platform();
    this.results = {
      system: [],
      cli: [],
      web: [],
      security: [],
      performance: []
    };
    this.totalTests = 0;
    this.passedTests = 0;
    this.failedTests = 0;
  }

  async runAllTests() {
    console.log('🦂 Scorpion Cross-Platform Testing Suite');
    console.log('========================================');
    console.log(`Platform: ${this.platform} ${os.arch()}`);
    console.log(`Node.js: ${process.version}`);
    console.log('');

    await this.testSystemRequirements();
    await this.testCLICommands();
    await this.testWebInterface();
    await this.testSecurityModules();
    await this.testPerformance();
    
    this.generateReport();
  }

  async testSystemRequirements() {
    console.log('🔍 Testing System Requirements...');
    
    const tests = [
      { name: 'Node.js Version', test: () => this.testNodeVersion() },
      { name: 'File Permissions', test: () => this.testFilePermissions() },
      { name: 'Network Access', test: () => this.testNetworkAccess() },
      { name: 'System Dependencies', test: () => this.testSystemDependencies() },
      { name: 'Process Management', test: () => this.testProcessManagement() }
    ];

    for (const test of tests) {
      await this.runTest('system', test.name, test.test);
    }
  }

  async testCLICommands() {
    console.log('\n🖥️  Testing CLI Commands...');
    
    const tests = [
      { name: 'CLI Help', test: () => this.testCLIHelp() },
      { name: 'Vulnerability Scanner', test: () => this.testVulnScanner() },
      { name: 'Network Reconnaissance', test: () => this.testRecon() },
      { name: 'Password Security', test: () => this.testPasswordSecurity() },
      { name: 'File Integrity', test: () => this.testFileIntegrity() },
      { name: 'Threat Intelligence', test: () => this.testThreatIntel() }
    ];

    for (const test of tests) {
      await this.runTest('cli', test.name, test.test);
    }
  }

  async testWebInterface() {
    console.log('\n🌐 Testing Web Interface...');
    
    const tests = [
      { name: 'Server Startup', test: () => this.testServerStartup() },
      { name: 'Authentication', test: () => this.testAuthentication() },
      { name: 'API Endpoints', test: () => this.testAPIEndpoints() },
      { name: 'WebSocket Connection', test: () => this.testWebSocket() },
      { name: 'Static Assets', test: () => this.testStaticAssets() }
    ];

    for (const test of tests) {
      await this.runTest('web', test.name, test.test);
    }
  }

  async testSecurityModules() {
    console.log('\n🛡️  Testing Security Modules...');
    
    const tests = [
      { name: 'CSRF Protection', test: () => this.testCSRFProtection() },
      { name: 'Rate Limiting', test: () => this.testRateLimiting() },
      { name: 'Input Validation', test: () => this.testInputValidation() },
      { name: 'Security Headers', test: () => this.testSecurityHeaders() },
      { name: 'SSL/TLS Support', test: () => this.testSSLSupport() }
    ];

    for (const test of tests) {
      await this.runTest('security', test.name, test.test);
    }
  }

  async testPerformance() {
    console.log('\n⚡ Testing Performance...');
    
    const tests = [
      { name: 'Memory Usage', test: () => this.testMemoryUsage() },
      { name: 'Response Times', test: () => this.testResponseTimes() },
      { name: 'Concurrent Connections', test: () => this.testConcurrentConnections() },
      { name: 'File I/O Performance', test: () => this.testFileIOPerformance() },
      { name: 'CPU Utilization', test: () => this.testCPUUtilization() }
    ];

    for (const test of tests) {
      await this.runTest('performance', test.name, test.test);
    }
  }

  async runTest(category, name, testFunction) {
    this.totalTests++;
    console.log(`   Testing ${name}...`);
    
    try {
      const startTime = Date.now();
      await testFunction();
      const duration = Date.now() - startTime;
      
      this.results[category].push({
        name,
        status: 'PASS',
        duration,
        message: 'Test completed successfully'
      });
      
      this.passedTests++;
      console.log(`   ✅ ${name} - PASSED (${duration}ms)`);
      
    } catch (error) {
      this.results[category].push({
        name,
        status: 'FAIL',
        duration: 0,
        message: error.message
      });
      
      this.failedTests++;
      console.log(`   ❌ ${name} - FAILED: ${error.message}`);
    }
  }

  // System Requirement Tests
  async testNodeVersion() {
    const version = process.version;
    const major = parseInt(version.slice(1).split('.')[0]);
    
    if (major < 16) {
      throw new Error(`Node.js ${major} is too old. Requires Node.js 16+`);
    }
  }

  async testFilePermissions() {
    const testFile = path.join(__dirname, 'test-permissions.tmp');
    
    try {
      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);
    } catch (error) {
      throw new Error('Cannot write to application directory');
    }
  }

  async testNetworkAccess() {
    const testUrls = ['https://google.com', 'https://github.com'];
    
    for (const url of testUrls) {
      try {
        const response = await fetch(url, { 
          method: 'HEAD',
          timeout: 5000 
        });
        if (!response.ok && response.status !== 405) {
          throw new Error(`Cannot access ${url}`);
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          throw new Error('Network timeout - check internet connection');
        }
        throw error;
      }
    }
  }

  async testSystemDependencies() {
    const commands = this.getSystemCommands();
    
    for (const cmd of commands) {
      try {
        execSync(cmd, { stdio: 'ignore', timeout: 5000 });
      } catch (error) {
        console.warn(`   ⚠️  Optional dependency missing: ${cmd.split(' ')[0]}`);
      }
    }
  }

  getSystemCommands() {
    const commonCmds = ['git --version', 'curl --version'];
    
    switch (this.platform) {
      case 'win32':
        return [...commonCmds, 'powershell -v'];
      case 'linux':
        return [...commonCmds, 'nmap --version', 'python3 --version'];
      case 'darwin':
        return [...commonCmds, 'python3 --version'];
      default:
        return commonCmds;
    }
  }

  async testProcessManagement() {
    // Test that we can spawn and kill processes
    const testProcess = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 10000)']);
    
    await new Promise(resolve => setTimeout(resolve, 100));
    
    if (!testProcess.pid) {
      throw new Error('Cannot spawn child processes');
    }
    
    testProcess.kill();
    
    await new Promise(resolve => {
      testProcess.on('close', resolve);
      setTimeout(resolve, 1000); // Timeout fallback
    });
  }

  // CLI Command Tests
  async testCLIHelp() {
    try {
      execSync('node cli/scorpion.js --help', { 
        stdio: 'pipe',
        timeout: 10000 
      });
    } catch (error) {
      throw new Error('CLI help command failed');
    }
  }

  async testVulnScanner() {
    try {
      // Test with local scan to avoid external dependencies
      execSync('node cli/scorpion.js scan 127.0.0.1 --quick', {
        stdio: 'pipe',
        timeout: 30000
      });
    } catch (error) {
      throw new Error('Vulnerability scanner failed');
    }
  }

  async testRecon() {
    try {
      execSync('node cli/scorpion.js recon 127.0.0.1 --quick', {
        stdio: 'pipe',
        timeout: 20000
      });
    } catch (error) {
      throw new Error('Network reconnaissance failed');
    }
  }

  async testPasswordSecurity() {
    try {
      execSync('node cli/scorpion.js password analyze "testpassword123"', {
        stdio: 'pipe',
        timeout: 10000
      });
    } catch (error) {
      throw new Error('Password security module failed');
    }
  }

  async testFileIntegrity() {
    try {
      const testFile = path.join(__dirname, 'test-file.tmp');
      fs.writeFileSync(testFile, 'test content');
      
      execSync(`node cli/scorpion.js fim baseline "${testFile}"`, {
        stdio: 'pipe',
        timeout: 10000
      });
      
      fs.unlinkSync(testFile);
    } catch (error) {
      throw new Error('File integrity monitoring failed');
    }
  }

  async testThreatIntel() {
    try {
      execSync('node cli/scorpion.js threat-intel ip 127.0.0.1', {
        stdio: 'pipe',
        timeout: 15000
      });
    } catch (error) {
      throw new Error('Threat intelligence failed');
    }
  }

  // Web Interface Tests
  async testServerStartup() {
    const server = spawn(process.execPath, ['server/simple-web-server.js'], {
      stdio: 'pipe'
    });

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        server.kill();
        reject(new Error('Server failed to start within 10 seconds'));
      }, 10000);

      server.stdout.on('data', (data) => {
        if (data.toString().includes('SCORPION SECURITY PLATFORM')) {
          clearTimeout(timeout);
          server.kill();
          resolve();
        }
      });

      server.on('error', (error) => {
        clearTimeout(timeout);
        reject(new Error(`Server startup failed: ${error.message}`));
      });
    });
  }

  async testAuthentication() {
    // This would require the server to be running
    // For now, just test that the auth module loads
    try {
      const authModule = await import('./server/simple-web-server.js');
      if (!authModule) {
        throw new Error('Authentication module not found');
      }
    } catch (error) {
      throw new Error('Authentication test failed');
    }
  }

  async testAPIEndpoints() {
    // Test API endpoint structure
    const serverFile = path.join(__dirname, 'server/simple-web-server.js');
    const content = fs.readFileSync(serverFile, 'utf8');
    
    const endpoints = ['/api/health', '/api/auth/login', '/api/dashboard/metrics'];
    
    for (const endpoint of endpoints) {
      if (!content.includes(endpoint)) {
        throw new Error(`API endpoint ${endpoint} not found`);
      }
    }
  }

  async testWebSocket() {
    // Test WebSocket module import
    try {
      const wsModule = await import('ws');
      if (!wsModule.WebSocketServer) {
        throw new Error('WebSocket server not available');
      }
    } catch (error) {
      throw new Error('WebSocket support test failed');
    }
  }

  async testStaticAssets() {
    const distPath = path.join(__dirname, 'dist');
    
    if (!fs.existsSync(distPath)) {
      throw new Error('Frontend build not found. Run "npm run build"');
    }
    
    const indexFile = path.join(distPath, 'index.html');
    if (!fs.existsSync(indexFile)) {
      throw new Error('Frontend index.html not found');
    }
  }

  // Security Tests
  async testCSRFProtection() {
    const serverFile = path.join(__dirname, 'server/simple-web-server.js');
    const content = fs.readFileSync(serverFile, 'utf8');
    
    if (!content.includes('csrf') && !content.includes('CSRF')) {
      throw new Error('CSRF protection not implemented');
    }
  }

  async testRateLimiting() {
    const serverFile = path.join(__dirname, 'server/simple-web-server.js');
    const content = fs.readFileSync(serverFile, 'utf8');
    
    if (!content.includes('rateLimit') && !content.includes('rate-limit')) {
      throw new Error('Rate limiting not implemented');
    }
  }

  async testInputValidation() {
    const serverFile = path.join(__dirname, 'server/simple-web-server.js');
    const content = fs.readFileSync(serverFile, 'utf8');
    
    if (!content.includes('validation') && !content.includes('sanitize')) {
      console.warn('Input validation might not be fully implemented');
    }
  }

  async testSecurityHeaders() {
    const serverFile = path.join(__dirname, 'server/simple-web-server.js');
    const content = fs.readFileSync(serverFile, 'utf8');
    
    if (!content.includes('helmet')) {
      throw new Error('Security headers (Helmet) not implemented');
    }
  }

  async testSSLSupport() {
    const httpsSupport = fs.existsSync(path.join(__dirname, 'certs')) ||
                        fs.readFileSync(path.join(__dirname, 'server/simple-web-server.js'), 'utf8').includes('https');
    
    if (!httpsSupport) {
      console.warn('HTTPS support not detected');
    }
  }

  // Performance Tests
  async testMemoryUsage() {
    const memUsage = process.memoryUsage();
    const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
    
    if (heapUsedMB > 500) {
      throw new Error(`High memory usage: ${heapUsedMB.toFixed(2)}MB`);
    }
  }

  async testResponseTimes() {
    // Test file system response times
    const testFile = path.join(__dirname, 'test-response.tmp');
    const iterations = 100;
    
    const startTime = Date.now();
    
    for (let i = 0; i < iterations; i++) {
      fs.writeFileSync(testFile, `test data ${i}`);
      fs.readFileSync(testFile);
    }
    
    fs.unlinkSync(testFile);
    
    const avgTime = (Date.now() - startTime) / iterations;
    
    if (avgTime > 10) {
      throw new Error(`Slow file I/O: ${avgTime.toFixed(2)}ms average`);
    }
  }

  async testConcurrentConnections() {
    // Test process spawning capability
    const processes = [];
    
    try {
      for (let i = 0; i < 5; i++) {
        const proc = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 1000)']);
        processes.push(proc);
      }
      
      await new Promise(resolve => setTimeout(resolve, 1500));
      
    } finally {
      processes.forEach(proc => proc.kill());
    }
  }

  async testFileIOPerformance() {
    const testDir = path.join(__dirname, 'test-io');
    
    try {
      fs.mkdirSync(testDir, { recursive: true });
      
      const startTime = Date.now();
      
      // Create, read, and delete multiple files
      for (let i = 0; i < 50; i++) {
        const testFile = path.join(testDir, `test-${i}.tmp`);
        fs.writeFileSync(testFile, `test data for file ${i}`);
        fs.readFileSync(testFile);
        fs.unlinkSync(testFile);
      }
      
      const duration = Date.now() - startTime;
      
      if (duration > 5000) {
        throw new Error(`Slow file I/O performance: ${duration}ms`);
      }
      
    } finally {
      try {
        fs.rmSync(testDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  async testCPUUtilization() {
    // Simple CPU test - compute intensive task
    const startTime = Date.now();
    let iterations = 0;
    
    while (Date.now() - startTime < 100) {
      Math.sqrt(Math.random() * 1000000);
      iterations++;
    }
    
    if (iterations < 1000) {
      console.warn('CPU performance may be limited');
    }
  }

  generateReport() {
    console.log('\n📊 Test Results Summary');
    console.log('=======================');
    console.log(`Total Tests: ${this.totalTests}`);
    console.log(`Passed: ${this.passedTests} ✅`);
    console.log(`Failed: ${this.failedTests} ❌`);
    console.log(`Success Rate: ${((this.passedTests / this.totalTests) * 100).toFixed(1)}%`);
    
    // Detailed results by category
    for (const [category, tests] of Object.entries(this.results)) {
      if (tests.length > 0) {
        console.log(`\n${category.toUpperCase()} Tests:`);
        
        tests.forEach(test => {
          const status = test.status === 'PASS' ? '✅' : '❌';
          console.log(`  ${status} ${test.name} (${test.duration}ms)`);
          
          if (test.status === 'FAIL') {
            console.log(`     Error: ${test.message}`);
          }
        });
      }
    }
    
    // Generate JSON report
    const report = {
      timestamp: new Date().toISOString(),
      platform: this.platform,
      nodeVersion: process.version,
      architecture: os.arch(),
      totalTests: this.totalTests,
      passedTests: this.passedTests,
      failedTests: this.failedTests,
      successRate: (this.passedTests / this.totalTests) * 100,
      results: this.results
    };
    
    const reportPath = path.join(__dirname, `test-report-${this.platform}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    console.log(`\n📋 Detailed report saved to: ${reportPath}`);
    
    if (this.failedTests > 0) {
      console.log('\n⚠️  Some tests failed. Please review the errors above.');
      process.exit(1);
    } else {
      console.log('\n🎉 All tests passed! Scorpion is ready for production.');
    }
  }
}

// Run tests if called directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const tester = new CrossPlatformTester();
  tester.runAllTests().catch(error => {
    console.error('❌ Test suite failed:', error);
    process.exit(1);
  });
}

export { CrossPlatformTester };
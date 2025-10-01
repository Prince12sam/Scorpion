#!/usr/bin/env node

/**
 * Scorpion Security Platform - Web Interface Testing Suite
 * Comprehensive testing of all web components and API endpoints
 */

import { spawn } from 'child_process';
import { setTimeout } from 'timers/promises';

const API_BASE = 'http://localhost:3001';
const WEB_BASE = 'http://localhost:5173';

console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  🦂 SCORPION PLATFORM - WEB INTERFACE TEST SUITE             ║
║                   Comprehensive Testing                      ║
╚═══════════════════════════════════════════════════════════════╝
`);

class ScorpionTester {
  constructor() {
    this.testResults = [];
    this.serverRunning = false;
    this.webRunning = false;
  }

  async testEndpoint(name, url, method = 'GET', body = null) {
    try {
      const options = {
        method,
        headers: { 'Content-Type': 'application/json' },
        ...(body && { body: JSON.stringify(body) })
      };

      const response = await fetch(url, options);
      const data = await response.json();
      
      if (response.ok) {
        console.log(`✅ ${name}: PASS`);
        this.testResults.push({ name, status: 'PASS', response: data });
        return data;
      } else {
        console.log(`❌ ${name}: FAIL - ${response.status}`);
        this.testResults.push({ name, status: 'FAIL', error: response.status });
        return null;
      }
    } catch (error) {
      console.log(`❌ ${name}: ERROR - ${error.message}`);
      this.testResults.push({ name, status: 'ERROR', error: error.message });
      return null;
    }
  }

  async checkServerHealth() {
    console.log('\n🔍 Testing API Server Health...');
    
    const health = await this.testEndpoint('Health Check', `${API_BASE}/api/health`);
    const dashboard = await this.testEndpoint('Dashboard Metrics', `${API_BASE}/api/dashboard/metrics`);
    const systemHealth = await this.testEndpoint('System Health', `${API_BASE}/api/system/health`);
    
    this.serverRunning = health !== null;
    return this.serverRunning;
  }

  async testVulnerabilityScanner() {
    console.log('\n🔍 Testing Vulnerability Scanner...');
    
    // Test vulnerability scan
    await this.testEndpoint(
      'Vulnerability Scan', 
      `${API_BASE}/api/scanner/scan`,
      'POST',
      { target: '127.0.0.1', ports: '80,443,22' }
    );

    // Test scan status
    await this.testEndpoint('Scanner Status', `${API_BASE}/api/scanner/status`);
  }

  async testNetworkRecon() {
    console.log('\n🕵️ Testing Network Reconnaissance...');
    
    await this.testEndpoint(
      'Network Discovery',
      `${API_BASE}/api/recon/discover`,
      'POST', 
      { target: 'google.com' }
    );

    await this.testEndpoint('WHOIS Lookup', `${API_BASE}/api/recon/whois`);
  }

  async testThreatIntelligence() {
    console.log('\n🧠 Testing Threat Intelligence...');
    
    await this.testEndpoint('Threat Feed Status', `${API_BASE}/api/threat-feeds/status`);
    await this.testEndpoint('Live Threat Map', `${API_BASE}/api/threat-map/live`);
    await this.testEndpoint('Threat Statistics', `${API_BASE}/api/threat-feeds/stats`);
    
    await this.testEndpoint(
      'IP Reputation Check',
      `${API_BASE}/api/threat-intelligence/ip`,
      'POST',
      { ip: '8.8.8.8' }
    );
  }

  async testFileIntegrity() {
    console.log('\n👁️ Testing File Integrity Monitor...');
    
    await this.testEndpoint(
      'File Integrity Scan',
      `${API_BASE}/api/file-integrity/scan`,
      'POST',
      { path: './src' }
    );

    await this.testEndpoint('FIM Status', `${API_BASE}/api/file-integrity/status`);
    await this.testEndpoint('FIM Files', `${API_BASE}/api/fim/files`);
  }

  async testPasswordSecurity() {
    console.log('\n🔐 Testing Password Security...');
    
    await this.testEndpoint(
      'Password Generation',
      `${API_BASE}/api/password/generate`,
      'POST',
      { length: 16, includeNumbers: true, includeSymbols: true }
    );

    await this.testEndpoint(
      'Password Strength Check',
      `${API_BASE}/api/password/check`,
      'POST',
      { password: 'TestPassword123!' }
    );
  }

  async testMonitoringCenter() {
    console.log('\n📊 Testing Monitoring Center...');
    
    await this.testEndpoint('Monitoring Alerts', `${API_BASE}/api/monitoring/alerts`);
    await this.testEndpoint('System Metrics', `${API_BASE}/api/monitoring/metrics`);
    await this.testEndpoint('Performance Stats', `${API_BASE}/api/monitoring/performance`);
  }

  async testComplianceTracker() {
    console.log('\n📋 Testing Compliance Tracker...');
    
    await this.testEndpoint('Compliance Status', `${API_BASE}/api/compliance/status`);
    await this.testEndpoint('Compliance Frameworks', `${API_BASE}/api/compliance/frameworks`);
  }

  async testReportsGenerator() {
    console.log('\n📊 Testing Reports Generator...');
    
    await this.testEndpoint('Report Templates', `${API_BASE}/api/reports/templates`);
    await this.testEndpoint(
      'Generate Report',
      `${API_BASE}/api/reports/generate`,
      'POST',
      { type: 'vulnerability', format: 'json' }
    );
  }

  async testUserManagement() {
    console.log('\n👥 Testing User Management...');
    
    await this.testEndpoint('User List', `${API_BASE}/api/users`);
    await this.testEndpoint('User Roles', `${API_BASE}/api/users/roles`);
  }

  async testInvestigationTools() {
    console.log('\n🔍 Testing Investigation Tools...');
    
    await this.testEndpoint(
      'Investigation Analysis',
      `${API_BASE}/api/investigation/analyze`,
      'POST',
      { target: 'sample-data', type: 'network' }
    );
  }

  async testAPITesting() {
    console.log('\n🔌 Testing API Testing Tools...');
    
    await this.testEndpoint(
      'API Endpoint Test',
      `${API_BASE}/api/testing/api`,
      'POST',
      { endpoints: ['/api/health'] }
    );
  }

  async checkWebInterface() {
    console.log('\n🌐 Checking Web Interface Accessibility...');
    
    try {
      const response = await fetch(WEB_BASE);
      if (response.ok) {
        console.log('✅ Web Interface: ACCESSIBLE');
        this.webRunning = true;
      } else {
        console.log('❌ Web Interface: NOT ACCESSIBLE');
      }
    } catch (error) {
      console.log('❌ Web Interface: CONNECTION FAILED');
    }
  }

  async runComprehensiveTest() {
    console.log('🚀 Starting comprehensive web interface testing...\n');

    // Check if servers are running
    const serverHealthy = await this.checkServerHealth();
    if (!serverHealthy) {
      console.log('\n❌ API Server is not running. Please start the server with: npm run server');
      return;
    }

    await this.checkWebInterface();

    // Test all components
    await this.testVulnerabilityScanner();
    await this.testNetworkRecon();
    await this.testThreatIntelligence();
    await this.testFileIntegrity();
    await this.testPasswordSecurity();
    await this.testMonitoringCenter();
    await this.testComplianceTracker();
    await this.testReportsGenerator();
    await this.testUserManagement();
    await this.testInvestigationTools();
    await this.testAPITesting();

    // Generate test report
    this.generateTestReport();
  }

  generateTestReport() {
    console.log('\n' + '='.repeat(60));
    console.log('📊 SCORPION WEB INTERFACE TEST RESULTS');
    console.log('='.repeat(60));

    const passed = this.testResults.filter(r => r.status === 'PASS');
    const failed = this.testResults.filter(r => r.status === 'FAIL');
    const errors = this.testResults.filter(r => r.status === 'ERROR');

    console.log(`✅ Passed Tests: ${passed.length}`);
    console.log(`❌ Failed Tests: ${failed.length}`);
    console.log(`⚠️  Error Tests: ${errors.length}`);
    console.log(`📈 Success Rate: ${((passed.length / this.testResults.length) * 100).toFixed(1)}%`);

    console.log('\n🔍 Component Status:');
    console.log(`🌐 Web Interface: ${this.webRunning ? 'RUNNING' : 'STOPPED'}`);
    console.log(`🔧 API Server: ${this.serverRunning ? 'RUNNING' : 'STOPPED'}`);

    if (failed.length > 0 || errors.length > 0) {
      console.log('\n⚠️  Issues Found:');
      [...failed, ...errors].forEach(result => {
        console.log(`   - ${result.name}: ${result.error || result.status}`);
      });
    }

    console.log('\n' + '='.repeat(60));
    
    if (passed.length === this.testResults.length && this.webRunning) {
      console.log('🎉 ALL TESTS PASSED - Platform ready for GitHub release!');
    } else {
      console.log('⚠️  Some issues detected - Please review and fix before release.');
    }
  }
}

// Run the test suite
const tester = new ScorpionTester();
tester.runComprehensiveTest().catch(console.error);
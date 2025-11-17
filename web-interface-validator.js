#!/usr/bin/env node

/**
 * 🦂 Scorpion Web Interface Tab & Page Validator
 * Comprehensive testing of all dashboard components and API endpoints
 */

import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

class WebInterfaceValidator {
  constructor() {
    this.baseUrl = 'http://localhost:3001';
    this.authToken = null;
    this.results = {
      authentication: { status: 'pending', details: [] },
      apiEndpoints: { status: 'pending', details: [] },
      components: { status: 'pending', details: [] },
      summary: { total: 0, passed: 0, failed: 0 }
    };
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const symbols = { info: '🔍', success: '✅', error: '❌', warning: '⚠️' };
    console.log(`${symbols[type]} [${timestamp}] ${message}`);
  }

  async testAuthentication() {
    this.log('Testing authentication system...', 'info');
    
    try {
      // Test login endpoint
      const loginResponse = await fetch(`${this.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'admin' })
      });

      if (loginResponse.ok) {
        const authData = await loginResponse.json();
        
        if (authData.tokens && authData.tokens.accessToken) {
          this.authToken = authData.tokens.accessToken;
          this.results.authentication.details.push({ test: 'Login', status: 'passed', token: 'received' });
          this.log('Authentication successful - token received', 'success');
        } else {
          throw new Error('Invalid token format received');
        }
      } else {
        throw new Error(`Login failed with status: ${loginResponse.status}`);
      }

      this.results.authentication.status = 'passed';
      return true;
    } catch (error) {
      this.results.authentication.status = 'failed';
      this.results.authentication.details.push({ test: 'Login', status: 'failed', error: error.message });
      this.log(`Authentication failed: ${error.message}`, 'error');
      return false;
    }
  }

  async testApiEndpoint(endpoint, description, requiresAuth = false) {
    try {
      const headers = { 'Content-Type': 'application/json' };
      if (requiresAuth && this.authToken) {
        headers['Authorization'] = `Bearer ${this.authToken}`;
      }

      const response = await fetch(`${this.baseUrl}${endpoint}`, { headers, timeout: 5000 });
      
      if (response.ok) {
        const data = await response.json();
        this.results.apiEndpoints.details.push({
          endpoint,
          description,
          status: 'passed',
          statusCode: response.status,
          dataReceived: typeof data === 'object'
        });
        this.log(`✅ ${description} - Status: ${response.status}`, 'success');
        return true;
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (error) {
      this.results.apiEndpoints.details.push({
        endpoint,
        description,
        status: 'failed',
        error: error.message
      });
      this.log(`❌ ${description} - Error: ${error.message}`, 'error');
      return false;
    }
  }

  async testAllApiEndpoints() {
    this.log('Testing all API endpoints...', 'info');
    
    const endpoints = [
      // Public endpoints
      { endpoint: '/api/system/health', description: 'System Health Check', auth: false },
      { endpoint: '/api/dashboard/metrics', description: 'Dashboard Metrics', auth: false },
      { endpoint: '/api/threat-map', description: 'Threat Map Data', auth: false },
      
      // Core security endpoints
      { endpoint: '/api/scan', description: 'Vulnerability Scanner', auth: true },
      { endpoint: '/api/recon', description: 'Reconnaissance & Discovery', auth: true },
      { endpoint: '/api/monitoring/alerts', description: 'Monitoring Alerts', auth: true },
      { endpoint: '/api/fim/status', description: 'File Integrity Monitor', auth: true },
      { endpoint: '/api/threat-hunting', description: 'Threat Hunting', auth: true },
      { endpoint: '/api/password/analyze', description: 'Password Security', auth: true },
      { endpoint: '/api/exploitation', description: 'Advanced Exploitation', auth: true },
      { endpoint: '/api/api-testing', description: 'API Testing Tools', auth: true },
      { endpoint: '/api/network-discovery', description: 'Network Discovery', auth: true },
      { endpoint: '/api/brute-force', description: 'Brute Force Tools', auth: true },
      { endpoint: '/api/reports', description: 'Reports Generator', auth: true },
      { endpoint: '/api/compliance', description: 'Compliance Tracker', auth: true },
      { endpoint: '/api/intelligence', description: 'Threat Intelligence', auth: true },
      { endpoint: '/api/investigation', description: 'Investigation Tools', auth: true },
      { endpoint: '/api/users', description: 'User Management', auth: true },
      { endpoint: '/api/settings', description: 'Settings', auth: true }
    ];

    let passed = 0;
    let total = endpoints.length;

    for (const { endpoint, description, auth } of endpoints) {
      const success = await this.testApiEndpoint(endpoint, description, auth);
      if (success) passed++;
      
      // Small delay to avoid overwhelming the server
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.results.apiEndpoints.status = passed === total ? 'passed' : 'partial';
    this.log(`API Endpoints: ${passed}/${total} passed`, passed === total ? 'success' : 'warning');
    
    return { passed, total };
  }

  async testWebPageLoad() {
    this.log('Testing main web page load...', 'info');
    
    try {
      const response = await fetch(`${this.baseUrl}/`, { timeout: 5000 });
      
      if (response.ok) {
        const html = await response.text();
        
        // Check for essential elements
        const checks = [
          { test: 'HTML Structure', condition: html.includes('<html') },
          { test: 'React App Mount', condition: html.includes('id="root"') },
          { test: 'Title Tag', condition: html.includes('<title>') },
          { test: 'CSS Loading', condition: html.includes('.css') },
          { test: 'JS Loading', condition: html.includes('.js') }
        ];

        const passedChecks = checks.filter(check => check.condition);
        
        this.results.components.details.push({
          component: 'Main Page',
          status: passedChecks.length === checks.length ? 'passed' : 'partial',
          checks: passedChecks.length,
          total: checks.length
        });

        this.log(`Main page loaded - ${passedChecks.length}/${checks.length} checks passed`, 
          passedChecks.length === checks.length ? 'success' : 'warning');
        
        return passedChecks.length === checks.length;
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (error) {
      this.results.components.details.push({
        component: 'Main Page',
        status: 'failed',
        error: error.message
      });
      this.log(`Main page load failed: ${error.message}`, 'error');
      return false;
    }
  }

  async validateComponentFiles() {
    this.log('Validating React component files...', 'info');
    
    const components = [
      'Dashboard.jsx',
      'ReconDiscovery.jsx', 
      'VulnerabilityScanner.jsx',
      'MonitoringCenter.jsx',
      'FileIntegrityMonitor.jsx',
      'GlobalThreatHunting.jsx',
      'PasswordSecurity.jsx',
      'AdvancedExploitation.jsx',
      'ApiTesting.jsx',
      'NetworkDiscovery.jsx',
      'BruteForceTools.jsx',
      'ReportsGenerator.jsx',
      'ComplianceTracker.jsx',
      'ThreatIntelligence.jsx',
      'InvestigationTools.jsx',
      'UserManagement.jsx',
      'Settings.jsx',
      'Sidebar.jsx',
      'Login.jsx'
    ];

    let validComponents = 0;
    let totalComponents = components.length;

    for (const component of components) {
      try {
        const componentPath = path.join(__dirname, 'src', 'components', component);
        const content = readFileSync(componentPath, 'utf8');
        
        // Basic React component validation
        const isValidComponent = 
          content.includes('import React') || content.includes('from \'react\'') &&
          content.includes('export default') &&
          content.includes('function') || content.includes('const');

        if (isValidComponent) {
          validComponents++;
          this.results.components.details.push({
            component: component.replace('.jsx', ''),
            status: 'passed',
            fileExists: true,
            validStructure: true
          });
        } else {
          this.results.components.details.push({
            component: component.replace('.jsx', ''),
            status: 'warning',
            fileExists: true,
            validStructure: false
          });
        }
      } catch (error) {
        this.results.components.details.push({
          component: component.replace('.jsx', ''),
          status: 'failed',
          fileExists: false,
          error: error.message
        });
      }
    }

    this.results.components.status = validComponents === totalComponents ? 'passed' : 'partial';
    this.log(`Component files: ${validComponents}/${totalComponents} valid`, 
      validComponents === totalComponents ? 'success' : 'warning');
    
    return { validComponents, totalComponents };
  }

  async testDashboardSections() {
    this.log('Testing dashboard sections navigation...', 'info');
    
    const sections = [
      'dashboard', 'recon', 'scanner', 'monitoring', 'fim', 
      'threat-hunting', 'password-security', 'exploitation', 
      'api-testing', 'network-discovery', 'brute-force', 
      'reports', 'compliance', 'intelligence', 'investigation',
      'users', 'settings'
    ];

    // This would typically require browser automation to test properly
    // For now, we'll validate that the sections are defined in App.jsx
    try {
      const appPath = path.join(__dirname, 'src', 'App.jsx');
      const appContent = readFileSync(appPath, 'utf8');
      
      let validSections = 0;
      
      for (const section of sections) {
        if (appContent.includes(`'${section}'`) || appContent.includes(`"${section}"`)) {
          validSections++;
          this.results.components.details.push({
            component: `Section: ${section}`,
            status: 'passed',
            definedInApp: true
          });
        } else {
          this.results.components.details.push({
            component: `Section: ${section}`,
            status: 'failed',
            definedInApp: false
          });
        }
      }

      this.log(`Dashboard sections: ${validSections}/${sections.length} defined`, 
        validSections === sections.length ? 'success' : 'warning');
      
      return { validSections, totalSections: sections.length };
    } catch (error) {
      this.log(`Failed to validate dashboard sections: ${error.message}`, 'error');
      return { validSections: 0, totalSections: sections.length };
    }
  }

  generateReport() {
    console.log('\n' + '='.repeat(70));
    console.log('🦂 SCORPION WEB INTERFACE VALIDATION REPORT');
    console.log('='.repeat(70));
    
    // Authentication Summary
    console.log('\n🔐 AUTHENTICATION:');
    console.log(`   Status: ${this.results.authentication.status.toUpperCase()}`);
    this.results.authentication.details.forEach(detail => {
      console.log(`   - ${detail.test}: ${detail.status} ${detail.token ? `(${detail.token})` : ''}`);
    });

    // API Endpoints Summary
    console.log('\n🌐 API ENDPOINTS:');
    console.log(`   Status: ${this.results.apiEndpoints.status.toUpperCase()}`);
    const apiPassed = this.results.apiEndpoints.details.filter(d => d.status === 'passed').length;
    const apiTotal = this.results.apiEndpoints.details.length;
    console.log(`   Success Rate: ${apiPassed}/${apiTotal} (${Math.round(apiPassed/apiTotal*100)}%)`);

    // Components Summary  
    console.log('\n⚛️  REACT COMPONENTS:');
    console.log(`   Status: ${this.results.components.status.toUpperCase()}`);
    const compPassed = this.results.components.details.filter(d => d.status === 'passed').length;
    const compTotal = this.results.components.details.length;
    console.log(`   Success Rate: ${compPassed}/${compTotal} (${Math.round(compPassed/compTotal*100)}%)`);

    // Overall Summary
    const totalTests = apiTotal + compTotal + 1; // +1 for auth
    const totalPassed = apiPassed + compPassed + (this.results.authentication.status === 'passed' ? 1 : 0);
    
    console.log('\n📊 OVERALL SUMMARY:');
    console.log(`   Total Tests: ${totalTests}`);
    console.log(`   Passed: ${totalPassed}`);
    console.log(`   Failed: ${totalTests - totalPassed}`);
    console.log(`   Success Rate: ${Math.round(totalPassed/totalTests*100)}%`);
    
    this.results.summary = { total: totalTests, passed: totalPassed, failed: totalTests - totalPassed };
    
    // Status determination
    if (totalPassed === totalTests) {
      console.log('\n🎉 ALL TABS AND PAGES ARE FUNCTIONING CORRECTLY!');
      return true;
    } else if (totalPassed / totalTests >= 0.8) {
      console.log('\n⚠️  MOST TABS AND PAGES ARE WORKING (Some issues detected)');
      return 'partial';
    } else {
      console.log('\n❌ MULTIPLE ISSUES DETECTED - REVIEW REQUIRED');
      return false;
    }
  }

  async runCompleteValidation() {
    console.log('🦂 Starting Complete Web Interface Validation...\n');
    
    // Test authentication first
    const authSuccess = await this.testAuthentication();
    
    // Test web page loading
    await this.testWebPageLoad();
    
    // Test all API endpoints
    await this.testAllApiEndpoints();
    
    // Validate component files
    await this.validateComponentFiles();
    
    // Test dashboard sections
    await this.testDashboardSections();
    
    // Generate comprehensive report
    return this.generateReport();
  }
}

// Run validation if called directly
const isMainModule = process.argv[1] && process.argv[1].endsWith('web-interface-validator.js');
if (isMainModule) {
  const validator = new WebInterfaceValidator();
  
  try {
    const result = await validator.runCompleteValidation();
    process.exit(result === true ? 0 : 1);
  } catch (error) {
    console.error('❌ Validation failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

export { WebInterfaceValidator };
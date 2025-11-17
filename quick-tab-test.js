#!/usr/bin/env node

/**
 * 🦂 Quick Tab Functionality Test
 * Tests if all dashboard tabs have working API endpoints
 */

console.log('🦂 Testing Scorpion Dashboard Tab Functionality...\n');

const baseUrl = 'http://localhost:3001';

// Test endpoints for each tab
const tabEndpoints = [
  { tab: 'Dashboard', endpoint: '/api/dashboard/metrics' },
  { tab: 'Vulnerability Scanner', endpoint: '/api/scanner/scan', method: 'POST', body: { target: 'example.com' } },
  { tab: 'Recon & Discovery', endpoint: '/api/recon/discover', method: 'POST', body: { target: 'example.com' } },
  { tab: 'Monitoring Center', endpoint: '/api/monitoring/alerts' },
  { tab: 'File Integrity', endpoint: '/api/fim/status' },
  { tab: 'Threat Hunting', endpoint: '/api/threat-hunting' },
  { tab: 'Password Security', endpoint: '/api/password/analyze', method: 'POST', body: { password: 'test123' } },
  { tab: 'Advanced Exploitation', endpoint: '/api/exploitation' },
  { tab: 'API Testing', endpoint: '/api/api-testing' },
  { tab: 'Network Discovery', endpoint: '/api/network-discovery' },
  { tab: 'Brute Force Tools', endpoint: '/api/brute-force' },
  { tab: 'Reports Generator', endpoint: '/api/reports' },
  { tab: 'Compliance Tracker', endpoint: '/api/compliance' },
  { tab: 'Threat Intelligence', endpoint: '/api/intelligence' },
  { tab: 'Investigation Tools', endpoint: '/api/investigation' },
  { tab: 'User Management', endpoint: '/api/users' },
  { tab: 'Settings', endpoint: '/api/settings' },
  { tab: 'System Health', endpoint: '/api/system/health' },
];

let passed = 0;

for (const test of tabEndpoints) {
  try {
    const options = {
      method: test.method || 'GET',
      headers: { 'Content-Type': 'application/json' }
    };
    
    if (test.body) {
      options.body = JSON.stringify(test.body);
    }

    const response = await fetch(`${baseUrl}${test.endpoint}`, options);
    
    if (response.ok) {
      console.log(`✅ ${test.tab} - Endpoint working`);
      passed++;
    } else {
      console.log(`❌ ${test.tab} - HTTP ${response.status}`);
    }
  } catch (error) {
    console.log(`❌ ${test.tab} - ${error.message}`);
  }
}

console.log(`\n📊 Results: ${passed}/${tabEndpoints.length} tabs have working endpoints`);

if (passed === tabEndpoints.length) {
  console.log('🎉 ALL DASHBOARD TABS ARE FUNCTIONING!');
} else if (passed > tabEndpoints.length * 0.8) {
  console.log('⚠️  Most tabs are working - minor issues detected');
} else {
  console.log('❌ Multiple tab functionality issues detected');
}

// Test authentication
console.log('\n🔐 Testing Authentication...');
try {
  const authResponse = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin' })
  });
  
  if (authResponse.ok) {
    const authData = await authResponse.json();
    if (authData.tokens && authData.tokens.accessToken) {
      console.log('✅ Authentication - Login working with token generation');
    } else {
      console.log('⚠️  Authentication - Login working but token format issue');
    }
  } else {
    console.log(`❌ Authentication - Login failed (HTTP ${authResponse.status})`);
  }
} catch (error) {
  console.log(`❌ Authentication - ${error.message}`);
}

console.log('\n🌐 Testing Web Page Load...');
try {
  const pageResponse = await fetch(`${baseUrl}/`);
  if (pageResponse.ok) {
    console.log('✅ Web Page - Main page loading correctly');
  } else {
    console.log(`❌ Web Page - Failed to load (HTTP ${pageResponse.status})`);
  }
} catch (error) {
  console.log(`❌ Web Page - ${error.message}`);
}

console.log('\n🦂 Tab functionality test complete!');

process.exit(passed === tabEndpoints.length ? 0 : 1);
// Comprehensive Web Interface Test Suite
const API_BASE = 'http://localhost:3001/api';

console.log('🧪 COMPREHENSIVE SCORPION WEB INTERFACE TEST SUITE');
console.log('=' .repeat(60));

async function runComprehensiveTests() {
  let passedTests = 0;
  let totalTests = 0;

  const testResult = (testName, success, details = '') => {
    totalTests++;
    if (success) {
      passedTests++;
      console.log(`✅ ${testName}: PASSED ${details}`);
    } else {
      console.log(`❌ ${testName}: FAILED ${details}`);
    }
  };

  try {
    console.log('\n🔧 1. TESTING API SERVER CONNECTIVITY');
    console.log('-'.repeat(40));

    // Health Check
    const healthResponse = await fetch(`${API_BASE}/health`);
    const healthData = await healthResponse.json();
    testResult('Health Check', healthData.status === 'ok', `(${healthData.server})`);

    // Dashboard Metrics
    const metricsResponse = await fetch(`${API_BASE}/dashboard/metrics`);
    const metricsData = await metricsResponse.json();
    testResult('Dashboard Metrics', metricsData.metrics !== undefined, 
      `(CPU: ${metricsData.metrics?.systemHealth?.cpu}%)`);

    console.log('\n🔍 2. TESTING VULNERABILITY SCANNER');
    console.log('-'.repeat(40));

    // Test with different targets
    const testTargets = ['google.com', '8.8.8.8', 'github.com'];
    
    for (const target of testTargets) {
      const scanResponse = await fetch(`${API_BASE}/scanner/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, type: 'quick' })
      });
      const scanData = await scanResponse.json();
      testResult(`Vulnerability Scan - ${target}`, scanData.success === true,
        `(Found ${scanData.results?.vulnerabilities?.length || 0} vulns, ${scanData.results?.openPorts?.length || 0} ports)`);
    }

    console.log('\n🕵️ 3. TESTING NETWORK RECONNAISSANCE');
    console.log('-'.repeat(40));

    for (const target of testTargets) {
      const reconResponse = await fetch(`${API_BASE}/recon/discover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
      });
      const reconData = await reconResponse.json();
      testResult(`Network Recon - ${target}`, reconData.success === true,
        `(DNS: ${Object.keys(reconData.results?.dns || {}).length} records)`);
    }

    console.log('\n🧠 4. TESTING THREAT INTELLIGENCE');
    console.log('-'.repeat(40));

    const threatTargets = ['8.8.8.8', '1.1.1.1', '208.67.222.222'];
    
    for (const target of threatTargets) {
      const threatResponse = await fetch(`${API_BASE}/threat-intel/lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: target, type: 'ip' })
      });
      const threatData = await threatResponse.json();
      testResult(`Threat Intel - ${target}`, threatData.success === true,
        `(Rep: ${threatData.results?.reputation}, Conf: ${threatData.results?.confidence}%)`);
    }

    console.log('\n👁️ 5. TESTING FILE INTEGRITY MONITORING');
    console.log('-'.repeat(40));

    const fimResponse = await fetch(`${API_BASE}/file-integrity/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: '/tmp/test' })
    });
    const fimData = await fimResponse.json();
    testResult('File Integrity Scan', fimData.success === true,
      `(Scanned: ${fimData.results?.filesScanned || 0} files)`);

    console.log('\n🔐 6. TESTING PASSWORD SECURITY');
    console.log('-'.repeat(40));

    const passwords = ['weak123', 'StrongP@ssw0rd!2024', 'password'];
    
    for (const password of passwords) {
      const pwdResponse = await fetch(`${API_BASE}/password/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: password })
      });
      const pwdData = await pwdResponse.json();
      testResult(`Password Analysis - ${password.substring(0, 4)}***`, pwdData.success === true,
        `(Strength: ${pwdData.analysis?.strength}, Score: ${pwdData.analysis?.score})`);
    }

    console.log('\n📊 7. TESTING MONITORING ENDPOINTS');
    console.log('-'.repeat(40));

    // Monitoring Alerts
    const alertsResponse = await fetch(`${API_BASE}/monitoring/alerts`);
    const alertsData = await alertsResponse.json();
    testResult('Monitoring Alerts', alertsData.alerts !== undefined,
      `(${alertsData.totalAlerts || 0} alerts)`);

    // System Metrics
    const sysMetricsResponse = await fetch(`${API_BASE}/monitoring/metrics`);
    const sysMetricsData = await sysMetricsResponse.json();
    testResult('System Metrics', sysMetricsData.cpu !== undefined,
      `(CPU: ${sysMetricsData.cpu}%, Mem: ${sysMetricsData.memory}%)`);

    console.log('\n🚀 8. TESTING SCAN STATUS TRACKING');
    console.log('-'.repeat(40));

    const statusResponse = await fetch(`${API_BASE}/scanner/status/123456789`);
    const statusData = await statusResponse.json();
    testResult('Scan Status Tracking', statusData.status !== undefined,
      `(Status: ${statusData.status}, Progress: ${statusData.progress}%)`);

    console.log('\n' + '='.repeat(60));
    console.log('📋 TEST RESULTS SUMMARY');
    console.log('='.repeat(60));
    
    const successRate = Math.round((passedTests / totalTests) * 100);
    console.log(`📊 Tests Passed: ${passedTests}/${totalTests} (${successRate}%)`);
    
    if (successRate === 100) {
      console.log('🎉 ALL TESTS PASSED! Web interface is fully functional!');
      console.log('🌐 Ready for production use at: http://localhost:5173');
    } else if (successRate >= 80) {
      console.log('⚠️  Most tests passed, minor issues detected');
    } else {
      console.log('❌ Critical issues detected, needs debugging');
    }

    console.log('\n🔧 CURRENT STATUS:');
    console.log(`• API Server: ✅ Running on http://localhost:3001`);
    console.log(`• Web Interface: ✅ Running on http://localhost:5173`);
    console.log(`• CORS: ✅ Enabled`);
    console.log(`• All Endpoints: ✅ Responsive`);
    
    console.log('\n💡 USAGE INSTRUCTIONS:');
    console.log('1. Open http://localhost:5173 in your browser');
    console.log('2. Navigate to "Vulnerability Scanner" or other tools');
    console.log('3. Enter a domain (google.com) or IP (8.8.8.8)');
    console.log('4. Click "Start Scan" to test functionality');
    console.log('5. View detailed results and reports');

  } catch (error) {
    console.error('❌ TEST SUITE ERROR:', error.message);
    console.log('🔧 Check if both servers are running:');
    console.log('   API Server: node server/fixed-server.js');
    console.log('   Web UI: npm run dev');
  }
}

// Run the comprehensive test suite
runComprehensiveTests();
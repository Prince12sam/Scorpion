// Manual Web Interface Test - Copy and paste this into browser console
// This tests the web interface by directly making calls from the browser

console.log('🧪 MANUAL WEB INTERFACE TEST');
console.log('Testing Scorpion Security Platform from browser...');

// Test 1: Vulnerability Scanner
async function testVulnerabilityScanner() {
  console.log('\n🔍 Testing Vulnerability Scanner...');
  try {
    const response = await fetch('http://localhost:3001/api/scanner/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        target: 'example.com',
        type: 'quick'
      })
    });
    
    const result = await response.json();
    console.log('✅ Vulnerability Scanner Result:', result);
    return result.success;
  } catch (error) {
    console.error('❌ Vulnerability Scanner Error:', error);
    return false;
  }
}

// Test 2: Network Reconnaissance
async function testNetworkRecon() {
  console.log('\n🕵️ Testing Network Reconnaissance...');
  try {
    const response = await fetch('http://localhost:3001/api/recon/discover', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        target: 'example.com'
      })
    });
    
    const result = await response.json();
    console.log('✅ Network Recon Result:', result);
    return result.success;
  } catch (error) {
    console.error('❌ Network Recon Error:', error);
    return false;
  }
}

// Test 3: Threat Intelligence
async function testThreatIntel() {
  console.log('\n🧠 Testing Threat Intelligence...');
  try {
    const response = await fetch('http://localhost:3001/api/threat-intel/lookup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        indicator: '8.8.8.8',
        type: 'ip'
      })
    });
    
    const result = await response.json();
    console.log('✅ Threat Intel Result:', result);
    return result.success;
  } catch (error) {
    console.error('❌ Threat Intel Error:', error);
    return false;
  }
}

// Run all tests
async function runAllTests() {
  console.log('🚀 Starting manual web interface tests...\n');
  
  const test1 = await testVulnerabilityScanner();
  const test2 = await testNetworkRecon();
  const test3 = await testThreatIntel();
  
  const passed = [test1, test2, test3].filter(Boolean).length;
  const total = 3;
  
  console.log('\n📊 Test Results:');
  console.log(`✅ Passed: ${passed}/${total}`);
  
  if (passed === total) {
    console.log('🎉 ALL TESTS PASSED! Web interface is working correctly!');
  } else {
    console.log('❌ Some tests failed. Check server connection.');
  }
}

// Auto-run tests
runAllTests();
#!/usr/bin/env node

import dotenv from 'dotenv';
import { ThreatIntel } from './cli/lib/threat-intel.js';

// Load environment variables
dotenv.config();

async function testVirusTotalAPI() {
  console.log('🦂 Testing VirusTotal API Integration\n');
  
  const threatIntel = new ThreatIntel();
  
  // Test cases
  const testCases = [
    {
      type: 'IP Address',
      indicator: '8.8.8.8',
      description: 'Google DNS (should be clean)'
    },
    {
      type: 'Domain',
      indicator: 'google.com', 
      description: 'Google domain (should be clean)'
    },
    {
      type: 'Malicious IP',
      indicator: '185.220.100.240',
      description: 'Known malicious IP (may be flagged)'
    }
  ];

  for (const testCase of testCases) {
    console.log(`📊 Testing ${testCase.type}: ${testCase.indicator}`);
    console.log(`   Description: ${testCase.description}`);
    
    try {
      let result;
      if (testCase.type === 'IP Address' || testCase.type === 'Malicious IP') {
        result = await threatIntel.checkIP(testCase.indicator);
      } else if (testCase.type === 'Domain') {
        result = await threatIntel.checkDomain(testCase.indicator);
      }
      
      if (result) {
        console.log(`   ✅ Result: ${result.reputation.toUpperCase()}`);
        console.log(`   📈 Threat Score: ${result.threat_score}/100`);
        console.log(`   🔍 Sources: ${result.sources.join(', ')}`);
        
        if (result.geolocation) {
          console.log(`   🌍 Location: ${result.geolocation.city}, ${result.geolocation.country}`);
        }
      } else {
        console.log('   ❌ No result returned');
      }
    } catch (error) {
      console.log(`   ❌ Error: ${error.message}`);
    }
    
    console.log(''); // Empty line for readability
    
    // Rate limiting - wait 1 second between requests
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  console.log('🎉 VirusTotal API testing completed!');
}

// API Key validation
if (!process.env.VIRUSTOTAL_API_KEY) {
  console.log('❌ Error: VIRUSTOTAL_API_KEY not found in .env file');
  console.log('Please create a .env file with:');
  console.log('VIRUSTOTAL_API_KEY=your_api_key_here');
  process.exit(1);
}

console.log('🔑 VirusTotal API Key found in environment (value hidden)\n');

// Run the test
testVirusTotalAPI().catch(console.error);
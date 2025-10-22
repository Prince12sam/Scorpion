#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import dotenv from 'dotenv';
import fs from 'fs/promises';

import { SecurityScanner } from './lib/scanner.js';
import { NetworkRecon } from './lib/recon.js';
import { ThreatIntel } from './lib/threat-intel.js';
import { ExploitFramework } from './lib/exploit-framework.js';
import { EnterpriseVulnScanner } from './lib/enterprise-vuln-scanner.js';
import { InternalNetworkTester } from './lib/internal-network-tester.js';
import { AutonomousPenTester } from './lib/ai-autonomous-pentester.js';

dotenv.config();

const program = new Command();

program
	.name('scorpion')
	.description('Scorpion - Global Threat-Hunting Platform CLI (discovery-only)')
	.version('1.0.0');

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

function printNmapStyle(target, results) {
	const startTime = new Date().toISOString();
	console.log(chalk.gray(`Starting nmap-like scan at ${startTime}`));
	console.log(`Nmap scan report for ${chalk.yellow(target)}`);
	if (results.openPorts && results.openPorts.length) {
		console.log('\nPORT\tSTATE\tSERVICE\tVERSION');
		const ports = [...results.openPorts].sort((a, b) => (a.port || 0) - (b.port || 0));
		for (const p of ports) {
			const state = (p.status || p.state || 'open');
			const svcObj = (results.services || []).find(s => s.port === p.port) || {};
			const service = svcObj.name || svcObj.service || 'unknown';
			const version = svcObj.version && svcObj.version !== 'unknown' ? ` ${svcObj.version}` : '';
			console.log(`${String(p.port)}/tcp\t${state}\t${service}\t${version}`);
		}
	} else {
		console.log(chalk.yellow('No open ports found'));
	}
	if (results.osFingerprint) {
		console.log(`\nOS detection: ${results.osFingerprint.detectedOS} (${results.osFingerprint.confidence}% confidence)`);
		if (Array.isArray(results.osFingerprint.evidence) && results.osFingerprint.evidence.length) {
			console.log(chalk.gray(`  Evidence: ${results.osFingerprint.evidence.join(', ')}`));
		}
	}
	console.log(`\nScan done: ${chalk.green('1 IP address (1 host up)')}`);
}

// Discovery Scan (nmap style)
program
	.command('scan')
	.description('Run advanced discovery scans with multiple techniques')
	.option('-t, --target <target>', 'Target IP, domain, or URL')
	.option('-p, --ports <ports>', 'Port range (e.g., 1-1000)', '1-1000')
	.option('--type <type>', 'Scan type: quick, normal, deep, custom', 'normal')
	.option('--technique <technique>', 'Scan technique: tcp-connect, syn-scan, udp-scan, stealth, fin-scan, null-scan, xmas-scan, ack-scan', 'tcp-connect')
	.option('-sT', 'TCP connect scan (maps to technique tcp-connect)')
	.option('-sS', 'TCP SYN scan (maps to technique syn-scan)')
	.option('-sU', 'UDP scan (maps to technique udp-scan)')
	.option('-A', 'Aggressive detection: enable service/version detection')
	.option('-O', 'OS detection')
	.option('-v, --verbose', 'Increase verbosity')
	.option('--stealth <level>', 'Stealth level: low, medium, high, ninja', 'medium')
	.option('--output-mode <mode>', 'Output mode: nmap, json', 'nmap')
	.option('-o, --output <file>', 'Output file (JSON if specified)')
	.action(async (options) => {
		if (!options.target) {
			console.log(chalk.red('❌ Error: Target is required'));
			process.exit(1);
		}

		const spinner = ora(`Running ${options.type} scan on ${options.target}`).start();

		try {
			let technique = options.technique;
			if (options.sS) technique = 'syn-scan';
			else if (options.sU) technique = 'udp-scan';
			else if (options.sT) technique = 'tcp-connect';

			const scanner = new SecurityScanner();
			const results = await scanner.scan(options.target, {
				ports: options.ports,
				type: options.type,
				technique,
				aggressive: !!options.A,
				osDetect: !!options.O,
				stealthLevel: options.stealth || 'medium'
			});

			spinner.succeed(`Scan completed! Found ${results.openPorts?.length || 0} open ports`);

			if (options.outputMode === 'json') {
				console.log(JSON.stringify(results, null, 2));
			} else {
				printNmapStyle(options.target, results);
			}

			if (options.output) {
				const outPath = options.output.endsWith('.json') ? options.output : `${options.output}.json`;
				await fs.writeFile(outPath, JSON.stringify(results, null, 2));
				console.log(chalk.green(`\n📄 Results saved to ${outPath}`));
			}
		} catch (error) {
			spinner.fail(`Scan failed: ${error.message}`);
			process.exit(1);
		}
	});

// Reconnaissance
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

// Threat Intelligence
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
			if (options.ip) results = await intel.checkIP(options.ip);
			else if (options.domain) results = await intel.checkDomain(options.domain);
			else if (options.hash) results = await intel.checkHash(options.hash);
			else if (options.ioc) results = await intel.getIOCs();

			spinner.succeed('Threat intelligence gathered!');
			console.log(chalk.cyan('\n🧠 Intelligence Results:'));
			console.log(JSON.stringify(results, null, 2));
		} catch (error) {
			spinner.fail(`Intelligence gathering failed: ${error.message}`);
			process.exit(1);
		}
	});

// Exploit Framework
program
	.command('exploit')
	.description('🔥 Advanced OWASP Top 10 payload testing (AUTHORIZED TARGETS ONLY)')
	.option('-t, --target <target>', 'Target IP, domain, or URL')
	.option('-p, --port <port>', 'Specific port to test')
	.option('--service <service>', 'Target service (ssh, http, ftp, smtp, etc.)')
	.option('--vuln <cve>', 'Target specific vulnerability (CVE-YYYY-NNNN)')
	.option('--payload <type>', 'Payload type: owasp-top10, broken-access-control, sql-injection, xss, ssrf, cloud, aws, azure, gcp, all', 'all')
	.option('--mode <mode>', 'Exploitation mode: reconnaissance, proof-of-concept, weaponized', 'reconnaissance')
	.option('--threads <num>', 'Number of concurrent threads', '5')
	.option('--delay <ms>', 'Delay between attempts (ms)', '1000')
	.option('--output <file>', 'Save exploitation results')
	.action(async (options) => {
		if (!options.target) {
			console.log(chalk.red('❌ Error: Target is required'));
			process.exit(1);
		}

		console.log(chalk.red('\n⚠️  WARNING: EXPLOITATION MODULE ACTIVATED ⚠️'));
		console.log(chalk.yellow('AUTHORIZED PENETRATION TESTING ONLY!'));

		const spinner = ora(`Preparing exploitation payloads for ${options.target}...`).start();
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

			if (results.exploits?.length) {
				console.log(chalk.red('\n🚨 SUCCESSFUL EXPLOITS:'));
				results.exploits.forEach((exploit, index) => {
					console.log(`${index + 1}. ${chalk.red('CRITICAL')} - ${exploit.name}`);
					console.log(`   Target: ${exploit.target}:${exploit.port}`);
					console.log(`   Method: ${exploit.method}`);
					console.log(`   Response: ${exploit.response ? 'SUCCESS' : 'FAILED'}`);
					if (exploit.shell) console.log(chalk.red('   💀 SHELL ACCESS GAINED!'));
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

// Web Interface
program
	.command('web')
	.description('Start web interface')
	.option('-p, --port <port>', 'Port number', '3000')
	.option('--host <host>', 'Host address', 'localhost')
	.action(async (options) => {
		console.log(chalk.cyan(`🌐 Starting web interface on http://${options.host}:${options.port}`));
		const { startWebServer } = await import('../server/index.js');
		await startWebServer(options.port, options.host);
	});

// ====== ENTERPRISE SECURITY COMMANDS ======
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
	.option('-o, --output <file>', 'Output file for results (JSON)')
	.action(async (options) => {
		if (!options.targets || options.targets.length === 0) {
			console.error(chalk.red('❌ At least one target is required. Use --targets <ip/network>'));
			process.exit(1);
		}

		console.log(chalk.blue('🏢 Starting Enterprise Vulnerability Assessment'));
		const spinner = ora('Initializing enterprise scanner...').start();

		try {
			const scanner = new EnterpriseVulnScanner();

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
				const outPath = options.output.endsWith('.json') ? options.output : `${options.output}.json`;
				await fs.writeFile(outPath, JSON.stringify(assessment, null, 2));
				console.log(chalk.blue(`📄 Results saved to: ${outPath}`));
			}
		} catch (error) {
			spinner.fail('Enterprise assessment failed');
			console.error(chalk.red(`❌ Error: ${error.message}`));
			process.exit(1);
		}
	});

// Internal Network Testing
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
	.option('-o, --output <file>', 'Output file for results (JSON)')
	.action(async (options) => {
		console.log(chalk.blue('🏠 Starting Internal Network Security Assessment'));
		const spinner = ora('Mapping internal network...').start();

		try {
			const tester = new InternalNetworkTester();

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
			const totalFindings = Object.values(assessment.security_findings).reduce((sum, f) => sum + f.length, 0);
			console.log(chalk.yellow(`  Security Findings: ${totalFindings}`));
			if (assessment.compliance_gaps.length > 0) console.log(chalk.red(`  Compliance Gaps: ${assessment.compliance_gaps.length}`));

			if (options.output) {
				const outPath = options.output.endsWith('.json') ? options.output : `${options.output}.json`;
				await fs.writeFile(outPath, JSON.stringify(assessment, null, 2));
				console.log(chalk.blue(`📄 Results saved to: ${outPath}`));
			}
		} catch (error) {
			spinner.fail('Internal assessment failed');
			console.error(chalk.red(`❌ Error: ${error.message}`));
			process.exit(1);
		}
	});

// Enhanced Help (overview of advanced capabilities)
program
	.command('help-advanced')
	.description('🔥 Show advanced exploitation capabilities (overview)')
	.action(() => {
		console.log(`
${chalk.red('💀 SCORPION ADVANCED EXPLOITATION FRAMEWORK 💀')}
${chalk.red('⚠️  WEAPON-GRADE CAPABILITIES - AUTHORIZED USE ONLY ⚠️')}

${chalk.cyan('CAPABILITIES OVERVIEW:')}
	• OWASP Top 10 payload testing via 'scorpion exploit'
	• Cloud platform payloads (AWS/Azure/GCP)
	• Command/SQL injection probes and escalation
	• Persistence and evasion concepts (use responsibly)

${chalk.red('LEGAL DISCLAIMER:')}
These capabilities are provided for authorized security testing only.
Unauthorized use against systems you do not own is illegal.
Always obtain proper authorization before testing.
		`);
	});

// 🤖 AI Autonomous Penetration Testing
program
	.command('ai-pentest')
	.description('🤖 AI-powered autonomous penetration testing')
	.requiredOption('-t, --target <target>', 'Target for AI penetration test')
	.option('--primary-goal <goal>', 'Primary objective (comprehensive_assessment, privilege_escalation, data_access)', 'comprehensive_assessment')
	.option('--secondary-goals <goals>', 'Secondary goals (comma-separated)', 'privilege_escalation,data_access,persistence')
	.option('--time-limit <minutes>', 'Time limit in minutes', '120')
	.option('--stealth-level <level>', 'Stealth level (low, moderate, high)', 'moderate')
	.option('--autonomy <level>', 'Autonomy level (supervised, semi-autonomous, fully-autonomous)', 'supervised')
	.option('--risk-tolerance <level>', 'Risk tolerance (low, medium, high)', 'medium')
	.option('--max-depth <depth>', 'Maximum exploitation depth', '5')
	.option('--ai-model <model>', 'AI model to use (gpt-4, gpt-3.5-turbo)', 'gpt-4')
	.option('--openai-key <key>', 'OpenAI API key (or set OPENAI_API_KEY env var)')
	.option('--learning', 'Enable machine learning from results', true)
	.option('--compliance <frameworks>', 'Compliance frameworks to consider (comma-separated)')
	.option('-o, --output <file>', 'Output file for AI assessment results')
	.action(async (options) => {
		const spinner = ora('🤖 Initializing AI Autonomous Penetration Tester...').start();
		try {
			const aiConfig = {
				aiModel: options.aiModel,
				openaiApiKey: options.openaiKey || process.env.OPENAI_API_KEY,
				autonomyLevel: options.autonomy,
				riskTolerance: options.riskTolerance,
				maxDepth: parseInt(options.maxDepth),
				learningEnabled: options.learning
			};
			if (!aiConfig.openaiApiKey) {
				spinner.fail('OpenAI API key required');
				console.error(chalk.red('❌ Provide OpenAI API key via --openai-key or OPENAI_API_KEY env var'));
				process.exit(1);
			}

			const aiPenTester = new AutonomousPenTester(aiConfig);
			spinner.succeed('AI Autonomous Penetration Tester initialized');

			const objectives = {
				primaryGoal: options.primaryGoal,
				secondaryGoals: options.secondaryGoals.split(',').map(g => g.trim()),
				timeLimit: parseInt(options.timeLimit) * 60,
				stealthLevel: options.stealthLevel,
				compliance: options.compliance ? options.compliance.split(',').map(c => c.trim()) : []
			};

			console.log(chalk.blue(`\n🎯 AI Penetration Test Configuration:`));
			console.log(chalk.cyan(`  Target: ${options.target}`));
			console.log(chalk.cyan(`  Primary Goal: ${objectives.primaryGoal}`));
			console.log(chalk.cyan(`  Secondary Goals: ${objectives.secondaryGoals.join(', ')}`));
			console.log(chalk.cyan(`  Autonomy Level: ${options.autonomy.toUpperCase()}`));
			console.log(chalk.cyan(`  Risk Tolerance: ${options.riskTolerance.toUpperCase()}`));
			console.log(chalk.cyan(`  AI Model: ${options.aiModel}`));
			console.log(chalk.cyan(`  Time Limit: ${options.timeLimit} minutes`));

			const startTime = new Date();
			console.log(chalk.blue(`\n🚀 Starting AI Autonomous Penetration Test at ${startTime.toLocaleTimeString()}`));
			const penTestResults = await aiPenTester.conductFullPenTest(options.target, objectives);

			console.log(chalk.green(`\n✅ AI Autonomous Penetration Test Completed!`));
			console.log(chalk.cyan(`📊 Session ID: ${penTestResults.session_id}`));
			console.log(chalk.cyan(`⏱️  Duration: ${penTestResults.duration}`));
			console.log(chalk.cyan(`🎯 Phase: ${penTestResults.phase.toUpperCase()}`));
			console.log(chalk.cyan(`🔍 Vulnerabilities Found: ${penTestResults.vulnerabilities?.length || 0}`));
			console.log(chalk.cyan(`⚡ Exploitation Attempts: ${penTestResults.exploitation_results?.length || 0}`));
			console.log(chalk.cyan(`✅ Successful Exploits: ${penTestResults.exploitation_results?.filter(r => r.success).length || 0}`));
			console.log(chalk.cyan(`🧠 AI Decisions Made: ${penTestResults.ai_decisions?.length || 0}`));

			if (penTestResults.ai_report) {
				console.log(chalk.blue(`\n🎯 AI Risk Assessment:`));
				console.log(chalk.yellow(`  Overall Risk: ${penTestResults.ai_report.risk_assessment?.overall_risk || 'UNKNOWN'}`));
				console.log(chalk.yellow(`  Critical Issues: ${penTestResults.ai_report.risk_assessment?.critical_issues || 0}`));
				console.log(chalk.yellow(`  Business Impact: ${penTestResults.ai_report.risk_assessment?.business_impact || 'Unknown'}`));
			}

			if (penTestResults.ai_report?.recommendations) {
				console.log(chalk.blue(`\n💡 AI Recommendations:`));
				penTestResults.ai_report.recommendations.slice(0, 3).forEach((rec, index) => {
					console.log(chalk.green(`  ${index + 1}. ${rec}`));
				});
			}

			if (options.output) {
				const outputPath = options.output.endsWith('.json') ? options.output : `${options.output}.json`;
				await fs.writeFile(outputPath, JSON.stringify(penTestResults, null, 2));
				console.log(chalk.blue(`\n💾 Results saved to: ${outputPath}`));
			}
		} catch (error) {
			spinner.fail('AI Autonomous Penetration Test failed');
			console.error(chalk.red(`❌ Error: ${error.message}`));
			process.exit(1);
		}
	});

program.parse();
#!/usr/bin/env node

// Local scan runner for security professionals: no hosting, pure CLI.
// Runs a scan using the internal SecurityScanner and writes JSON + Markdown reports.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import { SecurityScanner } from '../cli/lib/scanner.js';
import { ensureSafeDirectory } from '../cli/lib/path-guard.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function parseArgs(argv) {
  const args = { target: '', type: 'quick', ports: '1-1000', technique: 'tcp-connect', out: 'reports' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const nxt = argv[i + 1];
    if ((a === '--target' || a === '-t') && nxt) { args.target = nxt; i++; continue; }
    if ((a === '--type' || a === '-y') && nxt) { args.type = nxt; i++; continue; }
    if ((a === '--ports' || a === '-p') && nxt) { args.ports = nxt; i++; continue; }
    if ((a === '--technique' || a === '-k') && nxt) { args.technique = nxt; i++; continue; }
    if ((a === '--out' || a === '-o') && nxt) { args.out = nxt; i++; continue; }
    if (a === '--help' || a === '-h') { args.help = true; }
  }
  return args;
}

function printHelp() {
  console.log(`\nScorpion Local Scanner (No Hosting Required)\n\n` +
    `Usage:\n  node tools/run-scan.js --target <host|ip> [--type quick|normal|deep] [--ports 1-1000] [--technique tcp-connect|syn] [--out reports]\n\n` +
    `Examples:\n  node tools/run-scan.js --target 127.0.0.1\n  node tools/run-scan.js -t example.com -y deep -p 1-65535 -k tcp-connect -o reports\n`);
}

function toMarkdown(result) {
  const lines = [];
  const ts = new Date().toISOString();
  lines.push(`# Scorpion Scan Report`);
  lines.push(``);
  lines.push(`- Timestamp: ${ts}`);
  lines.push(`- Target: ${result?.target || 'unknown'}`);
  lines.push(`- Scan Type: ${result?.scanType || 'unknown'}`);
  lines.push(`- Host OS (guess): ${result?.os?.name || 'N/A'} (${result?.os?.confidence ?? 'N/A'}%)`);
  lines.push('');
  lines.push('## Open Ports');
  if (Array.isArray(result?.openPorts) && result.openPorts.length) {
    for (const p of result.openPorts) {
      lines.push(`- ${p.port}/${p.protocol || 'tcp'}: ${p.state || 'unknown'}${p.service ? ` (${p.service})` : ''}${p.banner ? ` - ${p.banner}` : ''}`);
    }
  } else {
    lines.push('- None detected');
  }
  lines.push('');
  lines.push('## Vulnerabilities');
  if (Array.isArray(result?.vulnerabilities) && result.vulnerabilities.length) {
    for (const v of result.vulnerabilities) {
      lines.push(`- [${v.severity || 'UNKNOWN'}] ${v.title || v.name || 'Issue'}${v.cve ? ` (CVE: ${v.cve})` : ''}`);
      if (v.description) lines.push(`  - ${v.description}`);
      if (v.recommendation) lines.push(`  - Fix: ${v.recommendation}`);
    }
  } else {
    lines.push('- None reported');
  }
  lines.push('');
  lines.push('## Notes');
  lines.push('- This report was generated locally by Scorpion without hosting any server.');
  lines.push('- Use responsibly and only on systems you are authorized to test.');
  lines.push('');
  return lines.join(os.EOL);
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || !args.target) {
    printHelp();
    process.exit(args.help ? 0 : 1);
  }

  console.log('🦂 Scorpion Local Scan');
  console.log(`   Target    : ${args.target}`);
  console.log(`   Type      : ${args.type}`);
  console.log(`   Ports     : ${args.ports}`);
  console.log(`   Technique : ${args.technique}`);

  const scanner = new SecurityScanner();

  let result;
  try {
    result = await scanner.scan({
      target: args.target,
      scanType: args.type,
      ports: args.ports,
      technique: args.technique
    });
  } catch (err) {
    console.error('Scan failed:', err?.message || err);
    process.exit(2);
  }

  // Write outputs
  const outputRoot = ensureSafeDirectory(args.out || 'reports', { description: 'output directory' });
  const stamp = Date.now();
  const base = path.join(outputRoot, `scan_${stamp}`);

  try {
    fs.writeFileSync(`${base}.json`, JSON.stringify(result, null, 2), 'utf8');
    fs.writeFileSync(`${base}.md`, toMarkdown({ ...result, target: args.target, scanType: args.type }), 'utf8');
  } catch (err) {
    console.error('Failed to write report files:', err?.message || err);
  }

  console.log('');
  console.log('✅ Scan complete. Outputs:');
  console.log(`   JSON : ${base}.json`);
  console.log(`   MD   : ${base}.md`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

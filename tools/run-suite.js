#!/usr/bin/env node
// Local suite: scan + intel (+recon optional). Unified JSON/MD output.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { SecurityScanner } from '../cli/lib/scanner.js';
import { ThreatIntel } from '../cli/lib/threat-intel.js';
import { NetworkRecon } from '../cli/lib/recon.js';

function parseArgs(argv){
  const a={ target:'', ports:'1-65535', type:'quick', technique:'tcp-connect', doRecon:false, out:'reports' };
  for(let i=2;i<argv.length;i++){
    const k=argv[i],n=argv[i+1];
    if((k==='--target'||k==='-t')&&n){a.target=n;i++;continue;}
    if((k==='--ports'||k==='-p')&&n){a.ports=n;i++;continue;}
    if((k==='--type'||k==='-y')&&n){a.type=n;i++;continue;}
    if((k==='--technique'||k==='-k')&&n){a.technique=n;i++;continue;}
    if(k==='--recon'){a.doRecon=true;}
    if((k==='--out'||k==='-o')&&n){a.out=n;i++;continue;}
    if(k==='--help'||k==='-h'){a.help=true;}
  }
  return a;
}

function mdReport(r){
  const l=[]; l.push(`# Scorpion Unified Report`,''); l.push(`- Target: ${r.target}`); l.push(`- Time: ${new Date().toISOString()}`,'');
  l.push('## Scan Summary');
  const s=r.scan||{};
  const osName = s.osFingerprint?.detectedOS || s.os?.name || 'N/A';
  const osConf = s.osFingerprint?.confidence ?? s.os?.confidence ?? 'N/A';
  l.push(`- OS Guess: ${osName} (${osConf}%)`);
  l.push('- Open Ports:');
  if(Array.isArray(s.openPorts)&&s.openPorts.length){
    for(const p of s.openPorts){
      const state = p.status || p.state || 'open';
      const proto = p.protocol || 'tcp';
      const svc = p.service || p.name || '';
      l.push(`  - ${p.port}/${proto} ${state}${svc?` (${svc})`:''}`);
    }
  } else l.push('  - None');
  if(Array.isArray(s.services)&&s.services.length){
    l.push('- Services:');
    for(const sv of s.services){
      const ver = sv.version && sv.version!=='unknown' ? ` v${sv.version}`:'';
      l.push(`  - ${sv.port}/tcp ${sv.name||sv.service||'Unknown'}${ver}`);
    }
  }
  l.push('- Vulnerabilities:');
  if(Array.isArray(s.vulnerabilities)&&s.vulnerabilities.length){ for(const v of s.vulnerabilities) l.push(`  - [${v.severity||'UNKNOWN'}] ${v.title||v.name||''}${v.cve?` (CVE: ${v.cve})`:''}`);} else l.push('  - None');
  l.push('', '## Threat Intel');
  const ti=r.intel||{}; l.push(`- Reputation: ${ti.reputation||'unknown'} (Score ${ti.threat_score??'N/A'})`);
  if(ti.sources?.length){ l.push('- Sources:'); for(const s of ti.sources) l.push(`  - ${s}`);} 
  if(ti.categories?.length){ l.push('- Categories:'); for(const c of ti.categories) l.push(`  - ${c}`);} 
  if(ti.malware_families?.length){ l.push('- Malware Families:'); for(const m of ti.malware_families) l.push(`  - ${m}`);} 
  if(r.recon){ l.push('', '## Recon (optional)'); l.push(`- DNS Records: ${Array.isArray(r.recon.dns)?r.recon.dns.length:0}`); }
  l.push('', '## Notes', '- Generated locally by Scorpion (no hosting).');
  return l.join(os.EOL);
}

async function main(){
  const args=parseArgs(process.argv); if(args.help||!args.target){
    console.log(`\nUsage: node tools/run-suite.js --target <host> [--recon] [--type quick|normal|deep] [--ports 1-1000] [--technique tcp-connect] [--out reports]\n`);
    process.exit(args.help?0:1);
  }
  const scanner=new SecurityScanner(); const intel=new ThreatIntel();
  const [scan,intelRes] = await Promise.all([
    // Pass target as string and align option keys with SecurityScanner
    scanner.scan(args.target, { ports: args.ports, type: args.type, technique: args.technique }),
    (args.target.match(/^\d+\.\d+\.\d+\.\d+$/) ? intel.checkIP(args.target) : intel.checkDomain(args.target))
  ]);
  let recon=null; if(args.doRecon){ const r=new NetworkRecon(); recon=await r.discover(args.target, { dns:true, whois:false, ports:false, subdomain:false }); }
  const unified={ target: args.target, scan, intel: intelRes, recon };
  fs.mkdirSync(args.out,{recursive:true}); const base=path.join(args.out,`suite_${Date.now()}`);
  fs.writeFileSync(`${base}.json`, JSON.stringify(unified,null,2),'utf8');
  fs.writeFileSync(`${base}.md`, mdReport(unified),'utf8');
  console.log('✅ Suite complete:', `${base}.json`);
}

main().catch(e=>{ console.error(e); process.exit(1); });

#!/usr/bin/env node
// Local threat intel runner (no hosting). Supports IP or domain, writes JSON/MD.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ThreatIntel } from '../cli/lib/threat-intel.js';
import { resolveSafePath, ensureSafeDirectory } from '../cli/lib/path-guard.js';

function parseArgs(argv){
  const args = { indicator: '', type: 'auto', out: 'reports' };
  for (let i=2;i<argv.length;i++){
    const a=argv[i],n=argv[i+1];
    if((a==='--indicator'||a==='-i')&&n){args.indicator=n;i++;continue;}
    if((a==='--type'||a==='-t')&&n){args.type=n;i++;continue;}
    if((a==='--out'||a==='-o')&&n){args.out=n;i++;continue;}
    if(a==='--help'||a==='-h'){args.help=true}
  }
  return args;
}

function toMarkdown(res){
  const l=[]; const ts=new Date().toISOString();
  l.push(`# Scorpion Threat Intel Report`,'');
  l.push(`- Timestamp: ${ts}`);
  if(res.ip) l.push(`- IP: ${res.ip}`);
  if(res.domain) l.push(`- Domain: ${res.domain}`);
  l.push(`- Reputation: ${res.reputation}`);
  l.push(`- Threat Score: ${res.threat_score ?? 'N/A'}`,'');
  l.push('## Sources');
  if(Array.isArray(res.sources)&&res.sources.length){
    for(const s of res.sources) l.push(`- ${s}`);
  } else l.push('- None');
  if(res.categories?.length){ l.push('', '## Categories'); for(const c of res.categories) l.push(`- ${c}`); }
  if(res.malware_families?.length){ l.push('', '## Malware Families'); for(const m of res.malware_families) l.push(`- ${m}`); }
  if(res.geolocation){ l.push('', '## Geolocation'); l.push(`- Country: ${res.geolocation.country || 'N/A'}`); if(res.geolocation.city) l.push(`- City: ${res.geolocation.city}`); }
  l.push('', '## Notes', '- Generated locally without hosting.');
  return l.join(os.EOL);
}

function printHelp(){
  console.log(`\nUsage: node tools/run-intel.js --indicator <ip|domain> [--type ip|domain|auto] [--out reports]\n`);
}

async function main(){
  const args=parseArgs(process.argv); if(args.help||!args.indicator){printHelp(); process.exit(args.help?0:1);} 
  const ti=new ThreatIntel();
  let res; const ind=args.indicator; const type=args.type;
  if(type==='ip'||(type==='auto' && ind.match(/^\d+\.\d+\.\d+\.\d+$/))){ res=await ti.checkIP(ind); }
  else { res=await ti.checkDomain(ind); }
  // Secure path resolution to prevent traversal
  const safeOut = ensureSafeDirectory(args.out);
  const base = resolveSafePath(safeOut, `intel_${Date.now()}`);
  fs.writeFileSync(`${base}.json`, JSON.stringify(res,null,2),'utf8');
  fs.writeFileSync(`${base}.md`, toMarkdown(res),'utf8');
  console.log('✅ Threat intel done:', `${base}.json`);
}

main().catch(e=>{ console.error(e); process.exit(1); });

#!/usr/bin/env node
// Local recon runner: DNS, headers, geolocation; outputs JSON/MD.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { NetworkRecon } from '../cli/lib/recon.js';

function parseArgs(argv){
  const args={ target:'', out:'reports', dns:true, whois:false, ports:false, subdomain:false };
  for(let i=2;i<argv.length;i++){
    const a=argv[i],n=argv[i+1];
    if((a==='--target'||a==='-t')&&n){args.target=n;i++;continue;}
    if(a==='--dns=false'){args.dns=false;}
    if(a==='--whois'){args.whois=true;}
    if(a==='--ports'){args.ports=true;}
    if(a==='--subdomain'){args.subdomain=true;}
    if((a==='--out'||a==='-o')&&n){args.out=n;i++;continue;}
    if(a==='--help'||a==='-h'){args.help=true}
  }
  return args;
}

function toMarkdown(res){
  const l=[]; l.push(`# Scorpion Recon Report`,''); l.push(`- Target: ${res.target}`); l.push(`- Time: ${res.timestamp}`,'');
  l.push('## DNS Records');
  if(Array.isArray(res.dns)&&res.dns.length){ for(const r of res.dns) l.push(`- ${r.type}: ${r.value}${r.priority?` (prio ${r.priority})`:''}`);} else l.push('- None');
  l.push('', '## Geolocation');
  if(res.geolocation){ l.push(`- ${JSON.stringify(res.geolocation)}`);} else l.push('- N/A');
  l.push('', '## Headers');
  if(res.headers){ l.push(`- ${JSON.stringify(res.headers)}`);} else l.push('- N/A');
  return l.join(os.EOL);
}

async function main(){
  const args=parseArgs(process.argv); if(args.help||!args.target){console.log(`\nUsage: node tools/run-recon.js --target <host> [--whois] [--ports] [--subdomain]\n`); process.exit(args.help?0:1);} 
  const recon=new NetworkRecon(); const res=await recon.discover(args.target, args);
  fs.mkdirSync(args.out,{recursive:true}); const base=path.join(args.out,`recon_${Date.now()}`);
  fs.writeFileSync(`${base}.json`, JSON.stringify(res,null,2),'utf8');
  fs.writeFileSync(`${base}.md`, toMarkdown(res),'utf8');
  console.log('✅ Recon done:', `${base}.json`);
}

main().catch(e=>{ console.error(e); process.exit(1); });

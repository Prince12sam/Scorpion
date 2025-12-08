#!/usr/bin/env node
// Local password audit runner: crack hashes, breach check, strength analysis. No hosting.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { PasswordSecurity } from '../cli/lib/password-security.js';
import { resolveSafePath, ensureSafeDirectory } from '../cli/lib/path-guard.js';

function parseArgs(argv){
  const a={ mode:'help', hashFile:'', wordlist:'', email:'', password:'', out:'reports' };
  for(let i=2;i<argv.length;i++){
    const k=argv[i], n=argv[i+1];
    if(k==='crack'){ a.mode='crack'; continue; }
    if(k==='breach'){ a.mode='breach'; continue; }
    if(k==='strength'){ a.mode='strength'; continue; }
    if((k==='--hashes'||k==='-h')&&n){ a.hashFile=n; i++; continue; }
    if((k==='--wordlist'||k==='-w')&&n){ a.wordlist=n; i++; continue; }
    if((k==='--email'||k==='-e')&&n){ a.email=n; i++; continue; }
    if((k==='--password'||k==='-p')&&n){ a.password=n; i++; continue; }
    if((k==='--out'||k==='-o')&&n){ a.out=n; i++; continue; }
    if(k==='--help'||k==='-?'){ a.mode='help'; }
  }
  return a;
}

function help(){
  console.log(`\nUsage:\n  node tools/run-password.js crack --hashes <file> [--wordlist <file>] [--out reports]\n  node tools/run-password.js breach --email <address> [--out reports]\n  node tools/run-password.js strength --password <string> [--out reports]\n`);
}

function writeOut(base, json, md){ fs.mkdirSync(path.dirname(base), { recursive: true }); fs.writeFileSync(base+`.json`, JSON.stringify(json,null,2),'utf8'); fs.writeFileSync(base+`.md`, md, 'utf8'); }

function mdCrack(r){ const l=[]; l.push(`# Scorpion Password Cracking Report`,''); l.push(`- Total: ${r.total}`); l.push(`- Cracked: ${r.cracked}`); l.push(`- Time: ${r.time_elapsed}s`,'', '## Results'); for(const it of r.results){ l.push(`- ${it.hash} [${it.hash_type}] => ${it.cracked? it.password : 'NOT CRACKED'} ${it.method? '('+it.method+')':''}`);} return l.join(os.EOL); }
function mdBreach(r){ const l=[]; l.push(`# Scorpion Breach Check`,''); l.push(`- Email: ${r.email}`); l.push(`- Breached: ${r.breached}`); l.push(`- Count: ${r.breach_count}`,''); if(r.breaches?.length){ l.push('## Breaches'); for(const b of r.breaches){ l.push(`- ${b.name} (${b.date||'N/A'})`);} } return l.join(os.EOL); }
function mdStrength(r){ const l=[]; l.push(`# Scorpion Password Strength`,''); l.push(`- Length: ${r.password_length}`); l.push(`- Strength: ${r.strength}`); l.push(`- Score: ${r.score}`); l.push(`- Entropy: ${r.entropy.toFixed ? r.entropy.toFixed(2) : r.entropy}`); l.push(`- Time to crack: ${r.time_to_crack}`); if(r.feedback?.length){ l.push('', '## Feedback'); for(const f of r.feedback) l.push(`- ${f}`);} return l.join(os.EOL); }

async function main(){
  const args=parseArgs(process.argv); if(args.mode==='help'){ help(); process.exit(0); }
  const ps=new PasswordSecurity();
  const outputRoot = ensureSafeDirectory(args.out || 'reports', { description: 'output directory' });
  const stamp = Date.now();
  if(args.mode==='crack'){
    if(!args.hashFile){ help(); process.exit(1); }
    const hashFilePath = resolveSafePath(args.hashFile, { mustExist: true, description: 'hash file' });
    const wordlistPath = args.wordlist ? resolveSafePath(args.wordlist, { mustExist: true, description: 'wordlist file' }) : null;
    const res = await ps.crackHashes(hashFilePath, wordlistPath);
    const base = path.join(outputRoot, `password_crack_${stamp}`);
    writeOut(base, res, mdCrack(res));
    console.log('✅ Crack results:', `${base}.json`);
    return;
  }
  if(args.mode==='breach'){
    if(!args.email){ help(); process.exit(1); }
    const res = await ps.checkBreach(args.email);
    const base = path.join(outputRoot, `password_breach_${stamp}`);
    writeOut(base, res, mdBreach(res));
    console.log('✅ Breach results:', `${base}.json`);
    return;
  }
  if(args.mode==='strength'){
    if(!args.password){ help(); process.exit(1); }
    const res = ps.analyzePasswordStrength(args.password);
    const base = path.join(outputRoot, `password_strength_${stamp}`);
    writeOut(base, res, mdStrength(res));
    console.log('✅ Strength results:', `${base}.json`);
    return;
  }
  help(); process.exit(1);
}

main().catch(e=>{ console.error(e); process.exit(1); });

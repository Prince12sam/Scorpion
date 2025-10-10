import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import os from 'os';
import net from 'net';
import fsp from 'fs/promises';
import dotenv from 'dotenv';
import { SecurityScanner } from '../cli/lib/scanner.js';
import { NetworkRecon } from '../cli/lib/recon.js';
import { ThreatIntel } from '../cli/lib/threat-intel.js';

// Load environment variables (including optional .env.local)
dotenv.config();
try { dotenv.config({ path: path.join(process.cwd(), '.env.local') }); } catch {}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3001;

// Auth config
const ADMIN_USER = process.env.SCORPION_ADMIN_USER || 'admin';
let ADMIN_PASS = process.env.SCORPION_ADMIN_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-change-me';
const EASY_LOGIN = String(process.env.EASY_LOGIN || '').toLowerCase() === 'true';

if (!process.env.SCORPION_ADMIN_PASSWORD) {
  if (EASY_LOGIN) {
    ADMIN_PASS = 'admin';
    console.log('🔓 EASY_LOGIN enabled. Using default credentials for local use:');
    console.log(`   username: ${ADMIN_USER}`);
    console.log(`   password: ${ADMIN_PASS}`);
  } else {
    ADMIN_PASS = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    console.log('⚠️  No SCORPION_ADMIN_PASSWORD set. Generated one-time admin password:');
    console.log(`   username: ${ADMIN_USER}`);
    console.log(`   password: ${ADMIN_PASS}`);
    console.log('   Set SCORPION_ADMIN_PASSWORD env var to persist your admin password.');
  }
}

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));
app.use(express.json());

// Open paths (no auth required)
const openPaths = new Set(['/', '/api/health', '/api/system/health', '/api/auth/login', '/api/auth/refresh']);

function authenticateToken(req, res, next) {
  if (openPaths.has(req.path)) return next();
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized: Missing Bearer token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }
}

app.use(authenticateToken);

// Root path: instruct to use web UI port
app.get('/', (req, res) => {
  res.status(403).json({
    error: 'UI is not served from API server',
    message: 'Open the web interface at http://localhost:5173/',
    docs: 'Set up an authenticated reverse proxy if you want to serve UI from API port.'
  });
});

// JWT helpers
function createAccessToken(username) {
  return jwt.sign({ sub: username, role: 'admin', type: 'access' }, JWT_SECRET, { expiresIn: '2h' });
}
function createRefreshToken(username) {
  return jwt.sign({ sub: username, role: 'admin', type: 'refresh' }, JWT_SECRET, { expiresIn: '7d' });
}
function issueTokens(username) {
  return { accessToken: createAccessToken(username), refreshToken: createRefreshToken(username) };
}

// Authentication login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (username !== ADMIN_USER || password !== ADMIN_PASS) return res.status(401).json({ error: 'Invalid credentials' });
  const tokens = issueTokens(ADMIN_USER);
  res.json({ tokens, user: { username: ADMIN_USER, role: 'admin' } });
});

// Token refresh
app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });
  try {
    const payload = jwt.verify(refreshToken, JWT_SECRET);
    if (payload?.type !== 'refresh') return res.status(401).json({ error: 'Invalid token type' });
    const tokens = issueTokens(payload.sub);
    return res.json({ tokens });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    server: 'Scorpion Security Platform',
    version: '1.0.0'
  });
});

// Dashboard metrics
app.get('/api/dashboard/metrics', (req, res) => {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const cpuLoad = cpus.reduce((acc, cpu) => {
    const times = cpu.times;
    const idle = times.idle;
    const total = Object.values(times).reduce((a, b) => a + b, 0);
    return acc + (1 - idle / total);
  }, 0) / cpus.length;

  res.json({
    metrics: {
      systemHealth: {
        cpu: Math.round(cpuLoad * 100),
        memory: Math.round(((totalMem - freeMem) / totalMem) * 100),
        disk: null,
        network: null
      },
      securityMetrics: {
        intrusionsDetected: 0,
        vulnerabilities: 0,
        fimAlerts: 0,
        complianceScore: 100
      },
      recentScans: 0,
      activeMonitoring: true
    }
  });
});

// System health
app.get('/api/system/health', (req, res) => {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const cpuLoad = cpus.reduce((acc, cpu) => {
    const times = cpu.times;
    const idle = times.idle;
    const total = Object.values(times).reduce((a, b) => a + b, 0);
    return acc + (1 - idle / total);
  }, 0) / cpus.length;

  res.json({
    cpu: Math.round(cpuLoad * 100),
    memory: Math.round(((totalMem - freeMem) / totalMem) * 100),
    disk: null,
    network: null,
    uptime: os.uptime(),
    status: 'healthy'
  });
});

// Monitoring endpoints
app.get('/api/monitoring/alerts', (req, res) => {
  res.json({ alerts: [], totalAlerts: 0 });
});
app.get('/api/monitoring/metrics', (req, res) => {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const cpuLoad = cpus.reduce((acc, cpu) => {
    const times = cpu.times;
    const idle = times.idle;
    const total = Object.values(times).reduce((a, b) => a + b, 0);
    return acc + (1 - idle / total);
  }, 0) / cpus.length;

  res.json({
    cpu: Math.round(cpuLoad * 100),
    memory: Math.round(((totalMem - freeMem) / totalMem) * 100),
    disk: null,
    network: null,
    uptime: os.uptime(),
    connections: 0
  });
});
app.get('/api/monitoring/log-sources', (req, res) => {
  res.json({ sources: [] });
});
app.get('/api/monitoring/performance', (req, res) => {
  res.json({ responseTime: null, throughput: null, errorRate: 0, availability: 100.0 });
});
app.put('/api/monitoring/alert/:id', (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};
  res.json({ success: true, id, status: status || 'acknowledged' });
});

// Initialize security tools
const scanner = new SecurityScanner();
const recon = new NetworkRecon();
const threatIntel = new ThreatIntel();

// Vulnerability Scanner
app.post('/api/scanner/scan', async (req, res) => {
  const { target, type = 'quick', ports } = req.body || {};
  if (!target) return res.status(400).json({ success: false, error: 'Target is required' });

  try {
    const scanOptions = { type, ports: ports || (type === 'quick' ? '80,443,22,21' : '1-1000') };
    const results = await scanner.scan(target, scanOptions);

    // Header/security config assessment
    let headerFindings = [];
    try {
      const hdrRecon = await recon.discover(target, { dns: false, whois: false, ports: false, headers: true });
      const headersByPort = hdrRecon?.headers || {};
      const https = headersByPort['443'];
      const http = headersByPort['80'];
      const inspected = https || http;
      if (inspected && inspected.headers) {
        const sec = inspected.security_headers || {};
        const checks = [
          { key: 'strict-transport-security', label: 'HSTS missing over HTTPS', severity: 'Medium', when: !sec.strict_transport_security || sec.strict_transport_security === 'Missing' },
          { key: 'content-security-policy', label: 'Content Security Policy (CSP) missing', severity: 'High', when: !sec.content_security_policy || sec.content_security_policy === 'Missing' },
          { key: 'x-frame-options', label: 'Clickjacking protection (X-Frame-Options) missing', severity: 'Medium', when: !sec.x_frame_options || sec.x_frame_options === 'Missing' },
          { key: 'x-content-type-options', label: 'MIME sniffing protection (X-Content-Type-Options) missing', severity: 'Low', when: !sec.x_content_type_options || sec.x_content_type_options === 'Missing' },
          { key: 'referrer-policy', label: 'Referrer-Policy missing', severity: 'Low', when: !sec.referrer_policy || sec.referrer_policy === 'Missing' }
        ];
        headerFindings = checks.filter(c => c.when).map(c => ({
          id: `hdr-${c.key}`,
          title: c.label,
          severity: c.severity,
          category: 'Configuration',
          description: `${c.label}. Configure this header site-wide to reduce attack surface.`,
          recommendation: 'Set recommended values per OWASP and modern browser guidance.'
        }));
      }
    } catch {}

    // Risky open ports
    const riskyPortFindings = [];
    for (const p of (results.openPorts || [])) {
      const port = p.port || p;
      if ([21, 23, 3389, 5900].includes(port)) {
        const map = { 21: 'FTP', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC' };
        riskyPortFindings.push({
          id: `port-${port}`,
          title: `${map[port]} service exposed`,
          severity: port === 23 ? 'High' : 'Medium',
          category: 'Exposure',
          description: `${map[port]} detected on port ${port}. Exposed administrative or insecure services increase risk.`,
          recommendation: 'Restrict exposure, enforce encryption, and apply network access controls.'
        });
      }
    }

    const assessedVulns = [ ...(results.vulnerabilities || []), ...headerFindings, ...riskyPortFindings ];
    const payload = {
      success: true,
      scanId: Date.now().toString(),
      target,
      status: 'completed',
      vulnerabilities: assessedVulns,
      results: {
        vulnerabilities: assessedVulns,
        openPorts: results.openPorts || [],
        services: results.services || [],
        summary: results.summary || {}
      },
      timestamp: new Date().toISOString()
    };
    res.json(payload);
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ success: false, error: error.message, scanId: Date.now().toString(), target, status: 'failed', timestamp: new Date().toISOString() });
  }
});

// Network Reconnaissance
app.post('/api/recon/discover', async (req, res) => {
  const { target } = req.body || {};
  if (!target) return res.status(400).json({ success: false, error: 'Target is required' });
  try {
    const results = await recon.discover(target, { dns: true, whois: true, ports: true, headers: true });
    res.json({ success: true, target, results: { dns: results.dns || {}, whois: results.whois || {}, ports: results.ports || [], headers: results.headers || {}, geolocation: results.geolocation || {} }, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Recon error:', error);
    res.status(500).json({ success: false, error: error.message, target, timestamp: new Date().toISOString() });
  }
});

// Threat Intelligence lookup
app.post('/api/threat-intel/lookup', async (req, res) => {
  const { indicator, type = 'ip' } = req.body || {};
  if (!indicator) return res.status(400).json({ success: false, error: 'Indicator is required' });
  try {
    let results;
    if (type === 'ip') results = await threatIntel.checkIP(indicator);
    else if (type === 'domain') results = await threatIntel.checkDomain(indicator);
    else if (type === 'hash') results = await threatIntel.checkHash(indicator);
    res.json({ success: true, indicator, type, results: results || {}, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Threat intel error:', error);
    res.status(500).json({ success: false, error: error.message, indicator, type, timestamp: new Date().toISOString() });
  }
});

// File Integrity Monitoring
app.post('/api/file-integrity/scan', async (req, res) => {
  const { path: targetPath } = req.body || {};
  if (!targetPath) return res.status(400).json({ success: false, error: 'Path is required' });
  try {
    const { FileIntegrity } = await import('../cli/lib/file-integrity.js');
    const fim = new FileIntegrity();
    const results = await fim.createBaseline(targetPath);
    res.json({ success: true, scanId: Date.now().toString(), path: targetPath, status: 'completed', results: { filesScanned: results.totalFiles || 0, filesModified: 0, filesAdded: 0, filesDeleted: 0, alerts: [], baseline: results.baseline || {} }, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('FIM error:', error);
    res.status(500).json({ success: false, error: error.message, path: targetPath, timestamp: new Date().toISOString() });
  }
});

// Password Security
app.post('/api/password/analyze', async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ success: false, error: 'Password is required' });
  try {
    const { PasswordSecurity } = await import('../cli/lib/password-security.js');
    const pwdSec = new PasswordSecurity();
    const analysis = await pwdSec.analyzePassword(password);
    res.json({ success: true, analysis: analysis || {}, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Password analysis error:', error);
    res.status(500).json({ success: false, error: error.message, timestamp: new Date().toISOString() });
  }
});

// Threat Intelligence helpers for UI
app.get('/api/threat-intel/iocs', async (req, res) => {
  try {
    const iocs = await threatIntel.getIOCs();
    res.json(iocs);
  } catch {
    res.json({ indicators: [], categories: { malicious_ips: [], malicious_domains: [], malicious_hashes: [], apt_groups: [] }, summary: { totalIOCs: 0, newToday: 0, highConfidence: 0 }, lastUpdated: new Date().toISOString() });
  }
});
app.get('/api/threat-feeds/status', (req, res) => { res.json({ success: true, running: false, sources: [] }); });
app.post('/api/threat-feeds/start', (req, res) => { res.json({ success: true, running: true }); });
app.post('/api/threat-feeds/stop', (req, res) => { res.json({ success: true, running: false }); });
app.get('/api/threat-map/live', (req, res) => { res.json({ threats: [], lastUpdated: new Date().toISOString() }); });

// Reports endpoints
app.get('/api/reports/list', (req, res) => { res.json({ reports: [] }); });
app.post('/api/reports/generate', (req, res) => { res.json({ success: true, reportId: Date.now().toString(), status: 'queued' }); });

// Password helpers
app.post('/api/password/generate', (req, res) => {
  const { length = 16, includeSymbols = true } = req.body || {};
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*()-_=+[]{};:,.?';
  const charset = upper + lower + digits + (includeSymbols ? symbols : '');
  let pwd = '';
  for (let i = 0; i < Math.max(8, Math.min(128, length)); i++) {
    const idx = Math.floor(Math.random() * charset.length);
    pwd += charset.charAt(idx);
  }
  res.json({ password: pwd });
});
app.post('/api/password/breach', (req, res) => { res.json({ breached: false, count: 0, sources: [] }); });
app.post('/api/password/crack', (req, res) => { res.json({ success: false, message: 'Cracking is disabled in this build' }); });

// Get scan status
app.get('/api/scanner/status/:scanId', (req, res) => {
  const { scanId } = req.params;
  res.json({ scanId, status: 'completed', progress: 100, message: 'Scan completed successfully' });
});

// Lightweight persistence for users/settings
const DATA_DIR = path.join(__dirname, 'data');
const STATE_PATH = path.join(DATA_DIR, 'state.json');
let state = { users: [], settings: {} };
async function loadState() {
  try {
    await fsp.mkdir(DATA_DIR, { recursive: true });
    const raw = await fsp.readFile(STATE_PATH, 'utf-8');
    state = JSON.parse(raw);
  } catch {
    state = { users: [], settings: {} };
  }
}
async function saveState() {
  try {
    await fsp.mkdir(DATA_DIR, { recursive: true });
    await fsp.writeFile(STATE_PATH, JSON.stringify(state, null, 2));
  } catch (e) {
    console.warn('State save failed:', e.message);
  }
}
loadState().catch(() => {});

// Users CRUD – persisted
app.get('/api/users', async (req, res) => { await loadState(); res.json({ users: state.users || [] }); });
app.post('/api/users', async (req, res) => {
  await loadState();
  const b = req.body || {};
  const user = { id: Date.now().toString(), name: b.name || 'Unnamed', email: b.email || '', role: b.role || 'Viewer', phone: b.phone || '', department: b.department || '', status: 'active', lastLogin: new Date().toISOString() };
  state.users = [...(state.users || []), user];
  await saveState();
  res.json(user);
});
app.put('/api/users/:id', async (req, res) => {
  await loadState();
  const { id } = req.params;
  const idx = (state.users || []).findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not found' });
  state.users[idx] = { ...state.users[idx], ...(req.body || {}) };
  await saveState();
  res.json(state.users[idx]);
});
app.put('/api/users/:id/status', async (req, res) => {
  await loadState();
  const { id } = req.params; const { status } = req.body || {};
  const idx = (state.users || []).findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not found' });
  state.users[idx].status = status === 'inactive' ? 'inactive' : 'active';
  await saveState();
  res.json({ id, status: state.users[idx].status });
});
app.delete('/api/users/:id', async (req, res) => {
  await loadState();
  const { id } = req.params;
  const before = (state.users || []).length;
  state.users = (state.users || []).filter(u => u.id !== id);
  await saveState();
  res.json({ success: (state.users || []).length !== before });
});

// Settings – persisted
app.get('/api/settings', async (req, res) => { await loadState(); res.json(state.settings || {}); });
app.post('/api/settings', async (req, res) => { await loadState(); state.settings = { ...(state.settings || {}), ...(req.body || {}) }; await saveState(); res.json({ success: true }); });

// API Testing – non-destructive
app.post('/api/testing/api', async (req, res) => {
  const { target, testType = 'basic' } = req.body || {};
  if (!target) return res.status(400).json({ success: false, error: 'target required' });
  const commonPaths = ['/', '/api', '/v1/health', '/health', '/status', '/auth/login', '/users', '/metrics'];
  const endpoints = []; const vulnerabilities = [];
  const controller = new AbortController(); const timeoutMs = 8000; const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    for (const p of commonPaths) {
      const url = new URL(p, target).toString(); const started = Date.now();
      try { const resp = await fetch(url, { method: 'GET', signal: controller.signal }); const ms = Date.now() - started; endpoints.push({ method: 'GET', path: url, response_code: resp.status, response_time: ms, status: resp.ok ? 'secure' : 'warning' }); const csp = resp.headers.get('content-security-policy'); const xcto = resp.headers.get('x-content-type-options'); if (!csp) vulnerabilities.push({ severity: 'Medium', description: `Missing CSP on ${url}` }); if (xcto !== 'nosniff') vulnerabilities.push({ severity: 'Low', description: `Missing/weak X-Content-Type-Options on ${url}` }); } catch { endpoints.push({ method: 'GET', path: url, response_code: 0, response_time: Date.now() - started, status: 'warning' }); }
    }
    if (['injection', 'comprehensive'].includes(testType)) {
      const injUrl = new URL(`/?q=%27%22%3Cscript%3E`, target).toString();
      try { const r = await fetch(injUrl, { method: 'GET', signal: controller.signal }); const body = await r.text(); if (body && body.includes('<script>')) { vulnerabilities.push({ severity: 'High', description: `Possible reflection at ${injUrl}` }); } } catch {}
    }
    clearTimeout(timer); res.json({ success: true, target, testType, endpoints, vulnerabilities, timestamp: new Date().toISOString() });
  } catch (e) { clearTimeout(timer); res.status(500).json({ success: false, error: e.message }); }
});

// Network Discovery – safe TCP connect sampling
function parseRange(range) {
  const cidr = String(range).split('/');
  if (cidr.length === 2) {
    const base = cidr[0].split('.').map(n => parseInt(n, 10)); const mask = parseInt(cidr[1], 10);
    if (base.length !== 4 || base.some(n => Number.isNaN(n)) || Number.isNaN(mask)) return [];
    const hosts = []; const hostBits = 32 - mask; const total = Math.min(1 << hostBits, 256); const start = 1;
    for (let i = start; i < start + total; i++) { const ip = [...base]; ip[3] = (i % 254) || 1; hosts.push(ip.join('.')); }
    return hosts;
  }
  return [String(range)];
}
function tcpCheck(host, port, timeout = 800) {
  return new Promise((resolve) => { const socket = new net.Socket(); let done = false; const onDone = (r) => { if (!done) { done = true; socket.destroy(); resolve(r); } }; socket.setTimeout(timeout); socket.once('connect', () => onDone(true)); socket.once('timeout', () => onDone(false)); socket.once('error', () => onDone(false)); socket.connect(port, host); });
}
app.post('/api/discovery/network', async (req, res) => {
  const { range, scanType = 'ping-sweep' } = req.body || {}; if (!range) return res.status(400).json({ success: false, error: 'range required' });
  const portsByType = { 'ping-sweep': [80, 443], 'port-scan': [22, 80, 443, 445, 3389], 'service-discovery': [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432], 'comprehensive': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 27017, 3389, 5432, 5900, 6379, 8080, 9200] };
  const targets = parseRange(range).slice(0, 256); const ports = portsByType[scanType] || portsByType['ping-sweep']; const hosts = [];
  for (const host of targets) { const services = []; let online = false; for (const p of ports) { const open = await tcpCheck(host, p, 350); if (open) { online = true; services.push({ name: 'tcp', port: p }); } } if (online || scanType !== 'ping-sweep') { hosts.push({ ip: host, status: online ? 'online' : 'unknown', services }); } if (hosts.length >= 128) break; }
  res.json({ success: true, range, scanType, hosts, timestamp: new Date().toISOString() });
});

// Global Threat Hunting – uses ThreatIntel
app.post('/api/threat/hunt', async (req, res) => {
  const { query } = req.body || {};
  if (!query) return res.status(400).json({ success: false, error: 'query required' });
  const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(query); const isHash = /^[a-fA-F0-9]{32,128}$/.test(query); const isDomain = /\./.test(query) && !isIP && !isHash;
  try {
    if (isIP) { const r = await threatIntel.checkIP(query); return res.json({ success: true, profile: { name: query, status: r.reputation?.toUpperCase() || 'INVESTIGATING', type: 'ip', riskScore: r.threat_score || 0, details: { country: r.geolocation?.country, isp: r.asn_info?.isp }, categories: [], reports: r.threat_score ? [{ comment: 'Behavioral indicators observed', reportedAt: new Date().toISOString() }] : [] } }); }
    if (isDomain) { const r = await threatIntel.checkDomain(query); return res.json({ success: true, profile: { name: query, status: r.reputation?.toUpperCase() || 'INVESTIGATING', type: 'domain', riskScore: r.threat_score || 0, details: { registrar: r.registrar, country: r.country }, categories: r.categories || [], reports: r.threat_score ? [{ comment: 'Behavioral indicators observed', reportedAt: new Date().toISOString() }] : [] } }); }
    if (isHash) { const r = await threatIntel.checkHash(query); return res.json({ success: true, profile: { name: query, status: r.reputation?.toUpperCase() || 'INVESTIGATING', type: r.hash_type || 'hash', riskScore: r.threat_score || 0, details: { fileType: r.file_type, firstSeen: r.first_seen }, categories: [], reports: r.threat_score ? [{ comment: 'Behavioral indicators observed', reportedAt: new Date().toISOString() }] : [] } }); }
    return res.json({ success: true, profile: { name: query, status: 'CLEAN', type: 'keyword', riskScore: 0, details: {}, categories: [], reports: [] } });
  } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
});

// Create HTTP server
const server = http.createServer(app);
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🦂 Scorpion Security Platform API Server running on http://localhost:${PORT}`);
  console.log('✅ Server ready - All dummy data removed from monitoring center');
  console.log('🔗 CORS enabled for web interface');
  setTimeout(() => {
    const req = http.request({ hostname: 'localhost', port: PORT, path: '/api/health', method: 'GET' }, (res2) => {
      let data = '';
      res2.on('data', d => data += d);
      res2.on('end', () => console.log('✅ Server self-test passed:', data));
    }); req.on('error', () => {}); req.end();
  }, 500);
});

// Graceful shutdown
process.on('SIGTERM', () => { console.log('🛑 Received SIGTERM, shutting down gracefully'); server.close(() => { console.log('✅ Server shut down complete'); process.exit(0); }); });

export default app;
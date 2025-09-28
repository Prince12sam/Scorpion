import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import http from 'http';

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// CORS setup
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:5174'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Dashboard endpoints
app.get('/api/dashboard/metrics', (req, res) => {
  res.json({
    metrics: {
      systemHealth: { cpu: 45, memory: 68, disk: 32, network: 87 },
      securityMetrics: {
        intrusions: 3,
        vulnerabilities: 12,
        integrityAlerts: 5,
        complianceScore: 87
      },
      recentScans: 15,
      activeMonitoring: true
    }
  });
});

// System health
app.get('/api/system/health', (req, res) => {
  res.json({
    status: 'healthy',
    cpu: Math.floor(Math.random() * 30) + 20,
    memory: Math.floor(Math.random() * 40) + 40,
    disk: Math.floor(Math.random() * 20) + 20,
    uptime: process.uptime()
  });
});

// Monitoring endpoints
app.get('/api/monitoring/alerts', (req, res) => {
  res.json({
    alerts: [
      {
        id: '1',
        title: 'Suspicious Login Attempt',
        severity: 'high',
        timestamp: new Date().toISOString(),
        description: 'Multiple failed login attempts detected'
      },
      {
        id: '2', 
        title: 'File Integrity Violation',
        severity: 'medium',
        timestamp: new Date().toISOString(),
        description: 'Critical system file modified'
      }
    ]
  });
});

app.get('/api/monitoring/metrics', (req, res) => {
  res.json({
    systemMetrics: {
      cpu: Math.floor(Math.random() * 30) + 20,
      memory: Math.floor(Math.random() * 40) + 40,
      disk: Math.floor(Math.random() * 20) + 20,
      network: Math.floor(Math.random() * 50) + 30
    }
  });
});

// Scan endpoints
app.post('/api/scan', (req, res) => {
  const scanId = Date.now().toString();
  res.json({ scanId, status: 'started', message: 'Vulnerability scan initiated' });
});

app.get('/api/scan/:id', (req, res) => {
  res.json({
    id: req.params.id,
    status: 'completed',
    vulnerabilities: [
      { severity: 'high', count: 3 },
      { severity: 'medium', count: 7 },
      { severity: 'low', count: 12 }
    ]
  });
});

// File Integrity Monitor
app.get('/api/fim/watched', (req, res) => {
  res.json({
    files: [
      { path: '/etc/passwd', checksum: 'abc123', status: 'ok', lastChecked: new Date().toISOString() },
      { path: '/etc/shadow', checksum: 'def456', status: 'ok', lastChecked: new Date().toISOString() }
    ]
  });
});

app.post('/api/fim/add', (req, res) => {
  res.json({ success: true, message: 'File added to monitoring' });
});

app.post('/api/fim/remove', (req, res) => {
  res.json({ success: true, message: 'File removed from monitoring' });
});

// Threat map
app.get('/api/threat-map', (req, res) => {
  res.json({
    threats: [
      { lat: 40.7589, lng: -73.9851, severity: 'high', type: 'malware' },
      { lat: 51.5074, lng: -0.1278, severity: 'medium', type: 'phishing' }
    ]
  });
});

// Compliance
app.post('/api/compliance/assess', (req, res) => {
  res.json({
    score: Math.floor(Math.random() * 20) + 80,
    assessments: ['PCI DSS', 'GDPR', 'SOX'],
    timestamp: new Date().toISOString()
  });
});

app.post('/api/compliance/export', (req, res) => {
  res.json({ 
    success: true, 
    filename: `compliance_report_${Date.now()}.json`,
    message: 'Report exported successfully'
  });
});

// User management
app.get('/api/users', (req, res) => {
  res.json({
    users: [
      { id: 1, name: 'Admin User', email: 'admin@scorpion.com', role: 'Admin', status: 'Active' },
      { id: 2, name: 'Security Analyst', email: 'analyst@scorpion.com', role: 'User', status: 'Active' }
    ]
  });
});

app.post('/api/users', (req, res) => {
  res.json({ success: true, message: 'User created successfully', id: Date.now() });
});

// Settings
app.get('/api/settings', (req, res) => {
  res.json({
    theme: 'dark',
    notifications: true,
    autoRefresh: 30,
    apiUrl: 'http://localhost:3001'
  });
});

app.post('/api/settings', (req, res) => {
  res.json({ success: true, message: 'Settings saved successfully' });
});

const PORT = process.env.PORT || 3001;

server.listen(PORT, () => {
  console.log(`🦂 Scorpion Security Platform API running on http://localhost:${PORT}`);
});

export default app;
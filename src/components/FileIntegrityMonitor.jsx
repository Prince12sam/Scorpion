import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Bot, Target, Zap, Shield, AlertTriangle, CheckCircle, XCircle, Play, Pause, 
  Search, Network, Lock, Unlock, Upload, Download, Terminal, Bug, 
  FileCode, Server, Database, Crosshair, Eye, Activity, Skull, Radio,
  Filter, Code, Globe, HardDrive, Wifi, Package, Key, ShieldAlert
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const AIPentestAgent = () => {
  const [isAgentRunning, setIsAgentRunning] = useState(false);
  const [currentPhase, setCurrentPhase] = useState('idle');
  const [targetIp, setTargetIp] = useState('');
  const [targetPort, setTargetPort] = useState('80,443,22,21,3306,3389');
  const [agentLogs, setAgentLogs] = useState([]);
  const [discoveries, setDiscoveries] = useState({
    openPorts: [],
    vulnerabilities: [],
    services: [],
    exploits: []
  });
  const [attackMode, setAttackMode] = useState('stealth'); // stealth, aggressive, surgical
  const [showConfig, setShowConfig] = useState(false);
  const [exploitResults, setExploitResults] = useState([]);
  const [shellSessions, setShellSessions] = useState([]);
  const [exfiltratedData, setExfiltratedData] = useState([]);
  const [autoDefense, setAutoDefense] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  const phases = [
    { id: 'reconnaissance', name: 'Reconnaissance', icon: Search, color: 'blue' },
    { id: 'enumeration', name: 'Enumeration', icon: Network, color: 'cyan' },
    { id: 'vulnerability', name: 'Vuln Discovery', icon: Bug, color: 'yellow' },
    { id: 'exploitation', name: 'Exploitation', icon: Zap, color: 'orange' },
    { id: 'post-exploitation', name: 'Post-Exploit', icon: Skull, color: 'red' },
    { id: 'persistence', name: 'Persistence', icon: Lock, color: 'purple' },
    { id: 'exfiltration', name: 'Data Exfil', icon: Download, color: 'pink' }
  ];

  const addLog = (message, type = 'info', phase = '') => {
    const log = {
      id: Date.now() + Math.random(),
      message,
      type, // info, success, warning, error
      phase,
      timestamp: new Date().toLocaleTimeString()
    };
    setAgentLogs(prev => [log, ...prev].slice(0, 100));
  };

  const runAIPentestAgent = async () => {
    if (!targetIp.trim()) {
      toast({
        title: "Target Required",
        description: "Please specify a target IP or domain",
        variant: "destructive"
      });
      return;
    }

    setIsAgentRunning(true);
    setAgentLogs([]);
    setScanProgress(0);
    addLog(`🤖 AI Pentesting Agent initialized - REAL MODE`, 'success');
    addLog(`⚠️  WARNING: Using REAL exploitation techniques`, 'warning');
    addLog(`🎯 Target: ${targetIp} | Mode: ${attackMode}`, 'info');

    try {
      // Phase 1: Reconnaissance
      setCurrentPhase('reconnaissance');
      addLog('🔍 Phase 1: Starting reconnaissance...', 'info', 'reconnaissance');
      setScanProgress(10);
      
      const reconResponse = await fetch('/api/ai-pentest/reconnaissance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetIp, mode: attackMode })
      });
      const reconData = await reconResponse.json();
      addLog(`✅ DNS: ${reconData.dns?.hostname || 'N/A'} | ${reconData.dns?.ips?.length || 0} IPs`, 'success', 'reconnaissance');
      addLog(`✅ GeoIP: ${reconData.geo?.country || 'Unknown'} | ISP: ${reconData.geo?.isp || 'Unknown'}`, 'success', 'reconnaissance');
      setScanProgress(20);

      // Phase 2: Enumeration (Port Scanning)
      setCurrentPhase('enumeration');
      addLog('🌐 Phase 2: Enumerating open ports and services...', 'info', 'enumeration');
      
      const enumResponse = await fetch('/api/ai-pentest/enumerate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetIp, ports: targetPort })
      });
      const enumData = await enumResponse.json();
      
      setDiscoveries(prev => ({
        ...prev,
        openPorts: enumData.openPorts || [],
        services: enumData.services || []
      }));
      
      addLog(`✅ Found ${enumData.openPorts?.length || 0} open ports`, 'success', 'enumeration');
      enumData.openPorts?.forEach(port => {
        addLog(`  ├─ Port ${port.port}/tcp OPEN [${port.service}] ${port.version || ''}`, 'info', 'enumeration');
      });
      setScanProgress(40);

      // Phase 3: Vulnerability Discovery
      setCurrentPhase('vulnerability');
      addLog('🐛 Phase 3: Scanning for vulnerabilities...', 'info', 'vulnerability');
      
      const vulnResponse = await fetch('/api/ai-pentest/scan-vulns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetIp, ports: enumData.openPorts })
      });
      const vulnData = await vulnResponse.json();
      
      setDiscoveries(prev => ({
        ...prev,
        vulnerabilities: vulnData.vulnerabilities || []
      }));
      
      addLog(`✅ Identified ${vulnData.vulnerabilities?.length || 0} vulnerabilities`, 'success', 'vulnerability');
      vulnData.vulnerabilities?.forEach(vuln => {
        const severity = vuln.severity?.toUpperCase();
        const emoji = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : '🟡';
        addLog(`  ${emoji} [${severity}] ${vuln.name} (${vuln.cve || 'N/A'})`, 'warning', 'vulnerability');
      });
      setScanProgress(60);

      // Phase 4: Exploitation
      setCurrentPhase('exploitation');
      addLog('⚡ Phase 4: Attempting exploitation...', 'info', 'exploitation');
      
      const exploitResponse = await fetch('/api/ai-pentest/exploit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          target: targetIp, 
          vulnerabilities: vulnData.vulnerabilities,
          mode: attackMode 
        })
      });
      const exploitData = await exploitResponse.json();
      
      setExploitResults(exploitData.results || []);
      addLog(`✅ ${exploitData.successful || 0} exploits successful`, 'success', 'exploitation');
      exploitData.results?.forEach(result => {
        if (result.success) {
          addLog(`  ✓ ${result.exploit} executed successfully`, 'success', 'exploitation');
        }
      });
      setScanProgress(75);

      // Phase 5: Post-Exploitation (Shell Access)
      if (exploitData.successful > 0) {
        setCurrentPhase('post-exploitation');
        addLog('💀 Phase 5: Post-exploitation activities...', 'info', 'post-exploitation');
        
        const postExploitResponse = await fetch('/api/ai-pentest/post-exploit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: targetIp, sessions: exploitData.sessions })
        });
        const postExploitData = await postExploitResponse.json();
        
        setShellSessions(postExploitData.shells || []);
        addLog(`✅ Established ${postExploitData.shells?.length || 0} shell sessions`, 'success', 'post-exploitation');
        addLog(`✅ Privilege level: ${postExploitData.privilege || 'user'}`, 'success', 'post-exploitation');
        setScanProgress(85);

        // Phase 6: Data Exfiltration
        setCurrentPhase('exfiltration');
        addLog('📤 Phase 6: Exfiltrating sensitive data...', 'info', 'exfiltration');
        
        const exfilResponse = await fetch('/api/ai-pentest/exfiltrate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: targetIp, shells: postExploitData.shells })
        });
        const exfilData = await exfilResponse.json();
        
        setExfiltratedData(exfilData.data || []);
        addLog(`✅ Exfiltrated ${exfilData.data?.length || 0} files/databases`, 'success', 'exfiltration');
        exfilData.data?.forEach(item => {
          addLog(`  ├─ ${item.type}: ${item.name} (${item.size})`, 'info', 'exfiltration');
        });
      }

      setScanProgress(100);
      addLog('🎉 AI Pentesting Agent completed all phases!', 'success');
      
      toast({
        title: "Pentest Complete",
        description: `Found ${discoveries.vulnerabilities.length} vulnerabilities, ${exploitResults.filter(r => r.success).length} exploits successful`
      });

    } catch (error) {
      addLog(`❌ Agent error: ${error.message}`, 'error');
      toast({
        title: "Agent Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsAgentRunning(false);
      setCurrentPhase('complete');
    }
  };

  const stopAgent = () => {
    setIsAgentRunning(false);
    setCurrentPhase('idle');
    addLog('🛑 Agent stopped by user', 'warning');
  };

  const fixMisconfigurations = async () => {
    addLog('🔧 Scanning for misconfigurations...', 'info');
    
    try {
      const response = await fetch('/api/ai-pentest/fix-misconfig', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetIp, discoveries })
      });
      const data = await response.json();
      
      addLog(`✅ Fixed ${data.fixed || 0} misconfigurations`, 'success');
      data.fixes?.forEach(fix => {
        addLog(`  ✓ ${fix.issue}: ${fix.action}`, 'success');
      });
      
      toast({
        title: "Hardening Complete",
        description: `Applied ${data.fixed || 0} security fixes`
      });
    } catch (error) {
      toast({
        title: "Fix Failed",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const blockAttacks = async () => {
    setAutoDefense(!autoDefense);
    
    if (!autoDefense) {
      addLog('🛡️ Auto-defense activated - monitoring for attacks', 'success');
      
      try {
        await fetch('/api/ai-pentest/auto-defense', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: true, target: targetIp })
        });
        
        toast({
          title: "Auto-Defense Activated",
          description: "Real-time attack blocking enabled"
        });
      } catch (error) {
        addLog(`❌ Defense activation failed: ${error.message}`, 'error');
      }
    } else {
      addLog('⚠️ Auto-defense deactivated', 'warning');
    }
  };

  const getPhaseIcon = (phase) => {
    const phaseObj = phases.find(p => p.id === phase);
    return phaseObj?.icon || Bot;
  };

  const getPhaseColor = (phase) => {
    const phaseObj = phases.find(p => p.id === phase);
    return phaseObj?.color || 'gray';
  };

  const stats = {
    openPorts: discoveries.openPorts.length,
    vulnerabilities: discoveries.vulnerabilities.length,
    exploits: exploitResults.filter(e => e.success).length,
    shells: shellSessions.length
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
            <Bot className="w-8 h-8 text-cyan-400" />
            AI Pentesting Agent
          </h1>
          <p className="text-slate-400">Autonomous threat hunting & exploitation system</p>
        </div>
        <div className="flex gap-3">
          {!isAgentRunning ? (
            <Button onClick={runAIPentestAgent} className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700">
              <Play className="w-4 h-4 mr-2" />
              Launch Agent
            </Button>
          ) : (
            <Button onClick={stopAgent} className="bg-red-600 hover:bg-red-700">
              <Pause className="w-4 h-4 mr-2" />
              Stop Agent
            </Button>
          )}
          <Button onClick={fixMisconfigurations} variant="outline" className="border-green-600 text-green-400 hover:bg-green-600/20">
            <Shield className="w-4 h-4 mr-2" />
            Fix Misconfig
          </Button>
          <Button 
            onClick={blockAttacks} 
            className={autoDefense ? 'bg-green-600 hover:bg-green-700' : 'bg-slate-600 hover:bg-slate-700'}
          >
            <ShieldAlert className="w-4 h-4 mr-2" />
            {autoDefense ? 'Defense ON' : 'Defense OFF'}
          </Button>
        </div>
      </motion.div>

      {/* Target Configuration */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6 rounded-xl">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Target className="w-5 h-5 text-cyan-400" />
          Target Configuration
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-2">Target IP/Domain</label>
            <input
              type="text"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              placeholder="192.168.1.100 or target.com"
              disabled={isAgentRunning}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-2">Target Ports</label>
            <input
              type="text"
              value={targetPort}
              onChange={(e) => setTargetPort(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              placeholder="80,443,22,21,3306"
              disabled={isAgentRunning}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-2">Attack Mode</label>
            <select
              value={attackMode}
              onChange={(e) => setAttackMode(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-cyan-500"
              disabled={isAgentRunning}
            >
              <option value="stealth">🕵️ Stealth (Low noise)</option>
              <option value="aggressive">⚡ Aggressive (Fast)</option>
              <option value="surgical">🎯 Surgical (Precise)</option>
            </select>
          </div>
        </div>
      </motion.div>

      {/* Stats Dashboard */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass-card p-6 rounded-xl border-l-4 border-cyan-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Open Ports</p>
              <p className="text-2xl font-bold text-white">{stats.openPorts}</p>
            </div>
            <Network className="w-8 h-8 text-cyan-400" />
          </div>
        </div>
        <div className="glass-card p-6 rounded-xl border-l-4 border-yellow-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Vulnerabilities</p>
              <p className="text-2xl font-bold text-white">{stats.vulnerabilities}</p>
            </div>
            <Bug className="w-8 h-8 text-yellow-400" />
          </div>
        </div>
        <div className="glass-card p-6 rounded-xl border-l-4 border-orange-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Exploits</p>
              <p className="text-2xl font-bold text-white">{stats.exploits}</p>
            </div>
            <Zap className="w-8 h-8 text-orange-400" />
          </div>
        </div>
        <div className="glass-card p-6 rounded-xl border-l-4 border-red-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Shell Access</p>
              <p className="text-2xl font-bold text-white">{stats.shells}</p>
            </div>
            <Terminal className="w-8 h-8 text-red-400" />
          </div>
        </div>
      </motion.div>

      {/* Progress Bar */}
      {isAgentRunning && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400 animate-pulse" />
              Agent Progress
            </h3>
            <span className="text-sm text-slate-400">{scanProgress}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-3 mb-4">
            <div 
              className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full transition-all duration-500" 
              style={{ width: `${scanProgress}%` }}
            ></div>
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-300">
            {React.createElement(getPhaseIcon(currentPhase), { className: `w-4 h-4 text-${getPhaseColor(currentPhase)}-400` })}
            <span className="capitalize">{currentPhase.replace('-', ' ')}</span>
          </div>
        </motion.div>
      )}

      {/* Phase Timeline */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">
        <h3 className="text-lg font-semibold text-white mb-4">Attack Phases</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          {phases.map((phase, idx) => {
            const Icon = phase.icon;
            const isActive = currentPhase === phase.id;
            const isComplete = phases.findIndex(p => p.id === currentPhase) > idx;
            
            return (
              <motion.div
                key={phase.id}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: idx * 0.1 }}
                className={`p-4 rounded-lg text-center transition-all ${
                  isActive 
                    ? `bg-${phase.color}-500/20 border-2 border-${phase.color}-500` 
                    : isComplete
                    ? 'bg-green-500/20 border border-green-500'
                    : 'bg-slate-800/50 border border-slate-700'
                }`}
              >
                <Icon className={`w-6 h-6 mx-auto mb-2 ${
                  isActive 
                    ? `text-${phase.color}-400 animate-pulse` 
                    : isComplete
                    ? 'text-green-400'
                    : 'text-slate-500'
                }`} />
                <p className={`text-xs font-medium ${
                  isActive || isComplete ? 'text-white' : 'text-slate-400'
                }`}>
                  {phase.name}
                </p>
              </motion.div>
            );
          })}
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Live Agent Logs */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="glass-card p-6 rounded-xl">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Radio className="w-5 h-5 text-cyan-400" />
            Live Agent Logs
          </h3>
          <div className="bg-slate-900 rounded-lg p-4 h-96 overflow-y-auto font-mono text-xs space-y-1">
            {agentLogs.length === 0 ? (
              <p className="text-slate-500 text-center py-8">Agent logs will appear here...</p>
            ) : (
              agentLogs.map(log => (
                <div key={log.id} className={`flex items-start gap-2 ${
                  log.type === 'error' ? 'text-red-400' :
                  log.type === 'success' ? 'text-green-400' :
                  log.type === 'warning' ? 'text-yellow-400' :
                  'text-slate-300'
                }`}>
                  <span className="text-slate-600">[{log.timestamp}]</span>
                  <span className="flex-1">{log.message}</span>
                </div>
              ))
            )}
          </div>
        </motion.div>

        {/* Discoveries */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="glass-card p-6 rounded-xl">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Eye className="w-5 h-5 text-yellow-400" />
            Discovered Assets
          </h3>
          <div className="space-y-4">
            {/* Open Ports */}
            <div>
              <h4 className="text-sm font-medium text-slate-400 mb-2 flex items-center gap-2">
                <Network className="w-4 h-4" />
                Open Ports ({discoveries.openPorts.length})
              </h4>
              <div className="space-y-1">
                {discoveries.openPorts.slice(0, 5).map((port, idx) => (
                  <div key={idx} className="bg-slate-800/50 p-2 rounded text-xs flex items-center justify-between">
                    <span className="text-cyan-400">Port {port.port}</span>
                    <span className="text-slate-400">{port.service}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Vulnerabilities */}
            <div>
              <h4 className="text-sm font-medium text-slate-400 mb-2 flex items-center gap-2">
                <Bug className="w-4 h-4" />
                Vulnerabilities ({discoveries.vulnerabilities.length})
              </h4>
              <div className="space-y-1">
                {discoveries.vulnerabilities.slice(0, 5).map((vuln, idx) => (
                  <div key={idx} className="bg-slate-800/50 p-2 rounded text-xs">
                    <div className="flex items-center justify-between mb-1">
                      <span className={`font-medium ${
                        vuln.severity === 'CRITICAL' ? 'text-red-400' :
                        vuln.severity === 'HIGH' ? 'text-orange-400' :
                        'text-yellow-400'
                      }`}>
                        {vuln.severity}
                      </span>
                      <span className="text-slate-500">{vuln.cve}</span>
                    </div>
                    <p className="text-slate-300">{vuln.name}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Shell Sessions */}
            {shellSessions.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-slate-400 mb-2 flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  Active Shells ({shellSessions.length})
                </h4>
                <div className="space-y-1">
                  {shellSessions.map((shell, idx) => (
                    <div key={idx} className="bg-green-900/20 border border-green-500/30 p-2 rounded text-xs">
                      <span className="text-green-400">✓ {shell.type} shell @ {shell.host}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </motion.div>
      </div>

      {/* Exfiltrated Data */}
      {exfiltratedData.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6 rounded-xl border-l-4 border-pink-500">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Download className="w-5 h-5 text-pink-400" />
            Exfiltrated Data
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {exfiltratedData.map((item, idx) => (
              <div key={idx} className="bg-slate-800/50 p-4 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-pink-400 font-medium">{item.type}</span>
                  <span className="text-slate-500 text-xs">{item.size}</span>
                </div>
                <p className="text-slate-300 text-sm">{item.name}</p>
                <Button size="sm" variant="outline" className="w-full mt-3 border-pink-500 text-pink-400 hover:bg-pink-500/20">
                  <Download className="w-3 h-3 mr-2" />
                  Download
                </Button>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default AIPentestAgent;

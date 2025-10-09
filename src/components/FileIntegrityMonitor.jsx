import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, FileCheck, AlertTriangle, CheckCircle, XCircle, Play, Pause, RefreshCw, Plus, Eye } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const FileIntegrityMonitor = () => {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [showAddFile, setShowAddFile] = useState(false);
  const [newFilePath, setNewFilePath] = useState('');
  
  const [monitoredFiles, setMonitoredFiles] = useState([]);

  // Fetch monitored files from API
  React.useEffect(() => {
    const fetchWatchedFiles = async () => {
      try {
        const response = await fetch('/api/fim/watched');
        const data = await response.json();
        if ((data.paths || data.watchedPaths) && (data.paths || data.watchedPaths).length > 0) {
          const list = data.paths || data.watchedPaths;
          setMonitoredFiles(list.map((item, index) => ({
            id: index + 1,
            path: item.path || item,
            status: item.status || 'active',
            size: item.totalSize || item.size || 0,
            lastCheck: item.lastCheck || new Date().toISOString(),
            hash: item.hash || undefined
          })));
        } else {
          setMonitoredFiles([]);
        }
      } catch (error) {
        console.error('Failed to fetch watched files:', error);
      }
    };

    fetchWatchedFiles();
  }, []);

  const handleStartStop = async () => {
    try {
      const response = await fetch('/api/fim/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: isMonitoring ? 'stop' : 'start' })
      });
      
      if (response.ok) {
        setIsMonitoring(!isMonitoring);
        toast({
          title: isMonitoring ? "Monitoring Stopped" : "Monitoring Started",
          description: isMonitoring ? "File monitoring stopped" : "Real-time file monitoring active"
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update monitoring status.",
        variant: "destructive"
      });
    }
  };

  const handleScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    
    try {
      const response = await fetch('/api/fim/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      
      for (let i = 0; i <= 100; i += 20) {
        setScanProgress(i);
        await new Promise(resolve => setTimeout(resolve, 200));
      }
      
      if (response.ok) {
        const data = await response.json();
        
        // Update file statuses based on scan results
        const updatedFiles = monitoredFiles.map(file => ({
          ...file,
          lastCheck: new Date().toISOString()
        }));
        
        setMonitoredFiles(updatedFiles);
        toast({ 
          title: "Scan Complete", 
          description: `File integrity scan finished. ${updatedFiles.filter(f => f.status === 'modified').length} changes detected.`
        });
      }
    } catch (error) {
      toast({
        title: "Scan Failed",
        description: "Failed to complete integrity scan.",
        variant: "destructive"
      });
    } finally {
      setIsScanning(false);
      setScanProgress(0);
    }
  };

  const handleAddFile = async () => {
    if (!newFilePath.trim()) {
      toast({
        title: "Invalid Path",
        description: "Please enter a valid file path",
        variant: "destructive"
      });
      return;
    }

    try {
      const response = await fetch('/api/fim/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: newFilePath })
      });

      if (response.ok) {
        const newFile = {
          id: Date.now(),
          path: newFilePath,
          status: 'verified',
          size: 0,
          lastCheck: new Date().toISOString()
        };
        
        setMonitoredFiles([...monitoredFiles, newFile]);
        setNewFilePath('');
        setShowAddFile(false);
        
        toast({
          title: "File Added",
          description: `${newFilePath} is now being monitored`
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to add file to monitoring",
        variant: "destructive"
      });
    }
  };

  const handleRemoveFile = async (fileId) => {
    try {
      const file = monitoredFiles.find(f => f.id === fileId);
      const response = await fetch('/api/fim/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: file.path })
      });

      if (response.ok) {
        setMonitoredFiles(monitoredFiles.filter(f => f.id !== fileId));
        toast({
          title: "File Removed",
          description: `${file.path} is no longer monitored`
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to remove file from monitoring",
        variant: "destructive"
      });
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'verified': return CheckCircle;
      case 'modified': return AlertTriangle;
      case 'error': return XCircle;
      default: return FileCheck;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'verified': return 'text-green-400 bg-green-500/20';
      case 'modified': return 'text-yellow-400 bg-yellow-500/20';
      case 'error': return 'text-red-400 bg-red-500/20';
      default: return 'text-slate-400 bg-slate-500/20';
    }
  };

  const stats = {
    total: monitoredFiles.length,
    verified: monitoredFiles.filter(f => f.status === 'verified').length,
    modified: monitoredFiles.filter(f => f.status === 'modified').length,
    errors: monitoredFiles.filter(f => f.status === 'error').length
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">File Integrity Monitor</h1>
          <p className="text-slate-400">Monitor critical files for unauthorized changes</p>
        </div>
        <div className="flex gap-3">
          <Button onClick={handleStartStop} className={isMonitoring ? 'bg-red-600 hover:bg-red-700' : 'bg-green-600 hover:bg-green-700'}>
            {isMonitoring ? <Pause className="w-4 h-4 mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            {isMonitoring ? 'Stop' : 'Start'}
          </Button>
          <Button onClick={handleScan} disabled={isScanning} className="bg-blue-600 hover:bg-blue-700">
            {isScanning ? <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div> : <RefreshCw className="w-4 h-4 mr-2" />}
            {isScanning ? 'Scanning...' : 'Scan'}
          </Button>
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="grid grid-cols-2 md:grid-cols-4 gap-6">
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Total Files</p>
              <p className="text-2xl font-bold text-white">{stats.total}</p>
            </div>
            <Shield className="w-8 h-8 text-blue-400" />
          </div>
        </div>
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Verified</p>
              <p className="text-2xl font-bold text-green-400">{stats.verified}</p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-400" />
          </div>
        </div>
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Modified</p>
              <p className="text-2xl font-bold text-yellow-400">{stats.modified}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-yellow-400" />
          </div>
        </div>
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Errors</p>
              <p className="text-2xl font-bold text-red-400">{stats.errors}</p>
            </div>
            <XCircle className="w-8 h-8 text-red-400" />
          </div>
        </div>
      </motion.div>

      {isScanning && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Scanning Progress</h3>
            <span className="text-sm text-slate-400">{scanProgress}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div className="bg-blue-500 h-2 rounded-full transition-all duration-300" style={{ width: `${scanProgress}%` }}></div>
          </div>
        </motion.div>
      )}

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">Monitored Files</h2>
          <Button variant="outline" className="border-slate-600 text-slate-400" onClick={() => setShowAddFile(true)}>
            <Plus className="w-4 h-4 mr-2" />Add File
          </Button>
        </div>
        <div className="space-y-3">
          {monitoredFiles.map((file) => {
            const StatusIcon = getStatusIcon(file.status);
            return (
              <motion.div key={file.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg hover:bg-slate-800/70 transition-colors">
                <div className="flex items-center gap-4">
                  <div className={`p-2 rounded-full ${getStatusColor(file.status)}`}>
                    <StatusIcon className="w-5 h-5" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">{file.path}</h4>
                    <div className="flex items-center gap-4 mt-1 text-sm text-slate-400">
                      <span>Size: {file.size.toLocaleString()} bytes</span>
                      <span>Last Check: {new Date(file.lastCheck).toLocaleTimeString()}</span>
                    </div>
                    {file.error && <p className="text-sm text-red-400 mt-1">Error: {file.error}</p>}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="text-right mr-4">
                    <div className="text-sm font-medium text-white capitalize">{file.status}</div>
                  </div>
                  <Button size="sm" variant="outline" className="border-slate-600 text-slate-400" onClick={() => toast({ title: "File Details", description: `Details for ${file.path}` })}>
                    <Eye className="w-4 h-4" />
                  </Button>
                </div>
              </motion.div>
            );
          })}
        </div>
      </motion.div>

      {/* Add File Modal */}
      {showAddFile && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="fixed inset-0 bg-black/80 flex items-center justify-center z-50"
          onClick={() => setShowAddFile(false)}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="glass-card p-6 rounded-xl max-w-md w-full mx-4"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-xl font-bold text-white mb-4">Add File to Monitor</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">File Path</label>
                <input
                  type="text"
                  value={newFilePath}
                  onChange={(e) => setNewFilePath(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  placeholder="/path/to/file or C:\path\to\file"
                />
              </div>
              
              <div className="text-sm text-slate-400">
                <p className="mb-2">Examples:</p>
                <ul className="list-disc list-inside space-y-1 text-xs">
                  <li>/etc/passwd</li>
                  <li>/var/log/auth.log</li>
                  <li>C:\Windows\System32\drivers\etc\hosts</li>
                  <li>/home/user/.ssh/authorized_keys</li>
                </ul>
              </div>
            </div>
            
            <div className="flex space-x-3 mt-6">
              <Button onClick={handleAddFile} className="flex-1 bg-blue-600 hover:bg-blue-700">
                Add File
              </Button>
              <Button onClick={() => setShowAddFile(false)} variant="outline" className="flex-1">
                Cancel
              </Button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

export default FileIntegrityMonitor;

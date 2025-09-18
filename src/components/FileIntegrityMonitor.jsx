import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { FileCheck2, AlertTriangle, CheckCircle, Clock, Filter, RefreshCw, Eye, FolderPlus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';
import apiClient from '@/lib/api-client';

const FileIntegrityMonitor = () => {
  const [fimAlerts, setFimAlerts] = useState([]);
  const [filterType, setFilterType] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [watchedPaths, setWatchedPaths] = useState([]);
  const [newPath, setNewPath] = useState('');
  const [monitoring, setMonitoring] = useState(false);

  useEffect(() => {
    fetchFIMAlerts();
    fetchWatchedPaths();
    
    let interval;
    if (autoRefresh) {
      interval = setInterval(fetchFIMAlerts, 5000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
      apiClient.cancelRequest('/fim/alerts');
      apiClient.cancelRequest('/fim/watched');
    };
  }, [autoRefresh]);

  const fetchFIMAlerts = async () => {
    try {
      const data = await apiClient.get('/fim/alerts');
      setFimAlerts(data.alerts || []);
    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('Error fetching FIM alerts:', error);
      }
    }
  };

  const fetchWatchedPaths = async () => {
    try {
      const data = await apiClient.get('/fim/watched');
      setWatchedPaths(data.paths || []);
    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('Error fetching watched paths:', error);
      }
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      default: return 'text-slate-400 bg-slate-500/20 border-slate-500/30';
    }
  };

  const getChangeTypeColor = (change) => {
    switch (change) {
      case 'Added': return 'bg-green-500/20 text-green-400';
      case 'Modified': return 'bg-yellow-500/20 text-yellow-400';
      case 'Deleted': return 'bg-red-500/20 text-red-400';
      default: return 'bg-slate-500/20 text-slate-400';
    }
  };

  const filteredAlerts = filterType === 'all'
    ? fimAlerts
    : fimAlerts.filter(alert => alert.change.toLowerCase() === filterType);

  const handleAlertAction = async (alertId, action) => {
    try {
      const response = await fetch(`${API_BASE}/fim/alert/${alertId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action })
      });

      if (response.ok) {
        toast({
          title: "Action Complete",
          description: `Alert ${action} successfully`,
        });
        fetchFIMAlerts();
      }
    } catch (error) {
      toast({
        title: "Action Failed",
        description: "Failed to perform action on alert",
        variant: "destructive"
      });
    }
  };

  const addWatchPath = async () => {
    if (!newPath.trim()) {
      toast({
        title: "Invalid Path",
        description: "Please enter a valid path to monitor",
        variant: "destructive"
      });
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/fim/watch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: newPath.trim() })
      });

      if (response.ok) {
        toast({
          title: "Path Added",
          description: `Now monitoring: ${newPath}`,
        });
        setNewPath('');
        fetchWatchedPaths();
      } else {
        throw new Error('Failed to add watch path');
      }
    } catch (error) {
      toast({
        title: "Failed to Add Path",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const startMonitoring = async () => {
    try {
      const response = await fetch(`${API_BASE}/fim/start`, { method: 'POST' });
      if (response.ok) {
        setMonitoring(true);
        toast({
          title: "Monitoring Started",
          description: "File integrity monitoring is now active",
        });
      }
    } catch (error) {
      toast({
        title: "Failed to Start Monitoring",
        description: "Could not start file integrity monitoring",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">File Integrity Monitoring</h1>
          <p className="text-slate-400">Detect changes to critical system and application files.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setAutoRefresh(!autoRefresh)} className={autoRefresh ? 'border-green-500 text-green-400' : 'border-slate-600 text-slate-400'}>
          <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />
          Auto Refresh
        </Button>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-red-600 rounded-lg flex items-center justify-center"><AlertTriangle className="w-6 h-6 text-white" /></div>
            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.severity === 'critical').length}</span>
          </div>
          <h3 className="text-sm text-slate-400">Critical Alerts</h3>
        </div>
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <div className="w-12 h-12 bg-gradient-to-br from-yellow-500 to-yellow-600 rounded-lg flex items-center justify-center"><FileCheck2 className="w-6 h-6 text-white" /></div>
            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.change === 'Modified').length}</span>
          </div>
          <h3 className="text-sm text-slate-400">Files Modified</h3>
        </div>
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-green-600 rounded-lg flex items-center justify-center"><FileCheck2 className="w-6 h-6 text-white" /></div>
            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.change === 'Added').length}</span>
          </div>
          <h3 className="text-sm text-slate-400">Files Added</h3>
        </div>
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center"><CheckCircle className="w-6 h-6 text-white" /></div>
            <span className="text-2xl font-bold text-white">{fimAlerts.filter(a => a.status === 'resolved').length}</span>
          </div>
          <h3 className="text-sm text-slate-400">Alerts Resolved</h3>
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white flex items-center"><Filter className="w-5 h-5 mr-2 text-blue-400" />Alert Filters</h2>
        </div>
        <div className="flex items-center space-x-4">
          <span className="text-sm text-slate-400">Filter by change type:</span>
          {['all', 'added', 'modified', 'deleted'].map((type) => (
            <Button key={type} variant={filterType === type ? 'default' : 'outline'} size="sm" onClick={() => setFilterType(type)} className={filterType === type ? 'bg-blue-600' : 'border-slate-600 text-slate-400'}>
              {type.charAt(0).toUpperCase() + type.slice(1)}
            </Button>
          ))}
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="glass-card p-6 rounded-xl">
        <h2 className="text-xl font-semibold text-white mb-6 flex items-center"><FileCheck2 className="w-5 h-5 mr-2 text-red-400" />FIM Alerts ({filteredAlerts.length})</h2>
        {filteredAlerts.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            <p>No file integrity alerts.</p>
            <p className="text-sm">The system is monitoring for file changes.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredAlerts.map((alert, index) => (
              <motion.div key={alert.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.1 }} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-semibold text-white font-mono truncate">{alert.file}</h3>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>{alert.severity.toUpperCase()}</span>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getChangeTypeColor(alert.change)}`}>{alert.change.toUpperCase()}</span>
                    </div>
                    <p className="text-slate-400 mb-2">{alert.details}</p>
                    <div className="flex items-center space-x-4 text-sm text-slate-500">
                      <span><Clock className="w-3 h-3 inline mr-1" />{alert.timestamp.toLocaleTimeString()}</span>
                      <span>Status: <span className="font-medium text-slate-300">{alert.status}</span></span>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'details')}><Eye className="w-4 h-4 mr-2" />Details</Button>
                    <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'resolve')}>Resolve</Button>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default FileIntegrityMonitor;
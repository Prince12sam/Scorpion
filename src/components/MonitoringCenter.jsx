import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Activity, Eye, Bell, Filter, RefreshCw, AlertCircle, CheckCircle, Clock, FileText, Server, Cloud, Globe } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const MonitoringCenter = () => {
  const [activeAlerts, setActiveAlerts] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [logSources, setLogSources] = useState([]);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'low': return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
      default: return 'text-slate-400 bg-slate-500/20 border-slate-500/30';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'text-red-400 bg-red-500/20';
      case 'investigating': return 'text-orange-400 bg-orange-500/20';
      case 'monitoring': return 'text-yellow-400 bg-yellow-500/20';
      case 'pending': return 'text-blue-400 bg-blue-500/20';
      case 'resolved': return 'text-green-400 bg-green-500/20';
      default: return 'text-slate-400 bg-slate-500/20';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active': return AlertCircle;
      case 'investigating': return Eye;
      case 'monitoring': return Activity;
      case 'pending': return Clock;
      case 'resolved': return CheckCircle;
      default: return AlertCircle;
    }
  };

  const getSourceIcon = (type) => {
    switch (type) {
      case 'server': return <Server className="w-5 h-5 text-blue-400" />;
      case 'cloud': return <Cloud className="w-5 h-5 text-purple-400" />;
      case 'public': return <Globe className="w-5 h-5 text-green-400" />;
      default: return <FileText className="w-5 h-5 text-slate-400" />;
    }
  };

  const filteredAlerts = filterSeverity === 'all' 
    ? activeAlerts 
    : activeAlerts.filter(alert => alert.severity === filterSeverity);

  const handleAlertAction = (alertId, action) => {
    toast({
      title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀"
    });
  };

  const handleAddSource = () => {
    toast({
      title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀"
    });
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Monitoring Center</h1>
          <p className="text-slate-400">Real-time intrusion detection, log analysis, and incident response.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => setAutoRefresh(!autoRefresh)} className={autoRefresh ? 'border-green-500 text-green-400' : 'border-slate-600 text-slate-400'}>
          <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />
          Auto Refresh
        </Button>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass-card p-6 rounded-xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white flex items-center"><Activity className="w-5 h-5 mr-2 text-blue-400" />Log Sources</h2>
          <Button size="sm" onClick={handleAddSource}>Add Source</Button>
        </div>
        {logSources.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            <p>No log sources connected.</p>
            <p className="text-sm">Click "Add Source" to start collecting logs.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {logSources.map(source => (
              <div key={source.id} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                <div className="flex items-center space-x-3 mb-2">
                  {getSourceIcon(source.type)}
                  <h3 className="font-medium text-white truncate">{source.name}</h3>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className={`flex items-center space-x-1.5 ${source.status === 'connected' ? 'text-green-400' : 'text-red-400'}`}>
                    <span className={`w-2 h-2 rounded-full ${source.status === 'connected' ? 'bg-green-500 security-pulse' : 'bg-red-500'}`}></span>
                    <span>{source.status === 'connected' ? 'Connected' : 'Disconnected'}</span>
                  </span>
                  <span className="text-slate-400">{source.logs.toLocaleString()} logs</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white flex items-center"><Filter className="w-5 h-5 mr-2 text-blue-400" />Alert Filters</h2>
        </div>
        <div className="flex items-center space-x-4">
          <span className="text-sm text-slate-400">Filter by severity:</span>
          {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
            <Button key={severity} variant={filterSeverity === severity ? 'default' : 'outline'} size="sm" onClick={() => setFilterSeverity(severity)} className={filterSeverity === severity ? 'bg-blue-600' : 'border-slate-600 text-slate-400'}>
              {severity.charAt(0).toUpperCase() + severity.slice(1)}
            </Button>
          ))}
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="glass-card p-6 rounded-xl">
        <h2 className="text-xl font-semibold text-white mb-6 flex items-center"><Bell className="w-5 h-5 mr-2 text-red-400" />Active Security Alerts ({filteredAlerts.length})</h2>
        {filteredAlerts.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            <p>No active alerts.</p>
            <p className="text-sm">The system is monitoring for threats from connected sources.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredAlerts.map((alert, index) => {
              const StatusIcon = getStatusIcon(alert.status);
              return (
                <motion.div key={alert.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.1 }} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-semibold text-white">{alert.title}</h3>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>{alert.severity.toUpperCase()}</span>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(alert.status)}`}><StatusIcon className="w-3 h-3 inline mr-1" />{alert.status.toUpperCase()}</span>
                      </div>
                      <p className="text-slate-400 mb-2">{alert.description}</p>
                      <div className="flex items-center space-x-4 text-sm text-slate-500">
                        <span>Source: {alert.source}</span>
                        <span>Time: {alert.timestamp.toLocaleTimeString()}</span>
                      </div>
                    </div>
                    <div className="flex space-x-2">
                      <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'investigate')}>Investigate</Button>
                      <Button variant="outline" size="sm" onClick={() => handleAlertAction(alert.id, 'resolve')}>Resolve</Button>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default MonitoringCenter;
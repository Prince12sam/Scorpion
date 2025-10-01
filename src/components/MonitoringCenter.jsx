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
  const [systemMetrics, setSystemMetrics] = useState({
    cpu: 0,
    memory: 0,
    disk: 0,
    network: 0
  });

  // Fetch data from API
  React.useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await fetch('/api/monitoring/alerts');
        const data = await response.json();
        if (data && data.alerts) {
          setActiveAlerts(data.alerts);
        } else {
          setActiveAlerts([]);
        }
      } catch (error) {
        console.error('Failed to fetch alerts:', error);
        // Set fallback data
        setActiveAlerts([]);
      }
    };

    const fetchLogSources = async () => {
      try {
        const response = await fetch('/api/monitoring/log-sources');
        const data = await response.json();
        if (data && data.sources) {
          setLogSources(data.sources);
        } else {
          setLogSources([]);
        }
      } catch (error) {
        console.error('Failed to fetch log sources:', error);
        setLogSources([]);
      }
    };

    const fetchMetrics = async () => {
      try {
        const response = await fetch('/api/monitoring/metrics');
        const data = await response.json();
        if (data && data.cpu !== undefined) {
          setSystemMetrics({
            cpu: data.cpu,
            memory: data.memory,
            disk: data.disk,
            network: data.network
          });
        } else {
          setSystemMetrics({ cpu: 0, memory: 0, disk: 0, network: 0 });
        }
      } catch (error) {
        console.error('Failed to fetch metrics:', error);
        setSystemMetrics({ cpu: 0, memory: 0, disk: 0, network: 0 });
      }
    };

    fetchAlerts();
    fetchLogSources();
    fetchMetrics();

    // Auto-refresh every 10 seconds if enabled
    const interval = setInterval(() => {
      if (autoRefresh) {
        fetchAlerts();
        fetchLogSources();
        fetchMetrics();
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [autoRefresh]);

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

  const handleAlertAction = async (alertId, action) => {
    try {
      const response = await fetch(`/api/monitoring/alert/${alertId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: action === 'acknowledge' ? 'acknowledged' : 'resolved' })
      });
      
      if (response.ok) {
        const updatedAlerts = activeAlerts.map(alert => {
          if (alert.id === alertId) {
            return { ...alert, status: action === 'acknowledge' ? 'acknowledged' : 'resolved' };
          }
          return alert;
        });
        setActiveAlerts(updatedAlerts);
        toast({
          title: "Alert Updated",
          description: `Alert ${action === 'acknowledge' ? 'acknowledged' : 'resolved'} successfully.`
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update alert.",
        variant: "destructive"
      });
    }
  };

  const handleAddSource = () => {
    const newSource = {
      id: logSources.length + 1,
      name: `New Log Source ${logSources.length + 1}`,
      type: 'server',
      status: 'connected',
      events: Math.floor(Math.random() * 1000)
    };
    setLogSources([...logSources, newSource]);
    toast({
      title: "Log Source Added",
      description: `${newSource.name} has been connected successfully.`
    });
  };

  const refreshMetrics = async () => {
    try {
      const response = await fetch('/api/monitoring/metrics');
      const data = await response.json();
      setSystemMetrics(data.metrics || {});
      toast({
        title: "Metrics Refreshed",
        description: "System metrics have been updated."
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to refresh metrics.",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Monitoring Center</h1>
          <p className="text-slate-400">Real-time intrusion detection, log analysis, and incident response.</p>
        </div>
        <div className="flex gap-3">
          <Button onClick={refreshMetrics} className="bg-blue-600 hover:bg-blue-700">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh Metrics
          </Button>
          <Button variant="outline" size="sm" onClick={() => setAutoRefresh(!autoRefresh)} className={autoRefresh ? 'border-green-500 text-green-400' : 'border-slate-600 text-slate-400'}>
            <RefreshCw className={`w-4 h-4 mr-2 ${autoRefresh ? 'animate-spin' : ''}`} />
            Auto Refresh
          </Button>
        </div>
      </motion.div>

      {/* System Health Metrics */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">CPU Usage</span>
            <span className={`text-sm ${systemMetrics.cpu > 80 ? 'text-red-400' : systemMetrics.cpu > 60 ? 'text-yellow-400' : 'text-green-400'}`}>
              {systemMetrics.cpu}%
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div 
              className={`h-2 rounded-full transition-all duration-300 ${systemMetrics.cpu > 80 ? 'bg-red-500' : systemMetrics.cpu > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
              style={{ width: `${systemMetrics.cpu}%` }}
            ></div>
          </div>
        </div>

        <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">Memory Usage</span>
            <span className={`text-sm ${systemMetrics.memory > 80 ? 'text-red-400' : systemMetrics.memory > 60 ? 'text-yellow-400' : 'text-green-400'}`}>
              {systemMetrics.memory}%
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div 
              className={`h-2 rounded-full transition-all duration-300 ${systemMetrics.memory > 80 ? 'bg-red-500' : systemMetrics.memory > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
              style={{ width: `${systemMetrics.memory}%` }}
            ></div>
          </div>
        </div>

        <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">Disk Usage</span>
            <span className={`text-sm ${systemMetrics.disk > 80 ? 'text-red-400' : systemMetrics.disk > 60 ? 'text-yellow-400' : 'text-green-400'}`}>
              {systemMetrics.disk}%
            </span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div 
              className={`h-2 rounded-full transition-all duration-300 ${systemMetrics.disk > 80 ? 'bg-red-500' : systemMetrics.disk > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
              style={{ width: `${systemMetrics.disk}%` }}
            ></div>
          </div>
        </div>

        <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-sm">Network I/O</span>
            <span className="text-sm text-blue-400">{systemMetrics.network} MB/s</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div 
              className="h-2 bg-blue-500 rounded-full transition-all duration-300"
              style={{ width: `${Math.min(systemMetrics.network * 10, 100)}%` }}
            ></div>
          </div>
        </div>
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
                  <span className="text-slate-400">{source.events?.toLocaleString() || '0'} events</span>
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
import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Wifi, WifiOff, CheckCircle, AlertTriangle, Clock } from 'lucide-react';

const APIStatus = ({ compact = false }) => {
  const [apiStatus, setApiStatus] = useState({});
  const [isVisible, setIsVisible] = useState(false);
  const [overallHealth, setOverallHealth] = useState('unknown');

  const criticalEndpoints = [
    { name: 'Dashboard', path: '/api/dashboard/metrics' },
    { name: 'Monitoring', path: '/api/monitoring/alerts' },
    { name: 'System Health', path: '/api/system/health' },
    { name: 'Threat Map', path: '/api/threat-map' }
  ];

  const checkAPIHealth = async () => {
    const results = {};
    let healthyCount = 0;
    
    for (const endpoint of criticalEndpoints) {
      try {
        const startTime = Date.now();
        const response = await fetch(`http://localhost:3001${endpoint.path}`, {
          method: 'GET',
          timeout: 5000
        });
        
        const duration = Date.now() - startTime;
        
        results[endpoint.name] = {
          status: response.ok ? 'healthy' : 'error',
          responseTime: duration,
          lastCheck: new Date().toISOString()
        };
        
        if (response.ok) healthyCount++;
        
      } catch (error) {
        results[endpoint.name] = {
          status: 'error',
          responseTime: null,
          error: error.message,
          lastCheck: new Date().toISOString()
        };
      }
    }
    
    setApiStatus(results);
    
    // Determine overall health
    const healthPercentage = (healthyCount / criticalEndpoints.length) * 100;
    if (healthPercentage === 100) setOverallHealth('healthy');
    else if (healthPercentage >= 75) setOverallHealth('warning');
    else setOverallHealth('error');
  };

  useEffect(() => {
    checkAPIHealth();
    const interval = setInterval(checkAPIHealth, 30000); // Check every 30 seconds
    
    return () => clearInterval(interval);
  }, []);

  const getHealthIcon = () => {
    switch (overallHealth) {
      case 'healthy': return <Wifi className="w-4 h-4 text-green-400" />;
      case 'warning': return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      case 'error': return <WifiOff className="w-4 h-4 text-red-400" />;
      default: return <Clock className="w-4 h-4 text-slate-400" />;
    }
  };

  const getHealthColor = () => {
    switch (overallHealth) {
      case 'healthy': return 'bg-green-500/20 border-green-500/30 text-green-400';
      case 'warning': return 'bg-yellow-500/20 border-yellow-500/30 text-yellow-400';
      case 'error': return 'bg-red-500/20 border-red-500/30 text-red-400';
      default: return 'bg-slate-500/20 border-slate-500/30 text-slate-400';
    }
  };

  const getStatusText = () => {
    const healthyCount = Object.values(apiStatus).filter(s => s.status === 'healthy').length;
    const totalCount = Object.keys(apiStatus).length;
    
    if (totalCount === 0) return 'Checking...';
    if (healthyCount === totalCount) return 'All APIs Online';
    if (healthyCount === 0) return 'APIs Offline';
    return `${healthyCount}/${totalCount} APIs Online`;
  };

  if (compact) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        className={`flex items-center space-x-2 px-3 py-2 rounded-lg border cursor-pointer ${getHealthColor()}`}
        onClick={() => setIsVisible(!isVisible)}
      >
        {getHealthIcon()}
        <span className="text-sm font-medium">{getStatusText()}</span>
      </motion.div>
    );
  }

  return (
    <div className="fixed bottom-4 right-4 z-50">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`px-3 py-2 rounded-lg border cursor-pointer ${getHealthColor()}`}
        onClick={() => setIsVisible(!isVisible)}
      >
        <div className="flex items-center space-x-2">
          {getHealthIcon()}
          <span className="text-sm font-medium">API Status</span>
        </div>
      </motion.div>

      {isVisible && (
        <motion.div
          initial={{ opacity: 0, y: 10, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          className="mt-2 bg-slate-900 border border-slate-700 rounded-lg p-4 min-w-[300px] shadow-xl"
        >
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-white">API Health Status</h3>
            <button
              onClick={() => checkAPIHealth()}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              Refresh
            </button>
          </div>
          
          <div className="space-y-2">
            {criticalEndpoints.map(endpoint => {
              const status = apiStatus[endpoint.name];
              if (!status) return null;

              return (
                <div key={endpoint.name} className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {status.status === 'healthy' ? (
                      <CheckCircle className="w-3 h-3 text-green-400" />
                    ) : (
                      <AlertTriangle className="w-3 h-3 text-red-400" />
                    )}
                    <span className="text-sm text-slate-300">{endpoint.name}</span>
                  </div>
                  <div className="text-right">
                    {status.responseTime && (
                      <div className="text-xs text-slate-400">{status.responseTime}ms</div>
                    )}
                    {status.error && (
                      <div className="text-xs text-red-400">Error</div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
          
          <div className="mt-3 pt-2 border-t border-slate-700 text-xs text-slate-400">
            Last checked: {new Date().toLocaleTimeString()}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default APIStatus;
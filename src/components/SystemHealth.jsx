import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, Cpu, HardDrive, Wifi, Server } from 'lucide-react';
import apiClient from '@/lib/api-client';

const SystemHealth = () => {
  const [metrics, setMetrics] = useState({
    cpu: 0,
    memory: 0,
    disk: 0,
    network: 0,
    uptime: 'N/A'
  });

  useEffect(() => {
    fetchSystemHealth();
    const interval = setInterval(fetchSystemHealth, 30000); // Update every 30 seconds
    
    return () => {
      clearInterval(interval);
      apiClient.cancelRequest('/system/health');
    };
  }, []);

  const fetchSystemHealth = async () => {
    try {
      const data = await apiClient.get('/system/health');
      if (data) {
        setMetrics({
          cpu: data.cpu || 0,
          memory: data.memory || 0,
          disk: data.disk || 0,
          network: data.network || 0,
          uptime: data.uptime ? formatUptime(data.uptime) : 'N/A'
        });
      }
    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('Failed to fetch system health:', error);
        // Keep existing values on error, don't reset to zeros
      }
    }
  };

  const formatUptime = (seconds) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const getHealthColor = (value) => {
    if (value < 30) return 'text-green-400';
    if (value < 70) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getHealthBg = (value) => {
    if (value < 30) return 'bg-green-500';
    if (value < 70) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const getOverallHealth = () => {
    const avg = (100 - metrics.cpu + 100 - metrics.memory + 100 - metrics.disk) / 3;
    return Math.round(avg);
  };

  const getSystemStatus = () => {
    const health = getOverallHealth();
    if (health > 80) return 'GOOD';
    if (health > 60) return 'FAIR';
    return 'POOR';
  };

  const getStatusBadge = () => {
    const health = getOverallHealth();
    if (health > 80) return 'bg-green-500/20 border-green-500/30';
    if (health > 60) return 'bg-yellow-500/20 border-yellow-500/30';
    return 'bg-red-500/20 border-red-500/30';
  };

  const getStatusDot = () => {
    const health = getOverallHealth();
    if (health > 80) return 'bg-green-500';
    if (health > 60) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const getStatusText = () => {
    const health = getOverallHealth();
    if (health > 80) return 'text-green-400';
    if (health > 60) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getSystemStatusText = () => {
    const health = getOverallHealth();
    if (health > 80) return 'System Healthy';
    if (health > 60) return 'System Fair';
    return 'System Issues';
  };

  const healthItems = [
    { label: 'CPU Usage', value: metrics.cpu, icon: Cpu, unit: '%' },
    { label: 'Memory', value: metrics.memory, icon: Server, unit: '%' },
    { label: 'Disk Usage', value: metrics.disk, icon: HardDrive, unit: '%' },
    { label: 'Network', value: metrics.network, icon: Wifi, unit: '%' }
  ];

  return (
    <div className="glass-card p-6 rounded-xl h-96">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-white flex items-center">
          <Activity className="w-5 h-5 mr-2 text-green-400" />
          System Health
        </h2>
        <div className="text-xs text-slate-400">
          Uptime: {metrics.uptime}
        </div>
      </div>

      <div className="space-y-4">
        {healthItems.map((item, index) => {
          const Icon = item.icon;
          return (
            <motion.div
              key={item.label}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="flex items-center justify-between"
            >
              <div className="flex items-center space-x-3">
                <Icon className="w-4 h-4 text-slate-400" />
                <span className="text-sm text-slate-300">{item.label}</span>
              </div>
              
              <div className="flex items-center space-x-3">
                <div className="w-24 bg-slate-700 rounded-full h-2">
                  <motion.div
                    className={`h-2 rounded-full ${getHealthBg(item.value)}`}
                    initial={{ width: 0 }}
                    animate={{ width: `${item.value}%` }}
                    transition={{ duration: 0.5, delay: index * 0.1 }}
                  />
                </div>
                <span className={`text-sm font-medium w-12 text-right ${getHealthColor(item.value)}`}>
                  {item.value}{item.unit}
                </span>
              </div>
            </motion.div>
          );
        })}
      </div>

      <div className="mt-6 pt-4 border-t border-slate-700">
        <div className="grid grid-cols-2 gap-4 text-center">
          <div>
            <div className="text-2xl font-bold text-green-400">
              {getOverallHealth()}%
            </div>
            <div className="text-xs text-slate-400">Health Score</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-blue-400">
              {getSystemStatus()}
            </div>
            <div className="text-xs text-slate-400">Status</div>
          </div>
        </div>
      </div>

      <div className="mt-4 flex items-center justify-center">
        <div className={`flex items-center space-x-2 px-3 py-1 rounded-full border ${getStatusBadge()}`}>
          <div className={`w-2 h-2 rounded-full ${getStatusDot()}`}></div>
          <span className={`text-xs font-medium ${getStatusText()}`}>
            {getSystemStatusText()}
          </span>
        </div>
      </div>
    </div>
  );
};

export default SystemHealth;
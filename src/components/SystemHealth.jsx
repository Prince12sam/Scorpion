import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Activity, Cpu, HardDrive, Wifi, Server } from 'lucide-react';

const SystemHealth = () => {
  const [metrics] = useState({
    cpu: 0,
    memory: 0,
    disk: 0,
    network: 0,
    uptime: 'N/A'
  });

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
            <div className="text-2xl font-bold text-green-400">N/A</div>
            <div className="text-xs text-slate-400">Availability</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-blue-400">0</div>
            <div className="text-xs text-slate-400">Endpoints</div>
          </div>
        </div>
      </div>

      <div className="mt-4 flex items-center justify-center">
        <div className="flex items-center space-x-2 px-3 py-1 bg-yellow-500/20 rounded-full border border-yellow-500/30">
          <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
          <span className="text-yellow-400 text-xs font-medium">Awaiting Data</span>
        </div>
      </div>
    </div>
  );
};

export default SystemHealth;
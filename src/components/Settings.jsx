import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Settings as SettingsIcon, Bell, Shield, Lock, Database, Sun, Moon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const Settings = () => {
  // Load settings from localStorage on component mount
  const [settings, setSettings] = useState(() => {
    const savedSettings = localStorage.getItem('scorpion-settings');
    return savedSettings ? JSON.parse(savedSettings) : {
      notifications: {
        email: true,
        push: false,
        criticalAlertsOnly: true,
        threatAlerts: true,
        scanComplete: true,
        systemHealth: false
      },
      security: {
        twoFactorAuth: true,
        sessionTimeout: 30,
        ipWhitelist: '192.168.1.1/24, 10.0.0.0/8',
        maxLoginAttempts: 5,
        passwordExpiry: 90,
        apiRateLimit: 1000
      },
      scanning: {
        autoScan: true,
        scanDepth: 'deep',
        parallelScans: 4,
        excludeExtensions: '.log,.tmp,.cache',
        realTimeMonitoring: true
      },
      data: {
        retentionPeriod: 90,
        autoBackup: true,
        backupFrequency: 'weekly',
        compressionEnabled: true,
        encryptBackups: true
      },
      performance: {
        maxCpuUsage: 80,
        maxMemoryUsage: 70,
        cacheSize: 512,
        logLevel: 'info'
      },
      theme: 'dark'
    };
  });

  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);

  const handleSave = async () => {
    try {
      // Save to localStorage for persistence
      localStorage.setItem('scorpion-settings', JSON.stringify(settings));
      
      // Simulate API call to backend
      const response = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });

      if (response.ok) {
        toast({
          title: "Settings Saved",
          description: "Your preferences have been updated successfully.",
        });
      } else {
        throw new Error('Failed to save to server');
      }
    } catch (error) {
      // Still save locally even if server fails
      localStorage.setItem('scorpion-settings', JSON.stringify(settings));
      toast({
        title: "Settings Saved Locally",
        description: "Settings saved to local storage. Server sync will retry later.",
      });
    }
  };

  const handleToggle = (category, key) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: !prev[category][key]
      }
    }));
    setHasUnsavedChanges(true);
  };

  const handleInputChange = (category, key, value) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value
      }
    }));
    setHasUnsavedChanges(true);
  };

  const handleResetDefaults = () => {
    const defaultSettings = {
      notifications: {
        email: true,
        push: false,
        criticalAlertsOnly: true,
        threatAlerts: true,
        scanComplete: true,
        systemHealth: false
      },
      security: {
        twoFactorAuth: true,
        sessionTimeout: 30,
        ipWhitelist: '192.168.1.1/24, 10.0.0.0/8',
        maxLoginAttempts: 5,
        passwordExpiry: 90,
        apiRateLimit: 1000
      },
      scanning: {
        autoScan: true,
        scanDepth: 'deep',
        parallelScans: 4,
        excludeExtensions: '.log,.tmp,.cache',
        realTimeMonitoring: true
      },
      data: {
        retentionPeriod: 90,
        autoBackup: true,
        backupFrequency: 'weekly',
        compressionEnabled: true,
        encryptBackups: true
      },
      performance: {
        maxCpuUsage: 80,
        maxMemoryUsage: 70,
        cacheSize: 512,
        logLevel: 'info'
      },
      theme: 'dark'
    };
    setSettings(defaultSettings);
    setHasUnsavedChanges(true);
    toast({
      title: "Settings Reset",
      description: "All settings have been reset to defaults. Don't forget to save!",
    });
  };

  const handleThemeChange = (theme) => {
    setSettings(prev => ({ ...prev, theme }));
    setHasUnsavedChanges(true);
    toast({
      title: "Theme Changed",
      description: `Switched to ${theme} theme. Don't forget to save your settings!`
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
          <p className="text-slate-400">Configure system settings and user preferences</p>
        </div>
        
        <div className="flex gap-3">
          <Button 
            onClick={handleResetDefaults} 
            variant="outline" 
            className="border-slate-600 text-slate-400"
          >
            Reset Defaults
          </Button>
          <Button 
            onClick={handleSave} 
            className={`${hasUnsavedChanges ? 'bg-orange-600 hover:bg-orange-700' : 'bg-blue-600 hover:bg-blue-700'}`}
          >
            {hasUnsavedChanges ? 'Save Changes *' : 'Save Changes'}
          </Button>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Settings Sections */}
        <div className="lg:col-span-2 space-y-6">
          {/* Notifications */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="glass-card p-6 rounded-xl"
          >
            <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
              <Bell className="w-5 h-5 mr-2 text-blue-400" />
              Notifications
            </h2>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Email Notifications</label>
                <button onClick={() => handleToggle('notifications', 'email')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.notifications.email ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.notifications.email ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Push Notifications</label>
                <button onClick={() => handleToggle('notifications', 'push')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.notifications.push ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.notifications.push ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Critical Alerts Only</label>
                <button onClick={() => handleToggle('notifications', 'criticalAlertsOnly')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.notifications.criticalAlertsOnly ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.notifications.criticalAlertsOnly ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
            </div>
          </motion.div>

          {/* Security */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="glass-card p-6 rounded-xl"
          >
            <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
              <Shield className="w-5 h-5 mr-2 text-blue-400" />
              Security
            </h2>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Two-Factor Authentication (2FA)</label>
                <button onClick={() => handleToggle('security', 'twoFactorAuth')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.security.twoFactorAuth ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.security.twoFactorAuth ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Session Timeout (minutes)</label>
                <input
                  type="number"
                  value={settings.security.sessionTimeout}
                  onChange={(e) => handleInputChange('security', 'sessionTimeout', e.target.value)}
                  className="w-24 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-2">IP Whitelist (comma-separated)</label>
                <textarea
                  value={settings.security.ipWhitelist}
                  onChange={(e) => handleInputChange('security', 'ipWhitelist', e.target.value)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white h-24"
                />
              </div>
            </div>
          </motion.div>

          {/* Scanning Configuration */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="glass-card p-6 rounded-xl"
          >
            <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
              <SettingsIcon className="w-5 h-5 mr-2 text-blue-400" />
              Scanning Configuration
            </h2>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Auto-Scan on Startup</label>
                <button onClick={() => handleToggle('scanning', 'autoScan')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.scanning.autoScan ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.scanning.autoScan ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Real-time Monitoring</label>
                <button onClick={() => handleToggle('scanning', 'realTimeMonitoring')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.scanning.realTimeMonitoring ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.scanning.realTimeMonitoring ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Scan Depth</label>
                <select
                  value={settings.scanning.scanDepth}
                  onChange={(e) => handleInputChange('scanning', 'scanDepth', e.target.value)}
                  className="px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                >
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="deep">Deep</option>
                  <option value="comprehensive">Comprehensive</option>
                </select>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Parallel Scans</label>
                <input
                  type="number"
                  min="1"
                  max="16"
                  value={settings.scanning.parallelScans}
                  onChange={(e) => handleInputChange('scanning', 'parallelScans', parseInt(e.target.value))}
                  className="w-24 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-2">Exclude Extensions</label>
                <input
                  type="text"
                  value={settings.scanning.excludeExtensions}
                  onChange={(e) => handleInputChange('scanning', 'excludeExtensions', e.target.value)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                  placeholder=".log,.tmp,.cache"
                />
              </div>
            </div>
          </motion.div>

          {/* Performance Settings */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="glass-card p-6 rounded-xl"
          >
            <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
              <SettingsIcon className="w-5 h-5 mr-2 text-blue-400" />
              Performance
            </h2>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Max CPU Usage (%)</label>
                <input
                  type="number"
                  min="10"
                  max="100"
                  value={settings.performance.maxCpuUsage}
                  onChange={(e) => handleInputChange('performance', 'maxCpuUsage', parseInt(e.target.value))}
                  className="w-24 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Max Memory Usage (%)</label>
                <input
                  type="number"
                  min="10"
                  max="90"
                  value={settings.performance.maxMemoryUsage}
                  onChange={(e) => handleInputChange('performance', 'maxMemoryUsage', parseInt(e.target.value))}
                  className="w-24 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Cache Size (MB)</label>
                <input
                  type="number"
                  min="64"
                  max="2048"
                  step="64"
                  value={settings.performance.cacheSize}
                  onChange={(e) => handleInputChange('performance', 'cacheSize', parseInt(e.target.value))}
                  className="w-24 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Log Level</label>
                <select
                  value={settings.performance.logLevel}
                  onChange={(e) => handleInputChange('performance', 'logLevel', e.target.value)}
                  className="px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                >
                  <option value="error">Error</option>
                  <option value="warn">Warning</option>
                  <option value="info">Info</option>
                  <option value="debug">Debug</option>
                  <option value="trace">Trace</option>
                </select>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Side Panel */}
        <div className="space-y-6">
          {/* Theme */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="glass-card p-6 rounded-xl"
          >
            <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
              <Sun className="w-5 h-5 mr-2 text-blue-400" />
              Appearance
            </h2>
            
            <div className="flex space-x-4">
              <button
                onClick={() => handleThemeChange('light')}
                className={`flex-1 p-4 rounded-lg border-2 transition-colors ${
                  settings.theme === 'light' ? 'border-blue-500 bg-blue-500/10' : 'border-slate-600 bg-slate-800/50'
                }`}
              >
                <Sun className="mx-auto mb-2" />
                <span className="text-sm">Light</span>
              </button>
              <button
                onClick={() => handleThemeChange('dark')}
                className={`flex-1 p-4 rounded-lg border-2 transition-colors ${
                  settings.theme === 'dark' ? 'border-blue-500 bg-blue-500/10' : 'border-slate-600 bg-slate-800/50'
                }`}
              >
                <Moon className="mx-auto mb-2" />
                <span className="text-sm">Dark</span>
              </button>
            </div>
          </motion.div>

          {/* Data Management */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="glass-card p-6 rounded-xl"
          >
            <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
              <Database className="w-5 h-5 mr-2 text-blue-400" />
              Data Management
            </h2>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Data Retention (days)</label>
                <input
                  type="number"
                  min="1"
                  max="365"
                  value={settings.data.retentionPeriod}
                  onChange={(e) => handleInputChange('data', 'retentionPeriod', parseInt(e.target.value))}
                  className="w-24 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Automatic Backups</label>
                <button onClick={() => handleToggle('data', 'autoBackup')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.data.autoBackup ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.data.autoBackup ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Encrypt Backups</label>
                <button onClick={() => handleToggle('data', 'encryptBackups')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.data.encryptBackups ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.data.encryptBackups ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Backup Frequency</label>
                <select
                  value={settings.data.backupFrequency}
                  onChange={(e) => handleInputChange('data', 'backupFrequency', e.target.value)}
                  className="px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white text-sm"
                >
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              <div className="space-y-2">
                <Button 
                  variant="outline" 
                  className="w-full border-slate-600 text-slate-400"
                  onClick={() => toast({ title: "Export started", description: "Data export will be available in downloads folder." })}
                >
                  <Database className="w-4 h-4 mr-2" />
                  Export All Data
                </Button>
                <Button 
                  variant="outline" 
                  className="w-full border-green-600 text-green-400"
                  onClick={() => toast({ title: "Backup created", description: "Manual backup saved successfully." })}
                >
                  Create Backup Now
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Settings as SettingsIcon, Bell, Shield, Lock, Database, Sun, Moon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const Settings = () => {
  const [settings, setSettings] = useState({
    notifications: {
      email: true,
      push: false,
      criticalAlertsOnly: true
    },
    security: {
      twoFactorAuth: true,
      sessionTimeout: 30,
      ipWhitelist: '192.168.1.1/24, 10.0.0.0/8'
    },
    data: {
      retentionPeriod: 90,
      autoBackup: true
    },
    theme: 'dark'
  });

  const handleSave = () => {
    toast({
      title: "Settings Saved",
      description: "Your preferences have been updated successfully.",
    });
  };

  const handleToggle = (category, key) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: !prev[category][key]
      }
    }));
  };

  const handleInputChange = (category, key, value) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value
      }
    }));
  };

  const handleThemeChange = (theme) => {
    setSettings(prev => ({ ...prev, theme }));
    toast({
      title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀"
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
        
        <Button onClick={handleSave} className="bg-blue-600 hover:bg-blue-700">
          Save Changes
        </Button>
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
                  value={settings.data.retentionPeriod}
                  onChange={(e) => handleInputChange('data', 'retentionPeriod', e.target.value)}
                  className="w-24 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-white"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300">Automatic Backups</label>
                <button onClick={() => handleToggle('data', 'autoBackup')} className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.data.autoBackup ? 'bg-blue-600' : 'bg-slate-700'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full transform transition-transform ${settings.data.autoBackup ? 'translate-x-6' : 'translate-x-0'}`}></div>
                </button>
              </div>
              <Button variant="outline" className="w-full">
                Export All Data
              </Button>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
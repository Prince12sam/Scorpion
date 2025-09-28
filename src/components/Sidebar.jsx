import React from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  Search, 
  Activity, 
  FileText, 
  CheckCircle, 
  Brain, 
  Users, 
  Settings, 
  Menu,
  ChevronLeft,
  Target,
  AlertTriangle,
  FileCheck2,
  Globe,
  Network,
  KeyRound
} from 'lucide-react';
import { Button } from '@/components/ui/button';

const Sidebar = ({ activeSection, setActiveSection, collapsed, setCollapsed }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Security Dashboard', icon: Shield },
    { id: 'recon', label: 'Recon & Discovery', icon: Network },
    { id: 'scanner', label: 'Vulnerability Scanner', icon: Search },
    { id: 'monitoring', label: 'Monitoring Center', icon: Activity },
    { id: 'fim', label: 'File Integrity', icon: FileCheck2 },
    { id: 'threat-hunting', label: 'Threat Hunting', icon: Globe },
    { id: 'password-security', label: 'Password Security', icon: KeyRound },
    { id: 'exploitation', label: 'Advanced Exploitation', icon: AlertTriangle },
    { id: 'api-testing', label: 'API Testing', icon: Target },
    { id: 'network-discovery', label: 'Network Discovery', icon: Network },
    { id: 'brute-force', label: 'Brute Force Tools', icon: Target },
    { id: 'reports', label: 'Reports Generator', icon: FileText },
    { id: 'compliance', label: 'Compliance Tracker', icon: CheckCircle },
    { id: 'intelligence', label: 'Threat Intelligence', icon: Brain },
    { id: 'investigation', label: 'Investigation Tools', icon: Target },
    { id: 'users', label: 'User Management', icon: Users },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  return (
    <motion.aside
      initial={{ x: -300 }}
      animate={{ x: 0 }}
      className={`fixed left-0 top-0 h-screen bg-slate-900 border-r border-slate-700 transition-all duration-300 z-50 ${
        collapsed ? 'w-16' : 'w-64'
      }`}
    >
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        {!collapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center space-x-2"
          >
            <div className="w-8 h-8 bg-gradient-to-br from-amber-500 to-red-600 rounded-lg flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">Scorpion</h1>
              <p className="text-xs text-slate-400">Threat Hunting Platform</p>
            </div>
          </motion.div>
        )}
        
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className="text-slate-400 hover:text-white"
        >
          {collapsed ? <Menu className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </Button>
      </div>

      <nav className="p-2 space-y-1 overflow-y-auto h-[calc(100vh-140px)]">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeSection === item.id;
          
          return (
            <motion.button
              key={item.id}
              onClick={() => setActiveSection(item.id)}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 ${
                isActive 
                  ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/25' 
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <Icon className={`w-5 h-5 ${isActive ? 'text-white' : 'text-slate-400'}`} />
              {!collapsed && (
                <span className="text-sm font-medium">{item.label}</span>
              )}
            </motion.button>
          );
        })}
      </nav>

      {!collapsed && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="absolute bottom-4 left-4 right-4"
        >
          <div className="glass-card p-3 rounded-lg">
            <div className="flex items-center space-x-2 mb-2">
              <AlertTriangle className="w-4 h-4 text-yellow-500" />
              <span className="text-xs font-medium text-white">System Status</span>
            </div>
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Active Scans</span>
                <span className="text-green-400">0</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Threats Blocked</span>
                <span className="text-red-400">0</span>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </motion.aside>
  );
};

export default Sidebar;
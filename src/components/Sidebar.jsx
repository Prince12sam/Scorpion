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

import { clearTokens } from '@/lib/auth';

const Sidebar = ({ activeSection, setActiveSection, collapsed, setCollapsed, onLogout }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Security Dashboard', icon: Shield },
    { id: 'recon', label: 'Recon & Discovery', icon: Network },
    { id: 'scanner', label: 'Vulnerability Scanner', icon: Search },
    { id: 'monitoring', label: 'Monitoring Center', icon: Activity },
    { id: 'fim', label: 'AI Pentest Agent', icon: FileCheck2 },
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
        
        <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className="text-slate-400 hover:text-white"
        >
          {collapsed ? <Menu className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </Button>
        {!collapsed && (
          <Button
            variant="outline"
            size="sm"
            className="text-slate-300 border-slate-600 hover:bg-slate-800"
            onClick={() => { clearTokens(); onLogout?.(); }}
          >
            Logout
          </Button>
        )}
        </div>
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


    </motion.aside>
  );
};

export default Sidebar;
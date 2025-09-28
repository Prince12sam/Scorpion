import React, { useState } from 'react';
import { Helmet } from 'react-helmet';
import { motion, AnimatePresence } from 'framer-motion';
import Sidebar from '@/components/Sidebar';
import Dashboard from '@/components/Dashboard';
import VulnerabilityScanner from '@/components/VulnerabilityScanner';
import MonitoringCenter from '@/components/MonitoringCenter';
import ReportsGenerator from '@/components/ReportsGenerator';
import ComplianceTracker from '@/components/ComplianceTracker';
import ThreatIntelligence from '@/components/ThreatIntelligence';
import UserManagement from '@/components/UserManagement';
import Settings from '@/components/Settings';
import InvestigationTools from '@/components/InvestigationTools';
import FileIntegrityMonitor from '@/components/FileIntegrityMonitor';
import GlobalThreatHunting from '@/components/GlobalThreatHunting';
import ReconDiscovery from '@/components/ReconDiscovery';
import PasswordSecurity from '@/components/PasswordSecurity';
import AdvancedExploitation from '@/components/AdvancedExploitation';
import ApiTesting from '@/components/ApiTesting';
import NetworkDiscovery from '@/components/NetworkDiscovery';
import BruteForceTools from '@/components/BruteForceTools';
import { Toaster } from '@/components/ui/toaster';

function App() {
  const [activeSection, setActiveSection] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const renderActiveSection = () => {
    const sections = {
      dashboard: <Dashboard />,
      recon: <ReconDiscovery />,
      scanner: <VulnerabilityScanner />,
      monitoring: <MonitoringCenter />,
      fim: <FileIntegrityMonitor />,
      'threat-hunting': <GlobalThreatHunting />,
      'password-security': <PasswordSecurity />,
      exploitation: <AdvancedExploitation />,
      'api-testing': <ApiTesting />,
      'network-discovery': <NetworkDiscovery />,
      'brute-force': <BruteForceTools />,
      reports: <ReportsGenerator />,
      compliance: <ComplianceTracker />,
      intelligence: <ThreatIntelligence />,
      users: <UserManagement />,
      settings: <Settings />,
      investigation: <InvestigationTools />
    };

    return sections[activeSection] || <Dashboard />;
  };

  return (
    <>
      <Helmet>
        <title>Scorpion - Global Threat-Hunting Platform</title>
        <meta name="description" content="Scorpion: Global threat-hunting platform with real-time intelligence, suspect profiling, and advanced cybersecurity tools." />
      </Helmet>
      
      <div className="min-h-screen bg-slate-950 text-white cyber-grid">
        <div className="flex">
          <Sidebar 
            activeSection={activeSection}
            setActiveSection={setActiveSection}
            collapsed={sidebarCollapsed}
            setCollapsed={setSidebarCollapsed}
          />
          
          <main className={`flex-1 transition-all duration-300 ${
            sidebarCollapsed ? 'ml-16' : 'ml-64'
          }`}>
            <div className="p-6">
              <AnimatePresence mode="wait">
                <motion.div
                  key={activeSection}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3 }}
                >
                  {renderActiveSection()}
                </motion.div>
              </AnimatePresence>
            </div>
          </main>
        </div>
        
        <Toaster />
      </div>
    </>
  );
}

export default App;
import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Activity, 
  Zap,
  FileCheck2,
  Bug,
  Search,
  FileText
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import SecurityMetricCard from '@/components/SecurityMetricCard';
import ThreatTraceMap from '@/components/ThreatTraceMap';
import RecentAlerts from '@/components/RecentAlerts';
import SystemHealth from '@/components/SystemHealth';
import { toast } from '@/components/ui/use-toast';

const Dashboard = () => {
  const [realTimeData, setRealTimeData] = useState({
    intrusionsDetected: 0,
    vulnerabilities: 0,
    fimAlerts: 0,
    complianceScore: 0,
  });

  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [loading, setLoading] = useState(true);

  // API Base URL - use environment variable or default to localhost
  const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:3001/api';

  // Fetch dashboard metrics on component mount
  useEffect(() => {
    fetchDashboardMetrics();
    
    // Set up periodic updates every 30 seconds
    const interval = setInterval(fetchDashboardMetrics, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardMetrics = async () => {
    try {
      const response = await fetch(`${API_BASE}/dashboard/metrics`);
      if (response.ok) {
        const data = await response.json();
        setRealTimeData(data.metrics);
      }
    } catch (error) {
      console.error('Failed to fetch dashboard metrics:', error);
      toast({
        title: "Connection Error",
        description: "Unable to fetch real-time metrics. Using offline mode.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const startQuickScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    
    try {
      // Start scan via API
      const response = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target: 'localhost',
          type: 'quick',
          ports: '1-1000'
        })
      });

      if (response.ok) {
        const { scanId } = await response.json();
        
        // Poll for scan progress
        const progressInterval = setInterval(async () => {
          try {
            const progressResponse = await fetch(`${API_BASE}/scan/${scanId}`);
            if (progressResponse.ok) {
              const scanData = await progressResponse.json();
              
              if (scanData.status === 'completed') {
                clearInterval(progressInterval);
                setIsScanning(false);
                setScanProgress(100);
                
                const vulnCount = scanData.results?.vulnerabilities?.length || 0;
                toast({
                  title: "Quick Scan Complete",
                  description: `Found ${vulnCount} vulnerabilities`,
                });
                
                // Update metrics after scan
                fetchDashboardMetrics();
              } else if (scanData.status === 'failed') {
                clearInterval(progressInterval);
                setIsScanning(false);
                toast({
                  title: "Scan Failed",
                  description: scanData.error || "Unknown error occurred",
                  variant: "destructive"
                });
              } else {
                // Update progress (simulate for now)
                setScanProgress(prev => Math.min(prev + Math.random() * 10, 95));
              }
            }
          } catch (error) {
            console.error('Failed to get scan progress:', error);
          }
        }, 1000);
        
        // Cleanup interval after 5 minutes
        setTimeout(() => {
          clearInterval(progressInterval);
          if (isScanning) {
            setIsScanning(false);
            toast({
              title: "Scan Timeout",
              description: "Scan took too long to complete",
              variant: "destructive"
            });
          }
        }, 300000);
        
      } else {
        throw new Error('Failed to start scan');
      }
    } catch (error) {
      console.error('Failed to start scan:', error);
      setIsScanning(false);
      toast({
        title: "Scan Failed",
        description: "Unable to start vulnerability scan. Check server connection.",
        variant: "destructive"
      });
    }
  };

  const securityMetrics = [
    {
      title: 'Intrusions Detected',
      value: realTimeData.intrusionsDetected,
      change: '',
      trend: 'none',
      icon: Bug,
      color: 'from-red-500 to-red-600',
      description: 'Last 24 hours'
    },
    {
      title: 'Active Vulnerabilities',
      value: realTimeData.vulnerabilities,
      change: '',
      trend: 'none',
      icon: AlertTriangle,
      color: 'from-orange-500 to-orange-600',
      description: 'Requiring attention'
    },
    {
      title: 'FIM Alerts',
      value: realTimeData.fimAlerts,
      change: '',
      trend: 'none',
      icon: FileCheck2,
      color: 'from-yellow-500 to-yellow-600',
      description: 'File integrity changes'
    },
    {
      title: 'Compliance Score',
      value: `${realTimeData.complianceScore}%`,
      change: '',
      trend: 'none',
      icon: CheckCircle,
      color: 'from-green-500 to-green-600',
      description: 'OWASP & regulatory'
    }
  ];

  const quickActions = [
    { label: 'Run Vulnerability Scan', icon: Search, action: startQuickScan },
    { label: 'Check System Health', icon: Activity, action: () => toast({ title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀" }) },
    { label: 'Generate Report', icon: FileText, action: () => toast({ title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀" }) },
    { label: 'Update Threat Intel', icon: Zap, action: () => toast({ title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀" }) }
  ];

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Security Dashboard</h1>
          <p className="text-slate-400">Real-time cybersecurity monitoring and threat detection</p>
        </div>
        
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 px-3 py-2 bg-green-500/20 rounded-lg border border-green-500/30">
            <div className="w-2 h-2 bg-green-500 rounded-full security-pulse"></div>
            <span className="text-green-400 text-sm font-medium">All Systems Operational</span>
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
      >
        {securityMetrics.map((metric, index) => (
          <SecurityMetricCard key={metric.title} {...metric} index={index} />
        ))}
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card p-6 rounded-xl"
      >
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
          <Zap className="w-5 h-5 mr-2 text-blue-400" />
          Quick Actions
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {quickActions.map((action, index) => {
            const Icon = action.icon;
            return (
              <Button
                key={action.label}
                onClick={action.action}
                variant="outline"
                className="h-auto p-4 flex flex-col items-center space-y-2 bg-slate-800/50 border-slate-600 hover:bg-slate-700/50 hover:border-blue-500/50 transition-all duration-200"
                disabled={action.label === 'Run Vulnerability Scan' && isScanning}
              >
                <Icon className="w-6 h-6 text-blue-400" />
                <span className="text-sm text-center">{action.label}</span>
                {action.label === 'Run Vulnerability Scan' && isScanning && (
                  <div className="w-full bg-slate-700 rounded-full h-2 mt-2">
                    <div 
                      className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${scanProgress}%` }}
                    ></div>
                  </div>
                )}
              </Button>
            );
          })}
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="lg:col-span-2"
        >
          <ThreatTraceMap />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
        >
          <SystemHealth />
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <RecentAlerts />
      </motion.div>
    </div>
  );
};

export default Dashboard;
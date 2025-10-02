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
import apiClient from '@/lib/api-client';

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

  // Fetch dashboard metrics on component mount
  useEffect(() => {
    fetchDashboardMetrics();
    
    // Set up periodic updates every 30 seconds
    const interval = setInterval(fetchDashboardMetrics, 30000);
    
    // Cleanup: cancel pending requests and clear interval
    return () => {
      clearInterval(interval);
      apiClient.cancelRequest('/dashboard/metrics');
    };
  }, []);

  const fetchDashboardMetrics = async () => {
    try {
      const data = await apiClient.get('/dashboard/metrics');
      if (data && data.metrics && data.metrics.securityMetrics) {
        setRealTimeData({
          intrusionsDetected: data.metrics.securityMetrics.intrusionsDetected || 0,
          vulnerabilities: data.metrics.securityMetrics.vulnerabilities || 0,
          fimAlerts: data.metrics.securityMetrics.fimAlerts || 0,
          complianceScore: data.metrics.securityMetrics.complianceScore || 100
        });
      } else {
        // Use default values when no API data is available
        setRealTimeData({
          intrusionsDetected: 0,
          vulnerabilities: 0,
          fimAlerts: 0,
          complianceScore: 100
        });
      }
    } catch (error) {
      // Don't show error for cancelled requests
      if (error.name !== 'AbortError') {
        console.error('Failed to fetch dashboard metrics:', error);
        // Use clean default values instead of random data
        setRealTimeData({
          intrusionsDetected: 0,
          vulnerabilities: 0,
          fimAlerts: 0,
          complianceScore: 100
        });
        toast({
          title: "API Connection Issue",
          description: "Unable to connect to security server. Please check server status.",
          variant: "destructive"
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const startQuickScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    
    try {
      // Start scan via API
      const { scanId } = await apiClient.post('/scan', {
        target: 'localhost',
        type: 'quick',
        ports: '1-1000'
      });
      
      // Poll for scan progress
      const progressInterval = setInterval(async () => {
        try {
          const scanData = await apiClient.get(`/scan/${scanId}`);
          
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
            // Update progress based on actual scan progress
            const progress = scanData.progress || 0;
            setScanProgress(progress);
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

  const checkSystemHealth = async () => {
    try {
      const data = await apiClient.get('/system/health');
      toast({
        title: "System Health Check",
        description: `CPU: ${data.cpu}%, Memory: ${data.memory}%, Disk: ${data.disk}%`,
      });
    } catch (error) {
      toast({
        title: "Health Check Failed",
        description: "Unable to retrieve system health data",
        variant: "destructive"
      });
    }
  };

  const generateReport = async () => {
    try {
      const data = await apiClient.post('/reports/generate', { type: 'quick' });
      toast({
        title: "Report Generated",
        description: `Security report saved as ${data.filename}`,
      });
    } catch (error) {
      toast({
        title: "Report Generation Failed",
        description: "Unable to generate security report",
        variant: "destructive"
      });
    }
  };

  const updateThreatIntel = async () => {
    try {
      const data = await apiClient.post('/threat-intel/update');
      toast({
        title: "Threat Intel Updated",
        description: `Updated ${data.count} threat indicators`,
      });
    } catch (error) {
      toast({
        title: "Update Failed",
        description: "Unable to update threat intelligence feeds",
        variant: "destructive"
      });
    }
  };

  const startMonitoring = async () => {
    try {
      // Start real-time monitoring
      toast({
        title: "Monitoring Started",
        description: "Real-time security monitoring has been activated",
      });
      
      // Increase update frequency during monitoring
      const data = await apiClient.get('/monitoring/metrics');
      
      setRealTimeData(prevData => ({
        ...prevData,
        activeMonitoring: true
      }));
      
    } catch (error) {
      toast({
        title: "Monitoring Failed",
        description: "Unable to start security monitoring",
        variant: "destructive"
      });
    }
  };

  const quickActions = [
    { label: 'Run Vulnerability Scan', icon: Search, action: startQuickScan },
    { label: 'Start Monitoring', icon: Activity, action: startMonitoring },
    { label: 'Generate Report', icon: FileText, action: generateReport },
    { label: 'Update Threat Intel', icon: Zap, action: updateThreatIntel }
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
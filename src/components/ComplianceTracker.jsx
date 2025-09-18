import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { CheckCircle, AlertTriangle, Clock, Shield, FileCheck, Award } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const ComplianceTracker = () => {
  const [selectedFramework, setSelectedFramework] = useState('owasp');
  const [complianceFrameworks, setComplianceFrameworks] = useState([]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'compliant': return 'text-green-400 bg-green-500/20 border-green-500/30';
      case 'partial': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'non-compliant': return 'text-red-400 bg-red-500/20 border-red-500/30';
      default: return 'text-slate-400 bg-slate-500/20 border-slate-500/30';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'compliant': return CheckCircle;
      case 'partial': return Clock;
      case 'non-compliant': return AlertTriangle;
      default: return AlertTriangle;
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-blue-400';
      default: return 'text-slate-400';
    }
  };

  const getFrameworkStatusColor = (status) => {
    switch (status) {
      case 'excellent': return 'text-green-400';
      case 'good': return 'text-blue-400';
      case 'needs-improvement': return 'text-yellow-400';
      case 'poor': return 'text-red-400';
      default: return 'text-slate-400';
    }
  };

  const currentFramework = complianceFrameworks.find(f => f.id === selectedFramework);

  const handleAssessment = () => {
    toast({
      title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀"
    });
  };

  const frameworkTemplates = [
    { id: 'owasp', name: 'OWASP Top 10', description: 'Web Application Security Risks' },
    { id: 'pci-dss', name: 'PCI DSS', description: 'Payment Card Industry Data Security Standard' },
    { id: 'hipaa', name: 'HIPAA', description: 'Health Insurance Portability and Accountability Act' },
    { id: 'iso27001', name: 'ISO 27001', description: 'Information Security Management System' },
  ];

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Compliance Tracker</h1>
          <p className="text-slate-400">Monitor regulatory compliance and security standards</p>
        </div>
        
        <Button onClick={handleAssessment} className="bg-blue-600 hover:bg-blue-700">
          <FileCheck className="w-4 h-4 mr-2" />
          Run Assessment
        </Button>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
      >
        {frameworkTemplates.map((framework, index) => (
          <motion.div
            key={framework.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            whileHover={{ scale: 1.02 }}
            className={`glass-card p-6 rounded-xl cursor-pointer transition-all duration-200 ${
              selectedFramework === framework.id
                ? 'border-blue-500 bg-blue-500/10'
                : 'border-slate-700/50 hover:border-slate-600/50'
            }`}
            onClick={() => setSelectedFramework(framework.id)}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold text-white">N/A</div>
                <div className="text-xs font-medium text-slate-400">NO DATA</div>
              </div>
            </div>
            
            <h3 className="text-lg font-semibold text-white mb-1">{framework.name}</h3>
            <p className="text-sm text-slate-400 mb-2">{framework.description}</p>
            <p className="text-xs text-slate-500">Last assessed: Never</p>
          </motion.div>
        ))}
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card p-6 rounded-xl"
      >
        <div className="text-center py-16 text-slate-400">
          <Award className="w-16 h-16 mx-auto mb-4 text-slate-500" />
          <h2 className="text-xl font-semibold text-white">No Compliance Data</h2>
          <p>Run an assessment to view compliance details for the selected framework.</p>
        </div>
      </motion.div>
    </div>
  );
};

export default ComplianceTracker;
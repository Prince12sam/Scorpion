import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { FileText, Download, Calendar, Filter, BarChart3, PieChart, TrendingUp, FileJson, FileSpreadsheet } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:3001/api';

const ReportsGenerator = () => {
  const [selectedReportType, setSelectedReportType] = useState('security-overview');
  const [dateRange, setDateRange] = useState('last-30-days');
  const [reportFormat, setReportFormat] = useState('pdf');
  const [isGenerating, setIsGenerating] = useState(false);
  const [recentReports, setRecentReports] = useState([]);

  const reportTypes = [
    {
      id: 'security-overview',
      name: 'Security Overview',
      description: 'Comprehensive security posture analysis',
      icon: BarChart3,
      estimatedTime: '2-3 minutes'
    },
    {
      id: 'vulnerability-assessment',
      name: 'Vulnerability Assessment',
      description: 'Detailed vulnerability analysis and recommendations',
      icon: FileText,
      estimatedTime: '3-5 minutes'
    },
    {
      id: 'compliance-report',
      name: 'Compliance Report',
      description: 'OWASP, PCI DSS, HIPAA compliance status',
      icon: PieChart,
      estimatedTime: '5-7 minutes'
    },
    {
      id: 'threat-intelligence',
      name: 'Threat Intelligence',
      description: 'Latest threat trends and indicators',
      icon: TrendingUp,
      estimatedTime: '2-4 minutes'
    }
  ];

  const dateRanges = [
    { value: 'last-7-days', label: 'Last 7 Days' },
    { value: 'last-30-days', label: 'Last 30 Days' },
    { value: 'last-90-days', label: 'Last 90 Days' },
    { value: 'custom', label: 'Custom Range' }
  ];

  const formats = [
    { value: 'pdf', label: 'PDF Report', description: 'Professional formatted document' },
    { value: 'html', label: 'HTML Report', description: 'Interactive web-based report' },
    { value: 'csv', label: 'CSV Data', description: 'Raw data for analysis' },
    { value: 'json', label: 'JSON Export', description: 'Machine-readable format' }
  ];

  useEffect(() => {
    fetchRecentReports();
  }, []);

  const fetchRecentReports = async () => {
    try {
      const response = await fetch(`${API_BASE}/reports/list`);
      if (response.ok) {
        const data = await response.json();
        setRecentReports(data.reports || []);
      }
    } catch (error) {
      console.error('Error fetching reports:', error);
    }
  };

  const generateReport = async () => {
    setIsGenerating(true);
    
    try {
      const response = await fetch(`${API_BASE}/reports/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: selectedReportType,
          dateRange,
          format: reportFormat
        })
      });

      if (response.ok) {
        const data = await response.json();
        
        if (reportFormat === 'pdf' || reportFormat === 'html') {
          // For downloadable files
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.style.display = 'none';
          a.href = url;
          a.download = data.filename || `report.${reportFormat}`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
        }

        toast({
          title: "Report Generated",
          description: `${reportTypes.find(t => t.id === selectedReportType)?.name} report created successfully`,
        });
        
        fetchRecentReports();
      } else {
        throw new Error('Report generation failed');
      }
    } catch (error) {
      toast({
        title: "Generation Failed",
        description: error.message || "Failed to generate report",
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Reports Generator</h1>
          <p className="text-slate-400">Generate comprehensive security reports and analytics</p>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-2 glass-card p-6 rounded-xl"
        >
          <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
            <FileText className="w-5 h-5 mr-2 text-blue-400" />
            Select Report Type
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {reportTypes.map((report) => {
              const Icon = report.icon;
              return (
                <motion.div
                  key={report.id}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className={`p-4 rounded-lg border-2 cursor-pointer transition-all duration-200 ${
                    selectedReportType === report.id
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-slate-600 bg-slate-800/50 hover:border-slate-500'
                  }`}
                  onClick={() => setSelectedReportType(report.id)}
                >
                  <div className="flex items-start space-x-3">
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                      selectedReportType === report.id
                        ? 'bg-blue-500'
                        : 'bg-slate-700'
                    }`}>
                      <Icon className="w-5 h-5 text-white" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-white mb-1">{report.name}</h3>
                      <p className="text-sm text-slate-400 mb-2">{report.description}</p>
                      <p className="text-xs text-slate-500">Est. time: {report.estimatedTime}</p>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-6"
        >
          <div className="glass-card p-6 rounded-xl">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <Calendar className="w-4 h-4 mr-2 text-blue-400" />
              Date Range
            </h3>
            
            <div className="space-y-2">
              {dateRanges.map((range) => (
                <label key={range.value} className="flex items-center space-x-3 cursor-pointer">
                  <input
                    type="radio"
                    name="dateRange"
                    value={range.value}
                    checked={dateRange === range.value}
                    onChange={(e) => setDateRange(e.target.value)}
                    className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 focus:ring-blue-500"
                  />
                  <span className="text-sm text-slate-300">{range.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="glass-card p-6 rounded-xl">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <Filter className="w-4 h-4 mr-2 text-blue-400" />
              Output Format
            </h3>
            
            <div className="space-y-3">
              {formats.map((format) => (
                <label key={format.value} className="flex items-start space-x-3 cursor-pointer">
                  <input
                    type="radio"
                    name="format"
                    value={format.value}
                    checked={reportFormat === format.value}
                    onChange={(e) => setReportFormat(e.target.value)}
                    className="w-4 h-4 text-blue-600 bg-slate-700 border-slate-600 focus:ring-blue-500 mt-0.5"
                  />
                  <div>
                    <div className="text-sm font-medium text-slate-300">{format.label}</div>
                    <div className="text-xs text-slate-500">{format.description}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <Button
            onClick={generateReport}
            disabled={isGenerating}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
          >
            {isGenerating ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                Generating...
              </>
            ) : (
              <>
                <Download className="w-4 h-4 mr-2" />
                Generate Report
              </>
            )}
          </Button>
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="glass-card p-6 rounded-xl"
      >
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
          <FileText className="w-5 h-5 mr-2 text-slate-400" />
          Recent Reports
        </h2>
        
        {recentReports.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            <p>No recent reports.</p>
            <p className="text-sm">Generate a report to see it here.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {recentReports.map((report, index) => (
              <motion.div
                key={report.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200"
              >
                <div className="flex items-center space-x-4">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                    <FileText className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="font-medium text-white">{report.name}</h3>
                    <div className="flex items-center space-x-4 text-sm text-slate-400">
                      <span>{report.type}</span>
                      <span>{report.generated}</span>
                      <span>{report.format} • {report.size}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <Button variant="outline" size="sm">
                    <Download className="w-4 h-4 mr-2" />
                    Download
                  </Button>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default ReportsGenerator;
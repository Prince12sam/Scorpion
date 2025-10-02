import React, { useState } from 'react';
import { Shield, FileCheck, Award, AlertCircle, CheckCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const ComplianceTracker = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [selectedFramework, setSelectedFramework] = useState('owasp');
  const [target, setTarget] = useState('');
  const [complianceData, setComplianceData] = useState(null);

  const frameworkTemplates = [
    { id: 'owasp', name: 'OWASP Top 10' },
    { id: 'nist', name: 'NIST Cybersecurity Framework' },
    { id: 'iso27001', name: 'ISO 27001' },
    { id: 'pci-dss', name: 'PCI DSS' },
    { id: 'hipaa', name: 'HIPAA' },
    { id: 'gdpr', name: 'GDPR' }
  ];

  const handleAssessment = async () => {
    if (!target.trim()) {
      toast({
        title: "Target Required",
        description: "Please enter a target domain or IP address",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    
    try {
      const response = await fetch('http://localhost:3001/api/compliance/assess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          framework: selectedFramework,
          target: target.trim()
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.assessment) {
          setComplianceData(data.assessment);
          toast({
            title: "Assessment Complete",
            description: `Compliance score: ${data.assessment.overallScore}%`
          });
        } else {
          throw new Error('No assessment data received');
        }
      } else {
        throw new Error(`Server error: ${response.status}`);
      }
    } catch (error) {
      console.error('Assessment error:', error);
      toast({
        title: "Assessment Failed",
        description: error.message || "Failed to complete compliance assessment",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Compliance Tracker</h1>
          <p className="text-slate-400">Monitor regulatory compliance and security standards</p>
        </div>
        
        <div className="flex items-center space-x-3">
          <Button 
            onClick={handleAssessment} 
            disabled={isLoading} 
            className="bg-blue-600 hover:bg-blue-700"
          >
            <Shield className="w-4 h-4 mr-2" />
            {isLoading ? 'Assessing...' : 'Run Assessment'}
          </Button>
          <Button variant="outline" disabled={!complianceData}>
            <FileCheck className="w-4 h-4 mr-2" />
            Export Report
          </Button>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-slate-800/30 rounded-lg border border-slate-700">
        <div>
          <label className="block text-sm font-medium mb-2 text-slate-300">Target System/Domain</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter domain or IP (e.g., example.com)"
            className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none"
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2 text-slate-300">Compliance Framework</label>
          <select
            value={selectedFramework}
            onChange={(e) => setSelectedFramework(e.target.value)}
            className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
          >
            {frameworkTemplates.map(framework => (
              <option key={framework.id} value={framework.id}>
                {framework.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {complianceData ? (
        <div className="glass-card p-6 rounded-xl">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white">Assessment Results</h2>
            <div className="text-right">
              <div className="text-2xl font-bold text-green-400">{complianceData.overallScore}%</div>
              <div className="text-sm text-slate-400">{complianceData.status?.toUpperCase()}</div>
            </div>
          </div>

          {complianceData.categories && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {complianceData.categories.map((category, index) => (
                <div key={index} className="p-4 bg-slate-800/50 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-medium text-white">{category.name}</h3>
                    {category.status === 'passed' ? (
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    ) : (
                      <AlertCircle className="w-4 h-4 text-yellow-400" />
                    )}
                  </div>
                  <div className="text-2xl font-bold text-slate-300">{category.score}%</div>
                  <div className="text-sm text-slate-400">{category.status}</div>
                </div>
              ))}
            </div>
          )}

          {complianceData.recommendations && complianceData.recommendations.length > 0 && (
            <div className="mt-6">
              <h3 className="text-lg font-semibold text-white mb-3">Recommendations</h3>
              <ul className="space-y-2">
                {complianceData.recommendations.map((rec, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <AlertCircle className="w-4 h-4 text-yellow-400 mt-0.5" />
                    <span className="text-slate-300">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : (
        <div className="glass-card p-6 rounded-xl">
          <div className="text-center py-16 text-slate-400">
            <Award className="w-16 h-16 mx-auto mb-4 text-slate-500" />
            <h2 className="text-xl font-semibold text-white">No Assessment Data</h2>
            <p>Run an assessment to view compliance details for the selected framework.</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default ComplianceTracker;

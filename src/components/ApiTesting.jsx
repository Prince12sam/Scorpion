import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Plug, 
  Play, 
  Target, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Globe,
  Code,
  Key,
  Shield,
  Clock,
  FileText
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/components/ui/use-toast';

const ApiTesting = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState([]);
  const [targetUrl, setTargetUrl] = useState('');
  const [testType, setTestType] = useState('basic');
  const [endpoints, setEndpoints] = useState([]);
  const { toast } = useToast();

  const testTypes = [
    { value: 'basic', label: 'Basic API Discovery', description: 'Discover API endpoints and methods' },
    { value: 'auth', label: 'Authentication Testing', description: 'Test authentication mechanisms' },
    { value: 'injection', label: 'Injection Testing', description: 'SQL injection, XSS, etc.' },
    { value: 'comprehensive', label: 'Comprehensive Scan', description: 'Full API security assessment' }
  ];

  const runApiTest = async () => {
    if (!targetUrl) {
      toast({
        title: "Error",
        description: "Please specify a target URL for API testing",
        variant: "destructive",
      });
      return;
    }

    setIsRunning(true);
    try {
      const response = await fetch('/api/testing/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: targetUrl,
          testType: testType,
          timestamp: new Date().toISOString()
        })
      });

      const data = await response.json();
      setResults(prev => [data, ...prev.slice(0, 9)]);
      setEndpoints(data.endpoints || []);
      
      toast({
        title: "API Testing Completed",
        description: `Found ${data.endpoints?.length || 0} endpoints with ${data.vulnerabilities?.length || 0} issues`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to run API test",
        variant: "destructive",
      });
    } finally {
      setIsRunning(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'vulnerable':
        return <XCircle className="w-4 h-4 text-red-400" />;
      case 'secure':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      default:
        return <Globe className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-r from-blue-900/20 to-purple-900/20 p-6 rounded-lg border border-blue-500/30"
      >
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-blue-500/20 rounded-lg">
            <Plug className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">API Vulnerability Testing</h1>
            <p className="text-blue-400">Comprehensive API security assessment and vulnerability discovery</p>
          </div>
        </div>
      </motion.div>

      {/* Testing Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="lg:col-span-2 bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-purple-400" />
            API Testing Configuration
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2 text-slate-300">Target API URL</label>
              <input
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://api.example.com"
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:border-purple-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-2 text-slate-300">Test Type</label>
              <select
                value={testType}
                onChange={(e) => setTestType(e.target.value)}
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-purple-500 focus:outline-none"
              >
                {testTypes.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
              <p className="text-xs text-slate-400 mt-1">
                {testTypes.find(t => t.value === testType)?.description}
              </p>
            </div>

            <Button
              onClick={runApiTest}
              disabled={isRunning || !targetUrl}
              className="bg-purple-600 hover:bg-purple-700 flex items-center gap-2"
            >
              {isRunning ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  Testing API...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Start API Test
                </>
              )}
            </Button>
          </div>
        </motion.div>

        {/* Test Types Info */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-green-400" />
            Testing Coverage
          </h2>
          
          <div className="space-y-3">
            <div className="p-3 bg-slate-900/50 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <Key className="w-4 h-4 text-yellow-400" />
                <span className="font-medium text-white">Authentication</span>
              </div>
              <p className="text-xs text-slate-400">JWT, OAuth, API keys, session management</p>
            </div>
            
            <div className="p-3 bg-slate-900/50 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <Code className="w-4 h-4 text-red-400" />
                <span className="font-medium text-white">Injection Attacks</span>
              </div>
              <p className="text-xs text-slate-400">SQL injection, NoSQL injection, LDAP injection</p>
            </div>
            
            <div className="p-3 bg-slate-900/50 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <Globe className="w-4 h-4 text-blue-400" />
                <span className="font-medium text-white">Endpoint Discovery</span>
              </div>
              <p className="text-xs text-slate-400">Hidden endpoints, method enumeration</p>
            </div>
            
            <div className="p-3 bg-slate-900/50 rounded-lg">
              <div className="flex items-center gap-2 mb-1">
                <Shield className="w-4 h-4 text-green-400" />
                <span className="font-medium text-white">Security Headers</span>
              </div>
              <p className="text-xs text-slate-400">CORS, CSP, security configurations</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Discovered Endpoints */}
      {endpoints.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Globe className="w-5 h-5 text-blue-400" />
            Discovered Endpoints ({endpoints.length})
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-64 overflow-y-auto">
            {endpoints.map((endpoint, index) => (
              <div
                key={index}
                className="p-3 bg-slate-900/50 rounded-lg border border-slate-600"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-sm text-white">{endpoint.method}</span>
                  {getStatusIcon(endpoint.status)}
                </div>
                <p className="text-xs text-slate-300 mb-1">{endpoint.path}</p>
                <p className="text-xs text-slate-400">
                  Response: {endpoint.response_code} | {endpoint.response_time}ms
                </p>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Results */}
      {results.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <FileText className="w-5 h-5 text-green-400" />
            API Testing Results
          </h2>
          
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {results.map((result, index) => (
              <div
                key={index}
                className="p-4 bg-slate-900/50 rounded-lg border border-slate-600"
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="font-medium text-white">
                    {result.target || 'Unknown Target'}
                  </span>
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <Clock className="w-3 h-3" />
                    {new Date(result.timestamp).toLocaleString()}
                  </div>
                </div>
                
                <div className="grid grid-cols-3 gap-4 text-sm mb-3">
                  <div>
                    <span className="text-slate-400">Endpoints:</span>
                    <span className="ml-2 text-blue-400">{result.endpoints?.length || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Vulnerabilities:</span>
                    <span className="ml-2 text-red-400">{result.vulnerabilities?.length || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Test Type:</span>
                    <span className="ml-2 text-white">{result.testType}</span>
                  </div>
                </div>

                {result.vulnerabilities && result.vulnerabilities.length > 0 && (
                  <div className="mt-3">
                    <span className="text-slate-400 text-sm">Security Issues:</span>
                    <div className="mt-1 space-y-1">
                      {result.vulnerabilities.map((vuln, vIndex) => (
                        <div key={vIndex} className="text-xs bg-red-950/30 p-2 rounded border border-red-500/30">
                          <span className="font-medium text-red-400">{vuln.severity}:</span> {vuln.description}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default ApiTesting;
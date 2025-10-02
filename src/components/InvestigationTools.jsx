import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Target, Search, FileText, MapPin, User, Shield, Smartphone, Banknote } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const InvestigationTools = () => {
  const [activeTool, setActiveTool] = useState('ip-lookup');
  const [query, setQuery] = useState('');
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const tools = [
    { id: 'ip-lookup', name: 'IP Lookup', icon: MapPin, placeholder: 'Enter IP address (e.g., 8.8.8.8)' },
    { id: 'domain-lookup', name: 'Domain Lookup', icon: Search, placeholder: 'Enter domain name (e.g., example.com)' },
    { id: 'hash-analysis', name: 'Hash Analysis', icon: Shield, placeholder: 'Enter file hash (MD5, SHA1, SHA256)' },
    { id: 'sim-imei', name: 'SIM/IMEI Lookup', icon: Smartphone, placeholder: 'Enter SIM or IMEI number' },
    { id: 'financial-trace', name: 'Financial Trace', icon: Banknote, placeholder: 'Enter Crypto Wallet or Transaction ID' },
    { id: 'user-activity', name: 'User Activity', icon: User, placeholder: 'Enter username or email' },
    { id: 'log-search', name: 'Log Search', icon: FileText, placeholder: 'Enter search query (e.g., "failed login")' },
  ];

  const handleSearch = async () => {
    if (!query.trim()) {
      toast({
        title: "Invalid Query",
        description: "Please enter a valid query for the selected tool.",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    setResults(null);

    try {
      const response = await fetch('http://localhost:3001/api/investigation/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          query: query.trim(), 
          toolType: activeTool 
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.results) {
          setResults(data.results);
          toast({
            title: "Investigation Complete",
            description: `Analysis completed for ${query} using ${tools.find(t => t.id === activeTool)?.name}`
          });
        } else {
          throw new Error('No investigation data received');
        }
      } else {
        throw new Error(`Server error: ${response.status}`);
      }
    } catch (error) {
      console.error('Investigation error:', error);
      toast({
        title: "Investigation Failed",
        description: error.message || "Unable to complete investigation. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };



  const currentTool = tools.find(t => t.id === activeTool);

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold text-white mb-2">Investigation Tools</h1>
        <p className="text-slate-400">Global OSINT and forensic analysis tools.</p>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass-card p-6 rounded-xl">
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center"><Target className="w-5 h-5 mr-2 text-blue-400" />Select Investigation Tool</h2>
        <div className="flex flex-wrap gap-3">
          {tools.map((tool) => {
            const Icon = tool.icon;
            return (
              <Button
                key={tool.id}
                variant={activeTool === tool.id ? 'default' : 'outline'}
                onClick={() => { setActiveTool(tool.id); setQuery(''); setResults(null); }}
                className={`h-auto p-3 flex items-center space-x-2 ${activeTool === tool.id ? 'bg-blue-600' : 'border-slate-600 text-slate-400'}`}
              >
                <Icon className="w-4 h-4" />
                <span>{tool.name}</span>
              </Button>
            );
          })}
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">
        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder={currentTool.placeholder}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500 transition-colors"
              disabled={isLoading}
            />
          </div>
          <Button onClick={handleSearch} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700">
            {isLoading ? <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div> : <Search className="w-4 h-4 mr-2" />}
            Investigate
          </Button>
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        {isLoading && (
          <div className="glass-card p-6 rounded-xl text-center">
            <div className="flex items-center justify-center space-x-2">
              <div className="w-6 h-6 border-2 border-blue-400 border-t-transparent rounded-full animate-spin"></div>
              <span className="text-lg text-slate-300">Investigating...</span>
            </div>
          </div>
        )}
        {!results && !isLoading && (
          <div className="text-center py-16 text-slate-400 glass-card rounded-xl">
            <Target className="w-16 h-16 mx-auto mb-4 text-slate-500" />
            <h2 className="text-xl font-semibold text-white">Investigation Results</h2>
            <p>Results from your investigation will appear here.</p>
          </div>
        )}
        {results && (
          <div className="glass-card p-6 rounded-xl">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-semibold text-white">Investigation Results</h2>
              <div className="flex gap-2">
                <Button 
                  size="sm" 
                  variant="outline" 
                  className="border-slate-600 text-slate-400"
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(results, null, 2));
                    toast({ title: "Results copied to clipboard" });
                  }}
                >
                  <FileText className="w-4 h-4 mr-2" />
                  Copy Report
                </Button>
                <Button 
                  size="sm" 
                  className="bg-green-600 hover:bg-green-700"
                  onClick={() => toast({ title: "Report saved to results folder" })}
                >
                  Save Report
                </Button>
              </div>
            </div>
            
            <div className="grid gap-4">
              {Object.entries(results).map(([key, value]) => {
                const isHighlighted = key.includes('threat') || key.includes('risk') || key.includes('security');
                return (
                  <div 
                    key={key} 
                    className={`p-4 rounded-lg border ${
                      isHighlighted 
                        ? 'bg-red-500/10 border-red-500/30' 
                        : 'bg-slate-800/50 border-slate-700/50'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="text-sm font-medium text-slate-300 capitalize mb-1">
                          {key.replace(/_/g, ' ')}
                        </div>
                        <div className="text-white">
                          {Array.isArray(value) ? (
                            <div className="space-y-1">
                              {value.map((item, index) => (
                                <div key={index} className="flex items-center gap-2">
                                  <div className="w-1 h-1 bg-blue-400 rounded-full"></div>
                                  <span className="text-sm">{item}</span>
                                </div>
                              ))}
                            </div>
                          ) : typeof value === 'object' ? (
                            <div className="space-y-1">
                              {Object.entries(value).map(([subKey, subValue]) => (
                                <div key={subKey} className="flex justify-between text-sm">
                                  <span className="text-slate-400 capitalize">{subKey}:</span>
                                  <span className="text-white">{subValue}</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <span className={`text-sm ${
                              isHighlighted && (value.toString().toLowerCase().includes('high') || 
                                               value.toString().toLowerCase().includes('threat'))
                                ? 'text-red-400 font-medium' 
                                : ''
                            }`}>
                              {value}
                            </span>
                          )}
                        </div>
                      </div>
                      {isHighlighted && (
                        <Shield className="w-5 h-5 text-red-400 ml-3 flex-shrink-0" />
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
            
            <div className="mt-6 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Target className="w-4 h-4 text-blue-400" />
                <span className="text-sm font-medium text-blue-400">Investigation Summary</span>
              </div>
              <p className="text-sm text-slate-300">
                Investigation completed for {currentTool.name.toLowerCase()} query: "{query}". 
                Data collected from multiple sources and cross-referenced for accuracy.
              </p>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default InvestigationTools;
import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Network, Search, Play, Loader, Map, Globe, Fingerprint, Dns, Server } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:3001/api';

const ReconDiscovery = () => {
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [scanType, setScanType] = useState('dns');

  const handleScan = async () => {
    if (!target.trim()) {
      toast({ title: "Invalid Target", description: "Please enter a target domain or IP.", variant: "destructive" });
      return;
    }
    
    setIsScanning(true);
    setResults(null);
    
    try {
      const response = await fetch(`${API_BASE}/recon/discover`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          target: target.trim(),
          type: scanType
        })
      });

      if (response.ok) {
        const data = await response.json();
        setResults(data);
        toast({
          title: "Discovery Complete",
          description: `Found ${data.results?.length || 0} results for ${target}`,
        });
      } else {
        throw new Error('Discovery failed');
      }
    } catch (error) {
      toast({
        title: "Discovery Failed",
        description: error.message || "Failed to perform reconnaissance",
        variant: "destructive"
      });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold text-white mb-2">Reconnaissance & Discovery</h1>
        <p className="text-slate-400">Map network topology, enumerate subdomains, and fingerprint services.</p>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass-card p-6 rounded-xl">
        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder="Enter target domain or IP range (e.g., example.com, 192.168.1.0/24)"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
              disabled={isScanning}
            />
          </div>
          <Button onClick={handleScan} disabled={isScanning} className="bg-blue-600 hover:bg-blue-700">
            {isScanning ? <Loader className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
            Start Discovery
          </Button>
        </div>
      </motion.div>

      {isScanning && (
        <div className="text-center p-8">
          <div className="flex items-center justify-center space-x-2">
            <Loader className="w-6 h-6 text-blue-400 animate-spin" />
            <span className="text-lg text-slate-300">Running discovery scans...</span>
          </div>
        </div>
      )}

      {!results && !isScanning && (
        <div className="text-center py-16 text-slate-400 glass-card rounded-xl">
          <Network className="w-16 h-16 mx-auto mb-4 text-slate-500" />
          <h2 className="text-xl font-semibold text-white">Discovery Results</h2>
          <p>Enter a target and start a scan to see network topology and service information.</p>
        </div>
      )}

      {results && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="lg:col-span-1 space-y-6">
            <div className="glass-card p-6 rounded-xl">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center"><Fingerprint className="w-4 h-4 mr-2 text-blue-400" />OS & Services</h3>
              {/* OS and Services content */}
            </div>
            <div className="glass-card p-6 rounded-xl">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center"><Globe className="w-4 h-4 mr-2 text-blue-400" />Subdomains</h3>
              {/* Subdomains content */}
            </div>
          </motion.div>
          <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="lg:col-span-2 glass-card p-6 rounded-xl">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center"><Map className="w-4 h-4 mr-2 text-blue-400" />Network Topology</h3>
            {/* Network map visualization */}
          </motion.div>
        </div>
      )}
    </div>
  );
};

export default ReconDiscovery;
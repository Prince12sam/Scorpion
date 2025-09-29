import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Brain, Globe, Eye, Zap, WifiOff, Search, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:3001/api';

const ThreatIntelligence = () => {
  const [threatFeeds, setThreatFeeds] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [searchTarget, setSearchTarget] = useState('');
  const [searchResults, setSearchResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [iocs, setIocs] = useState([]);

  useEffect(() => {
    fetchLatestIOCs();
    fetchIntelligenceSources();
    fetchLatestThreats();
  }, []);

  const fetchLatestIOCs = async () => {
    try {
      const response = await fetch(`${API_BASE}/threat-intel/iocs`);
      if (response.ok) {
        const data = await response.json();
        setIocs(data.iocs || []);
      }
    } catch (error) {
      console.error('Error fetching IOCs:', error);
    }
  };

  const fetchIntelligenceSources = async () => {
    try {
      const response = await fetch(`${API_BASE}/threat-feeds/status`);
      if (response.ok) {
        const data = await response.json();
        setIntelligenceSources(data.feeds || []);
      }
    } catch (error) {
      console.error('Error fetching intelligence sources:', error);
      // Fallback to empty array - no mockup data
      setIntelligenceSources([]);
    }
  };

  const fetchLatestThreats = async () => {
    try {
      const response = await fetch(`${API_BASE}/threat-map/live`);
      if (response.ok) {
        const data = await response.json();
        // Convert backend threat data to frontend format
        const formattedThreats = (data.recentThreats || []).map(threat => ({
          id: threat.id,
          title: threat.description,
          description: `${threat.type}: ${threat.indicator}`,
          severity: threat.severity,
          source: threat.source,
          category: threat.type,
          confidence: threat.metadata?.confidence || 85,
          affected_regions: [threat.geolocation?.country || 'Unknown'],
          timestamp: new Date(threat.timestamp),
          indicators: [threat.indicator],
          techniques: threat.tags || [],
          mitigation: `Block ${threat.type} indicator: ${threat.indicator}`
        }));
        setThreatFeeds(formattedThreats);
      }
    } catch (error) {
      console.error('Error fetching latest threats:', error);
      setThreatFeeds([]);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      default: return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
    }
  };

  const getConfidenceColor = (confidence) => {
    if (confidence >= 90) return 'text-green-400';
    if (confidence >= 70) return 'text-yellow-400';
    return 'text-red-400';
  };

  const handleThreatAction = async (action) => {
    if (action === 'refresh') {
      setLoading(true);
      try {
        await fetchLatestIOCs();
        await fetchIntelligenceSources();
        await fetchLatestThreats();
        toast({
          title: "Feeds Updated",
          description: "Threat intelligence feeds have been refreshed",
        });
      } catch (error) {
        toast({
          title: "Update Failed",
          description: "Failed to refresh threat feeds",
          variant: "destructive"
        });
      } finally {
        setLoading(false);
      }
    }
  };

  const searchThreatIntel = async () => {
    if (!searchTarget.trim()) {
      toast({
        title: "Invalid Input",
        description: "Please enter an IP address, domain, or hash to search",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    setSearchResults(null);

    try {
      const response = await fetch(`${API_BASE}/threat-intel/lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: searchTarget.trim() })
      });

      if (response.ok) {
        const data = await response.json();
        setSearchResults(data);
        toast({
          title: "Search Complete",
          description: `Found threat intelligence for ${searchTarget}`,
        });
      } else {
        throw new Error('Search failed');
      }
    } catch (error) {
      toast({
        title: "Search Failed",
        description: "Failed to lookup threat intelligence",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const [intelligenceSources, setIntelligenceSources] = useState([]);

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Global Threat Intelligence</h1>
          <p className="text-slate-400">Real-time OSINT, dark web, and vendor threat feeds.</p>
        </div>
        <Button onClick={() => handleThreatAction('refresh')} variant="outline"><Zap className="w-4 h-4 mr-2" />Update Feeds</Button>
      </motion.div>

      {/* Threat Intel Search */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass-card p-6 rounded-xl">
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center">
          <Search className="w-5 h-5 mr-2 text-blue-400" />
          Threat Intelligence Lookup
        </h2>
        <div className="flex gap-4 mb-4">
          <input
            type="text"
            value={searchTarget}
            onChange={(e) => setSearchTarget(e.target.value)}
            placeholder="Enter IP address, domain, or hash..."
            className="flex-1 px-4 py-2 bg-slate-800/50 border border-slate-600 rounded-lg text-white placeholder:text-slate-400 focus:border-blue-500 focus:outline-none"
            onKeyPress={(e) => e.key === 'Enter' && searchThreatIntel()}
          />
          <Button onClick={searchThreatIntel} disabled={loading}>
            {loading ? 'Searching...' : 'Search'}
          </Button>
        </div>
        
        {searchResults && (
          <div className="mt-4 p-4 bg-slate-800/30 rounded-lg border border-slate-600">
            <h3 className="text-lg font-semibold text-white mb-2">Results for: {searchTarget}</h3>
            <div className="space-y-2">
              {searchResults.reputation && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Reputation:</span>
                  <span className={`px-2 py-1 rounded text-xs ${
                    searchResults.reputation === 'malicious' ? 'bg-red-500/20 text-red-400' :
                    searchResults.reputation === 'suspicious' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-green-500/20 text-green-400'
                  }`}>
                    {searchResults.reputation}
                  </span>
                </div>
              )}
              {searchResults.sources && searchResults.sources.length > 0 && (
                <div>
                  <span className="text-slate-400">Sources:</span>
                  <div className="mt-1 space-y-1">
                    {searchResults.sources.map((source, index) => (
                      <div key={index} className="text-sm text-slate-300">
                        • {source}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center"><Brain className="w-5 h-5 mr-2 text-blue-400" />Intelligence Sources</h2>
        {intelligenceSources.length === 0 ? (
          <div className="text-center py-4 text-slate-400">
            <p>Loading intelligence sources...</p>
          </div>
        ) : (
          <div className="flex flex-wrap gap-4">
            {intelligenceSources.map((source) => (
              <div key={source.name} className="flex items-center space-x-2 p-2 bg-slate-800/50 rounded-lg">
                {source.status === 'active' ? <div className="w-2 h-2 bg-green-500 rounded-full security-pulse"></div> : <WifiOff className="w-4 h-4 text-red-500" />}
                <div className="text-sm font-medium text-white">{source.name}</div>
              </div>
            ))}
          </div>
        )}
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-6 rounded-xl">
        <h2 className="text-xl font-semibold text-white mb-6 flex items-center"><Eye className="w-5 h-5 mr-2 text-red-400" />Latest Threat Intelligence</h2>
        {threatFeeds.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            <p>Loading latest threat intelligence...</p>
            <p className="text-sm">Connect to live threat feeds for real-time updates.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {threatFeeds.map((threat, index) => (
              <motion.div
                key={threat.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200 cursor-pointer"
                onClick={() => setSelectedThreat(threat)}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-semibold text-white">{threat.title}</h3>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(threat.severity)}`}>{threat.severity.toUpperCase()}</span>
                    </div>
                    <p className="text-slate-400 mb-2">{threat.description}</p>
                    <div className="flex items-center space-x-4 text-sm text-slate-500">
                      <span>Source: {threat.source}</span>
                      <span>Category: {threat.category}</span>
                      <span className={`font-medium ${getConfidenceColor(threat.confidence)}`}>Confidence: {threat.confidence}%</span>
                    </div>
                  </div>
                  <div className="text-xs text-slate-400">{threat.timestamp.toLocaleTimeString()}</div>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2"><span className="text-xs text-slate-500">Affected: {threat.affected_regions.join(', ')}</span></div>
                  <div className="flex space-x-2">
                    <Button variant="outline" size="sm" onClick={(e) => { e.stopPropagation(); handleThreatAction('investigate'); }}>Investigate</Button>
                    <Button variant="outline" size="sm" onClick={(e) => { e.stopPropagation(); handleThreatAction('block'); }}>Block IOCs</Button>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </motion.div>

      {selectedThreat && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setSelectedThreat(null)}>
          <motion.div initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="bg-slate-900 border border-slate-700 rounded-xl p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold text-white">{selectedThreat.title}</h2>
              <Button variant="ghost" onClick={() => setSelectedThreat(null)}>×</Button>
            </div>
            <div className="space-y-4">
              <div><h3 className="text-sm font-medium text-slate-400 mb-2">Description</h3><p className="text-slate-300">{selectedThreat.description}</p></div>
              <div><h3 className="text-sm font-medium text-slate-400 mb-2">Indicators of Compromise</h3><div className="space-y-1">{selectedThreat.indicators.map((ioc, index) => (<div key={index} className="text-sm text-slate-300 font-mono bg-slate-800 px-2 py-1 rounded">{ioc}</div>))}</div></div>
              <div><h3 className="text-sm font-medium text-slate-400 mb-2">MITRE ATT&CK Techniques</h3><div className="flex flex-wrap gap-2">{selectedThreat.techniques.map((technique, index) => (<span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded border border-blue-500/30">{technique}</span>))}</div></div>
              <div><h3 className="text-sm font-medium text-slate-400 mb-2">Mitigation</h3><p className="text-slate-300">{selectedThreat.mitigation}</p></div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

export default ThreatIntelligence;
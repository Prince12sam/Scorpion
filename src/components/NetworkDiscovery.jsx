import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Network, 
  Radar, 
  MapPin, 
  Server, 
  Wifi,
  Globe,
  Search,
  Play,
  Pause,
  RefreshCw,
  Eye,
  Shield
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/components/ui/use-toast';

const NetworkDiscovery = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [discoveredHosts, setDiscoveredHosts] = useState([]);
  const [networkRange, setNetworkRange] = useState('192.168.1.0/24');
  const [scanType, setScanType] = useState('ping-sweep');
  const [results, setResults] = useState([]);
  const { toast } = useToast();

  const scanTypes = [
    { value: 'ping-sweep', label: 'Ping Sweep', description: 'ICMP ping scan for live hosts' },
    { value: 'port-scan', label: 'Port Scan', description: 'TCP port scanning on discovered hosts' },
    { value: 'service-discovery', label: 'Service Discovery', description: 'Identify running services' },
    { value: 'comprehensive', label: 'Comprehensive', description: 'Full network discovery and mapping' }
  ];

  const startNetworkDiscovery = async () => {
    if (!networkRange) {
      toast({
        title: "Error",
        description: "Please specify a network range for discovery",
        variant: "destructive",
      });
      return;
    }

    setIsScanning(true);
    try {
      const response = await fetch('/api/discovery/network', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          range: networkRange,
          scanType: scanType,
          timestamp: new Date().toISOString()
        })
      });

      const data = await response.json();
      setDiscoveredHosts(data.hosts || []);
      setResults(prev => [data, ...prev.slice(0, 4)]);
      
      toast({
        title: "Network Discovery Completed",
        description: `Discovered ${data.hosts?.length || 0} hosts in network`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to perform network discovery",
        variant: "destructive",
      });
    } finally {
      setIsScanning(false);
    }
  };

  const getHostStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'online':
      case 'up':
        return 'text-green-400 bg-green-500/20 border-green-500/50';
      case 'filtered':
      case 'protected':
        return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/50';
      case 'offline':
      case 'down':
        return 'text-red-400 bg-red-500/20 border-red-500/50';
      default:
        return 'text-slate-400 bg-slate-500/20 border-slate-500/50';
    }
  };

  const getServiceIcon = (service) => {
    const serviceMap = {
      'http': Globe,
      'https': Shield,
      'ssh': Server,
      'ftp': Server,
      'smtp': Server,
      'dns': Network,
      'default': Wifi
    };
    return serviceMap[service?.toLowerCase()] || serviceMap.default;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-r from-green-900/20 to-blue-900/20 p-6 rounded-lg border border-green-500/30"
      >
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-green-500/20 rounded-lg">
            <Radar className="w-6 h-6 text-green-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Advanced Network Discovery</h1>
            <p className="text-green-400">Comprehensive network mapping and host discovery</p>
          </div>
        </div>
      </motion.div>

      {/* Discovery Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="lg:col-span-2 bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Network className="w-5 h-5 text-blue-400" />
            Network Discovery Configuration
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2 text-slate-300">Network Range</label>
              <input
                type="text"
                value={networkRange}
                onChange={(e) => setNetworkRange(e.target.value)}
                placeholder="192.168.1.0/24 or 10.0.0.1-10.0.0.254"
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:border-blue-500 focus:outline-none"
              />
              <p className="text-xs text-slate-400 mt-1">
                Supports CIDR notation (192.168.1.0/24) or IP ranges (192.168.1.1-192.168.1.254)
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2 text-slate-300">Discovery Type</label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-blue-500 focus:outline-none"
              >
                {scanTypes.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
              <p className="text-xs text-slate-400 mt-1">
                {scanTypes.find(t => t.value === scanType)?.description}
              </p>
            </div>

            <Button
              onClick={startNetworkDiscovery}
              disabled={isScanning || !networkRange}
              className="bg-green-600 hover:bg-green-700 flex items-center gap-2"
            >
              {isScanning ? (
                <>
                  <Pause className="w-4 h-4" />
                  Scanning Network...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Start Discovery
                </>
              )}
            </Button>
          </div>
        </motion.div>

        {/* Scan Statistics */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Eye className="w-5 h-5 text-purple-400" />
            Discovery Stats
          </h2>
          
          <div className="space-y-4">
            <div className="bg-slate-900/50 p-3 rounded-lg">
              <div className="text-2xl font-bold text-green-400">{discoveredHosts.length}</div>
              <div className="text-sm text-slate-400">Hosts Discovered</div>
            </div>
            
            <div className="bg-slate-900/50 p-3 rounded-lg">
              <div className="text-2xl font-bold text-blue-400">
                {discoveredHosts.filter(h => h.status === 'online').length}
              </div>
              <div className="text-sm text-slate-400">Active Hosts</div>
            </div>
            
            <div className="bg-slate-900/50 p-3 rounded-lg">
              <div className="text-2xl font-bold text-purple-400">
                {discoveredHosts.reduce((acc, host) => acc + (host.services?.length || 0), 0)}
              </div>
              <div className="text-sm text-slate-400">Services Found</div>
            </div>
            
            <div className="bg-slate-900/50 p-3 rounded-lg">
              <div className="text-2xl font-bold text-orange-400">{results.length}</div>
              <div className="text-sm text-slate-400">Total Scans</div>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Discovered Hosts */}
      {discoveredHosts.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-400" />
            Discovered Hosts ({discoveredHosts.length})
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-96 overflow-y-auto">
            {discoveredHosts.map((host, index) => (
              <div
                key={index}
                className="p-4 bg-slate-900/50 rounded-lg border border-slate-600"
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="font-mono text-white font-medium">{host.ip}</span>
                  <span className={`px-2 py-1 rounded text-xs font-bold ${getHostStatusColor(host.status)}`}>
                    {host.status?.toUpperCase() || 'UNKNOWN'}
                  </span>
                </div>
                
                {host.hostname && (
                  <div className="text-sm text-slate-300 mb-2">
                    <MapPin className="w-3 h-3 inline mr-1" />
                    {host.hostname}
                  </div>
                )}
                
                {host.mac && (
                  <div className="text-xs text-slate-400 mb-2">
                    MAC: {host.mac}
                  </div>
                )}
                
                {host.os && (
                  <div className="text-xs text-slate-400 mb-2">
                    OS: {host.os}
                  </div>
                )}
                
                {host.services && host.services.length > 0 && (
                  <div className="mt-3">
                    <div className="text-xs text-slate-400 mb-2">Services:</div>
                    <div className="flex flex-wrap gap-1">
                      {host.services.slice(0, 4).map((service, serviceIndex) => {
                        const ServiceIcon = getServiceIcon(service.name);
                        return (
                          <div
                            key={serviceIndex}
                            className="flex items-center gap-1 px-2 py-1 bg-blue-500/20 rounded text-xs text-blue-400"
                          >
                            <ServiceIcon className="w-3 h-3" />
                            {service.port}
                          </div>
                        );
                      })}
                      {host.services.length > 4 && (
                        <div className="px-2 py-1 bg-slate-600/50 rounded text-xs text-slate-400">
                          +{host.services.length - 4}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Recent Scans */}
      {results.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <RefreshCw className="w-5 h-5 text-green-400" />
            Recent Discovery Results
          </h2>
          
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {results.map((result, index) => (
              <div
                key={index}
                className="p-3 bg-slate-900/50 rounded-lg border border-slate-600"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Network className="w-4 h-4 text-blue-400" />
                    <span className="font-mono text-white">{result.range}</span>
                  </div>
                  <span className="text-xs text-slate-400">
                    {new Date(result.timestamp).toLocaleString()}
                  </span>
                </div>
                
                <div className="grid grid-cols-4 gap-2 text-xs">
                  <div>
                    <span className="text-slate-400">Type:</span>
                    <span className="ml-1 text-white">{result.scanType}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Hosts:</span>
                    <span className="ml-1 text-green-400">{result.hosts?.length || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Active:</span>
                    <span className="ml-1 text-blue-400">
                      {result.hosts?.filter(h => h.status === 'online').length || 0}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Services:</span>
                    <span className="ml-1 text-purple-400">
                      {result.hosts?.reduce((acc, host) => acc + (host.services?.length || 0), 0) || 0}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default NetworkDiscovery;
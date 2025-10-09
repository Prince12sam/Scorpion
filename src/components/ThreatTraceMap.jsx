import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Globe, MapPin, AlertTriangle, ZoomIn, ZoomOut, LocateFixed, Activity, Play, Pause, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import apiClient from '@/lib/api-client';
import LiveThreatMap from './LiveThreatMap';

const ThreatTraceMap = () => {
  const [threats, setThreats] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [view, setView] = useState({
    lat: 20,
    lng: 0,
    zoom: 1.5,
  });
  const [liveMode, setLiveMode] = useState(false);
  const [isMonitoring, setIsMonitoring] = useState(false);

  useEffect(() => {
    fetchLiveThreatData();
    const interval = setInterval(fetchLiveThreatData, 10000);
    return () => {
      clearInterval(interval);
      apiClient.cancelRequest('/threat-map');
    };
  }, []);

  const fetchLiveThreatData = async () => {
    try {
      const data = await apiClient.get('/threat-map');
      if (data && data.threats) {
        const transformedThreats = data.threats.map((threat, index) => ({
          id: threat.ip || `threat-${index}`,
          ip: threat.ip || '0.0.0.0',
          country: threat.country || 'Unknown',
          type: threat.attack_type || 'Unknown Attack',
          severity: threat.severity || 'medium',
          lat: threat.latitude,
          lng: threat.longitude,
          timestamp: threat.timestamp || new Date().toISOString()
        }));
        setThreats(transformedThreats);
      } else {
        setThreats([]);
      }
    } catch (error) {
      console.error('Failed to fetch threat data:', error);
      setThreats([]);
    }
  };

  const handleZoom = (delta) => {
    setView(prev => ({
      ...prev,
      zoom: Math.max(0.5, Math.min(5, prev.zoom + delta))
    }));
  };

  const handleThreatClick = (threat) => {
    setSelectedThreat(threat);
    setView(prev => ({
      ...prev,
      lat: threat.lat,
      lng: threat.lng,
      zoom: Math.max(prev.zoom, 2)
    }));
  };

  const toggleLiveMonitoring = async () => {
    try {
      const endpoint = isMonitoring ? '/api/threat-feeds/stop' : '/api/threat-feeds/start';
      const response = await fetch(`http://localhost:3001${endpoint}`, {
        method: 'POST'
      });
      const result = await response.json();
      if (result.success) {
        setIsMonitoring(!isMonitoring);
      }
    } catch (error) {
      console.error('Failed to toggle monitoring:', error);
    }
  };

  if (liveMode) {
    return <LiveThreatMap />;
  }

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Global Threat Intelligence Map</h1>
            <p className="text-slate-400">Visualize and trace threats across geographical regions.</p>
          </div>
          <div className="flex items-center space-x-4">
            <Button
              onClick={() => setLiveMode(true)}
              className="bg-green-600 hover:bg-green-700"
            >
              <Activity className="w-4 h-4 mr-2" />
              Switch to Live Mode
            </Button>
            <Button
              onClick={toggleLiveMonitoring}
              className={`${isMonitoring ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'}`}
            >
              {isMonitoring ? <Pause className="w-4 h-4 mr-2" /> : <Play className="w-4 h-4 mr-2" />}
              {isMonitoring ? 'Stop Monitoring' : 'Start Monitoring'}
            </Button>
          </div>
        </div>
      </motion.div>

      <div className="glass-card p-6 rounded-xl h-[450px] flex flex-col">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white flex items-center">
            <Globe className="w-5 h-5 mr-2 text-blue-400" />
            Static Threat Map
          </h2>
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="icon" onClick={() => handleZoom(0.5)}><ZoomIn className="w-4 h-4" /></Button>
            <Button variant="outline" size="icon" onClick={() => handleZoom(-0.5)}><ZoomOut className="w-4 h-4" /></Button>
            <Button variant="outline" size="icon" onClick={() => setView({ lat: 20, lng: 0, zoom: 1.5 })}><LocateFixed className="w-4 h-4" /></Button>
          </div>
        </div>

        <div className="flex-1 relative bg-slate-800 rounded-lg overflow-hidden">
          {threats.length === 0 ? (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Shield className="w-16 h-16 mx-auto mb-4 text-green-500" />
                <h3 className="text-xl font-semibold text-white mb-2">No Active Threats</h3>
                <p className="text-slate-400">Your network is secure. No threats detected in the current monitoring period.</p>
              </div>
            </div>
          ) : (
            <>
              <div 
                className="absolute inset-0 bg-gradient-to-br from-slate-900 to-slate-700"
                style={{
                  backgroundImage: 'url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'60\' height=\'60\' viewBox=\'0 0 60 60\'%3E%3Cg fill-rule=\'evenodd\'%3E%3Cg fill=\'%23334155\' fill-opacity=\'0.1\'%3E%3Cpath d=\'M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z\'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")',
                  transform: `scale(${view.zoom}) translate(${-view.lng * 2}px, ${-view.lat * 2}px)`
                }}
              />
              
              {threats.map(threat => {
                const x = ((threat.lng + 180) / 360) * 100;
                const y = ((90 - threat.lat) / 180) * 100;
                
                return (
                  <motion.div
                    key={threat.id}
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    className={`absolute w-4 h-4 -translate-x-2 -translate-y-2 rounded-full cursor-pointer z-10 ${
                      threat.severity === 'critical' ? 'bg-red-500 shadow-red-500/50' : 'bg-orange-500 shadow-orange-500/50'
                    } shadow-lg animate-pulse`}
                    style={{ left: `${x}%`, top: `${y}%` }}
                    onClick={() => handleThreatClick(threat)}
                  >
                    <div className={`absolute inset-0 rounded-full animate-ping ${
                      threat.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'
                    }`} />
                  </motion.div>
                );
              })}
            </>
          )}
        </div>

        {selectedThreat && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="absolute bottom-4 left-4 bg-slate-900/80 backdrop-blur-sm border border-slate-600 rounded-lg p-3 max-w-sm"
          >
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-white flex items-center">
                <MapPin className={`w-4 h-4 mr-2 ${selectedThreat.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}`} />
                {selectedThreat.country}
              </h3>
              <button onClick={() => setSelectedThreat(null)} className="text-slate-400 hover:text-white text-lg">&times;</button>
            </div>
            <div className="space-y-1 text-sm">
              <p className="text-slate-300"><strong>Type:</strong> {selectedThreat.type}</p>
              <p className="text-slate-300 font-mono"><strong>IP:</strong> {selectedThreat.ip}</p>
              <p className={`font-medium capitalize ${selectedThreat.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}`}>
                <strong>Severity:</strong> {selectedThreat.severity}
              </p>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default ThreatTraceMap;
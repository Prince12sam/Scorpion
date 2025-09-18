
import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Globe, MapPin, AlertTriangle, ZoomIn, ZoomOut, LocateFixed } from 'lucide-react';
import { Button } from '@/components/ui/button';

const ThreatTraceMap = () => {
  const [threats, setThreats] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [view, setView] = useState({
    lat: 20,
    lng: 0,
    zoom: 1.5,
  });

  useEffect(() => {
    const generateThreats = () => {
      const locations = [
        { country: 'United States', lat: 39.8, lng: -98.5, type: 'Malware C&C', ip: '172.217.14.238' },
        { country: 'China', lat: 35.8, lng: 104.1, type: 'Phishing Host', ip: '202.108.22.5' },
        { country: 'Russia', lat: 61.5, lng: 105.3, type: 'Botnet Controller', ip: '93.184.216.34' },
        { country: 'Germany', lat: 51.1, lng: 10.4, type: 'Ransomware Node', ip: '193.99.144.85' },
        { country: 'Brazil', lat: -14.2, lng: -51.9, type: 'DDoS Attacker', ip: '200.221.11.101' },
        { country: 'Nigeria', lat: 9.0, lng: 8.6, type: 'Scam Operation', ip: '41.223.144.50' },
      ];

      return locations.map(location => ({
        ...location,
        id: Math.random().toString(36).substr(2, 9),
        severity: ['high', 'critical'][Math.floor(Math.random() * 2)],
        timestamp: new Date().toISOString(),
      }));
    };

    setThreats(generateThreats());

    const interval = setInterval(() => {
      setThreats(prevThreats => {
        const newThreat = {
          country: 'Netherlands', lat: 52.3, lng: 4.9, type: 'Exploit Kit Server', ip: '149.154.167.91',
          id: Math.random().toString(36).substr(2, 9),
          severity: 'critical',
          timestamp: new Date().toISOString(),
        };
        const updatedThreats = [newThreat, ...prevThreats];
        return updatedThreats.slice(0, 10);
      });
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity) => {
    return severity === 'critical' ? 'bg-red-500' : 'bg-orange-500';
  };

  const handleZoom = (direction) => {
    setView(v => ({ ...v, zoom: Math.max(1, Math.min(8, v.zoom + direction)) }));
  };

  const resetView = () => {
    setView({ lat: 20, lng: 0, zoom: 1.5 });
  };

  const selectAndCenter = (threat) => {
    setSelectedThreat(threat);
    setView({ lat: threat.lat, lng: threat.lng, zoom: 4 });
  };

  return (
    <div className="glass-card p-6 rounded-xl h-[450px] flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold text-white flex items-center">
          <Globe className="w-5 h-5 mr-2 text-blue-400" />
          Live Threat Trace
        </h2>
        <div className="flex items-center space-x-2">
          <Button variant="outline" size="icon" onClick={() => handleZoom(0.5)}><ZoomIn className="w-4 h-4" /></Button>
          <Button variant="outline" size="icon" onClick={() => handleZoom(-0.5)}><ZoomOut className="w-4 h-4" /></Button>
          <Button variant="outline" size="icon" onClick={resetView}><LocateFixed className="w-4 h-4" /></Button>
        </div>
      </div>

      <div className="flex-grow relative bg-slate-800/50 rounded-lg overflow-hidden">
        <div className="absolute inset-0 transition-transform duration-500" style={{ transform: `scale(${view.zoom}) translate(${-view.lng / 20}px, ${view.lat / 10}px)` }}>
          <img alt="Stylized world map for threat visualization" className="w-full h-full object-cover opacity-20" src="https://images.unsplash.com/photo-1628945168072-c4c9213c5225" />
          
          {threats.map((threat) => {
            const x = (threat.lng + 180) / 360 * 100;
            const y = (-threat.lat + 90) / 180 * 100;
            return (
              <motion.div
                key={threat.id}
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                className="absolute w-3 h-3 rounded-full cursor-pointer"
                style={{ left: `${x}%`, top: `${y}%`, transform: 'translate(-50%, -50%)' }}
                onClick={() => selectAndCenter(threat)}
                whileHover={{ scale: 2.5, zIndex: 10 }}
              >
                <div className={`absolute inset-0 rounded-full ${getSeverityColor(threat.severity)}`}></div>
                <div className={`absolute inset-0 rounded-full ${getSeverityColor(threat.severity)} animate-ping opacity-75`}></div>
              </motion.div>
            );
          })}
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

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Globe, MapPin, AlertTriangle, Shield } from 'lucide-react';

const ThreatMap = () => {
  const [threats, setThreats] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);

  useEffect(() => {
    // Simulate real-time threat data
    const generateThreats = () => {
      const locations = [
        { country: 'United States', lat: 39.8283, lng: -98.5795, threats: 23 },
        { country: 'China', lat: 35.8617, lng: 104.1954, threats: 45 },
        { country: 'Russia', lat: 61.5240, lng: 105.3188, threats: 31 },
        { country: 'Germany', lat: 51.1657, lng: 10.4515, threats: 12 },
        { country: 'Brazil', lat: -14.2350, lng: -51.9253, threats: 18 },
        { country: 'India', lat: 20.5937, lng: 78.9629, threats: 27 }
      ];

      return locations.map(location => ({
        ...location,
        id: Math.random().toString(36).substr(2, 9),
        severity: location.threats > 30 ? 'high' : location.threats > 20 ? 'medium' : 'low',
        lastUpdate: new Date().toLocaleTimeString()
      }));
    };

    setThreats(generateThreats());

    const interval = setInterval(() => {
      setThreats(generateThreats());
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'bg-red-500';
      case 'medium': return 'bg-orange-500';
      case 'low': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  return (
    <div className="glass-card p-6 rounded-xl h-96">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-white flex items-center">
          <Globe className="w-5 h-5 mr-2 text-blue-400" />
          Global Threat Map
        </h2>
        <div className="flex items-center space-x-2 text-sm text-slate-400">
          <div className="w-2 h-2 bg-green-500 rounded-full security-pulse"></div>
          <span>Live Updates</span>
        </div>
      </div>

      <div className="relative h-64 bg-slate-800/50 rounded-lg overflow-hidden">
        {/* World Map Background */}
        <div className="absolute inset-0 flex items-center justify-center">
          <img 
            alt="World map showing global threat distribution"
            className="w-full h-full object-cover opacity-20"
           src="https://images.unsplash.com/photo-1585858229735-cd08d8cb510d" />
        </div>

        {/* Threat Indicators */}
        <div className="absolute inset-0">
          {threats.map((threat, index) => (
            <motion.div
              key={threat.id}
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: index * 0.1 }}
              className={`absolute w-4 h-4 rounded-full ${getSeverityColor(threat.severity)} cursor-pointer`}
              style={{
                left: `${(threat.lng + 180) * (100 / 360)}%`,
                top: `${(90 - threat.lat) * (100 / 180)}%`,
                transform: 'translate(-50%, -50%)'
              }}
              onClick={() => setSelectedThreat(threat)}
              whileHover={{ scale: 1.5 }}
            >
              <div className={`absolute inset-0 rounded-full ${getSeverityColor(threat.severity)} animate-ping opacity-75`}></div>
            </motion.div>
          ))}
        </div>

        {/* Threat Details Popup */}
        {selectedThreat && (
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            className="absolute top-4 right-4 bg-slate-900 border border-slate-600 rounded-lg p-4 min-w-48"
          >
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-white">{selectedThreat.country}</h3>
              <button
                onClick={() => setSelectedThreat(null)}
                className="text-slate-400 hover:text-white"
              >
                ×
              </button>
            </div>
            <div className="space-y-1 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Threats:</span>
                <span className="text-red-400 font-medium">{selectedThreat.threats}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Severity:</span>
                <span className={`font-medium capitalize ${
                  selectedThreat.severity === 'high' ? 'text-red-400' :
                  selectedThreat.severity === 'medium' ? 'text-orange-400' :
                  'text-yellow-400'
                }`}>
                  {selectedThreat.severity}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Updated:</span>
                <span className="text-slate-300">{selectedThreat.lastUpdate}</span>
              </div>
            </div>
          </motion.div>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center justify-center space-x-6 mt-4 text-sm">
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-red-500 rounded-full"></div>
          <span className="text-slate-400">High Risk</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
          <span className="text-slate-400">Medium Risk</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
          <span className="text-slate-400">Low Risk</span>
        </div>
      </div>
    </div>
  );
};

export default ThreatMap;
import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Globe, AlertTriangle, Shield, Activity, Zap, MapPin, Clock, TrendingUp } from 'lucide-react';

const LiveThreatMap = () => {
  const [liveThreats, setLiveThreats] = useState([]);
  const [threatStats, setThreatStats] = useState({
    totalThreats: 0,
    threatsByType: {},
    threatsBySeverity: { high: 0, medium: 0, low: 0 },
    geolocationData: {}
  });
  const [isConnected, setIsConnected] = useState(false);
  const [alertHistory, setAlertHistory] = useState([]);
  const wsRef = useRef(null);

  useEffect(() => {
    // Connect to WebSocket for real-time alerts
    connectWebSocket();
    
    // Fetch initial threat map data
    fetchLiveThreatData();
    
    // Set up polling for threat statistics
    const interval = setInterval(fetchLiveThreatData, 10000); // Update every 10 seconds
    
    return () => {
      clearInterval(interval);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const connectWebSocket = () => {
    try {
      wsRef.current = new WebSocket('ws://localhost:3001/threat-alerts');
      
      wsRef.current.onopen = () => {
        setIsConnected(true);
        console.log('🔗 Connected to live threat feed');
      };
      
      wsRef.current.onmessage = (event) => {
        const message = JSON.parse(event.data);
        
        if (message.type === 'threat_alert') {
          // Add new threat to the list
          setLiveThreats(prev => [message.data, ...prev.slice(0, 49)]); // Keep last 50
          
          // Add to alert history
          setAlertHistory(prev => [
            {
              id: message.data.id,
              type: message.data.type,
              indicator: message.data.indicator,
              severity: message.data.severity,
              timestamp: message.data.timestamp,
              source: message.data.source
            },
            ...prev.slice(0, 99) // Keep last 100 alerts
          ]);
          
          // Update stats
          fetchLiveThreatData();
        }
      };
      
      wsRef.current.onclose = () => {
        setIsConnected(false);
        console.log('🔌 Disconnected from live threat feed');
        // Attempt to reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
      };
      
      wsRef.current.onerror = (error) => {
        console.error('❌ WebSocket error:', error);
        setIsConnected(false);
      };
    } catch (error) {
      console.error('Failed to connect to WebSocket:', error);
      setIsConnected(false);
    }
  };

  const fetchLiveThreatData = async () => {
    try {
      const response = await fetch('http://localhost:3001/api/threat-map/live');
      const data = await response.json();
      
      setThreatStats({
        totalThreats: data.totalThreats || 0,
        threatsByType: data.threatsByType || {},
        threatsBySeverity: data.threatsBySeverity || { high: 0, medium: 0, low: 0 },
        geolocationData: data.geolocationData || {}
      });
      
      if (data.recentThreats) {
        setLiveThreats(data.recentThreats.slice(0, 20)); // Show last 20 threats
      }
    } catch (error) {
      console.error('Failed to fetch live threat data:', error);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'text-red-400 bg-red-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20';
      case 'low': return 'text-green-400 bg-green-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'malicious_ip': return <Globe className="w-4 h-4" />;
      case 'malicious_domain': return <Globe className="w-4 h-4" />;
      case 'file_hash': return <Shield className="w-4 h-4" />;
      default: return <AlertTriangle className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold text-white mb-2 flex items-center">
          <Activity className="w-8 h-8 mr-3 text-red-400" />
          Live Threat Intelligence
        </h1>
        <p className="text-slate-400">Real-time global threat monitoring and analysis</p>
      </motion.div>

      {/* Connection Status */}
      <motion.div 
        initial={{ opacity: 0, x: -20 }} 
        animate={{ opacity: 1, x: 0 }} 
        className="glass-card p-4 rounded-xl flex items-center justify-between"
      >
        <div className="flex items-center space-x-3">
          <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`}></div>
          <span className="text-white font-medium">
            {isConnected ? 'Live Feed Active' : 'Connecting...'}
          </span>
        </div>
        <div className="text-slate-400 text-sm">
          {threatStats.totalThreats} active threats tracked
        </div>
      </motion.div>

      {/* Threat Statistics Dashboard */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }} 
          transition={{ delay: 0.1 }}
          className="glass-card p-6 rounded-xl"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Total Threats</h3>
            <TrendingUp className="w-5 h-5 text-red-400" />
          </div>
          <div className="text-3xl font-bold text-red-400 mb-2">{threatStats.totalThreats}</div>
          <div className="text-sm text-slate-400">Active indicators</div>
        </motion.div>

        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }} 
          transition={{ delay: 0.2 }}
          className="glass-card p-6 rounded-xl"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">High Severity</h3>
            <AlertTriangle className="w-5 h-5 text-red-400" />
          </div>
          <div className="text-3xl font-bold text-red-400 mb-2">{threatStats.threatsBySeverity.high}</div>
          <div className="text-sm text-slate-400">Critical threats</div>
        </motion.div>

        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }} 
          transition={{ delay: 0.3 }}
          className="glass-card p-6 rounded-xl"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Medium Severity</h3>
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
          </div>
          <div className="text-3xl font-bold text-yellow-400 mb-2">{threatStats.threatsBySeverity.medium}</div>
          <div className="text-sm text-slate-400">Moderate threats</div>
        </motion.div>

        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }} 
          transition={{ delay: 0.4 }}
          className="glass-card p-6 rounded-xl"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Low Severity</h3>
            <Shield className="w-5 h-5 text-green-400" />
          </div>
          <div className="text-3xl font-bold text-green-400 mb-2">{threatStats.threatsBySeverity.low}</div>
          <div className="text-sm text-slate-400">Minor threats</div>
        </motion.div>
      </div>

      {/* Live Threat Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div 
          initial={{ opacity: 0, x: -20 }} 
          animate={{ opacity: 1, x: 0 }} 
          transition={{ delay: 0.5 }}
          className="glass-card p-6 rounded-xl"
        >
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <Zap className="w-5 h-5 mr-2 text-red-400" />
            Live Threat Feed
          </h3>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {liveThreats.length > 0 ? (
              liveThreats.map((threat, index) => (
                <motion.div
                  key={threat.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-slate-700"
                >
                  <div className="flex items-center space-x-3">
                    <div className={`p-2 rounded-full ${getSeverityColor(threat.severity)}`}>
                      {getTypeIcon(threat.type)}
                    </div>
                    <div>
                      <div className="text-white font-medium text-sm truncate max-w-48">
                        {threat.indicator}
                      </div>
                      <div className="text-slate-400 text-xs">
                        {threat.source} • {new Date(threat.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                  <div className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                    {threat.severity.toUpperCase()}
                  </div>
                </motion.div>
              ))
            ) : (
              <div className="text-center py-8 text-slate-400">
                <Activity className="w-12 h-12 mx-auto mb-3 text-slate-600" />
                <p>Monitoring for live threats...</p>
              </div>
            )}
          </div>
        </motion.div>

        {/* Geographic Distribution */}
        <motion.div 
          initial={{ opacity: 0, x: 20 }} 
          animate={{ opacity: 1, x: 0 }} 
          transition={{ delay: 0.6 }}
          className="glass-card p-6 rounded-xl"
        >
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <MapPin className="w-5 h-5 mr-2 text-blue-400" />
            Geographic Distribution
          </h3>
          <div className="space-y-3">
            {Object.entries(threatStats.geolocationData).length > 0 ? (
              Object.entries(threatStats.geolocationData)
                .sort(([,a], [,b]) => b - a)
                .slice(0, 8)
                .map(([country, count]) => (
                  <div key={country} className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                      <span className="text-white">{country}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="bg-slate-700 h-2 w-20 rounded-full overflow-hidden">
                        <div 
                          className="bg-red-400 h-full transition-all duration-300"
                          style={{ width: `${Math.min((count / Math.max(...Object.values(threatStats.geolocationData))) * 100, 100)}%` }}
                        ></div>
                      </div>
                      <span className="text-slate-400 text-sm w-8 text-right">{count}</span>
                    </div>
                  </div>
                ))
            ) : (
              <div className="text-center py-8 text-slate-400">
                <Globe className="w-12 h-12 mx-auto mb-3 text-slate-600" />
                <p>No geographic data available</p>
              </div>
            )}
          </div>
        </motion.div>
      </div>

      {/* Threat Type Breakdown */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ delay: 0.7 }}
        className="glass-card p-6 rounded-xl"
      >
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Shield className="w-5 h-5 mr-2 text-purple-400" />
          Threat Type Breakdown
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {Object.entries(threatStats.threatsByType).map(([type, count]) => (
            <div key={type} className="bg-slate-800/50 p-4 rounded-lg border border-slate-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-white capitalize">{type.replace('_', ' ')}</span>
                <span className="text-slate-400 text-sm">{count}</span>
              </div>
              <div className="bg-slate-700 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-purple-400 h-full transition-all duration-300"
                  style={{ width: `${Math.min((count / Math.max(...Object.values(threatStats.threatsByType))) * 100, 100)}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Last Update */}
      <motion.div 
        initial={{ opacity: 0 }} 
        animate={{ opacity: 1 }} 
        transition={{ delay: 0.8 }}
        className="text-center text-slate-400 text-sm"
      >
        <Clock className="w-4 h-4 inline mr-1" />
        Last updated: {new Date().toLocaleString()}
      </motion.div>
    </div>
  );
};

export default LiveThreatMap;
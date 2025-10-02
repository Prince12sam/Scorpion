import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Globe, User, Users, Link, MapPin, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const GlobalThreatHunting = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [profile, setProfile] = useState(null);

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      toast({ title: "Invalid Search", description: "Please enter an IP address, domain, email, or keyword.", variant: "destructive" });
      return;
    }
    
    setIsLoading(true);
    setProfile(null);
    
    try {
      const response = await fetch('http://localhost:3001/api/threat/hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: searchQuery.trim() })
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.profile) {
          setProfile(data.profile);
          toast({ 
            title: "Hunt Complete", 
            description: `Digital profile created for ${searchQuery}` 
          });
        } else {
          throw new Error('No profile data received');
        }
      } else {
        throw new Error(`Server error: ${response.status}`);
      }
    } catch (error) {
      console.error('Threat hunting error:', error);
      toast({ 
        title: "Hunt Failed", 
        description: error.message || "Failed to complete threat hunt", 
        variant: "destructive" 
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold text-white mb-2">Global Threat Hunting</h1>
        <p className="text-slate-400">Track malicious actors and build digital profiles in real-time.</p>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass-card p-6 rounded-xl">
        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder="Enter IP address (e.g., 8.8.8.8), domain, email, or hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && !isLoading && handleSearch()}
              className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
              disabled={isLoading}
            />
          </div>
          <Button onClick={handleSearch} disabled={isLoading || !searchQuery.trim()} className="bg-blue-600 hover:bg-blue-700">
            {isLoading ? <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div> : <Search className="w-4 h-4 mr-2" />}
            Hunt
          </Button>
        </div>
      </motion.div>

      {isLoading && (
        <div className="text-center p-8">
          <div className="flex items-center justify-center space-x-2">
            <div className="w-6 h-6 border-2 border-blue-400 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-lg text-slate-300">Building Digital Dossier...</span>
          </div>
        </div>
      )}

      {!profile && !isLoading && (
        <div className="text-center py-16 text-slate-400 glass-card rounded-xl">
          <Globe className="w-16 h-16 mx-auto mb-4 text-slate-500" />
          <h2 className="text-xl font-semibold text-white">Start Your Hunt</h2>
          <p>Enter a query to begin tracking suspects and networks.</p>
        </div>
      )}

      {profile && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 space-y-6">
            <div className="glass-card p-6 rounded-xl text-center">
              <div className={`w-24 h-24 rounded-full mx-auto mb-4 flex items-center justify-center ${
                profile.status === 'MALICIOUS' ? 'bg-gradient-to-br from-red-600 to-red-800' :
                profile.status === 'SUSPICIOUS' ? 'bg-gradient-to-br from-orange-600 to-orange-800' :
                'bg-gradient-to-br from-green-600 to-green-800'
              }`}>
                <User className="w-12 h-12 text-white" />
              </div>
              <h2 className="text-2xl font-bold text-white">{profile.name}</h2>
              <span className={`px-3 py-1 mt-2 inline-block rounded-full text-sm font-medium border ${
                profile.status === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                profile.status === 'SUSPICIOUS' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                'bg-green-500/20 text-green-400 border-green-500/30'
              }`}>{profile.status}</span>
              <p className="text-slate-400 mt-2">Type: {profile.type?.toUpperCase()}</p>
              {profile.nationality && profile.nationality !== 'Unknown' && (
                <p className="text-slate-400">Country: {profile.nationality}</p>
              )}
              {profile.riskScore !== undefined && (
                <div className="mt-3">
                  <p className="text-sm text-slate-400 mb-1">Risk Score</p>
                  <div className="w-full bg-slate-700 rounded-full h-2">
                    <div className={`h-2 rounded-full ${
                      profile.riskScore > 50 ? 'bg-red-500' :
                      profile.riskScore > 25 ? 'bg-orange-500' : 'bg-green-500'
                    }`} style={{ width: `${Math.min(profile.riskScore, 100)}%` }}></div>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{profile.riskScore}%</p>
                </div>
              )}
            </div>

            {profile.details && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Link className="w-4 h-4 mr-2 text-blue-400" />Details
                </h3>
                <div className="space-y-3">
                  {Object.entries(profile.details).map(([key, value], index) => {
                    if (value === null || value === undefined || value === '') return null;
                    return (
                      <div key={index} className="flex justify-between items-center py-2 border-b border-slate-700 last:border-0">
                        <span className="text-sm font-medium text-slate-300 capitalize">
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </span>
                        <span className="text-sm text-white font-mono truncate max-w-[150px]">
                          {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          <div className="lg:col-span-2 space-y-6">
            {profile.categories && profile.categories.length > 0 && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <MapPin className="w-4 h-4 mr-2 text-blue-400" />Threat Categories
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  {profile.categories.map((category, index) => (
                    <div key={index} className="bg-red-500/20 text-red-400 px-3 py-2 rounded-lg text-sm text-center">
                      {category}
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {profile.reports && profile.reports.length > 0 && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Users className="w-4 h-4 mr-2 text-blue-400" />Recent Reports
                </h3>
                <div className="space-y-3 max-h-64 overflow-y-auto">
                  {profile.reports.slice(0, 5).map((report, index) => (
                    <div key={index} className="flex items-start space-x-3 p-3 bg-slate-800/50 rounded-lg">
                      <div className="w-2 h-2 bg-red-400 rounded-full mt-1.5"></div>
                      <div>
                        <p className="text-white text-sm">{report.comment || 'Abuse report'}</p>
                        <p className="text-xs text-slate-400">{report.reportedAt || 'Recent report'}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!profile.categories?.length && !profile.reports?.length && (
              <div className="glass-card p-6 rounded-xl text-center">
                <Globe className="w-12 h-12 mx-auto mb-4 text-slate-500" />
                <h3 className="text-lg font-semibold text-white mb-2">Profile Analysis Complete</h3>
                <p className="text-slate-400">
                  {profile.status === 'CLEAN' ? 'No malicious activity detected' : 
                   profile.status === 'INVESTIGATING' ? 'Investigation in progress' :
                   'Threat profile has been built'}
                </p>
              </div>
            )}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default GlobalThreatHunting;
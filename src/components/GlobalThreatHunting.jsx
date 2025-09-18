import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Globe, User, Users, Link, MapPin, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const GlobalThreatHunting = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [profile, setProfile] = useState(null);

  const handleSearch = () => {
    if (!searchQuery.trim()) {
      toast({ title: "Invalid Search", description: "Please enter a name, ID, or keyword.", variant: "destructive" });
      return;
    }
    setIsLoading(true);
    setProfile(null);
    setTimeout(() => {
      toast({ title: "🚧 This feature isn't implemented yet—but don't worry! You can request it in your next prompt! 🚀" });
      setIsLoading(false);
    }, 2000);
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
              placeholder="Search for suspect, organization, IP, device ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
              disabled={isLoading}
            />
          </div>
          <Button onClick={handleSearch} disabled={isLoading} className="bg-blue-600 hover:bg-blue-700">
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
              <div className="w-24 h-24 bg-gradient-to-br from-purple-600 to-blue-600 rounded-full mx-auto mb-4 flex items-center justify-center">
                <User className="w-12 h-12 text-white" />
              </div>
              <h2 className="text-2xl font-bold text-white">{profile.name}</h2>
              <span className="px-3 py-1 mt-2 inline-block rounded-full text-sm font-medium bg-red-500/20 text-red-400 border border-red-500/30">{profile.status}</span>
              <p className="text-slate-400 mt-2">Nationality: {profile.nationality}</p>
            </div>

            <div className="glass-card p-6 rounded-xl">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center"><Link className="w-4 h-4 mr-2 text-blue-400" />Digital Footprint</h3>
              <div className="space-y-3">
                {profile.digitalFootprint.map((item, index) => (
                  <div key={index} className="p-3 bg-slate-800/50 rounded-lg">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium text-slate-300">{item.type}</span>
                      <span className={`text-xs font-bold ${item.risk === 'High' ? 'text-orange-400' : item.risk === 'Critical' ? 'text-red-400' : 'text-yellow-400'}`}>{item.risk} Risk</span>
                    </div>
                    <p className="text-sm text-white font-mono truncate">{item.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="lg:col-span-2 space-y-6">
            <div className="glass-card p-6 rounded-xl">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center"><MapPin className="w-4 h-4 mr-2 text-blue-400" />Real-Time Activity</h3>
              <div className="space-y-4">
                {profile.activity.map((act, index) => (
                  <div key={index} className="flex items-start space-x-3">
                    <div className="w-2 h-2 bg-blue-400 rounded-full mt-1.5 security-pulse"></div>
                    <div>
                      <p className="text-white">{act.action}</p>
                      <p className="text-xs text-slate-400">{act.time} &bull; Location: {act.location}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-card p-6 rounded-xl">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center"><Users className="w-4 h-4 mr-2 text-blue-400" />Known Associates</h3>
              <div className="flex flex-wrap gap-4">
                {profile.associates.map((name, index) => (
                  <div key={index} className="flex items-center space-x-2 p-2 bg-slate-800/50 rounded-lg">
                    <User className="w-4 h-4 text-slate-400" />
                    <span className="text-sm text-white">{name}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default GlobalThreatHunting;
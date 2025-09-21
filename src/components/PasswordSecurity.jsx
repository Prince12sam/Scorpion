import React, { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { KeyRound, Upload, Search, ShieldCheck, ShieldAlert, Hash, Lock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:3001/api';

const PasswordSecurity = () => {
  const [activeTab, setActiveTab] = useState('audit');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [password, setPassword] = useState('');
  const [hash, setHash] = useState('');
  const fileInputRef = useRef(null);

  const handleFileAudit = async (event) => {
    const file = event.target.files[0];
    if (file) {
      setIsLoading(true);
      setResults(null);
      
      const formData = new FormData();
      formData.append('hashfile', file);
      
      try {
        const response = await fetch(`${API_BASE}/password/crack`, {
          method: 'POST',
          body: formData
        });

        if (response.ok) {
          const data = await response.json();
          setResults(data);
          toast({
            title: "Audit Complete",
            description: `Cracked ${data.cracked?.length || 0} out of ${data.total || 0} hashes`,
          });
        } else {
          throw new Error('File audit failed');
        }
      } catch (error) {
        toast({
          title: "Audit Failed",
          description: error.message || "Failed to audit password file",
          variant: "destructive"
        });
      } finally {
        setIsLoading(false);
      }
    }
  };

  const triggerFileUpload = () => {
    fileInputRef.current.click();
  };

  const handlePwnedCheck = async () => {
    if (!password.trim()) {
      toast({
        title: "Invalid Input",
        description: "Please enter a password to check",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    setResults(null);
    
    try {
      const response = await fetch(`${API_BASE}/password/breach`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: password.trim() })
      });

      if (response.ok) {
        const data = await response.json();
        setResults(data);
        toast({
          title: data.breached ? "Password Compromised!" : "Password Safe",
          description: data.breached 
            ? `Found in ${data.breaches?.length || data.count} breaches` 
            : "No breaches found for this password",
          variant: data.breached ? "destructive" : "default"
        });
      } else {
        throw new Error('Breach check failed');
      }
    } catch (error) {
      toast({
        title: "Check Failed",
        description: error.message || "Failed to check password breach status",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };



  const generateSecurePassword = async () => {
    try {
      const response = await fetch(`${API_BASE}/password/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ length: 16, includeSymbols: true })
      });

      if (response.ok) {
        const data = await response.json();
        setPassword(data.password);
        toast({
          title: "Secure Password Generated",
          description: `Strength: ${data.strength}`,
        });
      }
    } catch (error) {
      toast({
        title: "Generation Failed",
        description: "Failed to generate secure password",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold text-white mb-2">Password & Credential Security</h1>
        <p className="text-slate-400">Audit local hashes and check for leaked credentials.</p>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass-card p-6 rounded-xl">
        <div className="flex border-b border-slate-700 mb-6">
          <button
            className={`px-4 py-2 text-sm font-medium transition-colors ${activeTab === 'audit' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-white'}`}
            onClick={() => setActiveTab('audit')}
          >
            Local Hash Audit
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium transition-colors ${activeTab === 'pwned' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-white'}`}
            onClick={() => setActiveTab('pwned')}
          >
            Leaked Credential Check
          </button>
        </div>

        {activeTab === 'audit' && (
          <div>
            <h2 className="text-xl font-semibold text-white mb-4">Audit Local Password Hashes</h2>
            <p className="text-slate-400 mb-6">Upload a password hash file (e.g., from `/etc/shadow`, SAM dump) to check for weak passwords against common dictionaries.</p>
            <Button onClick={triggerFileUpload} disabled={isLoading} className="w-full md:w-auto">
              <Upload className="w-4 h-4 mr-2" />
              Upload and Audit Hash File
            </Button>
            <input type="file" ref={fileInputRef} onChange={handleFileAudit} className="hidden" />
          </div>
        )}

        {activeTab === 'pwned' && (
          <div>
            <h2 className="text-xl font-semibold text-white mb-4">Check for Leaked Credentials</h2>
            <p className="text-slate-400 mb-6">Enter an email address or username to check against the "Have I Been Pwned" database and other breach collections.</p>
            <div className="flex items-center space-x-4">
              <input
                type="text"
                placeholder="Enter email or username"
                className="w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
                disabled={isLoading}
              />
              <Button onClick={handlePwnedCheck} disabled={isLoading}>
                <Search className="w-4 h-4 mr-2" />
                Check
              </Button>
            </div>
          </div>
        )}
      </motion.div>

      {isLoading && (
        <div className="text-center p-8">
          <div className="flex items-center justify-center space-x-2">
            <div className="w-6 h-6 border-2 border-blue-400 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-lg text-slate-300">Processing...</span>
          </div>
        </div>
      )}

      {!results && !isLoading && (
        <div className="text-center py-16 text-slate-400 glass-card rounded-xl">
          <KeyRound className="w-16 h-16 mx-auto mb-4 text-slate-500" />
          <h2 className="text-xl font-semibold text-white">Credential Audit Results</h2>
          <p>Results from your audit will appear here.</p>
        </div>
      )}

      {results && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6 rounded-xl">
          {/* Results display here */}
        </motion.div>
      )}
    </div>
  );
};

export default PasswordSecurity;
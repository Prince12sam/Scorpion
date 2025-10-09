import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Hammer, 
  Target, 
  Key, 
  Shield, 
  AlertTriangle,
  Play,
  Pause,
  StopCircle,
  Clock,
  Lock,
  Unlock,
  User
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/components/ui/use-toast';

const BruteForceTools = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState([]);
  const [targetHost, setTargetHost] = useState('');
  const [targetPort, setTargetPort] = useState('22');
  const [service, setService] = useState('ssh');
  const [username, setUsername] = useState('admin');
  const [maxAttempts, setMaxAttempts] = useState(100);
  const [currentProgress, setCurrentProgress] = useState(0);
  const { toast } = useToast();

  const services = [
    { value: 'ssh', label: 'SSH (22)', port: '22', description: 'Secure Shell Protocol' },
    { value: 'ftp', label: 'FTP (21)', port: '21', description: 'File Transfer Protocol' },
    { value: 'telnet', label: 'Telnet (23)', port: '23', description: 'Telnet Protocol' },
    { value: 'http', label: 'HTTP (80)', port: '80', description: 'Web Authentication' },
    { value: 'https', label: 'HTTPS (443)', port: '443', description: 'Secure Web Authentication' },
    { value: 'rdp', label: 'RDP (3389)', port: '3389', description: 'Remote Desktop Protocol' },
    { value: 'smb', label: 'SMB (445)', port: '445', description: 'Server Message Block' }
  ];

  const startBruteForce = async () => {
    if (!targetHost || !username) {
      toast({
        title: "Error",
        description: "Please specify target host and username",
        variant: "destructive",
      });
      return;
    }

    setIsRunning(true);
    setCurrentProgress(0);
    
    try {
      const response = await fetch('/api/bruteforce/attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: targetHost,
          port: targetPort,
          service: service,
          username: username,
          maxAttempts: maxAttempts,
          timestamp: new Date().toISOString()
        })
      });

      const data = await response.json();
      setResults(prev => [data, ...prev.slice(0, 9)]);
      
      toast({
        title: "Brute Force Attack Completed",
        description: `Completed ${data.attempts_made} attempts. Found ${data.successful_logins?.length || 0} credentials.`,
        variant: data.successful_logins?.length > 0 ? "default" : "destructive"
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to execute brute force attack",
        variant: "destructive",
      });
    } finally {
      setIsRunning(false);
      setCurrentProgress(0);
    }
  };

  const stopBruteForce = () => {
    setIsRunning(false);
    setCurrentProgress(0);
    toast({
      title: "Attack Stopped",
      description: "Brute force attack has been terminated",
    });
  };

  // Progress is controlled by server responses only (no simulation)
  useEffect(() => {
    if (!isRunning) {
      setCurrentProgress(0);
    }
  }, [isRunning]);

  const handleServiceChange = (selectedService) => {
    setService(selectedService);
    const serviceConfig = services.find(s => s.value === selectedService);
    if (serviceConfig) {
      setTargetPort(serviceConfig.port);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header with Warning */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gradient-to-r from-red-900/20 to-orange-900/20 p-6 rounded-lg border border-red-500/30"
      >
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-red-500/20 rounded-lg">
            <Hammer className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Brute Force Attack Tools</h1>
            <p className="text-red-400 font-medium">⚠️ AUTHORIZED SYSTEMS ONLY - Ethical Use Required</p>
          </div>
        </div>
        
        <div className="bg-red-950/30 border border-red-500/50 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <span className="font-semibold text-red-400">ETHICAL USAGE WARNING</span>
          </div>
          <p className="text-sm text-red-300">
            This tool is designed for authorized penetration testing and security assessments only. 
            Unauthorized brute force attacks are illegal and unethical. Always obtain proper authorization.
          </p>
        </div>
      </motion.div>

      {/* Attack Configuration */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="lg:col-span-2 bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-orange-400" />
            Attack Configuration
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2 text-slate-300">Target Host</label>
              <input
                type="text"
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                placeholder="192.168.1.100 or target.com"
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:border-orange-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-2 text-slate-300">Service</label>
              <select
                value={service}
                onChange={(e) => handleServiceChange(e.target.value)}
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:outline-none"
              >
                {services.map((svc) => (
                  <option key={svc.value} value={svc.value}>
                    {svc.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2 text-slate-300">Port</label>
              <input
                type="number"
                value={targetPort}
                onChange={(e) => setTargetPort(e.target.value)}
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-2 text-slate-300">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin, root, administrator"
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:border-orange-500 focus:outline-none"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-sm font-medium mb-2 text-slate-300">Max Attempts</label>
              <input
                type="number"
                value={maxAttempts}
                onChange={(e) => setMaxAttempts(parseInt(e.target.value))}
                min="1"
                max="10000"
                className="w-full p-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:border-orange-500 focus:outline-none"
              />
              <p className="text-xs text-slate-400 mt-1">
                Number of password attempts to try (1-10000)
              </p>
            </div>
          </div>

          <div className="flex gap-3 mt-6">
            <Button
              onClick={startBruteForce}
              disabled={isRunning || !targetHost || !username}
              className="bg-red-600 hover:bg-red-700 flex items-center gap-2"
            >
              {isRunning ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  Running Attack...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Start Brute Force
                </>
              )}
            </Button>
            
            {isRunning && (
              <Button
                onClick={stopBruteForce}
                variant="outline"
                className="border-red-600 text-red-400 hover:bg-red-600 hover:text-white"
              >
                <StopCircle className="w-4 h-4 mr-2" />
                Stop Attack
              </Button>
            )}
          </div>

          {/* Progress Bar */}
          {isRunning && (
            <div className="mt-4">
              <div className="flex justify-between mb-2">
                <span className="text-sm text-slate-300">Attack Progress</span>
                <span className="text-sm text-slate-400">{Math.round(currentProgress)}%</span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div 
                  className="bg-red-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${currentProgress}%` }}
                ></div>
              </div>
            </div>
          )}
        </motion.div>

        {/* Service Information */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            Service Info
          </h2>
          
          <div className="space-y-4">
            <div className="p-3 bg-slate-900/50 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Key className="w-4 h-4 text-yellow-400" />
                <span className="font-medium text-white">Selected Service</span>
              </div>
              <p className="text-sm text-slate-300">
                {services.find(s => s.value === service)?.label || 'Unknown'}
              </p>
              <p className="text-xs text-slate-400 mt-1">
                {services.find(s => s.value === service)?.description || 'No description'}
              </p>
            </div>

            <div className="p-3 bg-slate-900/50 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="w-4 h-4 text-green-400" />
                <span className="font-medium text-white">Common Passwords</span>
              </div>
              <div className="space-y-1 text-xs text-slate-400">
                <p>• admin, password, 123456</p>
                <p>• root, toor, administrator</p>
                <p>• guest, user, default</p>
                <p>• + Dictionary wordlists</p>
              </div>
            </div>

            <div className="p-3 bg-slate-900/50 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span className="font-medium text-white">Rate Limiting</span>
              </div>
              <p className="text-xs text-slate-400">
                Automatically detects and respects rate limiting to avoid account lockouts
              </p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Results */}
      {results.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 p-6 rounded-lg border border-slate-700"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Lock className="w-5 h-5 text-purple-400" />
            Brute Force Results
          </h2>
          
          <div className="space-y-4 max-h-96 overflow-y-auto">
            {results.map((result, index) => (
              <div
                key={index}
                className="p-4 bg-slate-900/50 rounded-lg border border-slate-600"
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <User className="w-4 h-4 text-blue-400" />
                    <span className="font-medium text-white">
                      {result.username}@{result.target}:{result.port || targetPort}
                    </span>
                  </div>
                  <span className="text-xs text-slate-400">
                    {new Date(result.timestamp).toLocaleString()}
                  </span>
                </div>
                
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm mb-3">
                  <div>
                    <span className="text-slate-400">Service:</span>
                    <span className="ml-2 text-white">{result.service}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Attempts:</span>
                    <span className="ml-2 text-blue-400">{result.attempts_made || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Success:</span>
                    <span className="ml-2 text-green-400">{result.successful_logins?.length || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Locked:</span>
                    <span className="ml-2 text-red-400">{result.locked_accounts?.length || 0}</span>
                  </div>
                </div>

                {result.successful_logins && result.successful_logins.length > 0 && (
                  <div className="mt-3">
                    <div className="flex items-center gap-2 mb-2">
                      <Unlock className="w-4 h-4 text-green-400" />
                      <span className="text-sm font-medium text-green-400">Successful Credentials:</span>
                    </div>
                    <div className="space-y-1">
                      {result.successful_logins.map((cred, credIndex) => (
                        <div key={credIndex} className="text-xs bg-green-950/30 p-2 rounded border border-green-500/30">
                          <span className="font-mono text-green-400">{cred.username}:{cred.password}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.rate_limiting_detected && (
                  <div className="mt-3 p-2 bg-yellow-950/30 rounded border border-yellow-500/30">
                    <div className="flex items-center gap-1 text-yellow-400 text-xs">
                      <AlertTriangle className="w-3 h-3" />
                      Rate limiting detected - Attack throttled to prevent lockout
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default BruteForceTools;
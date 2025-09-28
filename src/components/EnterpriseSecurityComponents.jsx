// 🦂 ADVANCED SECURITY FRONTEND ENHANCEMENTS
// Enterprise-Grade React Components with Security Hardening

import React, { useState, useEffect, useContext, createContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  Lock, 
  Key, 
  AlertTriangle, 
  CheckCircle, 
  Eye, 
  EyeOff,
  Smartphone,
  QrCode,
  Download,
  Copy,
  RefreshCw
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from '@/components/ui/use-toast';

// Security Context for Enterprise Features
const SecurityContext = createContext();

export const SecurityProvider = ({ children }) => {
  const [securityLevel, setSecurityLevel] = useState('STANDARD');
  const [threatLevel, setThreatLevel] = useState('LOW');
  const [securityMetrics, setSecurityMetrics] = useState({
    blockedAttacks: 0,
    activeScans: 0,
    lastThreatUpdate: new Date().toISOString()
  });
  
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [sessionId, setSessionId] = useState(null);

  // Enhanced API Client with Security Features
  const secureApiCall = async (endpoint, options = {}) => {
    const token = localStorage.getItem('accessToken');
    const deviceFingerprint = generateDeviceFingerprint();
    
    const config = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Fingerprint': deviceFingerprint,
        'X-Session-ID': sessionId,
        ...options.headers
      }
    };

    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(`${import.meta.env.VITE_API_BASE || 'http://localhost:3001/api'}${endpoint}`, config);
      
      // Handle token refresh if needed
      if (response.status === 401) {
        const refreshed = await refreshToken();
        if (refreshed) {
          config.headers['Authorization'] = `Bearer ${localStorage.getItem('accessToken')}`;
          return fetch(`${import.meta.env.VITE_API_BASE || 'http://localhost:3001/api'}${endpoint}`, config);
        } else {
          logout();
          throw new Error('Authentication failed');
        }
      }

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'API request failed');
      }

      return await response.json();
    } catch (error) {
      console.error('Secure API call failed:', error);
      throw error;
    }
  };

  // Device Fingerprinting
  const generateDeviceFingerprint = () => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Device fingerprint', 2, 2);
    
    const fingerprint = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      screen: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      canvas: canvas.toDataURL()
    };

    return btoa(JSON.stringify(fingerprint)).substring(0, 32);
  };

  // Token Management
  const refreshToken = async () => {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) return false;

      const response = await fetch(`${import.meta.env.VITE_API_BASE || 'http://localhost:3001/api'}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('accessToken', data.tokens.accessToken);
        localStorage.setItem('refreshToken', data.tokens.refreshToken);
        return true;
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    }
    return false;
  };

  const logout = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    setUser(null);
    setIsAuthenticated(false);
    setSessionId(null);
    toast({
      title: "Logged Out",
      description: "You have been securely logged out",
      variant: "default"
    });
  };

  return (
    <SecurityContext.Provider value={{
      securityLevel,
      threatLevel,
      securityMetrics,
      user,
      isAuthenticated,
      sessionId,
      secureApiCall,
      logout,
      setUser,
      setIsAuthenticated,
      setSessionId
    }}>
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurityContext = () => {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurityContext must be used within SecurityProvider');
  }
  return context;
};

// Advanced Login Component with 2FA
export const AdvancedLogin = ({ onLogin }) => {
  const [step, setStep] = useState('credentials'); // credentials, 2fa, success
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [requiresTwoFactor, setRequiresTwoFactor] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [isLocked, setIsLocked] = useState(false);
  const [lockoutTime, setLockoutTime] = useState(0);
  
  const { secureApiCall, setUser, setIsAuthenticated, setSessionId } = useSecurityContext();

  // Lockout timer
  useEffect(() => {
    if (isLocked && lockoutTime > 0) {
      const timer = setInterval(() => {
        setLockoutTime(prev => {
          if (prev <= 1) {
            setIsLocked(false);
            setLoginAttempts(0);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [isLocked, lockoutTime]);

  const handleCredentialsSubmit = async (e) => {
    e.preventDefault();
    
    if (isLocked) {
      toast({
        title: "Account Locked",
        description: `Please wait ${lockoutTime} seconds before trying again`,
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);

    try {
      const response = await secureApiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify(credentials)
      });

      if (response.requiresTwoFactor) {
        setRequiresTwoFactor(true);
        setStep('2fa');
        toast({
          title: "2FA Required",
          description: "Please enter your 2FA code",
          variant: "default"
        });
      } else if (response.success) {
        handleSuccessfulLogin(response);
      }

      setLoginAttempts(0);
    } catch (error) {
      const newAttempts = loginAttempts + 1;
      setLoginAttempts(newAttempts);

      if (newAttempts >= 5) {
        setIsLocked(true);
        setLockoutTime(300); // 5 minutes
        toast({
          title: "Account Locked",
          description: "Too many failed attempts. Account locked for 5 minutes.",
          variant: "destructive"
        });
      } else {
        toast({
          title: "Login Failed",
          description: `${error.message}. ${5 - newAttempts} attempts remaining.`,
          variant: "destructive"
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handle2FASubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await secureApiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          ...credentials,
          twoFactorCode
        })
      });

      if (response.success) {
        handleSuccessfulLogin(response);
      }
    } catch (error) {
      toast({
        title: "2FA Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleSuccessfulLogin = (response) => {
    localStorage.setItem('accessToken', response.tokens.accessToken);
    localStorage.setItem('refreshToken', response.tokens.refreshToken);
    setUser(response.user);
    setIsAuthenticated(true);
    setSessionId(response.sessionId);
    setStep('success');
    
    setTimeout(() => {
      onLogin(response.user);
    }, 1000);

    toast({
      title: "Login Successful",
      description: `Welcome back, ${response.user.username}!`,
      variant: "default"
    });
  };

  const renderCredentialsForm = () => (
    <motion.form
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      onSubmit={handleCredentialsSubmit}
      className="space-y-6"
    >
      <div className="text-center mb-8">
        <div className="flex justify-center mb-4">
          <div className="p-3 bg-blue-500/20 rounded-full">
            <Shield className="w-8 h-8 text-blue-400" />
          </div>
        </div>
        <h1 className="text-2xl font-bold text-white mb-2">Secure Login</h1>
        <p className="text-slate-400">Enterprise Security Platform</p>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Username
          </label>
          <input
            type="text"
            required
            disabled={isLocked}
            value={credentials.username}
            onChange={(e) => setCredentials(prev => ({ ...prev, username: e.target.value }))}
            className="w-full px-4 py-3 bg-slate-800/50 border border-slate-600 rounded-lg text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-50"
            placeholder="Enter your username"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Password
          </label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              required
              disabled={isLocked}
              value={credentials.password}
              onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
              className="w-full px-4 py-3 bg-slate-800/50 border border-slate-600 rounded-lg text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-50 pr-12"
              placeholder="Enter your password"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-white"
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {loginAttempts > 0 && !isLocked && (
        <div className="flex items-center gap-2 text-yellow-400 text-sm">
          <AlertTriangle className="w-4 h-4" />
          {5 - loginAttempts} attempts remaining
        </div>
      )}

      {isLocked && (
        <div className="flex items-center gap-2 text-red-400 text-sm">
          <Lock className="w-4 h-4" />
          Account locked for {Math.floor(lockoutTime / 60)}:{(lockoutTime % 60).toString().padStart(2, '0')}
        </div>
      )}

      <Button
        type="submit"
        disabled={isLoading || isLocked}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white py-3"
      >
        {isLoading ? (
          <div className="flex items-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin" />
            Authenticating...
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4" />
            Sign In
          </div>
        )}
      </Button>
    </motion.form>
  );

  const render2FAForm = () => (
    <motion.form
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      onSubmit={handle2FASubmit}
      className="space-y-6"
    >
      <div className="text-center mb-8">
        <div className="flex justify-center mb-4">
          <div className="p-3 bg-green-500/20 rounded-full">
            <Smartphone className="w-8 h-8 text-green-400" />
          </div>
        </div>
        <h1 className="text-2xl font-bold text-white mb-2">Two-Factor Authentication</h1>
        <p className="text-slate-400">Enter the 6-digit code from your authenticator app</p>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">
          Authentication Code
        </label>
        <input
          type="text"
          required
          maxLength="6"
          value={twoFactorCode}
          onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, ''))}
          className="w-full px-4 py-3 bg-slate-800/50 border border-slate-600 rounded-lg text-white text-center text-2xl tracking-widest focus:border-green-500 focus:ring-1 focus:ring-green-500"
          placeholder="000000"
        />
      </div>

      <div className="flex gap-3">
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            setStep('credentials');
            setTwoFactorCode('');
          }}
          className="flex-1 border-slate-600 text-slate-300 hover:text-white"
        >
          Back
        </Button>
        <Button
          type="submit"
          disabled={isLoading || twoFactorCode.length !== 6}
          className="flex-1 bg-green-600 hover:bg-green-700 text-white"
        >
          {isLoading ? (
            <RefreshCw className="w-4 h-4 animate-spin" />
          ) : (
            'Verify'
          )}
        </Button>
      </div>
    </motion.form>
  );

  const renderSuccessScreen = () => (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className="text-center space-y-6"
    >
      <div className="flex justify-center mb-4">
        <div className="p-4 bg-green-500/20 rounded-full">
          <CheckCircle className="w-12 h-12 text-green-400" />
        </div>
      </div>
      <h1 className="text-2xl font-bold text-white">Login Successful!</h1>
      <p className="text-slate-400">Redirecting to dashboard...</p>
    </motion.div>
  );

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-700 rounded-xl p-8">
          <AnimatePresence mode="wait">
            {step === 'credentials' && renderCredentialsForm()}
            {step === '2fa' && render2FAForm()}
            {step === 'success' && renderSuccessScreen()}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};

// Two-Factor Setup Component
export const TwoFactorSetup = ({ onComplete }) => {
  const [step, setStep] = useState('intro'); // intro, scan, verify, complete
  const [qrCode, setQrCode] = useState('');
  const [secret, setSecret] = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [verificationCode, setVerificationCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const { secureApiCall } = useSecurityContext();

  const handleSetup2FA = async () => {
    setIsLoading(true);
    try {
      const response = await secureApiCall('/auth/setup-2fa', {
        method: 'POST'
      });

      setQrCode(response.qrCode);
      setSecret(response.secret);
      setBackupCodes(response.backupCodes);
      setStep('scan');
    } catch (error) {
      toast({
        title: "Setup Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerification = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await secureApiCall('/auth/verify-2fa', {
        method: 'POST',
        body: JSON.stringify({
          secret,
          token: verificationCode
        })
      });

      if (response.success) {
        setStep('complete');
        toast({
          title: "2FA Enabled",
          description: "Two-factor authentication has been successfully enabled",
          variant: "default"
        });
      }
    } catch (error) {
      toast({
        title: "Verification Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Copied to clipboard",
      variant: "default"
    });
  };

  const downloadBackupCodes = () => {
    const content = `Scorpion Security Platform - Backup Codes\n\nGenerated: ${new Date().toISOString()}\n\n${backupCodes.join('\n')}\n\nKeep these codes safe and secure!`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'scorpion-backup-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <AnimatePresence mode="wait">
        {step === 'intro' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="text-center space-y-6"
          >
            <div className="flex justify-center">
              <div className="p-4 bg-green-500/20 rounded-full">
                <Shield className="w-12 h-12 text-green-400" />
              </div>
            </div>
            <h2 className="text-2xl font-bold text-white">Enable Two-Factor Authentication</h2>
            <p className="text-slate-400 max-w-md mx-auto">
              Add an extra layer of security to your account by enabling two-factor authentication using your mobile device.
            </p>
            <Button
              onClick={handleSetup2FA}
              disabled={isLoading}
              className="bg-green-600 hover:bg-green-700 text-white px-8"
            >
              {isLoading ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                'Enable 2FA'
              )}
            </Button>
          </motion.div>
        )}

        {step === 'scan' && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            className="space-y-6"
          >
            <h2 className="text-2xl font-bold text-white text-center">Scan QR Code</h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div className="bg-white p-4 rounded-lg">
                  <img src={qrCode} alt="2FA QR Code" className="w-full" />
                </div>
                <div className="text-center">
                  <p className="text-slate-400 text-sm">
                    Can't scan? Enter this key manually:
                  </p>
                  <div className="flex items-center gap-2 mt-2">
                    <code className="bg-slate-800 px-3 py-2 rounded text-sm text-green-400 flex-1">
                      {secret}
                    </code>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => copyToClipboard(secret)}
                      className="border-slate-600"
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-white">Instructions</h3>
                <ol className="space-y-2 text-slate-300 text-sm">
                  <li>1. Install an authenticator app (Google Authenticator, Authy, etc.)</li>
                  <li>2. Scan the QR code with your app</li>
                  <li>3. Enter the 6-digit code below to verify</li>
                </ol>

                <form onSubmit={handleVerification} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Verification Code
                    </label>
                    <input
                      type="text"
                      required
                      maxLength="6"
                      value={verificationCode}
                      onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ''))}
                      className="w-full px-4 py-3 bg-slate-800/50 border border-slate-600 rounded-lg text-white text-center text-xl tracking-widest focus:border-green-500 focus:ring-1 focus:ring-green-500"
                      placeholder="000000"
                    />
                  </div>
                  <Button
                    type="submit"
                    disabled={isLoading || verificationCode.length !== 6}
                    className="w-full bg-green-600 hover:bg-green-700 text-white"
                  >
                    {isLoading ? (
                      <RefreshCw className="w-4 h-4 animate-spin" />
                    ) : (
                      'Verify & Enable'
                    )}
                  </Button>
                </form>
              </div>
            </div>
          </motion.div>
        )}

        {step === 'complete' && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="text-center space-y-6"
          >
            <div className="flex justify-center">
              <div className="p-4 bg-green-500/20 rounded-full">
                <CheckCircle className="w-12 h-12 text-green-400" />
              </div>
            </div>
            <h2 className="text-2xl font-bold text-white">2FA Successfully Enabled!</h2>
            
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-yellow-400 mb-4 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Save Your Backup Codes
              </h3>
              <p className="text-slate-300 text-sm mb-4">
                These backup codes can be used to access your account if you lose your device. 
                Store them in a safe place!
              </p>
              
              <div className="grid grid-cols-2 gap-2 mb-4">
                {backupCodes.map((code, index) => (
                  <code key={index} className="bg-slate-800 px-3 py-2 rounded text-sm text-green-400 text-center">
                    {code}
                  </code>
                ))}
              </div>

              <div className="flex gap-3">
                <Button
                  onClick={downloadBackupCodes}
                  variant="outline"
                  className="flex-1 border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download Codes
                </Button>
                <Button
                  onClick={() => copyToClipboard(backupCodes.join('\n'))}
                  variant="outline"
                  className="flex-1 border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10"
                >
                  <Copy className="w-4 h-4 mr-2" />
                  Copy Codes
                </Button>
              </div>
            </div>

            <Button
              onClick={() => onComplete?.()}
              className="bg-green-600 hover:bg-green-700 text-white px-8"
            >
              Complete Setup
            </Button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// Security Dashboard Component
export const SecurityDashboard = () => {
  const [securityData, setSecurityData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const { secureApiCall, securityLevel, threatLevel } = useSecurityContext();

  useEffect(() => {
    fetchSecurityData();
    const interval = setInterval(fetchSecurityData, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchSecurityData = async () => {
    try {
      const data = await secureApiCall('/security/dashboard');
      setSecurityData(data);
    } catch (error) {
      console.error('Failed to fetch security data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3 text-slate-400">
          <RefreshCw className="w-6 h-6 animate-spin" />
          Loading security dashboard...
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
        <div className="flex items-center gap-4">
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${
            securityLevel === 'ENTERPRISE' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'
          }`}>
            Security Level: {securityLevel}
          </div>
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${
            threatLevel === 'LOW' ? 'bg-green-500/20 text-green-400' : 
            threatLevel === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
            'bg-red-500/20 text-red-400'
          }`}>
            Threat Level: {threatLevel}
          </div>
        </div>
      </div>

      {/* Security Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <SecurityMetricCard
          icon={Shield}
          title="Security Score"
          value={securityData?.systemHardening?.securityScore || 95}
          unit="/100"
          trend="stable"
          color="green"
        />
        <SecurityMetricCard
          icon={AlertTriangle}
          title="Blocked Attacks"
          value={securityData?.securityOverview?.blockedAttacks || 0}
          trend="increasing"
          color="red"
        />
        <SecurityMetricCard
          icon={Eye}
          title="Active Scans"
          value={securityData?.securityOverview?.activeScans || 0}
          trend="stable"
          color="blue"
        />
        <SecurityMetricCard
          icon={CheckCircle}
          title="System Health"
          value="Optimal"
          trend="stable"
          color="green"
        />
      </div>

      {/* Security Features Status */}
      <div className="grid md:grid-cols-2 gap-6">
        <SecurityFeaturesCard features={securityData?.systemHardening} />
        <RecentSecurityEvents events={securityData?.recentEvents} />
      </div>
    </div>
  );
};

// Security Metric Card Component
const SecurityMetricCard = ({ icon: Icon, title, value, unit, trend, color }) => {
  const colorClasses = {
    green: 'text-green-400 bg-green-500/20',
    red: 'text-red-400 bg-red-500/20',
    blue: 'text-blue-400 bg-blue-500/20',
    yellow: 'text-yellow-400 bg-yellow-500/20'
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`p-2 rounded-lg ${colorClasses[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div className={`text-xs px-2 py-1 rounded ${colorClasses[color]}`}>
          {trend}
        </div>
      </div>
      <div className="space-y-1">
        <h3 className="text-slate-400 text-sm font-medium">{title}</h3>
        <div className="text-2xl font-bold text-white">
          {value}{unit}
        </div>
      </div>
    </motion.div>
  );
};

// Security Features Status Card
const SecurityFeaturesCard = ({ features }) => {
  const featureList = [
    { key: 'httpsEnabled', name: 'HTTPS Enabled', icon: Lock },
    { key: 'sessionSecure', name: 'Secure Sessions', icon: Key },
    { key: 'rateLimitingActive', name: 'Rate Limiting', icon: Shield },
    { key: 'bruteForceProtection', name: 'Brute Force Protection', icon: AlertTriangle },
    { key: 'advancedLogging', name: 'Advanced Logging', icon: Eye },
    { key: 'twoFactorAvailable', name: '2FA Available', icon: Smartphone },
    { key: 'deviceFingerprinting', name: 'Device Fingerprinting', icon: QrCode }
  ];

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
    >
      <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
        <Shield className="w-5 h-5 text-green-400" />
        Security Features
      </h2>
      
      <div className="space-y-3">
        {featureList.map(({ key, name, icon: Icon }) => {
          const isEnabled = features?.[key] ?? false;
          return (
            <div key={key} className="flex items-center justify-between py-2">
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isEnabled ? 'text-green-400' : 'text-slate-500'}`} />
                <span className="text-slate-300">{name}</span>
              </div>
              <div className={`w-3 h-3 rounded-full ${isEnabled ? 'bg-green-400' : 'bg-slate-500'}`} />
            </div>
          );
        })}
      </div>
    </motion.div>
  );
};

// Recent Security Events Card
const RecentSecurityEvents = ({ events }) => {
  const getEventIcon = (type) => {
    switch (type) {
      case 'AUTHENTICATION': return Key;
      case 'RATE_LIMIT': return AlertTriangle;
      case 'SCAN': return Eye;
      default: return Shield;
    }
  };

  const getEventColor = (severity) => {
    switch (severity) {
      case 'INFO': return 'text-blue-400';
      case 'WARN': return 'text-yellow-400';
      case 'ERROR': return 'text-red-400';
      default: return 'text-slate-400';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      className="bg-slate-800/50 border border-slate-700 rounded-lg p-6"
    >
      <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
        <AlertTriangle className="w-5 h-5 text-yellow-400" />
        Recent Events
      </h2>
      
      <div className="space-y-3">
        {events?.length ? events.map((event, index) => {
          const Icon = getEventIcon(event.type);
          return (
            <div key={index} className="flex items-start gap-3 py-2">
              <Icon className={`w-4 h-4 mt-1 ${getEventColor(event.severity)}`} />
              <div className="flex-1 min-w-0">
                <p className="text-slate-300 text-sm">{event.message}</p>
                <p className="text-slate-500 text-xs">
                  {new Date(event.timestamp).toLocaleString()}
                </p>
              </div>
            </div>
          );
        }) : (
          <div className="text-center py-4 text-slate-500">
            No recent security events
          </div>
        )}
      </div>
    </motion.div>
  );
};

export default { 
  SecurityProvider, 
  AdvancedLogin, 
  TwoFactorSetup, 
  SecurityDashboard, 
  useSecurityContext 
};
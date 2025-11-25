import React, { useState, useEffect } from 'react';
import { installFetchAuthInterceptor, setTokens, clearTokens } from '@/lib/auth';

export default function Login({ onSuccess }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    installFetchAuthInterceptor();
  }, []);

  async function handleLogin(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, twoFactorCode: requires2FA ? twoFactorCode : undefined })
      });
      // Safely parse JSON if present; otherwise capture text
      const contentType = res.headers.get('content-type') || '';
      let data = null;
      let raw = '';
      try {
        if (contentType.includes('application/json')) {
          data = await res.json();
        } else {
          raw = await res.text();
          try { data = JSON.parse(raw); } catch { /* not json */ }
        }
      } catch {
        // If body is empty or invalid JSON, fall back to text
        try { raw = await res.text(); } catch {}
      }

      if (!res.ok) {
        // Handle proxy/network issues where body is HTML or empty
        const msg = (data && (data.error || data.message)) || raw || `Login failed (HTTP ${res.status})`;
        throw new Error(msg);
      }

      if (data?.requiresTwoFactor) {
        setRequires2FA(true);
        return;
      }

      // Expect data.tokens { accessToken, refreshToken }
      if (data?.tokens?.accessToken) {
        setTokens({ accessToken: data.tokens.accessToken, refreshToken: data.tokens.refreshToken });
        installFetchAuthInterceptor();
        onSuccess?.(data);
      } else {
        throw new Error('Invalid token response');
      }
    } catch (err) {
      // Improve messaging for unreachable API
      if (/Failed to fetch|NetworkError|ECONNREFUSED|ENOTFOUND/i.test(String(err?.message))) {
        setError('Cannot reach API. Ensure the Enterprise API is running and Vite proxy is configured.');
      } else if (err?.message?.includes('Unexpected end of JSON input')) {
        setError('Received an empty/invalid response from API. Please try again.');
      } else {
        setError(err.message || 'Login failed');
      }
      clearTokens();
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-xl">
        <h1 className="text-xl font-semibold mb-4">🦂 Scorpion Security Platform</h1>
        <p className="text-slate-400 text-sm mb-2">Enterprise Security Platform</p>
        <div className="bg-cyan-900/30 border border-cyan-700/50 rounded p-3 mb-6">
          <p className="text-cyan-300 text-xs font-medium mb-1">Default Credentials:</p>
          <p className="text-cyan-200 text-sm font-mono">admin / admin</p>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-900/30 border border-red-700/50 rounded text-red-300 text-sm">{error}</div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm mb-1 text-slate-300">Username</label>
            <input
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 outline-none focus:ring-2 focus:ring-cyan-600 text-white"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              placeholder="admin"
              required
            />
          </div>
          <div>
            <label className="block text-sm mb-1 text-slate-300">Password</label>
            <input
              type="password"
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 outline-none focus:ring-2 focus:ring-cyan-600 text-white"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              placeholder="admin"
              required
            />
          </div>

          {requires2FA && (
            <div>
              <label className="block text-sm mb-1">2FA Code</label>
              <input
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 outline-none focus:ring-2 focus:ring-cyan-600"
                value={twoFactorCode}
                onChange={(e) => setTwoFactorCode(e.target.value)}
                placeholder="123456"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:opacity-60 rounded py-2 font-medium transition-colors"
          >
            {loading ? '🔄 Authenticating…' : requires2FA ? 'Verify 2FA' : '🚀 Launch Platform'}
          </button>
        </form>

        <div className="text-xs text-slate-500 mt-6 text-center">
          <p className="mb-1">🔒 For authorized security operations only</p>
          <p className="text-slate-600">Enterprise vulnerability assessment platform</p>
        </div>
      </div>
    </div>
  );
}

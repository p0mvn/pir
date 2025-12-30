'use client';

import { useState, useCallback, useEffect } from 'react';

// SHA-1 hash function using Web Crypto API
async function sha1Hash(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Format large numbers with commas
function formatNumber(num: number): string {
  return num.toLocaleString('en-US');
}

interface CheckResult {
  pwned: boolean;
  count: number;
}

interface ServerHealth {
  status: string;
  ranges_loaded: number;
  total_hashes: number;
}

type CheckState = 'idle' | 'checking' | 'result' | 'error';

export default function Home() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [checkState, setCheckState] = useState<CheckState>('idle');
  const [result, setResult] = useState<CheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [serverHealth, setServerHealth] = useState<ServerHealth | null>(null);
  const [serverOnline, setServerOnline] = useState<boolean | null>(null);

  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

  // Check server health on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await fetch(`${apiUrl}/health`);
        if (response.ok) {
          const data = await response.json();
          setServerHealth(data);
          setServerOnline(true);
        } else {
          setServerOnline(false);
        }
      } catch {
        setServerOnline(false);
      }
    };

    checkHealth();
  }, [apiUrl]);

  const checkPassword = useCallback(async () => {
    if (!password.trim()) return;

    setCheckState('checking');
    setError(null);
    setResult(null);

    try {
      // Hash the password client-side (password never leaves browser in plaintext)
      const hash = await sha1Hash(password);

      // Send hash to server
      const response = await fetch(`${apiUrl}/check`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ hash }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || `Server error: ${response.status}`);
      }

      const data: CheckResult = await response.json();
      setResult(data);
      setCheckState('result');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred');
      setCheckState('error');
    }
  }, [password, apiUrl]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      checkPassword();
    }
  };

  const resetCheck = () => {
    setCheckState('idle');
    setResult(null);
    setError(null);
  };

  return (
    <main className="min-h-screen grid-pattern radial-overlay relative overflow-hidden">
      {/* Decorative elements */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyber-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-cyber-500/5 rounded-full blur-3xl" />
      
      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-4 py-12">
        {/* Header */}
        <div className="text-center mb-12 animate-fade-in">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-cyber-500/10 border border-cyber-500/20 mb-6">
            <span className={`w-2 h-2 rounded-full ${serverOnline === null ? 'bg-yellow-500 animate-pulse' : serverOnline ? 'bg-safe-500' : 'bg-danger-500'}`} />
            <span className="text-sm text-gray-400 font-mono">
              {serverOnline === null ? 'Connecting...' : serverOnline ? 'Server Online' : 'Server Offline'}
            </span>
          </div>
          
          <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-4">
            <span className="bg-gradient-to-r from-cyber-400 via-cyber-300 to-cyber-400 bg-clip-text text-transparent">
              Password Breach
            </span>
            <br />
            <span className="text-white">Checker</span>
          </h1>
          
          <p className="text-gray-400 max-w-md mx-auto text-lg">
            Check if your password has been exposed in data breaches. 
            <span className="text-cyber-400"> Your password is hashed locally</span> and never leaves your browser.
          </p>
        </div>

        {/* Main Card */}
        <div className="w-full max-w-xl">
          <div className="bg-gray-900/60 backdrop-blur-xl rounded-2xl border border-gray-800/50 p-8 shadow-2xl animate-slide-up">
            {/* Password Input */}
            <div className="relative mb-6">
              <label htmlFor="password" className="block text-sm font-medium text-gray-400 mb-2">
                Enter a password to check
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (checkState === 'result' || checkState === 'error') {
                      resetCheck();
                    }
                  }}
                  onKeyDown={handleKeyDown}
                  placeholder="Type your password..."
                  className="w-full px-5 py-4 bg-gray-800/50 border border-gray-700/50 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-cyber-500/50 input-glow transition-all font-mono text-lg"
                  autoComplete="off"
                  spellCheck={false}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors eye-icon"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                  )}
                </button>
              </div>
            </div>

            {/* Check Button */}
            <button
              onClick={checkPassword}
              disabled={!password.trim() || checkState === 'checking' || !serverOnline}
              className="w-full py-4 px-6 bg-gradient-to-r from-cyber-600 to-cyber-500 hover:from-cyber-500 hover:to-cyber-400 disabled:from-gray-700 disabled:to-gray-600 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all duration-300 shadow-lg shadow-cyber-500/20 hover:shadow-cyber-500/40 disabled:shadow-none flex items-center justify-center gap-3"
            >
              {checkState === 'checking' ? (
                <>
                  <svg className="w-5 h-5 spinner" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Checking...
                </>
              ) : (
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                  </svg>
                  Check Password
                </>
              )}
            </button>

            {/* Result Display */}
            {checkState === 'result' && result && (
              <div className={`mt-6 p-6 rounded-xl border ${result.pwned ? 'status-danger' : 'status-safe'} animate-fade-in`}>
                {result.pwned ? (
                  <div className="text-center">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-danger-500/20 mb-4">
                      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-8 h-8 text-danger-400">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                      </svg>
                    </div>
                    <h3 className="text-xl font-bold text-danger-400 mb-2">Password Compromised!</h3>
                    <p className="text-gray-300">
                      This password has been seen{' '}
                      <span className="font-mono font-bold text-danger-300 text-2xl count-animate">
                        {formatNumber(result.count)}
                      </span>{' '}
                      {result.count === 1 ? 'time' : 'times'} in data breaches.
                    </p>
                    <p className="text-sm text-gray-500 mt-3">
                      If you use this password anywhere, you should change it immediately.
                    </p>
                  </div>
                ) : (
                  <div className="text-center">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-safe-500/20 mb-4">
                      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-8 h-8 text-safe-400">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <h3 className="text-xl font-bold text-safe-400 mb-2">Password Not Found</h3>
                    <p className="text-gray-300">
                      Good news! This password wasn&apos;t found in any known data breaches.
                    </p>
                    <p className="text-sm text-gray-500 mt-3">
                      This doesn&apos;t guarantee the password is secure, but it hasn&apos;t been exposed in breaches we know about.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Error Display */}
            {checkState === 'error' && error && (
              <div className="mt-6 p-6 rounded-xl bg-danger-500/10 border border-danger-500/30 animate-fade-in">
                <div className="flex items-start gap-3">
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-6 h-6 text-danger-400 flex-shrink-0 mt-0.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                  </svg>
                  <div>
                    <h3 className="font-semibold text-danger-400 mb-1">Error</h3>
                    <p className="text-gray-400 text-sm">{error}</p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Server Stats */}
          {serverHealth && (
            <div className="mt-6 flex items-center justify-center gap-6 text-sm text-gray-500 animate-fade-in">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-500" />
                <span>{formatNumber(serverHealth.ranges_loaded)} ranges</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-500" />
                <span>{formatNumber(serverHealth.total_hashes)} hashes indexed</span>
              </div>
            </div>
          )}
        </div>

        {/* How it works section */}
        <div className="mt-16 w-full max-w-3xl animate-fade-in">
          <h2 className="text-xl font-semibold text-center text-gray-300 mb-8">How it works</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-gray-900/40 backdrop-blur-sm rounded-xl p-6 border border-gray-800/50">
              <div className="w-10 h-10 rounded-lg bg-cyber-500/20 flex items-center justify-center mb-4">
                <span className="text-cyber-400 font-bold">1</span>
              </div>
              <h3 className="font-semibold text-white mb-2">Local Hashing</h3>
              <p className="text-sm text-gray-400">
                Your password is converted to a SHA-1 hash right in your browser. The actual password never leaves your device.
              </p>
            </div>
            <div className="bg-gray-900/40 backdrop-blur-sm rounded-xl p-6 border border-gray-800/50">
              <div className="w-10 h-10 rounded-lg bg-cyber-500/20 flex items-center justify-center mb-4">
                <span className="text-cyber-400 font-bold">2</span>
              </div>
              <h3 className="font-semibold text-white mb-2">Secure Lookup</h3>
              <p className="text-sm text-gray-400">
                The hash is checked against the Have I Been Pwned database containing over 900 million leaked passwords.
              </p>
            </div>
            <div className="bg-gray-900/40 backdrop-blur-sm rounded-xl p-6 border border-gray-800/50">
              <div className="w-10 h-10 rounded-lg bg-cyber-500/20 flex items-center justify-center mb-4">
                <span className="text-cyber-400 font-bold">3</span>
              </div>
              <h3 className="font-semibold text-white mb-2">Instant Results</h3>
              <p className="text-sm text-gray-400">
                Get immediate feedback on whether your password has appeared in known data breaches and how many times.
              </p>
            </div>
          </div>
        </div>

        {/* PIR Demo Link */}
        <div className="mt-12 animate-fade-in">
          <a
            href="/pir-demo"
            className="inline-flex items-center gap-3 px-6 py-3 bg-gradient-to-r from-purple-600/20 to-pink-600/20 hover:from-purple-600/30 hover:to-pink-600/30 border border-purple-500/30 hover:border-purple-500/50 rounded-xl transition-all group"
          >
            <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5 text-purple-400">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23.693L5 15.3m14.8 0l.853 10.66a.75.75 0 01-.22.57 3.026 3.026 0 01-1.907.84H5.474a3.025 3.025 0 01-1.907-.84.75.75 0 01-.22-.57L5 15.3" />
              </svg>
            </div>
            <div className="text-left">
              <div className="font-semibold text-white group-hover:text-purple-300 transition-colors">
                Try DoublePIR Demo
              </div>
              <div className="text-xs text-gray-400">
                Private Information Retrieval with Binary Fuse Filters
              </div>
            </div>
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5 text-purple-400 group-hover:translate-x-1 transition-transform">
              <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
            </svg>
          </a>
        </div>

        {/* Attribution Footer */}
        <footer className="mt-16 text-center text-sm text-gray-500 animate-fade-in">
          <p className="mb-2">
            Password data provided by{' '}
            <a 
              href="https://haveibeenpwned.com" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-cyber-400 hover:text-cyber-300 transition-colors attribution-link"
            >
              Have I Been Pwned
            </a>
          </p>
          <p className="text-gray-600 text-xs">
            Built with privacy in mind. Your passwords are hashed locally and never stored.
          </p>
        </footer>
      </div>
    </main>
  );
}



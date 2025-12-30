'use client';

import { useState, useCallback, useEffect, useRef } from 'react';

// ============================================================================
// Types
// ============================================================================

interface BinaryFuseParams {
  seed: string;
  segment_size: number;
  filter_size: number;
  value_size: number;
  segment_length_mask: number;
}

interface LweParams {
  n: number;
  p: number;
  noise_stddev: number;
}

interface DoublePirSetup {
  seed_col: number[];
  seed_row: number[];
  hint_col_data: number[];
  hint_col_rows: number;
  hint_col_cols: number;
  hint_row_data: number[];
  hint_row_rows: number;
  hint_row_cols: number;
  hint_cross: number[];
  num_cols: number;
  num_rows: number;
  record_size: number;
  num_records: number;
  lwe_dim: number;
}

interface PirSetupResponse {
  filter_params: BinaryFuseParams;
  lwe_params: LweParams;
  pir_setup: DoublePirSetup;
}

interface DoublePirAnswer {
  data: number[];
}

interface HealthResponse {
  status: string;
  ranges_loaded: number;
  total_hashes: number;
  pir_enabled: boolean;
  pir_num_records?: number;
}

// WASM module types
interface PirClientWasm {
  free(): void;
  num_records(): number;
  record_size(): number;
  get_keyword_indices(keyword: string): Uint32Array;
  get_password_indices(password: string): Uint32Array;
  query(record_idx: number): string;
  recover(state_json: string, answer_json: string): Uint8Array;
  decode_keyword(rec0: Uint8Array, rec1: Uint8Array, rec2: Uint8Array): Uint8Array;
}

type AppState = 'initializing' | 'ready' | 'checking' | 'result' | 'error';

interface QueryProgress {
  step: number;
  total: number;
  message: string;
}

// ============================================================================
// Main Component
// ============================================================================

export default function Home() {
  const [appState, setAppState] = useState<AppState>('initializing');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [breachCount, setBreachCount] = useState<number | null>(null);
  const [queryProgress, setQueryProgress] = useState<QueryProgress | null>(null);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  
  // WASM client ref
  const pirClientRef = useRef<PirClientWasm | null>(null);

  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

  // Initialize WASM and load setup
  useEffect(() => {
    const initialize = async () => {
      try {
        // Import WASM module
        const wasmModule = await import('../lib/pir_wasm.js');
        await wasmModule.default('/wasm/pir_wasm_bg.wasm');
        
        // Check health
        const healthResponse = await fetch(`${apiUrl}/health`);
        if (healthResponse.ok) {
          const healthData = await healthResponse.json();
          setHealth(healthData);
          
          if (!healthData.pir_enabled) {
            throw new Error('Private lookup service is not available');
          }
        } else {
          throw new Error('Server is not responding');
        }
        
        // Load PIR setup
        const setupResponse = await fetch(`${apiUrl}/pir/setup`);
        if (!setupResponse.ok) {
          throw new Error('Failed to initialize private lookup');
        }
        
        const setupData: PirSetupResponse = await setupResponse.json();
        
        // Create PIR client
        const client = new wasmModule.PirClient(
          JSON.stringify(setupData.pir_setup),
          JSON.stringify(setupData.lwe_params),
          JSON.stringify(setupData.filter_params)
        );
        pirClientRef.current = client;
        
        setAppState('ready');
      } catch (err) {
        console.error('Initialization error:', err);
        setError(err instanceof Error ? err.message : 'Failed to initialize');
        setAppState('error');
      }
    };
    
    initialize();
    
    return () => {
      if (pirClientRef.current) {
        pirClientRef.current.free();
        pirClientRef.current = null;
      }
    };
  }, [apiUrl]);

  // Check password using PIR
  const checkPassword = useCallback(async () => {
    const client = pirClientRef.current;
    if (!client || !password.trim()) return;
    
    setAppState('checking');
    setError(null);
    setBreachCount(null);
    setQueryProgress({ step: 0, total: 3, message: 'Hashing password locally...' });
    
    try {
      // Get positions using WASM (password is hashed locally)
      const positionsArray = client.get_password_indices(password);
      const positions = Array.from(positionsArray);
      
      // Execute 3 PIR queries
      const recoveredRecords: Uint8Array[] = [];
      
      for (let i = 0; i < 3; i++) {
        setQueryProgress({ 
          step: i + 1, 
          total: 3, 
          message: `Sending encrypted query ${i + 1} of 3...` 
        });
        
        // Generate encrypted query using WASM
        const queryJson = client.query(positions[i]);
        const { state: queryState, query } = JSON.parse(queryJson);
        
        // Send to server
        const response = await fetch(`${apiUrl}/pir/query`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query }),
        });
        
        if (!response.ok) {
          throw new Error('Server error during lookup');
        }
        
        const { answer }: { answer: DoublePirAnswer } = await response.json();
        
        // Recover record using WASM
        const recovered = client.recover(JSON.stringify(queryState), JSON.stringify(answer));
        recoveredRecords.push(recovered);
      }
      
      setQueryProgress({ step: 3, total: 3, message: 'Decoding result...' });
      
      // XOR decode final result
      const result = client.decode_keyword(
        recoveredRecords[0],
        recoveredRecords[1],
        recoveredRecords[2]
      );
      
      // Interpret as little-endian u32
      const bytes = Array.from(result);
      const count = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
      
      setBreachCount(count);
      setAppState('result');
      setQueryProgress(null);
      
    } catch (err) {
      console.error('Query error:', err);
      setError(err instanceof Error ? err.message : 'Lookup failed');
      setAppState('error');
      setQueryProgress(null);
    }
  }, [password, apiUrl]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && appState === 'ready') {
      checkPassword();
    }
  };

  const resetCheck = () => {
    setAppState('ready');
    setBreachCount(null);
    setError(null);
    setQueryProgress(null);
  };

  const formatNumber = (num: number): string => {
    return num.toLocaleString('en-US');
  };

  const isPwned = breachCount !== null && breachCount > 0;

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(120,119,198,0.15),transparent_50%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_right,rgba(74,222,128,0.08),transparent_50%)]" />
      <div className="absolute inset-0" style={{
        backgroundImage: `radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px)`,
        backgroundSize: '32px 32px'
      }} />
      
      <div className="relative z-10 flex flex-col items-center min-h-screen px-4 py-12">
        {/* Header */}
        <div className="text-center mb-10 mt-8 max-w-2xl">
          {/* Status indicator */}
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 mb-8">
            <span className={`w-2 h-2 rounded-full transition-colors ${
              appState === 'initializing' ? 'bg-amber-400 animate-pulse' :
              appState === 'error' ? 'bg-red-400' :
              'bg-emerald-400'
            }`} />
            <span className="text-sm text-slate-400 font-medium">
              {appState === 'initializing' ? 'Initializing secure lookup...' :
               appState === 'error' ? 'Service unavailable' :
               'Private lookup ready'}
            </span>
          </div>
          
          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight mb-6">
            <span className="text-white">Password</span>{' '}
            <span className="bg-gradient-to-r from-violet-400 via-fuchsia-400 to-violet-400 bg-clip-text text-transparent">
              Breach Checker
            </span>
          </h1>
          
          <p className="text-slate-400 text-lg md:text-xl leading-relaxed">
            Check if your password has been exposed in data breaches—
            <span className="text-violet-400 font-medium"> without revealing it to anyone</span>, 
            not even our servers.
          </p>
        </div>

        {/* Main Card */}
        <div className="w-full max-w-xl">
          <div className="bg-slate-900/80 backdrop-blur-xl rounded-3xl border border-slate-700/50 p-8 shadow-2xl shadow-black/20">
            
            {/* Password Input */}
            <div className="mb-6">
              <label htmlFor="password" className="block text-sm font-medium text-slate-300 mb-3">
                Enter a password to check
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (appState === 'result' || appState === 'error') {
                      resetCheck();
                    }
                  }}
                  onKeyDown={handleKeyDown}
                  placeholder="Type your password..."
                  className="w-full px-5 py-4 bg-slate-800/50 border border-slate-600/50 rounded-2xl text-white placeholder-slate-500 focus:outline-none focus:border-violet-500/50 focus:ring-2 focus:ring-violet-500/20 transition-all font-mono text-lg"
                  autoComplete="off"
                  spellCheck={false}
                  disabled={appState === 'checking' || appState === 'initializing'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors p-1"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                  )}
                </button>
              </div>
            </div>

            {/* Progress indicator */}
            {queryProgress && (
              <div className="mb-6 p-4 bg-violet-500/10 border border-violet-500/20 rounded-2xl">
                <div className="flex items-center gap-3">
                  <svg className="w-5 h-5 text-violet-400 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  <div className="flex-1">
                    <div className="text-sm text-violet-300 font-medium">{queryProgress.message}</div>
                    <div className="mt-2 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-violet-500 to-fuchsia-500 transition-all duration-300 rounded-full"
                        style={{ width: `${(queryProgress.step / queryProgress.total) * 100}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Check Button */}
            <button
              onClick={appState === 'result' ? resetCheck : checkPassword}
              disabled={!password.trim() || appState === 'checking' || appState === 'initializing'}
              className="w-full py-4 px-6 bg-gradient-to-r from-violet-600 to-fuchsia-600 hover:from-violet-500 hover:to-fuchsia-500 disabled:from-slate-700 disabled:to-slate-600 disabled:cursor-not-allowed text-white font-semibold rounded-2xl transition-all duration-300 shadow-lg shadow-violet-500/25 hover:shadow-violet-500/40 disabled:shadow-none flex items-center justify-center gap-3"
            >
              {appState === 'initializing' && (
                <>
                  <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Initializing...
                </>
              )}
              {appState === 'checking' && (
                <>
                  <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Checking Privately...
                </>
              )}
              {appState === 'result' && (
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
                  </svg>
                  Check Another Password
                </>
              )}
              {(appState === 'ready' || appState === 'error') && (
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                  </svg>
                  Check Password Privately
                </>
              )}
            </button>

            {/* Result Display */}
            {appState === 'result' && breachCount !== null && (
              <div className={`mt-6 p-6 rounded-2xl border transition-all ${
                isPwned 
                  ? 'bg-gradient-to-br from-red-500/10 to-orange-500/5 border-red-500/30' 
                  : 'bg-gradient-to-br from-emerald-500/10 to-teal-500/5 border-emerald-500/30'
              }`}>
                <div className="text-center">
                  <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full mb-4 ${
                    isPwned ? 'bg-red-500/20' : 'bg-emerald-500/20'
                  }`}>
                    {isPwned ? (
                      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-8 h-8 text-red-400">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                      </svg>
                    ) : (
                      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-8 h-8 text-emerald-400">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
                      </svg>
                    )}
                  </div>
                  
                  {isPwned ? (
                    <>
                      <h3 className="text-xl font-bold text-red-400 mb-2">Password Compromised</h3>
                      <p className="text-slate-300 mb-1">
                        This password appeared in{' '}
                        <span className="font-mono font-bold text-red-300 text-2xl">
                          {formatNumber(breachCount)}
                        </span>{' '}
                        data {breachCount === 1 ? 'breach' : 'breaches'}.
                      </p>
                      <p className="text-sm text-slate-500 mt-3">
                        If you use this password anywhere, change it immediately.
                      </p>
                    </>
                  ) : (
                    <>
                      <h3 className="text-xl font-bold text-emerald-400 mb-2">No Breaches Found</h3>
                      <p className="text-slate-300">
                        This password wasn&apos;t found in any known data breaches.
                      </p>
                      <p className="text-sm text-slate-500 mt-3">
                        However, always use unique passwords for each account.
                      </p>
                    </>
                  )}
                  
                  {/* Privacy note */}
                  <div className="mt-4 pt-4 border-t border-slate-700/50">
                    <div className="flex items-center justify-center gap-2 text-xs text-violet-400">
                      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                      </svg>
                      <span>Your password remained private—the server never saw it</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Error Display */}
            {appState === 'error' && error && (
              <div className="mt-6 p-5 rounded-2xl bg-red-500/10 border border-red-500/30">
                <div className="flex items-start gap-3">
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                  </svg>
                  <div>
                    <p className="text-red-300 text-sm">{error}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* How it works section */}
        <div className="mt-16 w-full max-w-4xl">
          <h2 className="text-2xl font-bold text-center text-white mb-3">How It Works</h2>
          <p className="text-slate-400 text-center mb-10 max-w-2xl mx-auto">
            We use <span className="text-violet-400 font-medium">Private Information Retrieval (PIR)</span> to check your password without ever learning what it is.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-slate-900/60 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-violet-500/20 to-fuchsia-500/20 flex items-center justify-center mb-4">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6 text-violet-400">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                </svg>
              </div>
              <h3 className="font-semibold text-white text-lg mb-2">Local Hashing</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Your password is hashed using SHA-1 right in your browser. The actual password never leaves your device.
              </p>
            </div>
            
            <div className="bg-slate-900/60 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-violet-500/20 to-fuchsia-500/20 flex items-center justify-center mb-4">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6 text-violet-400">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
                </svg>
              </div>
              <h3 className="font-semibold text-white text-lg mb-2">Encrypted Queries</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Using homomorphic encryption, we query the breach database without revealing which record we&apos;re looking for.
              </p>
            </div>
            
            <div className="bg-slate-900/60 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-violet-500/20 to-fuchsia-500/20 flex items-center justify-center mb-4">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6 text-violet-400">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              </div>
              <h3 className="font-semibold text-white text-lg mb-2">Private Results</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Only your browser can decrypt the result. The server processes your query without ever knowing what you searched for.
              </p>
            </div>
          </div>

          {/* Technical details toggle */}
          <div className="mt-8 text-center">
            <button
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-violet-400 transition-colors"
            >
              <span>{showTechnicalDetails ? 'Hide' : 'Show'} technical details</span>
              <svg 
                xmlns="http://www.w3.org/2000/svg" 
                fill="none" 
                viewBox="0 0 24 24" 
                strokeWidth={2} 
                stroke="currentColor" 
                className={`w-4 h-4 transition-transform ${showTechnicalDetails ? 'rotate-180' : ''}`}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
              </svg>
            </button>
          </div>

          {/* Technical details */}
          {showTechnicalDetails && (
            <div className="mt-6 bg-slate-900/60 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50">
              <h3 className="font-semibold text-white mb-4">DoublePIR with Binary Fuse Filters</h3>
              <div className="space-y-4 text-sm text-slate-400">
                <p>
                  This implementation uses <span className="text-violet-300">DoublePIR</span>, a Private Information Retrieval protocol 
                  based on Learning With Errors (LWE) encryption. The database is encoded using a 
                  <span className="text-violet-300"> Binary Fuse Filter</span>, enabling keyword-based lookups with just 3 PIR queries.
                </p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2">
                  {health && (
                    <>
                      <div className="bg-slate-800/50 rounded-xl p-3">
                        <div className="text-xs text-slate-500 mb-1">Records</div>
                        <div className="text-white font-mono">{health.pir_num_records || 'N/A'}</div>
                      </div>
                      <div className="bg-slate-800/50 rounded-xl p-3">
                        <div className="text-xs text-slate-500 mb-1">Hash Ranges</div>
                        <div className="text-white font-mono">{formatNumber(health.ranges_loaded)}</div>
                      </div>
                    </>
                  )}
                  <div className="bg-slate-800/50 rounded-xl p-3">
                    <div className="text-xs text-slate-500 mb-1">Protocol</div>
                    <div className="text-white font-mono">DoublePIR</div>
                  </div>
                  <div className="bg-slate-800/50 rounded-xl p-3">
                    <div className="text-xs text-slate-500 mb-1">Queries</div>
                    <div className="text-white font-mono">3 per lookup</div>
                  </div>
                </div>
                <p className="text-xs pt-2">
                  Based on the{' '}
                  <a 
                    href="https://eprint.iacr.org/2022/081" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-violet-400 hover:text-violet-300 underline underline-offset-2"
                  >
                    SimplePIR/DoublePIR paper
                  </a>
                  {' '}by Henzinger et al.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer with attribution */}
        <footer className="mt-20 pb-8 text-center">
          <div className="flex flex-col items-center gap-4">
            <div className="flex items-center gap-2 text-sm text-slate-500">
              <span>Breach data from</span>
              <a 
                href="https://haveibeenpwned.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/50 hover:bg-slate-800 border border-slate-700/50 rounded-full text-slate-300 hover:text-white transition-colors"
              >
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                </svg>
                Have I Been Pwned
              </a>
            </div>
            <p className="text-xs text-slate-600 max-w-md">
              This service uses Private Information Retrieval to protect your privacy.
              Your password is hashed locally and never transmitted or stored.
            </p>
          </div>
        </footer>
      </div>
    </main>
  );
}

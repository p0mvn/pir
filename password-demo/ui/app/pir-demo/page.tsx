'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import Link from 'next/link';

// ============================================================================
// Types matching server responses
// ============================================================================

interface BinaryFuseParams {
  seed: number;
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

// Static methods on PirClient class
interface PirClientClass {
  new(setup_json: string, lwe_params_json: string, filter_params_json: string): PirClientWasm;
  hash_password(password: string): string;
}

// ============================================================================
// Demo Component
// ============================================================================

type DemoState = 'idle' | 'loading_wasm' | 'loading_setup' | 'ready' | 'querying' | 'result' | 'error';

interface QueryStep {
  position: number;
  status: 'pending' | 'querying' | 'done';
  decoded?: number[];
  state?: string;
}

export default function PirDemo() {
  const [state, setState] = useState<DemoState>('idle');
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  
  // WASM client ref
  const pirClientRef = useRef<PirClientWasm | null>(null);
  
  // PIR setup data
  const [setup, setSetup] = useState<PirSetupResponse | null>(null);
  
  // Query state
  const [keyword, setKeyword] = useState('6117');
  const [querySteps, setQuerySteps] = useState<QueryStep[]>([]);
  const [finalResult, setFinalResult] = useState<number[] | null>(null);

  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

  // Initialize WASM and load setup
  useEffect(() => {
    const initialize = async () => {
      try {
        setState('loading_wasm');
        
        // Import WASM module
        const wasmModule = await import('../../lib/pir_wasm.js');
        
        // Initialize with the WASM file from public directory
        await wasmModule.default('/wasm/pir_wasm_bg.wasm');
        
        console.log('WASM loaded:', wasmModule.version());
        
        // Check health
        const healthResponse = await fetch(`${apiUrl}/health`);
        if (healthResponse.ok) {
          const healthData = await healthResponse.json();
          setHealth(healthData);
          
          if (!healthData.pir_enabled) {
            throw new Error('PIR is not enabled on the server. Set PIR_DEMO_ENABLED=1');
          }
        }
        
        // Load PIR setup
        setState('loading_setup');
        const setupResponse = await fetch(`${apiUrl}/pir/setup`);
        if (!setupResponse.ok) {
          throw new Error(`Failed to load setup: ${setupResponse.statusText}`);
        }
        
        const setupData: PirSetupResponse = await setupResponse.json();
        setSetup(setupData);
        
        // Create PIR client
        const client = new wasmModule.PirClient(
          JSON.stringify(setupData.pir_setup),
          JSON.stringify(setupData.lwe_params),
          JSON.stringify(setupData.filter_params)
        );
        pirClientRef.current = client;
        
        console.log('PIR client created:', {
          numRecords: client.num_records(),
          recordSize: client.record_size(),
        });
        
        setState('ready');
      } catch (err) {
        console.error('Initialization error:', err);
        setError(err instanceof Error ? err.message : 'Failed to initialize');
        setState('error');
      }
    };
    
    initialize();
    
    // Cleanup
    return () => {
      if (pirClientRef.current) {
        pirClientRef.current.free();
        pirClientRef.current = null;
      }
    };
  }, [apiUrl]);

  // Run full keyword lookup using WASM
  const runKeywordLookup = useCallback(async () => {
    const client = pirClientRef.current;
    if (!client || !setup) return;
    
    setState('querying');
    setError(null);
    setFinalResult(null);
    
    try {
      // Hash password and get positions using WASM
      const positionsArray = client.get_password_indices(keyword);
      const positions = Array.from(positionsArray);
      
      console.log('Password positions:', positions);
      
      // Initialize query steps
      const steps: QueryStep[] = positions.map(pos => ({
        position: pos,
        status: 'pending',
      }));
      setQuerySteps(steps);
      
      // Execute queries sequentially with visual feedback
      const recoveredRecords: Uint8Array[] = [];
      
      for (let i = 0; i < 3; i++) {
        // Update status to querying
        setQuerySteps(prev => prev.map((s, idx) => 
          idx === i ? { ...s, status: 'querying' } : s
        ));
        
        // Generate encrypted query using WASM
        const queryJson = client.query(positions[i]);
        const { state: queryState, query } = JSON.parse(queryJson);
        
        console.log(`Query ${i} for position ${positions[i]}:`, { 
          queryColLen: query.query_col.length,
          queryRowLen: query.query_row.length 
        });
        
        // Send to server
        const response = await fetch(`${apiUrl}/pir/query`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query }),
        });
        
        if (!response.ok) {
          throw new Error(`Query ${i} failed: ${response.statusText}`);
        }
        
        const { answer }: { answer: DoublePirAnswer } = await response.json();
        
        // Recover record using WASM
        const recovered = client.recover(JSON.stringify(queryState), JSON.stringify(answer));
        recoveredRecords.push(recovered);
        
        const decoded = Array.from(recovered);
        console.log(`Recovered ${i}:`, decoded);
        
        // Update with result
        setQuerySteps(prev => prev.map((s, idx) => 
          idx === i ? { ...s, status: 'done', decoded, state: JSON.stringify(queryState) } : s
        ));
        
        // Small delay for visual effect
        await new Promise(resolve => setTimeout(resolve, 300));
      }
      
      // XOR decode final result using WASM
      const result = client.decode_keyword(
        recoveredRecords[0],
        recoveredRecords[1],
        recoveredRecords[2]
      );
      
      const finalBytes = Array.from(result);
      console.log('Final XOR result:', finalBytes);
      
      setFinalResult(finalBytes);
      setState('result');
      
    } catch (err) {
      console.error('Query error:', err);
      setError(err instanceof Error ? err.message : 'Query failed');
      setState('error');
    }
  }, [setup, keyword, apiUrl]);

  const reset = () => {
    setState('ready');
    setQuerySteps([]);
    setFinalResult(null);
    setError(null);
  };

  // Format bytes as value
  const formatResult = (bytes: number[]): string => {
    if (bytes.length === 4) {
      // Interpret as little-endian u32
      const value = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
      return value.toLocaleString();
    }
    return bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
  };

  return (
    <main className="min-h-screen grid-pattern radial-overlay relative overflow-hidden">
      {/* Decorative elements */}
      <div className="absolute top-0 right-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-0 left-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl" />
      
      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-4 py-12">
        {/* Header */}
        <div className="text-center mb-12 animate-fade-in">
          <Link href="/" className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-6 transition-colors">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-5 h-5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
            </svg>
            Back to Password Checker
          </Link>
          
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-purple-500/10 border border-purple-500/20 mb-6">
            <span className={`w-2 h-2 rounded-full ${
              state === 'ready' || state === 'result' ? 'bg-green-500' : 
              state === 'error' ? 'bg-red-500' : 
              'bg-yellow-500 animate-pulse'
            }`} />
            <span className="text-sm text-gray-400 font-mono">
              {state === 'loading_wasm' && 'Loading WASM...'}
              {state === 'loading_setup' && 'Loading PIR Setup...'}
              {(state === 'ready' || state === 'result') && health?.pir_enabled && `PIR Ready • ${health.pir_num_records} records`}
              {state === 'querying' && 'Executing PIR Queries...'}
              {state === 'error' && 'Error'}
              {state === 'idle' && 'Initializing...'}
            </span>
          </div>
          
          <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-4">
            <span className="bg-gradient-to-r from-purple-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">
              DoublePIR
            </span>
            <br />
            <span className="text-white">Demo</span>
          </h1>
          
          <p className="text-gray-400 max-w-lg mx-auto text-lg">
            Private Information Retrieval with Binary Fuse Filters.
            <span className="text-purple-400"> Server learns nothing</span> about which record you&apos;re querying.
          </p>
        </div>

        {/* Main Card */}
        <div className="w-full max-w-2xl">
          <div className="bg-gray-900/60 backdrop-blur-xl rounded-2xl border border-gray-800/50 p-8 shadow-2xl">
            {/* Keyword Input */}
            <div className="mb-6">
              <label htmlFor="keyword" className="block text-sm font-medium text-gray-400 mb-2">
                Password to check (will be SHA-1 hashed before lookup)
              </label>
              <input
                id="keyword"
                type="text"
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                placeholder="e.g., 6117 or password123"
                className="w-full px-5 py-4 bg-gray-800/50 border border-gray-700/50 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-purple-500/50 input-glow transition-all font-mono text-lg"
                disabled={state === 'querying'}
              />
            </div>

            {/* Setup Info */}
            {setup && (
              <div className="mb-6 p-4 bg-gray-800/30 rounded-xl border border-gray-700/30">
                <h3 className="text-sm font-semibold text-gray-300 mb-2">PIR Setup</h3>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500">Filter size:</span>
                    <span className="text-gray-300 ml-2">{setup.filter_params.filter_size} slots</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Value size:</span>
                    <span className="text-gray-300 ml-2">{setup.filter_params.value_size} bytes</span>
                  </div>
                  <div>
                    <span className="text-gray-500">LWE dim (n):</span>
                    <span className="text-gray-300 ml-2">{setup.lwe_params.n}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Grid:</span>
                    <span className="text-gray-300 ml-2">{setup.pir_setup.num_rows}×{setup.pir_setup.num_cols}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Query Button */}
            <button
              onClick={state === 'result' ? reset : runKeywordLookup}
              disabled={state === 'querying' || state === 'loading_setup' || state === 'loading_wasm' || !setup}
              className="w-full py-4 px-6 bg-gradient-to-r from-purple-600 to-pink-500 hover:from-purple-500 hover:to-pink-400 disabled:from-gray-700 disabled:to-gray-600 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all duration-300 shadow-lg shadow-purple-500/20 hover:shadow-purple-500/40 disabled:shadow-none flex items-center justify-center gap-3"
            >
              {(state === 'loading_wasm' || state === 'loading_setup') && (
                <>
                  <svg className="w-5 h-5 spinner" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  {state === 'loading_wasm' ? 'Loading WASM...' : 'Loading Setup...'}
                </>
              )}
              {state === 'querying' && (
                <>
                  <svg className="w-5 h-5 spinner" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Executing PIR Queries...
                </>
              )}
              {state === 'result' && (
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
                  </svg>
                  Try Another Keyword
                </>
              )}
              {(state === 'ready' || state === 'idle' || state === 'error') && setup && (
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                  </svg>
                  Run Private Lookup
                </>
              )}
              {!setup && state !== 'loading_wasm' && state !== 'loading_setup' && 'Loading...'}
            </button>

            {/* Query Steps */}
            {querySteps.length > 0 && (
              <div className="mt-6 space-y-3">
                <h3 className="text-sm font-semibold text-gray-300 mb-3">
                  3 PIR Queries (Binary Fuse Filter positions)
                </h3>
                {querySteps.map((step, idx) => (
                  <div
                    key={idx}
                    className={`p-4 rounded-xl border transition-all ${
                      step.status === 'done'
                        ? 'bg-green-500/10 border-green-500/30'
                        : step.status === 'querying'
                        ? 'bg-purple-500/10 border-purple-500/30'
                        : 'bg-gray-800/30 border-gray-700/30'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                          step.status === 'done'
                            ? 'bg-green-500/20 text-green-400'
                            : step.status === 'querying'
                            ? 'bg-purple-500/20 text-purple-400'
                            : 'bg-gray-700/50 text-gray-500'
                        }`}>
                          {step.status === 'done' ? '✓' : idx + 1}
                        </span>
                        <div>
                          <span className="text-gray-300">h{idx}(key)</span>
                          <span className="text-gray-500 ml-2">→ position {step.position}</span>
                        </div>
                      </div>
                      {step.status === 'querying' && (
                        <svg className="w-5 h-5 spinner text-purple-400" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                      )}
                      {step.decoded && (
                        <span className="font-mono text-sm text-gray-400">
                          [{step.decoded.slice(0, 4).map(b => b.toString(16).padStart(2, '0')).join(' ')}]
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Final Result */}
            {finalResult && (
              <div className="mt-6 p-6 rounded-xl bg-gradient-to-br from-green-500/10 to-purple-500/10 border border-green-500/30">
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-500/20 mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-8 h-8 text-green-400">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
                    </svg>
                  </div>
                  <h3 className="text-xl font-bold text-green-400 mb-2">Value Recovered!</h3>
                  <p className="text-gray-300 mb-4">
                    XOR of 3 PIR responses = <span className="font-mono text-purple-300 text-2xl">{formatResult(finalResult)}</span>
                  </p>
                  <p className="text-sm text-gray-500">
                    The server processed 3 encrypted queries but learned nothing about which keyword you looked up.
                  </p>
                </div>
              </div>
            )}

            {/* Error Display */}
            {state === 'error' && error && (
              <div className="mt-6 p-6 rounded-xl bg-red-500/10 border border-red-500/30">
                <div className="flex items-start gap-3">
                  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                  </svg>
                  <div>
                    <h3 className="font-semibold text-red-400 mb-1">Error</h3>
                    <p className="text-gray-400 text-sm">{error}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* How it works section */}
        <div className="mt-16 w-full max-w-4xl">
          <h2 className="text-xl font-semibold text-center text-gray-300 mb-8">How DoublePIR Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-gray-900/40 backdrop-blur-sm rounded-xl p-6 border border-gray-800/50">
              <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center mb-4">
                <span className="text-purple-400 font-bold">1</span>
              </div>
              <h3 className="font-semibold text-white mb-2">Hash Key</h3>
              <p className="text-sm text-gray-400">
                Client hashes keyword to get 3 positions in the Binary Fuse Filter.
              </p>
            </div>
            <div className="bg-gray-900/40 backdrop-blur-sm rounded-xl p-6 border border-gray-800/50">
              <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center mb-4">
                <span className="text-purple-400 font-bold">2</span>
              </div>
              <h3 className="font-semibold text-white mb-2">Encrypt Queries</h3>
              <p className="text-sm text-gray-400">
                Client encrypts each position using LWE. Server can&apos;t see which position.
              </p>
            </div>
            <div className="bg-gray-900/40 backdrop-blur-sm rounded-xl p-6 border border-gray-800/50">
              <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center mb-4">
                <span className="text-purple-400 font-bold">3</span>
              </div>
              <h3 className="font-semibold text-white mb-2">Server Computes</h3>
              <p className="text-sm text-gray-400">
                Server processes encrypted queries, returning encrypted answers.
              </p>
            </div>
            <div className="bg-gray-900/40 backdrop-blur-sm rounded-xl p-6 border border-gray-800/50">
              <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center mb-4">
                <span className="text-purple-400 font-bold">4</span>
              </div>
              <h3 className="font-semibold text-white mb-2">XOR Decode</h3>
              <p className="text-sm text-gray-400">
                Client decrypts responses and XORs them to recover the value.
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-16 text-center text-sm text-gray-500">
          <p className="mb-2">
            DoublePIR implementation based on{' '}
            <a 
              href="https://eprint.iacr.org/2022/081" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-purple-400 hover:text-purple-300 transition-colors attribution-link"
            >
              SimplePIR/DoublePIR paper
            </a>
          </p>
          <p className="text-gray-600 text-xs">
            Binary Fuse Filter enables keyword PIR with just 3 queries.
          </p>
        </footer>
      </div>

      <style jsx>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fade-in {
          animation: fadeIn 0.5s ease-out forwards;
        }
      `}</style>
    </main>
  );
}

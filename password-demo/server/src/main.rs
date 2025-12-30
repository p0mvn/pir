//! HIBP Password Checker HTTP Server with DoublePIR Support
//!
//! A simple HTTP server that checks if password hashes exist in the HIBP database.
//! Also provides DoublePIR-based private information retrieval for demo purposes.
//!
//! ## Endpoints
//!
//! ### Password Checking
//! - `GET /health` - Health check
//! - `POST /check` - Check if a SHA-1 hash is pwned
//!
//! ### DoublePIR Demo
//! - `GET /pir/setup` - Get PIR setup data (filter params, LWE params, hints)
//! - `POST /pir/query` - Answer a PIR query
//!
//! ## Usage
//!
//! ```bash
//! # Start server loading data from local files (default)
//! HIBP_DATA_DIR=./data/ranges cargo run --release
//!
//! # Start server and download data on startup (no local files needed)
//! HIBP_DOWNLOAD_ON_START=tiny cargo run --release   # 256 ranges, ~20MB
//! HIBP_DOWNLOAD_ON_START=sample cargo run --release # 65k ranges, ~2.5GB
//! HIBP_DOWNLOAD_ON_START=full cargo run --release   # 1M ranges, ~38GB
//!
//! # Check a password hash
//! curl -X POST http://localhost:3000/check \
//!   -H "Content-Type: application/json" \
//!   -d '{"hash": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"}'
//! ```

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use hibp::{CompactChecker, CompactDownloader, DownloadSize, PasswordChecker};
use pir::binary_fuse::{BinaryFuseFilter, BinaryFuseParams};
use pir::double::{DoublePirAnswer, DoublePirQuery, DoublePirServer, DoublePirSetup};
use pir::matrix_database::DoublePirDatabase;
use pir::params::LweParams;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info, warn};

// ============================================================================
// Memory Observability
// ============================================================================

/// Log memory usage estimate for a data structure
fn log_memory_gb(label: &str, bytes: usize) {
    let gb = bytes as f64 / 1024.0 / 1024.0 / 1024.0;
    info!("[MEM] {}: {:.2} GB ({} bytes)", label, gb, bytes);
}

/// Estimate memory for a Vec
fn vec_memory<T>(v: &[T]) -> usize {
    std::mem::size_of::<T>() * v.len()
}

/// Log a memory checkpoint with description
fn log_checkpoint(phase: &str) {
    info!("[MEM] ========== {} ==========", phase);
}

// ============================================================================
// Application State
// ============================================================================

/// Wrapper enum to support both checker types
enum Checker {
    /// Standard checker (file-based or old in-memory format)
    Standard(PasswordChecker),
    /// Compact checker (memory-efficient binary format)
    Compact(CompactChecker),
}

impl Checker {
    fn check_hash(&self, hash: &str) -> Result<Option<u32>, hibp::Error> {
        match self {
            Checker::Standard(c) => c.check_hash(hash),
            Checker::Compact(c) => c.check_hash(hash),
        }
    }

    fn stats(&self) -> hibp::CheckerStats {
        match self {
            Checker::Standard(c) => c.stats(),
            Checker::Compact(c) => c.stats(),
        }
    }
}

/// Application state shared across all handlers
struct AppState {
    /// Checker for direct hash lookups (None when PIR-only mode is active)
    checker: Option<Checker>,
    /// DoublePIR server (initialized lazily or on startup)
    pir_server: Option<DoublePirServer>,
    /// Binary Fuse Filter parameters for client
    filter_params: Option<BinaryFuseParams>,
    /// LWE parameters
    lwe_params: Option<LweParams>,
    /// Stats captured before dropping checker (for health endpoint)
    cached_stats: Option<hibp::CheckerStats>,
}

// ============================================================================
// Password Checking Types
// ============================================================================

/// Request body for /check endpoint
#[derive(Debug, Deserialize)]
struct CheckRequest {
    /// SHA-1 hash of the password (40 hex characters, uppercase)
    hash: String,
}

/// Response body for /check endpoint
#[derive(Debug, Serialize)]
struct CheckResponse {
    /// Whether the password hash was found in the database
    pwned: bool,
    /// Number of times the password appeared in breaches (0 if not found)
    count: u32,
}

/// Response body for /health endpoint
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    ranges_loaded: usize,
    total_hashes: usize,
    pir_enabled: bool,
    pir_num_records: Option<usize>,
}

// ============================================================================
// DoublePIR Types (JSON-serializable for HTTP transport)
// ============================================================================

/// Binary Fuse Filter parameters (seed as string to avoid JS precision loss)
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsBinaryFuseParams {
    seed: String, // Serialized as string to preserve u64 precision
    segment_size: usize,
    filter_size: usize,
    value_size: usize,
    segment_length_mask: u32,
}

impl From<BinaryFuseParams> for JsBinaryFuseParams {
    fn from(p: BinaryFuseParams) -> Self {
        Self {
            seed: p.seed.to_string(), // Convert to string for JS compatibility
            segment_size: p.segment_size,
            filter_size: p.filter_size,
            value_size: p.value_size,
            segment_length_mask: p.segment_length_mask,
        }
    }
}

/// LWE parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsLweParams {
    n: usize,
    p: u32,
    noise_stddev: f64,
}

impl From<LweParams> for JsLweParams {
    fn from(p: LweParams) -> Self {
        Self {
            n: p.n,
            p: p.p,
            noise_stddev: p.noise_stddev,
        }
    }
}

/// DoublePIR setup data
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsDoublePirSetup {
    seed_col: Vec<u8>,
    seed_row: Vec<u8>,
    hint_col_data: Vec<u32>,
    hint_col_rows: usize,
    hint_col_cols: usize,
    hint_row_data: Vec<u32>,
    hint_row_rows: usize,
    hint_row_cols: usize,
    hint_cross: Vec<u32>,
    num_cols: usize,
    num_rows: usize,
    record_size: usize,
    num_records: usize,
    lwe_dim: usize,
}

impl From<DoublePirSetup> for JsDoublePirSetup {
    fn from(s: DoublePirSetup) -> Self {
        Self {
            seed_col: s.seed_col.to_vec(),
            seed_row: s.seed_row.to_vec(),
            hint_col_data: s.hint_col.data,
            hint_col_rows: s.hint_col.rows,
            hint_col_cols: s.hint_col.cols,
            hint_row_data: s.hint_row.data,
            hint_row_rows: s.hint_row.rows,
            hint_row_cols: s.hint_row.cols,
            hint_cross: s.hint_cross,
            num_cols: s.num_cols,
            num_rows: s.num_rows,
            record_size: s.record_size,
            num_records: s.num_records,
            lwe_dim: s.lwe_dim,
        }
    }
}

/// DoublePIR query (from client)
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsDoublePirQuery {
    query_col: Vec<u32>,
    query_row: Vec<u32>,
}

impl From<JsDoublePirQuery> for DoublePirQuery {
    fn from(q: JsDoublePirQuery) -> Self {
        Self {
            query_col: q.query_col,
            query_row: q.query_row,
        }
    }
}

/// DoublePIR answer (to client)
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsDoublePirAnswer {
    data: Vec<u32>,
}

impl From<DoublePirAnswer> for JsDoublePirAnswer {
    fn from(a: DoublePirAnswer) -> Self {
        Self { data: a.data }
    }
}

/// PIR setup response (combined setup data)
#[derive(Debug, Serialize)]
struct PirSetupResponse {
    filter_params: JsBinaryFuseParams,
    lwe_params: JsLweParams,
    pir_setup: JsDoublePirSetup,
}

/// PIR query request
#[derive(Debug, Deserialize)]
struct PirQueryRequest {
    query: JsDoublePirQuery,
}

/// PIR query response
#[derive(Debug, Serialize)]
struct PirQueryResponse {
    answer: JsDoublePirAnswer,
}

// ============================================================================
// Handlers
// ============================================================================

/// Health check endpoint
async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let (ranges_loaded, total_hashes) = if let Some(ref checker) = state.checker {
        let stats = checker.stats();
        (stats.ranges_loaded, stats.total_hashes)
    } else if let Some(ref stats) = state.cached_stats {
        (stats.ranges_loaded, stats.total_hashes)
    } else {
        (0, 0)
    };
    
    Json(HealthResponse {
        status: "ok",
        ranges_loaded,
        total_hashes,
        pir_enabled: state.pir_server.is_some(),
        pir_num_records: state.pir_server.as_ref().map(|s| s.num_records()),
    })
}

/// Check if a password hash is pwned
/// Note: Disabled in PIR-only mode. Use /pir/query for private lookups.
async fn check(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    let checker = state.checker.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Direct hash checking disabled in PIR-only mode. Use /pir/query for private lookups.".to_string(),
    ))?;

    // Validate hash format
    if payload.hash.len() != 40 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid hash length: expected 40 characters, got {}",
                payload.hash.len()
            ),
        ));
    }

    // Check if all characters are valid hex
    if !payload.hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid hash: must contain only hexadecimal characters".to_string(),
        ));
    }

    // Look up the hash
    match checker.check_hash(&payload.hash) {
        Ok(Some(count)) => Ok(Json(CheckResponse { pwned: true, count })),
        Ok(None) => Ok(Json(CheckResponse {
            pwned: false,
            count: 0,
        })),
        Err(e) => {
            error!("Error checking hash: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Get PIR setup data
async fn pir_setup(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PirSetupResponse>, (StatusCode, String)> {
    let pir_server = state.pir_server.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "PIR not initialized".to_string(),
    ))?;

    let filter_params = state.filter_params.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Filter params not available".to_string(),
    ))?;

    let lwe_params = state.lwe_params.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "LWE params not available".to_string(),
    ))?;

    let setup = pir_server.setup();

    Ok(Json(PirSetupResponse {
        filter_params: filter_params.clone().into(),
        lwe_params: (*lwe_params).into(),
        pir_setup: setup.into(),
    }))
}

/// Answer a PIR query
async fn pir_query(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PirQueryRequest>,
) -> Result<Json<PirQueryResponse>, (StatusCode, String)> {
    let pir_server = state.pir_server.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "PIR not initialized".to_string(),
    ))?;

    let query: DoublePirQuery = payload.query.into();
    let answer = pir_server.answer(&query);

    Ok(Json(PirQueryResponse {
        answer: answer.into(),
    }))
}

// ============================================================================
// PIR Demo Database
// ============================================================================

/// Create a demo database for PIR using real HIBP data from PasswordChecker
fn create_pir_demo_database(
    checker: &PasswordChecker,
) -> (BinaryFuseParams, DoublePirDatabase, LweParams) {
    info!("Creating PIR demo database from PasswordChecker...");

    // Get real HIBP data from the loaded cache
    // We use the full SHA-1 hash as the key (prefix + suffix)
    let mut database: Vec<(String, Vec<u8>)> = Vec::new();

    if let Some(cache) = checker.get_cache() {
        // Collect a small, deterministic subset of records for the demo
        let mut all_entries: Vec<(String, u32)> = Vec::new();
        for (prefix, range_data) in cache.iter() {
            for (suffix, count) in range_data.iter() {
                let full_hash = format!("{}{}", prefix, suffix);
                all_entries.push((full_hash, *count));
            }
        }

        // Sort by count descending to get most-breached passwords
        all_entries.sort_by(|a, b| b.1.cmp(&a.1));

        // Take top 200 entries
        let selected: Vec<_> = all_entries.into_iter().take(200).collect();

        for (hash, count) in selected {
            let value = count.to_le_bytes().to_vec();
            database.push((hash, value));
        }

        info!("Loaded {} real HIBP entries for PIR demo", database.len());
    }

    if database.is_empty() {
        // Fallback to synthetic data if no HIBP data available
        warn!("No HIBP data found, using synthetic demo data");
        database = (0..200)
            .map(|i| {
                let key = format!("password_{:04}", i);
                let count = ((i + 1) * 100) as u32;
                let value = count.to_le_bytes().to_vec();
                (key, value)
            })
            .collect();
    }

    build_pir_from_database(database)
}

/// Create PIR database by consuming CompactChecker data
/// 
/// This takes ownership of the checker and frees its ~48 GB of data
/// after converting to PIR format. Returns cached stats for health endpoint.
/// 
/// Memory optimization: Uses [u8; 20] keys directly instead of String,
/// saving ~61 GB for the full dataset (92 bytes/entry → 24 bytes/entry).
fn create_pir_demo_database_compact(
    checker: CompactChecker,
) -> (BinaryFuseParams, DoublePirDatabase, LweParams, hibp::CheckerStats) {
    log_checkpoint("START: create_pir_demo_database_compact");

    // Capture stats before consuming the data
    let stats = checker.stats();
    let total_entries = stats.total_hashes;
    
    info!("Building PIR database with {} entries...", total_entries);
    log_memory_gb("Expected database size", total_entries * 24); // 24 bytes per entry

    // Consume the checker and get ownership of entries
    log_checkpoint("Consuming CompactChecker");
    let mut entries = checker.into_data().into_entries();
    log_memory_gb("entries Vec allocated", vec_memory(&entries));
    
    // CRITICAL MEMORY OPTIMIZATION:
    // Instead of collecting into a new Vec (which doubles memory to ~96 GB),
    // we convert in-place. HashEntry and ([u8;20], [u8;4]) are both 24 bytes.
    // This keeps peak memory at ~48 GB instead of ~96 GB.
    log_checkpoint("In-place conversion starting");
    
    // Convert count to little-endian bytes in-place
    for entry in entries.iter_mut() {
        entry.count = u32::from_ne_bytes(entry.count.to_le_bytes());
    }
    
    // Transmute Vec<HashEntry> to Vec<([u8; 20], [u8; 4])>
    let database: Vec<([u8; 20], [u8; 4])> = unsafe {
        let mut entries = std::mem::ManuallyDrop::new(entries);
        Vec::from_raw_parts(
            entries.as_mut_ptr() as *mut ([u8; 20], [u8; 4]),
            entries.len(),
            entries.capacity(),
        )
    };
    
    log_checkpoint("In-place conversion complete");
    log_memory_gb("database Vec", vec_memory(&database));

    let (params, db, lwe) = build_pir_from_database_fixed(database);
    
    log_checkpoint("END: create_pir_demo_database_compact");
    (params, db, lwe, stats)
}

/// Build PIR database from String key-value pairs (for PasswordChecker)
fn build_pir_from_database(
    database: Vec<(String, Vec<u8>)>,
) -> (BinaryFuseParams, DoublePirDatabase, LweParams) {
    build_pir_from_database_generic(database)
}

/// Build PIR database from fixed-size key-value pairs (most memory efficient)
/// Uses [u8; 20] keys AND [u8; 4] values - zero heap allocation per entry
fn build_pir_from_database_fixed(
    database: Vec<([u8; 20], [u8; 4])>,
) -> (BinaryFuseParams, DoublePirDatabase, LweParams) {
    log_checkpoint("START: build_pir_from_database_fixed");
    
    let n = database.len();
    log_memory_gb("Input database", vec_memory(&database));
    
    // Estimate filter memory requirements
    let segment_size = (n as f64 * 1.23 / 3.0).ceil() as usize;
    let filter_size = 3 * segment_size.next_power_of_two();
    let value_size = 4;
    
    info!("Filter construction will allocate:");
    log_memory_gb("  positions (12 bytes/entry)", n * 12); // Optimized: no value refs stored
    log_memory_gb("  slot_key_pairs (8 bytes * 3n)", n * 3 * 8);
    log_memory_gb("  slot_start (8 bytes * filter_size)", filter_size * 8); // u64 for >4B indices
    log_memory_gb("  degree (4 bytes * filter_size)", filter_size * 4);
    log_memory_gb("  stack (8 bytes * n)", n * 8);
    log_memory_gb("  processed (1 byte * n)", n);
    log_memory_gb("  final data (value_size * filter_size)", filter_size * value_size);
    
    // Peak = database + positions + slot_key_pairs + slot_start + degree + stack + processed + queue(~degree)
    let estimated_peak = (n * 24) + (n * 12) + (n * 3 * 8) + (filter_size * 8) + (filter_size * 4) + (n * 8) + n + (filter_size * 4);
    log_memory_gb("  ESTIMATED PEAK (all concurrent)", estimated_peak);

    log_checkpoint("Starting Binary Fuse Filter construction");
    let filter = BinaryFuseFilter::build_from_fixed_unchecked(&database, 0xDEADBEEF_CAFEBABE)
        .expect("Failed to build Binary Fuse Filter");
    log_checkpoint("Binary Fuse Filter construction complete");

    // Drop input database
    log_checkpoint("Dropping input database");
    drop(database);
    info!("Freed input database memory");

    info!(
        "Binary Fuse Filter: {} entries -> {} slots (expansion: {:.2}x)",
        filter.num_entries(),
        filter.filter_size(),
        filter.expansion_factor()
    );
    log_memory_gb("Filter data size", filter.filter_size() * value_size);

    log_checkpoint("Creating DoublePirDatabase");
    let filter_params = filter.params();
    let record_refs = filter.as_records();
    let db = DoublePirDatabase::new(&record_refs, value_size);
    
    log_checkpoint("Dropping Binary Fuse Filter");
    drop(filter);
    info!("Freed Binary Fuse Filter data");

    let lwe_params = LweParams {
        n: 64,
        p: 256,
        noise_stddev: 0.0,
    };

    (filter_params, db, lwe_params)
}

/// Generic PIR database builder - works with any hashable key type
/// Memory is carefully managed - drops intermediates as soon as possible
fn build_pir_from_database_generic<K: std::hash::Hash + Eq + Clone>(
    database: Vec<(K, Vec<u8>)>,
) -> (BinaryFuseParams, DoublePirDatabase, LweParams) {
    info!("PIR database: {} entries", database.len());

    let value_size = 4;

    // Build Binary Fuse Filter with deterministic seed
    // Use unchecked version to skip duplicate detection (saves RAM)
    let filter = BinaryFuseFilter::build_with_seed_unchecked(&database, value_size, 0xDEADBEEF_CAFEBABE)
        .expect("Failed to build Binary Fuse Filter");

    // Drop input database - no longer needed
    drop(database);
    info!("Freed input database memory");

    info!(
        "Binary Fuse Filter: {} entries -> {} slots (expansion: {:.2}x)",
        filter.num_entries(),
        filter.filter_size(),
        filter.expansion_factor()
    );

    // Extract params before dropping filter
    let filter_params = filter.params();

    // Convert to PIR database
    let record_refs = filter.as_records();
    let db = DoublePirDatabase::new(&record_refs, value_size);
    
    // Drop filter - data copied into PIR matrix
    drop(filter);
    info!("Freed Binary Fuse Filter data");

    // LWE parameters (test-friendly, not production secure)
    let lwe_params = LweParams {
        n: 64,
        p: 256,
        noise_stddev: 0.0, // Zero noise for demo (correctness over security)
    };

    (filter_params, db, lwe_params)
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() {
    // Load .env file if present
    match dotenvy::dotenv() {
        Ok(path) => eprintln!("Loaded .env from {:?}", path),
        Err(_) => {} // .env file is optional
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .init();

    // Get configuration from environment
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    // Check if we should download data on startup
    let download_on_start = std::env::var("HIBP_DOWNLOAD_ON_START").ok();

    // Check if PIR demo is enabled
    let pir_enabled = std::env::var("PIR_DEMO_ENABLED")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(true); // Enabled by default

    info!("Starting HIBP server...");
    info!("Port: {}", port);
    info!(
        "PIR demo: {}",
        if pir_enabled { "enabled" } else { "disabled" }
    );

    let checker = if let Some(size_str) = download_on_start {
        // Download data directly to memory on startup
        let size = match DownloadSize::from_str(&size_str) {
            Some(s) => s,
            None => {
                error!(
                    "Invalid HIBP_DOWNLOAD_ON_START value: '{}'. Use 'tiny', 'sample', or 'full'",
                    size_str
                );
                std::process::exit(1);
            }
        };

        info!("==============================================");
        info!("HIBP_DOWNLOAD_ON_START={}", size_str);
        info!(
            "Downloading {} dataset from HaveIBeenPwned API...",
            size.description()
        );
        info!(
            "This will download {} ranges directly into memory",
            size.range_count()
        );
        info!("==============================================");

        let start = Instant::now();
        // Use CompactDownloader for memory-efficient binary format
        // Uses ~24 bytes per entry vs ~63 bytes with old format
        let downloader = CompactDownloader::new();

        match downloader.download_compact(size).await {
            Ok(data) => {
                let elapsed = start.elapsed();
                let total_hashes = data.len();
                let memory_gb = data.memory_usage() as f64 / 1024.0 / 1024.0 / 1024.0;

                info!("==============================================");
                info!("Download completed successfully!");
                info!("  Total hashes: {}", total_hashes);
                info!("  Memory usage: {:.2} GB", memory_gb);
                info!("  Time: {:.1}s", elapsed.as_secs_f64());
                info!("==============================================");

                Checker::Compact(CompactChecker::new(data))
            }
            Err(e) => {
                error!("Failed to download HIBP data: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Load from local files (default behavior)
        let data_dir =
            std::env::var("HIBP_DATA_DIR").unwrap_or_else(|_| "./data/ranges".to_string());
        let load_into_memory = std::env::var("HIBP_MEMORY_MODE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true);

        info!("Data source: local files");
        info!("Data directory: {}", data_dir);
        info!("Memory mode: {}", load_into_memory);

        // Load HIBP data from files
        info!("Loading HIBP data from {}...", data_dir);
        let password_checker = match PasswordChecker::from_directory(&data_dir) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to load HIBP data: {}", e);
                warn!("Hint: Set HIBP_DOWNLOAD_ON_START=tiny to download data on startup");
                std::process::exit(1);
            }
        };

        // Optionally load into memory for faster lookups
        let password_checker = if load_into_memory {
            info!("Loading data into memory (this may take a while for full dataset)...");
            match password_checker.load_into_memory() {
                Ok(c) => {
                    let stats = c.stats();
                    info!(
                        "Loaded {} ranges with {} total hashes",
                        stats.ranges_loaded, stats.total_hashes
                    );
                    c
                }
                Err(e) => {
                    error!("Failed to load data into memory: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            info!("Running in disk mode (slower lookups, less memory)");
            password_checker
        };
        
        Checker::Standard(password_checker)
    };

    // Initialize PIR if enabled
    // For Compact checker: consume the data to free ~48 GB after PIR is built
    // For Standard checker: keep the checker for /check endpoint  
    let (checker, pir_server, filter_params, lwe_params, cached_stats) = if pir_enabled {
        match checker {
            Checker::Standard(password_checker) => {
                let (fuse_params, db, lwe_params) = create_pir_demo_database(&password_checker);
                
                let mut rng = rand::rng();
                let server = DoublePirServer::new(db, &lwe_params, &mut rng);

                info!("PIR server initialized:");
                info!("  Records: {}", server.num_records());
                info!("  Record size: {} bytes", server.record_size());
                info!("  LWE dimension: {}", lwe_params.n);

                (Some(Checker::Standard(password_checker)), Some(server), Some(fuse_params), Some(lwe_params), None)
            }
            Checker::Compact(compact_checker) => {
                // CONSUME the checker to free ~48 GB RAM after PIR is built
                let (fuse_params, db, lwe_params, stats) = create_pir_demo_database_compact(compact_checker);
                
                let mut rng = rand::rng();
                let server = DoublePirServer::new(db, &lwe_params, &mut rng);

                info!("PIR server initialized (PIR-only mode):");
                info!("  Records: {}", server.num_records());
                info!("  Record size: {} bytes", server.record_size());
                info!("  LWE dimension: {}", lwe_params.n);
                info!("  /check disabled - use /pir/query for private lookups");

                (None, Some(server), Some(fuse_params), Some(lwe_params), Some(stats))
            }
        }
    } else {
        (Some(checker), None, None, None, None)
    };

    let state = Arc::new(AppState {
        checker,
        pir_server,
        filter_params,
        lwe_params,
        cached_stats,
    });

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/check", post(check))
        .route("/pir/setup", get(pir_setup))
        .route("/pir/query", post(pir_query))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

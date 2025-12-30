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
use hibp::{DownloadSize, InMemoryDownloader, PasswordChecker};
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
// Application State
// ============================================================================

/// Application state shared across all handlers
struct AppState {
    checker: PasswordChecker,
    /// DoublePIR server (initialized lazily or on startup)
    pir_server: Option<DoublePirServer>,
    /// Binary Fuse Filter parameters for client
    filter_params: Option<BinaryFuseParams>,
    /// LWE parameters
    lwe_params: Option<LweParams>,
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
    let stats = state.checker.stats();
    Json(HealthResponse {
        status: "ok",
        ranges_loaded: stats.ranges_loaded,
        total_hashes: stats.total_hashes,
        pir_enabled: state.pir_server.is_some(),
        pir_num_records: state.pir_server.as_ref().map(|s| s.num_records()),
    })
}

/// Check if a password hash is pwned
async fn check(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
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
    match state.checker.check_hash(&payload.hash) {
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

/// Debug endpoint to get A matrix data
#[derive(Debug, Serialize)]
struct PirDebugResponse {
    a_col_data: Vec<u32>,
    a_row_data: Vec<u32>,
    seed_col: Vec<u8>,
    seed_row: Vec<u8>,
}

async fn pir_debug(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PirDebugResponse>, (StatusCode, String)> {
    let pir_server = state.pir_server.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "PIR not initialized".to_string(),
    ))?;

    let setup = pir_server.setup();
    
    // Generate A matrices from the same seeds
    let a_col = pir::pir::LweMatrix::from_seed(&setup.seed_col, setup.num_cols, setup.lwe_dim);
    let a_row = pir::pir::LweMatrix::from_seed(&setup.seed_row, setup.num_rows, setup.lwe_dim);

    Ok(Json(PirDebugResponse {
        a_col_data: a_col.data.iter().take(16).cloned().collect(),
        a_row_data: a_row.data.iter().take(16).cloned().collect(),
        seed_col: setup.seed_col.to_vec(),
        seed_row: setup.seed_row.to_vec(),
    }))
}

/// Debug endpoint for end-to-end PIR test on server side
#[derive(Debug, Deserialize)]
struct PirTestRequest {
    record_idx: usize,
}

#[derive(Debug, Serialize)]
struct PirTestResponse {
    record_idx: usize,
    col_idx: usize,
    row_idx: usize,
    answer: Vec<u32>,
    server_recovered: Vec<u8>,
    query_col_len: usize,
    query_row_len: usize,
    secret_col_first4: Vec<u32>,
    secret_row_first4: Vec<u32>,
}

/// Debug endpoint to get keyword positions
#[derive(Debug, Deserialize)]
struct KeywordPositionsRequest {
    keyword: String,
}

#[derive(Debug, Serialize)]
struct KeywordPositionsResponse {
    keyword: String,
    positions: Vec<usize>,
    filter_seed: u64,
}

async fn pir_test(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PirTestRequest>,
) -> Result<Json<PirTestResponse>, (StatusCode, String)> {
    use pir::double::DoublePirClient;
    
    let pir_server = state.pir_server.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "PIR not initialized".to_string(),
    ))?;
    
    let lwe_params = state.lwe_params.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "LWE params not available".to_string(),
    ))?;
    
    let setup = pir_server.setup();
    let client = DoublePirClient::new(setup, *lwe_params);
    
    let mut rng = rand::rng();
    let (query_state, query) = client.query(payload.record_idx, &mut rng);
    
    let answer = pir_server.answer(&query);
    let recovered = client.recover(&query_state, &answer);
    
    Ok(Json(PirTestResponse {
        record_idx: payload.record_idx,
        col_idx: query_state.col_idx,
        row_idx: query_state.row_idx,
        answer: answer.data.clone(),
        server_recovered: recovered,
        query_col_len: query.query_col.len(),
        query_row_len: query.query_row.len(),
        secret_col_first4: query_state.secret_col.iter().take(4).cloned().collect(),
        secret_row_first4: query_state.secret_row.iter().take(4).cloned().collect(),
    }))
}

async fn pir_keyword_positions(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<KeywordPositionsRequest>,
) -> Result<Json<KeywordPositionsResponse>, (StatusCode, String)> {
    use pir::binary_fuse::KeywordQuery;
    
    let filter_params = state.filter_params.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Filter params not available".to_string(),
    ))?;
    
    let kw_query = KeywordQuery::new(filter_params, &payload.keyword);
    let positions = kw_query.record_indices();
    
    Ok(Json(KeywordPositionsResponse {
        keyword: payload.keyword,
        positions: positions.to_vec(),
        filter_seed: filter_params.seed,
    }))
}

// ============================================================================
// PIR Demo Database
// ============================================================================

/// Create a demo database for PIR using real HIBP data
fn create_pir_demo_database(checker: &PasswordChecker) -> (BinaryFuseFilter, DoublePirDatabase, LweParams) {
    info!("Creating PIR demo database from real HIBP data...");

    // Get real HIBP data from the loaded cache
    // We use the full SHA-1 hash as the key (prefix + suffix)
    let mut database: Vec<(String, Vec<u8>)> = Vec::new();
    
    if let Some(cache) = checker.get_cache() {
        // First pass: collect high-breach-count hashes as samples
        let mut all_entries: Vec<(String, u32)> = Vec::new();
        for (prefix, range_data) in cache.iter() {
            for (suffix, &count) in range_data.iter() {
                let full_hash = format!("{}{}", prefix, suffix);
                all_entries.push((full_hash, count));
            }
        }
        
        // Sort by count descending to get most-breached passwords
        all_entries.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Take top 200 entries
        let selected: Vec<_> = all_entries.into_iter().take(200).collect();
        
        // Log top 5 for testing
        info!("Top 5 hashes by breach count (use these for testing):");
        for (hash, count) in selected.iter().take(5) {
            info!("  {}: {} breaches", hash, count);
        }
        
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

    info!("PIR database: {} entries", database.len());

    let value_size = 4;

    // Build Binary Fuse Filter with deterministic seed for consistent positions across restarts
    let filter = BinaryFuseFilter::build_with_seed(&database, value_size, 0xDEADBEEF_CAFEBABE)
        .expect("Failed to build Binary Fuse Filter");

    info!(
        "Binary Fuse Filter: {} entries -> {} slots (expansion: {:.2}x)",
        filter.num_entries(),
        filter.filter_size(),
        filter.expansion_factor()
    );

    // Convert to PIR database
    let pir_records = filter.to_pir_records();
    let record_refs: Vec<&[u8]> = pir_records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, value_size);

    // LWE parameters (test-friendly, not production secure)
    let lwe_params = LweParams {
        n: 64,
        p: 256,
        noise_stddev: 0.0, // Zero noise for demo (correctness over security)
    };

    (filter, db, lwe_params)
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
    info!("PIR demo: {}", if pir_enabled { "enabled" } else { "disabled" });

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
        info!("Downloading {} dataset from HaveIBeenPwned API...", size.description());
        info!("This will download {} ranges directly into memory", size.range_count());
        info!("==============================================");

        let start = Instant::now();
        let downloader = InMemoryDownloader::new();

        match downloader.download_to_memory(size).await {
            Ok(cache) => {
                let elapsed = start.elapsed();
                let total_hashes: usize = cache.values().map(|m| m.len()).sum();

                info!("==============================================");
                info!("Download completed successfully!");
                info!("  Ranges: {}", cache.len());
                info!("  Total hashes: {}", total_hashes);
                info!("  Time: {:.1}s", elapsed.as_secs_f64());
                info!("==============================================");

                PasswordChecker::from_cache(cache)
            }
            Err(e) => {
                error!("Failed to download HIBP data: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Load from local files (default behavior)
        let data_dir = std::env::var("HIBP_DATA_DIR").unwrap_or_else(|_| "./data/ranges".to_string());
        let load_into_memory = std::env::var("HIBP_MEMORY_MODE")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(true);

        info!("Data source: local files");
        info!("Data directory: {}", data_dir);
        info!("Memory mode: {}", load_into_memory);

        // Load HIBP data from files
        info!("Loading HIBP data from {}...", data_dir);
        let checker = match PasswordChecker::from_directory(&data_dir) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to load HIBP data: {}", e);
                warn!("Hint: Set HIBP_DOWNLOAD_ON_START=tiny to download data on startup");
                std::process::exit(1);
            }
        };

        // Optionally load into memory for faster lookups
        if load_into_memory {
            info!("Loading data into memory (this may take a while for full dataset)...");
            match checker.load_into_memory() {
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
            checker
        }
    };

    // Initialize PIR if enabled
    let (pir_server, filter_params, lwe_params) = if pir_enabled {
        let (filter, db, params) = create_pir_demo_database(&checker);
        let mut rng = rand::rng();
        let server = DoublePirServer::new(db, &params, &mut rng);
        
        info!("PIR server initialized:");
        info!("  Records: {}", server.num_records());
        info!("  Record size: {} bytes", server.record_size());
        info!("  LWE dimension: {}", params.n);

        (Some(server), Some(filter.params()), Some(params))
    } else {
        (None, None, None)
    };

    let state = Arc::new(AppState {
        checker,
        pir_server,
        filter_params,
        lwe_params,
    });

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/check", post(check))
        .route("/pir/setup", get(pir_setup))
        .route("/pir/query", post(pir_query))
        .route("/pir/debug", get(pir_debug))
        .route("/pir/test", post(pir_test))
        .route("/pir/keyword_positions", post(pir_keyword_positions))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

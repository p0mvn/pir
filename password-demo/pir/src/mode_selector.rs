//! Unified PIR mode selection and construction.
//!
//! This module provides a clean API for choosing between SimplePIR and DoublePIR,
//! with utilities for:
//! - Building client/server pairs for either mode
//! - Estimating and comparing communication costs
//! - Runtime polymorphism when the mode isn't known at compile time
//!
//! # Example
//!
//! ```ignore
//! use pir::mode_selector::{PirBuilder, PirMode};
//!
//! // Estimate costs before choosing a mode
//! let costs = PirBuilder::estimate_costs(num_records, record_size, lwe_dim);
//! println!("SimplePIR: {} bytes/query", costs.simple.per_query_bytes());
//! println!("DoublePIR: {} bytes/query", costs.double.per_query_bytes());
//!
//! // Build a DoublePIR setup
//! let (server, setup) = PirBuilder::new(records)
//!     .with_params(params)
//!     .mode(PirMode::Double)
//!     .build_server(&mut rng);
//! ```

use rand::Rng;

use crate::{
    simple::PirClient as SimplePirClient,
    double::{DoublePirClient, DoublePirServer, DoublePirSetup},
    matrix_database::{DoublePirDatabase, MatrixDatabase},
    params::LweParams,
    pir::SetupMessage as SimplePirSetup,
    pir_trait::{CommunicationCost, PirCosts, PirMode},
    simple::PirServer as SimplePirServer,
};

// ============================================================================
// Cost Estimation
// ============================================================================

/// Estimated communication costs for both PIR modes.
///
/// Use this to compare modes before committing to one.
#[derive(Debug, Clone)]
pub struct ModeCosts {
    /// SimplePIR communication costs
    pub simple: PirCosts,
    /// DoublePIR communication costs
    pub double: PirCosts,
    /// Database parameters used for estimation
    pub params: CostParams,
}

/// Parameters used for cost estimation
#[derive(Debug, Clone, Copy)]
pub struct CostParams {
    pub num_records: usize,
    pub record_size: usize,
    pub lwe_dim: usize,
    pub sqrt_n: usize,
}

impl ModeCosts {
    /// Estimate costs for both PIR modes.
    ///
    /// # Arguments
    /// - `num_records`: Total number of records in the database
    /// - `record_size`: Size of each record in bytes
    /// - `lwe_dim`: LWE security parameter (n)
    pub fn estimate(num_records: usize, record_size: usize, lwe_dim: usize) -> Self {
        let sqrt_n = (num_records as f64).sqrt().ceil() as usize;

        let params = CostParams {
            num_records,
            record_size,
            lwe_dim,
            sqrt_n,
        };

        // SimplePIR costs:
        // - Setup: seed (32 bytes) + hint (√N × record_size × n × 4 bytes)
        // - Query: √N × 4 bytes
        // - Answer: √N × record_size × 4 bytes
        let simple_setup = 32 + sqrt_n * record_size * lwe_dim * 4;
        let simple_query = sqrt_n * 4;
        let simple_answer = sqrt_n * record_size * 4;

        // DoublePIR costs:
        // - Setup: 2 seeds (64 bytes) + hint_col + hint_row + hint_cross
        //   - hint_col: (√N × record_size) × n × 4 bytes
        //   - hint_row: (√N × record_size) × n × 4 bytes
        //   - hint_cross: record_size × n × n × 4 bytes
        // - Query: 2 × √N × 4 bytes
        // - Answer: record_size × 4 bytes
        let double_hint_col = sqrt_n * record_size * lwe_dim * 4;
        let double_hint_row = sqrt_n * record_size * lwe_dim * 4;
        let double_hint_cross = record_size * lwe_dim * lwe_dim * 4;
        let double_setup = 64 + double_hint_col + double_hint_row + double_hint_cross;
        let double_query = 2 * sqrt_n * 4;
        let double_answer = record_size * 4;

        ModeCosts {
            simple: PirCosts {
                setup_bytes: simple_setup,
                query_bytes: simple_query,
                answer_bytes: simple_answer,
            },
            double: PirCosts {
                setup_bytes: double_setup,
                query_bytes: double_query,
                answer_bytes: double_answer,
            },
            params,
        }
    }

    /// Get costs for the specified mode
    pub fn for_mode(&self, mode: PirMode) -> &PirCosts {
        match mode {
            PirMode::Simple => &self.simple,
            PirMode::Double => &self.double,
        }
    }

    /// Recommend the best mode based on expected query count.
    ///
    /// For few queries, SimplePIR is better (smaller setup).
    /// For many queries, DoublePIR is better (smaller per-query cost).
    ///
    /// Returns `(recommended_mode, crossover_query_count)`.
    pub fn recommend(&self) -> (PirMode, usize) {
        // Total cost = setup + num_queries × per_query
        // Find crossover point where DoublePIR becomes better:
        // simple_setup + q × simple_per_query = double_setup + q × double_per_query
        // q × (simple_per_query - double_per_query) = double_setup - simple_setup
        // q = (double_setup - simple_setup) / (simple_per_query - double_per_query)

        let simple_per_query = self.simple.per_query_bytes() as i64;
        let double_per_query = self.double.per_query_bytes() as i64;
        let setup_diff = self.double.setup_bytes as i64 - self.simple.setup_bytes as i64;
        let per_query_diff = simple_per_query - double_per_query;

        if per_query_diff <= 0 {
            // SimplePIR is always better (shouldn't happen normally)
            (PirMode::Simple, usize::MAX)
        } else if setup_diff <= 0 {
            // DoublePIR is always better (shouldn't happen normally)
            (PirMode::Double, 0)
        } else {
            let crossover = (setup_diff / per_query_diff) as usize;
            // Default recommendation: if typical usage is many queries, use DoublePIR
            let recommended = if crossover < 100 {
                PirMode::Double
            } else {
                PirMode::Simple
            };
            (recommended, crossover)
        }
    }

    /// Format costs as a comparison table
    pub fn format_comparison(&self) -> String {
        let (recommended, crossover) = self.recommend();
        format!(
            "PIR Mode Comparison (N={}, record_size={}, n={})\n\
             ═══════════════════════════════════════════════════════════\n\
             │ Metric         │ SimplePIR      │ DoublePIR      │\n\
             ├────────────────┼────────────────┼────────────────┤\n\
             │ Setup          │ {:>12} B │ {:>12} B │\n\
             │ Query          │ {:>12} B │ {:>12} B │\n\
             │ Answer         │ {:>12} B │ {:>12} B │\n\
             │ Per-query      │ {:>12} B │ {:>12} B │\n\
             ═══════════════════════════════════════════════════════════\n\
             Crossover point: {} queries\n\
             Recommended: {} (for typical workloads)",
            self.params.num_records,
            self.params.record_size,
            self.params.lwe_dim,
            self.simple.setup_bytes,
            self.double.setup_bytes,
            self.simple.query_bytes,
            self.double.query_bytes,
            self.simple.answer_bytes,
            self.double.answer_bytes,
            self.simple.per_query_bytes(),
            self.double.per_query_bytes(),
            crossover,
            recommended.name()
        )
    }
}

// ============================================================================
// PirBuilder
// ============================================================================

/// Builder for creating PIR client/server pairs.
///
/// Supports both SimplePIR and DoublePIR modes with a unified API.
pub struct PirBuilder<'a> {
    records: Vec<&'a [u8]>,
    record_size: usize,
    params: Option<LweParams>,
    mode: PirMode,
}

impl<'a> PirBuilder<'a> {
    /// Create a new builder with the given records.
    ///
    /// All records must have the same size.
    pub fn new(records: &'a [&'a [u8]], record_size: usize) -> Self {
        Self {
            records: records.to_vec(),
            record_size,
            params: None,
            mode: PirMode::Simple, // Default to SimplePIR
        }
    }

    /// Set LWE parameters.
    ///
    /// If not set, defaults to `LweParams::default_128bit()`.
    pub fn with_params(mut self, params: LweParams) -> Self {
        self.params = Some(params);
        self
    }

    /// Set the PIR mode.
    pub fn mode(mut self, mode: PirMode) -> Self {
        self.mode = mode;
        self
    }

    /// Use SimplePIR mode.
    pub fn simple(self) -> Self {
        self.mode(PirMode::Simple)
    }

    /// Use DoublePIR mode.
    pub fn double(self) -> Self {
        self.mode(PirMode::Double)
    }

    /// Get estimated costs for current configuration.
    pub fn estimate_costs(&self) -> ModeCosts {
        let params = self.params.unwrap_or_else(LweParams::default_128bit);
        ModeCosts::estimate(self.records.len(), self.record_size, params.n)
    }

    /// Build a SimplePIR server.
    ///
    /// Returns the server and setup message.
    pub fn build_simple_server(self, rng: &mut impl Rng) -> (SimplePirServer, SimplePirSetup) {
        let params = self.params.unwrap_or_else(LweParams::default_128bit);
        let db = MatrixDatabase::new(&self.records, self.record_size);
        let server = SimplePirServer::new(db, &params, rng);
        let setup = server.setup_message();
        (server, setup)
    }

    /// Build a DoublePIR server.
    ///
    /// Returns the server and setup message.
    pub fn build_double_server(self, rng: &mut impl Rng) -> (DoublePirServer, DoublePirSetup) {
        let params = self.params.unwrap_or_else(LweParams::default_128bit);
        let db = DoublePirDatabase::new(&self.records, self.record_size);
        let server = DoublePirServer::new(db, &params, rng);
        let setup = server.setup();
        (server, setup)
    }

    /// Build a server for the configured mode.
    ///
    /// Returns a `UnifiedServer` that can be used polymorphically.
    pub fn build_server(self, rng: &mut impl Rng) -> UnifiedServer {
        let params = self.params.unwrap_or_else(LweParams::default_128bit);
        match self.mode {
            PirMode::Simple => {
                let db = MatrixDatabase::new(&self.records, self.record_size);
                let server = SimplePirServer::new(db, &params, rng);
                UnifiedServer::Simple(server)
            }
            PirMode::Double => {
                let db = DoublePirDatabase::new(&self.records, self.record_size);
                let server = DoublePirServer::new(db, &params, rng);
                UnifiedServer::Double(server)
            }
        }
    }
}

// ============================================================================
// Unified Server/Client (Runtime Polymorphism)
// ============================================================================

/// Unified server that can be either SimplePIR or DoublePIR.
///
/// Use this when the mode is determined at runtime.
pub enum UnifiedServer {
    Simple(SimplePirServer),
    Double(DoublePirServer),
}

impl UnifiedServer {
    /// Get the PIR mode
    pub fn mode(&self) -> PirMode {
        match self {
            UnifiedServer::Simple(_) => PirMode::Simple,
            UnifiedServer::Double(_) => PirMode::Double,
        }
    }

    /// Get setup data as a `UnifiedSetup`
    pub fn setup(&self) -> UnifiedSetup {
        match self {
            UnifiedServer::Simple(s) => UnifiedSetup::Simple(s.setup_message()),
            UnifiedServer::Double(s) => UnifiedSetup::Double(s.setup()),
        }
    }

    /// Answer a query
    pub fn answer(&self, query: &UnifiedQuery) -> UnifiedAnswer {
        match (self, query) {
            (UnifiedServer::Simple(s), UnifiedQuery::Simple(q)) => {
                UnifiedAnswer::Simple(s.answer(q))
            }
            (UnifiedServer::Double(s), UnifiedQuery::Double(q)) => {
                UnifiedAnswer::Double(s.answer(q))
            }
            _ => panic!("Query mode does not match server mode"),
        }
    }

    /// Number of records
    pub fn num_records(&self) -> usize {
        match self {
            UnifiedServer::Simple(s) => s.num_records(),
            UnifiedServer::Double(s) => s.num_records(),
        }
    }

    /// Record size
    pub fn record_size(&self) -> usize {
        match self {
            UnifiedServer::Simple(s) => s.record_size(),
            UnifiedServer::Double(s) => s.record_size(),
        }
    }
}

/// Unified setup data
pub enum UnifiedSetup {
    Simple(SimplePirSetup),
    Double(DoublePirSetup),
}

impl UnifiedSetup {
    pub fn mode(&self) -> PirMode {
        match self {
            UnifiedSetup::Simple(_) => PirMode::Simple,
            UnifiedSetup::Double(_) => PirMode::Double,
        }
    }
}

impl CommunicationCost for UnifiedSetup {
    fn size_bytes(&self) -> usize {
        match self {
            UnifiedSetup::Simple(s) => s.size_bytes(),
            UnifiedSetup::Double(s) => s.size_bytes(),
        }
    }
}

/// Unified client
pub enum UnifiedClient {
    Simple(SimplePirClient),
    Double(DoublePirClient),
}

impl UnifiedClient {
    /// Create a client from setup data
    pub fn from_setup(setup: UnifiedSetup, params: LweParams) -> Self {
        match setup {
            UnifiedSetup::Simple(s) => UnifiedClient::Simple(SimplePirClient::new(s, params)),
            UnifiedSetup::Double(s) => UnifiedClient::Double(DoublePirClient::new(s, params)),
        }
    }

    /// Get the PIR mode
    pub fn mode(&self) -> PirMode {
        match self {
            UnifiedClient::Simple(_) => PirMode::Simple,
            UnifiedClient::Double(_) => PirMode::Double,
        }
    }

    /// Generate a query for the given record index
    pub fn query(&self, record_idx: usize, rng: &mut impl Rng) -> (UnifiedQueryState, UnifiedQuery) {
        match self {
            UnifiedClient::Simple(c) => {
                let (state, query) = c.query(record_idx, rng);
                (UnifiedQueryState::Simple(state), UnifiedQuery::Simple(query))
            }
            UnifiedClient::Double(c) => {
                let (state, query) = c.query(record_idx, rng);
                (UnifiedQueryState::Double(state), UnifiedQuery::Double(query))
            }
        }
    }

    /// Recover the record from the answer
    pub fn recover(&self, state: &UnifiedQueryState, answer: &UnifiedAnswer) -> Vec<u8> {
        match (self, state, answer) {
            (UnifiedClient::Simple(c), UnifiedQueryState::Simple(s), UnifiedAnswer::Simple(a)) => {
                c.recover(s, a)
            }
            (UnifiedClient::Double(c), UnifiedQueryState::Double(s), UnifiedAnswer::Double(a)) => {
                c.recover(s, a)
            }
            _ => panic!("Query state and answer mode do not match client mode"),
        }
    }

    /// Number of records
    pub fn num_records(&self) -> usize {
        match self {
            UnifiedClient::Simple(c) => c.num_records(),
            UnifiedClient::Double(c) => c.num_records(),
        }
    }

    /// Record size
    pub fn record_size(&self) -> usize {
        match self {
            UnifiedClient::Simple(c) => c.record_size(),
            UnifiedClient::Double(c) => c.record_size(),
        }
    }
}

/// Unified query
pub enum UnifiedQuery {
    Simple(crate::pir::Query),
    Double(crate::double::DoublePirQuery),
}

impl UnifiedQuery {
    pub fn mode(&self) -> PirMode {
        match self {
            UnifiedQuery::Simple(_) => PirMode::Simple,
            UnifiedQuery::Double(_) => PirMode::Double,
        }
    }
}

impl CommunicationCost for UnifiedQuery {
    fn size_bytes(&self) -> usize {
        match self {
            UnifiedQuery::Simple(q) => q.size_bytes(),
            UnifiedQuery::Double(q) => q.size_bytes(),
        }
    }
}

/// Unified query state
pub enum UnifiedQueryState {
    Simple(crate::simple::QueryState),
    Double(crate::double::DoublePirQueryState),
}

/// Unified answer
pub enum UnifiedAnswer {
    Simple(crate::pir::Answer),
    Double(crate::double::DoublePirAnswer),
}

impl UnifiedAnswer {
    pub fn mode(&self) -> PirMode {
        match self {
            UnifiedAnswer::Simple(_) => PirMode::Simple,
            UnifiedAnswer::Double(_) => PirMode::Double,
        }
    }
}

impl CommunicationCost for UnifiedAnswer {
    fn size_bytes(&self) -> usize {
        match self {
            UnifiedAnswer::Simple(a) => a.size_bytes(),
            UnifiedAnswer::Double(a) => a.size_bytes(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_records(count: usize, size: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                (0..size)
                    .map(|j| ((i * size + j) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn test_cost_estimation() {
        let costs = ModeCosts::estimate(1000, 32, 2048);

        // SimplePIR should have smaller setup but larger answer
        assert!(costs.simple.setup_bytes < costs.double.setup_bytes);
        assert!(costs.simple.answer_bytes > costs.double.answer_bytes);

        // DoublePIR should have larger query (2×)
        assert!(costs.double.query_bytes > costs.simple.query_bytes);

        // Verify sqrt_n calculation
        assert_eq!(costs.params.sqrt_n, 32); // ceil(sqrt(1000)) = 32
    }

    #[test]
    fn test_cost_estimation_small() {
        let costs = ModeCosts::estimate(16, 4, 64);

        // For small databases, SimplePIR might be better overall
        println!("{}", costs.format_comparison());

        // Basic sanity checks
        assert!(costs.simple.setup_bytes > 0);
        assert!(costs.double.setup_bytes > 0);
    }

    #[test]
    fn test_recommend_mode() {
        // Large database, small records - DoublePIR should be recommended
        let costs_large = ModeCosts::estimate(10000, 8, 2048);
        let (rec, _crossover) = costs_large.recommend();
        println!(
            "Large DB: recommended={}, crossover={}",
            rec.name(),
            _crossover
        );

        // Very small database - SimplePIR might be recommended
        let costs_small = ModeCosts::estimate(4, 4, 64);
        let (rec_small, crossover_small) = costs_small.recommend();
        println!(
            "Small DB: recommended={}, crossover={}",
            rec_small.name(),
            crossover_small
        );
    }

    #[test]
    fn test_builder_simple_pir() {
        let records = create_test_records(16, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };

        let mut rng = rand::rng();
        let (server, setup) = PirBuilder::new(&record_refs, 4)
            .with_params(params)
            .simple()
            .build_simple_server(&mut rng);

        // Create client and test
        let client = SimplePirClient::new(setup, params);
        let target_idx = 7;
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(recovered, records[target_idx]);
    }

    #[test]
    fn test_builder_double_pir() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };

        let mut rng = rand::rng();
        let (server, setup) = PirBuilder::new(&record_refs, 2)
            .with_params(params)
            .double()
            .build_double_server(&mut rng);

        // Create client and test
        let client = DoublePirClient::new(setup, params);
        let target_idx = 4;
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(recovered, records[target_idx]);
    }

    #[test]
    fn test_unified_simple_pir() {
        let records = create_test_records(16, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };

        let mut rng = rand::rng();
        let server = PirBuilder::new(&record_refs, 4)
            .with_params(params)
            .simple()
            .build_server(&mut rng);

        assert_eq!(server.mode(), PirMode::Simple);

        let setup = server.setup();
        let client = UnifiedClient::from_setup(setup, params);
        assert_eq!(client.mode(), PirMode::Simple);

        // Test query
        let target_idx = 5;
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(recovered, records[target_idx]);
    }

    #[test]
    fn test_unified_double_pir() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };

        let mut rng = rand::rng();
        let server = PirBuilder::new(&record_refs, 2)
            .with_params(params)
            .double()
            .build_server(&mut rng);

        assert_eq!(server.mode(), PirMode::Double);

        let setup = server.setup();
        let client = UnifiedClient::from_setup(setup, params);
        assert_eq!(client.mode(), PirMode::Double);

        // Test all records
        for target_idx in 0..9 {
            let (state, query) = client.query(target_idx, &mut rng);
            let answer = server.answer(&query);
            let recovered = client.recover(&state, &answer);

            assert_eq!(recovered, records[target_idx], "Failed for record {}", target_idx);
        }
    }

    #[test]
    fn test_unified_communication_costs() {
        let records = create_test_records(100, 32);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };

        let mut rng = rand::rng();

        // Build both modes
        let simple_server = PirBuilder::new(&record_refs, 32)
            .with_params(params)
            .simple()
            .build_server(&mut rng);

        let double_server = PirBuilder::new(&record_refs, 32)
            .with_params(params)
            .double()
            .build_server(&mut rng);

        let simple_setup = simple_server.setup();
        let double_setup = double_server.setup();

        // Compare setup sizes
        println!("SimplePIR setup: {} bytes", simple_setup.size_bytes());
        println!("DoublePIR setup: {} bytes", double_setup.size_bytes());

        // Create clients and compare query/answer sizes
        let simple_client = UnifiedClient::from_setup(simple_setup, params);
        let double_client = UnifiedClient::from_setup(double_setup, params);

        let (_, simple_query) = simple_client.query(50, &mut rng);
        let (_, double_query) = double_client.query(50, &mut rng);

        println!("SimplePIR query: {} bytes", simple_query.size_bytes());
        println!("DoublePIR query: {} bytes", double_query.size_bytes());

        let simple_answer = simple_server.answer(&simple_query);
        let double_answer = double_server.answer(&double_query);

        println!("SimplePIR answer: {} bytes", simple_answer.size_bytes());
        println!("DoublePIR answer: {} bytes", double_answer.size_bytes());

        // DoublePIR should have much smaller answers
        assert!(double_answer.size_bytes() < simple_answer.size_bytes());

        // DoublePIR should have larger queries (2×)
        assert!(double_query.size_bytes() > simple_query.size_bytes());
    }

    #[test]
    fn test_mode_switching() {
        let records = create_test_records(16, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };

        let mut rng = rand::rng();

        // Test with runtime mode selection
        for mode in [PirMode::Simple, PirMode::Double] {
            let server = PirBuilder::new(&record_refs, 4)
                .with_params(params)
                .mode(mode)
                .build_server(&mut rng);

            assert_eq!(server.mode(), mode);

            let setup = server.setup();
            let client = UnifiedClient::from_setup(setup, params);

            let target_idx = 7;
            let (state, query) = client.query(target_idx, &mut rng);
            let answer = server.answer(&query);
            let recovered = client.recover(&state, &answer);

            assert_eq!(
                recovered,
                records[target_idx],
                "Failed for mode {:?}",
                mode
            );
        }
    }

    #[test]
    fn test_builder_estimate_costs() {
        let records = create_test_records(100, 32);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };

        let costs = PirBuilder::new(&record_refs, 32)
            .with_params(params)
            .estimate_costs();

        // Verify estimates match expected formula
        let sqrt_n = 10; // ceil(sqrt(100)) = 10
        assert_eq!(costs.params.sqrt_n, sqrt_n);

        // SimplePIR query = √N × 4 = 40 bytes
        assert_eq!(costs.simple.query_bytes, sqrt_n * 4);

        // DoublePIR query = 2 × √N × 4 = 80 bytes
        assert_eq!(costs.double.query_bytes, 2 * sqrt_n * 4);

        // DoublePIR answer = record_size × 4 = 128 bytes
        assert_eq!(costs.double.answer_bytes, 32 * 4);
    }
}



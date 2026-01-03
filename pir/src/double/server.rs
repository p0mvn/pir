//! DoublePIR server implementation.

use rand::Rng;

use crate::{
    double::{
        hint::{CpuHintComputation, HintComputation},
        DoublePir, DoublePirAnswer, DoublePirQuery, DoublePirSetup,
    },
    matrix_database::DoublePirDatabase,
    params::LweParams,
    pir::{ClientHint, LweMatrix, MatrixSeed},
    pir_trait::PirServer as PirServerTrait,
};

/// DoublePIR server state
pub struct DoublePirServer {
    /// Database in DoublePIR layout
    db: DoublePirDatabase,
    /// Seed for first matrix
    seed_col: MatrixSeed,
    /// Seed for second matrix
    seed_row: MatrixSeed,
    /// First hint
    hint_col: ClientHint,
    /// Second hint
    hint_row: ClientHint,
    /// Cross hint for canceling (H_col · s₁) × (A₂ · s₂)
    hint_cross: Vec<u32>,
    /// LWE dimension
    lwe_dim: usize,
}

impl DoublePirServer {
    /// Create a new DoublePIR server.
    ///
    /// # Panics
    ///
    /// Panics if parameters are invalid:
    /// - LWE dimension must be positive
    /// - Plaintext modulus must be positive
    /// - Database must have positive dimensions
    pub fn new(db: DoublePirDatabase, params: &LweParams, rng: &mut impl Rng) -> Self {
        // Validate LWE parameters
        assert!(params.n > 0, "LWE dimension must be positive");
        assert!(params.p > 0, "Plaintext modulus must be positive");

        // Validate database dimensions
        assert!(
            db.num_cols > 0,
            "Database must have positive number of columns"
        );
        assert!(
            db.num_rows > 0,
            "Database must have positive number of rows"
        );
        assert!(db.record_size > 0, "Record size must be positive");

        // Generate seeds for both matrices
        let seed_col = LweMatrix::generate_seed(rng);
        let seed_row = LweMatrix::generate_seed(rng);

        // Generate matrices from seeds
        let a_col = LweMatrix::from_seed(&seed_col, db.num_cols, params.n);
        let a_row = LweMatrix::from_seed(&seed_row, db.num_rows, params.n);

        // Compute hints using CPU implementation
        let hint_col = CpuHintComputation::compute_hint_col(&db, &a_col);
        let hint_row = CpuHintComputation::compute_hint_row(&db, &a_row);
        let hint_cross = CpuHintComputation::compute_hint_cross(&db, &hint_col, &a_row, params.n);

        Self {
            db,
            seed_col,
            seed_row,
            hint_col,
            hint_row,
            hint_cross,
            lwe_dim: params.n,
        }
    }

    /// Get setup data to send to client
    pub fn setup(&self) -> DoublePirSetup {
        DoublePirSetup {
            seed_col: self.seed_col,
            seed_row: self.seed_row,
            hint_col: ClientHint {
                data: self.hint_col.data.clone(),
                rows: self.hint_col.rows,
                cols: self.hint_col.cols,
            },
            hint_row: ClientHint {
                data: self.hint_row.data.clone(),
                rows: self.hint_row.rows,
                cols: self.hint_row.cols,
            },
            hint_cross: self.hint_cross.clone(),
            num_cols: self.db.num_cols,
            num_rows: self.db.num_rows,
            record_size: self.db.record_size,
            num_records: self.db.num_records,
            lwe_dim: self.lwe_dim,
        }
    }

    /// Answer a DoublePIR query.
    ///
    /// Performs two-stage multiplication:
    /// 1. intermediate = DB · query_col (for each row, byte)
    /// 2. result = intermediate · query_row (for each byte)
    ///
    /// # Panics
    ///
    /// Panics if query dimensions don't match database dimensions:
    /// - `query.query_col.len()` must equal `num_cols`
    /// - `query.query_row.len()` must equal `num_rows`
    pub fn answer(&self, query: &DoublePirQuery) -> DoublePirAnswer {
        // Validate query dimensions
        assert_eq!(
            query.query_col.len(),
            self.db.num_cols,
            "query_col length ({}) must match database columns ({})",
            query.query_col.len(),
            self.db.num_cols
        );
        assert_eq!(
            query.query_row.len(),
            self.db.num_rows,
            "query_row length ({}) must match database rows ({})",
            query.query_row.len(),
            self.db.num_rows
        );

        // Stage 1: For each (row, byte), compute dot product with query_col
        // intermediate[row][byte] = Σ_col DB[row][col][byte] × query_col[col]
        let intermediate = self.db.multiply_first(&query.query_col);

        // Stage 2: For each byte, compute dot product with query_row
        // result[byte] = Σ_row intermediate[row][byte] × query_row[row]
        let data = self.db.multiply_second(&intermediate, &query.query_row);

        DoublePirAnswer { data }
    }

    /// Number of records in the database
    pub fn num_records(&self) -> usize {
        self.db.num_records
    }

    /// Size of each record in bytes
    pub fn record_size(&self) -> usize {
        self.db.record_size
    }
}

// ============================================================================
// Trait Implementation
// ============================================================================

impl PirServerTrait for DoublePirServer {
    type Protocol = DoublePir;

    fn setup(&self) -> DoublePirSetup {
        self.setup()
    }

    fn answer(&self, query: &DoublePirQuery) -> DoublePirAnswer {
        self.answer(query)
    }

    fn num_records(&self) -> usize {
        self.num_records()
    }

    fn record_size(&self) -> usize {
        self.record_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::double::{DoublePirClient, DoublePirQuery};
    use crate::pir_trait::{CommunicationCost, PirClient, PirServer};

    fn create_test_records(n: usize, record_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                (0..record_size)
                    .map(|j| ((i * record_size + j) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    /// Basic DoublePIR correctness test.
    #[test]
    fn test_double_pir_basic() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = DoublePirClient::new(setup, params);

        let target_idx = 4;
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(
            recovered, records[target_idx],
            "Failed to recover record {target_idx}"
        );
    }

    /// Test that all records can be correctly recovered.
    #[test]
    fn test_double_pir_all_records() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = DoublePirClient::new(setup, params);

        for target_idx in 0..9 {
            let (state, query) = client.query(target_idx, &mut rng);
            let answer = server.answer(&query);
            let recovered = client.recover(&state, &answer);

            assert_eq!(
                recovered, records[target_idx],
                "Failed to recover record {target_idx}"
            );
        }
    }

    /// Test DoublePIR with larger records (32 bytes each).
    #[test]
    fn test_double_pir_larger_records() {
        let records = create_test_records(16, 32);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 32);

        let params = LweParams {
            n: 128,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = DoublePirClient::new(setup, params);

        for target_idx in [0, 7, 15] {
            let (state, query) = client.query(target_idx, &mut rng);
            let answer = server.answer(&query);
            let recovered = client.recover(&state, &answer);

            assert_eq!(
                recovered, records[target_idx],
                "Failed to recover record {target_idx}"
            );
        }
    }

    #[test]
    fn test_double_pir_via_trait() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        // Use trait interface
        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = <DoublePirServer as PirServer>::setup(&server);
        let client = <DoublePirClient as PirClient>::from_setup(setup, params);

        let target_idx = 4;
        let (state, query) = <DoublePirClient as PirClient>::query(&client, target_idx, &mut rng);
        let answer = <DoublePirServer as PirServer>::answer(&server, &query);
        let recovered = <DoublePirClient as PirClient>::recover(&client, &state, &answer);

        assert_eq!(recovered, records[target_idx]);
    }

    #[test]
    fn test_double_pir_communication_cost() {
        let records = create_test_records(100, 32);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 32);

        let params = LweParams {
            n: 1024,
            p: 256,
            noise_stddev: 6.4,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = DoublePirClient::new(setup, params);

        let (_, query) = client.query(50, &mut rng);
        let answer = server.answer(&query);

        // Query size: 2 × √100 × 4 = 80 bytes
        let query_size = query.size_bytes();
        assert_eq!(query_size, 2 * 10 * 4);

        // Answer size: record_size × 4 = 32 × 4 = 128 bytes
        let answer_size = answer.size_bytes();
        assert_eq!(answer_size, 32 * 4);

        println!("DoublePIR answer size: {} bytes", answer_size);
        println!("SimplePIR answer would be: {} bytes", 10 * 32 * 4);
    }

    #[test]
    fn test_double_pir_imperfect_square() {
        // 10 records (not a perfect square)
        let records = create_test_records(10, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = DoublePirClient::new(setup, params);

        for target_idx in 0..10 {
            let (state, query) = client.query(target_idx, &mut rng);
            let answer = server.answer(&query);
            let recovered = client.recover(&state, &answer);

            assert_eq!(
                recovered, records[target_idx],
                "Failed to recover record {target_idx}"
            );
        }
    }

    #[test]
    fn test_hint_dimensions() {
        let records = create_test_records(9, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 3.2,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        // hint_col: (num_rows * record_size) × lwe_dim = (3 * 4) × 64 = 12 × 64
        assert_eq!(setup.hint_col.rows, 3 * 4);
        assert_eq!(setup.hint_col.cols, 64);

        // hint_row: (num_cols * record_size) × lwe_dim = (3 * 4) × 64 = 12 × 64
        assert_eq!(setup.hint_row.rows, 3 * 4);
        assert_eq!(setup.hint_row.cols, 64);
    }

    // ========================================================================
    // Dimension Validation Tests
    // ========================================================================

    #[test]
    #[should_panic(expected = "must match params.n")]
    fn test_client_rejects_mismatched_lwe_dim() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        // Try to create client with different LWE dimension
        let wrong_params = LweParams {
            n: 128,
            p: 256,
            noise_stddev: 0.0,
        };
        let _client = DoublePirClient::new(setup, wrong_params);
    }

    #[test]
    #[should_panic(expected = "query_col length")]
    fn test_server_rejects_wrong_query_col_size() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);

        let bad_query = DoublePirQuery {
            query_col: vec![0u32; 5],
            query_row: vec![0u32; 3],
        };
        let _answer = server.answer(&bad_query);
    }

    #[test]
    #[should_panic(expected = "query_row length")]
    fn test_server_rejects_wrong_query_row_size() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);

        let bad_query = DoublePirQuery {
            query_col: vec![0u32; 3],
            query_row: vec![0u32; 5],
        };
        let _answer = server.answer(&bad_query);
    }

    // ========================================================================
    // Serialization Tests
    // ========================================================================

    #[test]
    fn test_double_pir_query_serialization() {
        let query = DoublePirQuery {
            query_col: vec![1, 2, 3, 4, 5],
            query_row: vec![10, 20, 30],
        };
        let encoded = bincode::serialize(&query).unwrap();
        let decoded: DoublePirQuery = bincode::deserialize(&encoded).unwrap();
        assert_eq!(query.query_col, decoded.query_col);
        assert_eq!(query.query_row, decoded.query_row);
    }

    #[test]
    fn test_double_pir_answer_serialization() {
        let answer = crate::double::DoublePirAnswer {
            data: vec![100, 200, 300, 400],
        };
        let encoded = bincode::serialize(&answer).unwrap();
        let decoded: crate::double::DoublePirAnswer = bincode::deserialize(&encoded).unwrap();
        assert_eq!(answer.data, decoded.data);
    }

    #[test]
    fn test_double_pir_setup_serialization() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        let encoded = bincode::serialize(&setup).unwrap();
        let decoded: crate::double::DoublePirSetup = bincode::deserialize(&encoded).unwrap();

        assert_eq!(setup.seed_col, decoded.seed_col);
        assert_eq!(setup.seed_row, decoded.seed_row);
        assert_eq!(setup.hint_col.data, decoded.hint_col.data);
        assert_eq!(setup.hint_row.data, decoded.hint_row.data);
        assert_eq!(setup.hint_cross, decoded.hint_cross);
        assert_eq!(setup.num_cols, decoded.num_cols);
        assert_eq!(setup.num_rows, decoded.num_rows);
        assert_eq!(setup.record_size, decoded.record_size);
        assert_eq!(setup.num_records, decoded.num_records);
        assert_eq!(setup.lwe_dim, decoded.lwe_dim);
    }

    #[test]
    fn test_double_pir_end_to_end_with_serialization() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        // Simulate network: serialize setup
        let setup_bytes = bincode::serialize(&setup).unwrap();
        let setup_received: crate::double::DoublePirSetup =
            bincode::deserialize(&setup_bytes).unwrap();

        // Client creates query
        let client = DoublePirClient::new(setup_received, params);
        let target_idx = 4;
        let (state, query) = client.query(target_idx, &mut rng);

        // Simulate network: serialize query
        let query_bytes = bincode::serialize(&query).unwrap();
        let query_received: DoublePirQuery = bincode::deserialize(&query_bytes).unwrap();

        // Server answers
        let answer = server.answer(&query_received);

        // Simulate network: serialize answer
        let answer_bytes = bincode::serialize(&answer).unwrap();
        let answer_received: crate::double::DoublePirAnswer =
            bincode::deserialize(&answer_bytes).unwrap();

        // Client recovers
        let recovered = client.recover(&state, &answer_received);

        assert_eq!(recovered, records[target_idx]);
    }

    #[test]
    fn test_serialization_sizes_match_communication_cost() {
        let records = create_test_records(100, 32);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 32);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = DoublePirClient::new(setup.clone(), params);

        let (_state, query) = client.query(50, &mut rng);
        let answer = server.answer(&query);

        let query_bytes = bincode::serialize(&query).unwrap();
        let answer_bytes = bincode::serialize(&answer).unwrap();
        let setup_bytes = bincode::serialize(&setup).unwrap();

        let query_cost = query.size_bytes();
        let answer_cost = answer.size_bytes();
        let setup_cost = setup.size_bytes();

        println!(
            "Query: serialized={}, estimated={}",
            query_bytes.len(),
            query_cost
        );
        println!(
            "Answer: serialized={}, estimated={}",
            answer_bytes.len(),
            answer_cost
        );
        println!(
            "Setup: serialized={}, estimated={}",
            setup_bytes.len(),
            setup_cost
        );

        // Allow some overhead for bincode length prefixes
        assert!(query_bytes.len() <= query_cost + 32);
        assert!(answer_bytes.len() <= answer_cost + 16);
        assert!(setup_bytes.len() <= setup_cost + 128);
    }

    /// Test end-to-end with JSON serialization (like WASM does)
    #[test]
    fn test_double_pir_json_serialization() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        // Simulate JSON serialization/deserialization like WASM does
        let setup_json = serde_json::to_string(&setup).unwrap();
        println!("Setup JSON length: {} bytes", setup_json.len());
        let setup_received: crate::double::DoublePirSetup =
            serde_json::from_str(&setup_json).unwrap();

        // Client creates query
        let client = DoublePirClient::new(setup_received, params);
        let target_idx = 4;
        let (state, query) = client.query(target_idx, &mut rng);

        // Serialize query via JSON
        let query_json = serde_json::to_string(&query).unwrap();
        let query_received: DoublePirQuery = serde_json::from_str(&query_json).unwrap();

        // Server answers
        let answer = server.answer(&query_received);

        // Serialize answer via JSON
        let answer_json = serde_json::to_string(&answer).unwrap();
        println!("Answer JSON: {}", answer_json);
        let answer_received: crate::double::DoublePirAnswer =
            serde_json::from_str(&answer_json).unwrap();

        // Client recovers
        let recovered = client.recover(&state, &answer_received);

        println!("Expected: {:?}", records[target_idx]);
        println!("Recovered: {:?}", recovered);

        assert_eq!(recovered, records[target_idx]);
    }

    /// Test that A matrices from seed are consistent
    #[test]
    fn test_a_matrix_from_specific_seed() {
        // Use the same seed as the demo server
        let seed_col: [u8; 32] = [
            26, 233, 94, 103, 221, 251, 149, 36, 32, 7, 43, 22, 27, 35, 28, 49, 183, 63, 181, 37,
            128, 126, 176, 0, 102, 94, 118, 43, 56, 23, 99, 36,
        ];
        let a_col = LweMatrix::from_seed(&seed_col, 20, 64);

        println!("A_col first 8 elements: {:?}", &a_col.data[..8]);

        // These values should match what WASM generates
        assert!(a_col.data.len() == 20 * 64);
    }

    /// Test simulating the password demo scenario
    #[test]
    fn test_password_demo_scenario() {
        use crate::binary_fuse::{BinaryFuseFilter, KeywordQuery};

        // Create demo database same as the server
        let database: Vec<(String, Vec<u8>)> = (0..200)
            .map(|i| {
                let key = format!("password_{:04}", i);
                let count = ((i + 1) * 100) as u32;
                let value = count.to_le_bytes().to_vec();
                (key, value)
            })
            .collect();

        let value_size = 4;
        let filter = BinaryFuseFilter::build(&database, value_size)
            .expect("Failed to build Binary Fuse Filter");

        println!("Filter size: {} slots", filter.filter_size());

        let pir_records = filter.to_pir_records();
        let record_refs: Vec<&[u8]> = pir_records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, value_size);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        println!(
            "Seeds: col={:?}, row={:?}",
            &setup.seed_col[..8],
            &setup.seed_row[..8]
        );
        println!(
            "Grid: {}x{}, records={}",
            setup.num_cols, setup.num_rows, setup.num_records
        );

        // Simulate JSON serialization like WASM
        let setup_json = serde_json::to_string(&setup).unwrap();
        let setup_received: crate::double::DoublePirSetup =
            serde_json::from_str(&setup_json).unwrap();

        let client = DoublePirClient::new(setup_received, params);

        // Query for password_0042
        let keyword = "password_0042".to_string();
        let kw_query = KeywordQuery::new(&filter.params(), &keyword);
        let positions = kw_query.record_indices();
        println!("Keyword '{}' positions: {:?}", keyword, positions);

        let expected_value = 43 * 100; // (42 + 1) * 100 = 4300
        println!(
            "Expected value: {} = {:?}",
            expected_value,
            expected_value.to_le_bytes()
        );

        // Query each position
        let mut recovered_records = Vec::new();
        for (_i, &pos) in positions.iter().enumerate() {
            let (state, query) = client.query(pos, &mut rng);

            // JSON round-trip the query
            let query_json = serde_json::to_string(&query).unwrap();
            let query_received: DoublePirQuery = serde_json::from_str(&query_json).unwrap();

            let answer = server.answer(&query_received);

            // JSON round-trip the answer
            let answer_json = serde_json::to_string(&answer).unwrap();
            let answer_received: crate::double::DoublePirAnswer =
                serde_json::from_str(&answer_json).unwrap();

            let recovered = client.recover(&state, &answer_received);
            println!(
                "Position {} (col={}, row={}): answer={:?}, recovered={:?}",
                pos, state.col_idx, state.row_idx, answer.data, recovered
            );
            recovered_records.push(recovered);
        }

        // XOR the three records
        let final_result: Vec<u8> = recovered_records[0]
            .iter()
            .zip(recovered_records[1].iter())
            .zip(recovered_records[2].iter())
            .map(|((&a, &b), &c)| a ^ b ^ c)
            .collect();

        let result_value = u32::from_le_bytes([
            final_result[0],
            final_result[1],
            final_result[2],
            final_result[3],
        ]);
        println!("Final XOR result: {:?} = {}", final_result, result_value);

        assert_eq!(
            result_value, expected_value,
            "Recovered value should match expected"
        );
    }
}

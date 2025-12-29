//! DoublePIR: Two-stage PIR for reduced answer size.
//!
//! DoublePIR applies PIR twice to compress the response:
//! 1. First query selects a column of records → intermediate result
//! 2. Second query selects a row from that → final record
//!
//! ## Communication Complexity
//!
//! | Metric | SimplePIR | DoublePIR |
//! |--------|-----------|-----------|
//! | Query size | √N × (n+1) | 2 × √N × (n+1) |
//! | Answer size | √N × record_size | record_size × (n+1) |
//!
//! For large record sizes and databases, DoublePIR significantly reduces
//! the answer size at the cost of slightly larger queries.

use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    matrix_database::DoublePirDatabase,
    params::LweParams,
    pir::{ClientHint, LweMatrix, MatrixSeed},
    pir_trait::{CommunicationCost, PirClient as PirClientTrait, PirProtocol, PirServer as PirServerTrait},
    regev::{SecretKey, encrypt},
};

// ============================================================================
// Protocol Types
// ============================================================================

/// Marker type for DoublePIR protocol
pub struct DoublePir;

impl PirProtocol for DoublePir {
    type Query = DoublePirQuery;
    type Answer = DoublePirAnswer;
    type QueryState = DoublePirQueryState;
    type SetupData = DoublePirSetup;
}

/// DoublePIR query: two encrypted unit vectors
#[derive(Clone, Serialize, Deserialize)]
pub struct DoublePirQuery {
    /// First query: selects column (√N elements)
    pub query_col: Vec<u32>,
    /// Second query: selects row (√N elements)
    pub query_row: Vec<u32>,
}

/// DoublePIR answer: compressed result
#[derive(Clone, Serialize, Deserialize)]
pub struct DoublePirAnswer {
    /// Encrypted record bytes (record_size elements)
    pub data: Vec<u32>,
}

/// Client state for DoublePIR recovery (kept secret, not transmitted)
pub struct DoublePirQueryState {
    /// Column index being queried
    pub col_idx: usize,
    /// Row index being queried
    pub row_idx: usize,
    /// Secret for first query
    pub secret_col: Vec<u32>,
    /// Secret for second query
    pub secret_row: Vec<u32>,
}

/// Setup data sent from server to client
#[derive(Clone, Serialize, Deserialize)]
pub struct DoublePirSetup {
    /// Seed for first matrix A₁ (column selection)
    pub seed_col: MatrixSeed,
    /// Seed for second matrix A₂ (row selection)
    pub seed_row: MatrixSeed,
    /// First hint: H_col[row, byte, j] = Σ_col DB[row][col][byte] × A₁[col, j]
    pub hint_col: ClientHint,
    /// Second hint: H_row[col, byte, j] = Σ_row DB[row][col][byte] × A₂[row, j]
    pub hint_row: ClientHint,
    /// Cross hint: H_cross[byte, j, k] = Σ_row H_col[row, byte, j] × A₂[row, k]
    /// Used to cancel the cross term (H_col · s₁) × (A₂ · s₂)
    /// Shape: record_size × lwe_dim × lwe_dim (flattened)
    pub hint_cross: Vec<u32>,
    /// √N — number of record columns
    pub num_cols: usize,
    /// √N — number of record rows
    pub num_rows: usize,
    /// Bytes per record
    pub record_size: usize,
    /// Total number of records
    pub num_records: usize,
    /// LWE dimension
    pub lwe_dim: usize,
}

// ============================================================================
// DoublePIR Client
// ============================================================================

/// DoublePIR client state
pub struct DoublePirClient {
    /// First matrix A₁ (for column query)
    a_col: LweMatrix,
    /// Second matrix A₂ (for row query)
    a_row: LweMatrix,
    /// First hint: for canceling H_col · s_col term
    hint_col: ClientHint,
    /// Second hint: for canceling Δ × H_row · s_row term
    hint_row: ClientHint,
    /// Cross hint: for canceling (H_col · s_col) × (A₂ · s_row) term
    hint_cross: Vec<u32>,
    /// LWE parameters
    params: LweParams,
    /// √N — number of record columns
    num_cols: usize,
    /// √N — number of record rows
    num_rows: usize,
    /// Bytes per record
    record_size: usize,
    /// Total number of records
    num_records: usize,
}

impl DoublePirClient {
    /// Initialize client from setup data.
    ///
    /// # Panics
    ///
    /// Panics if setup data dimensions are inconsistent with LWE parameters:
    /// - `setup.lwe_dim` must equal `params.n`
    /// - Hint dimensions must match expected sizes
    /// - Database dimensions must be positive
    pub fn new(setup: DoublePirSetup, params: LweParams) -> Self {
        // Validate LWE parameters
        assert!(params.n > 0, "LWE dimension must be positive");
        assert!(params.p > 0, "Plaintext modulus must be positive");

        // Validate setup dimensions match params
        assert_eq!(
            setup.lwe_dim, params.n,
            "Setup LWE dimension ({}) must match params.n ({})",
            setup.lwe_dim, params.n
        );

        // Validate database dimensions
        assert!(setup.num_cols > 0, "Number of columns must be positive");
        assert!(setup.num_rows > 0, "Number of rows must be positive");
        assert!(setup.record_size > 0, "Record size must be positive");
        assert!(setup.num_records > 0, "Number of records must be positive");

        // Validate hint_col dimensions: (num_rows * record_size) × lwe_dim
        let expected_hint_col_rows = setup.num_rows * setup.record_size;
        assert_eq!(
            setup.hint_col.rows, expected_hint_col_rows,
            "hint_col rows ({}) must equal num_rows × record_size ({})",
            setup.hint_col.rows, expected_hint_col_rows
        );
        assert_eq!(
            setup.hint_col.cols, params.n,
            "hint_col cols ({}) must equal LWE dimension ({})",
            setup.hint_col.cols, params.n
        );

        // Validate hint_row dimensions: (num_cols * record_size) × lwe_dim
        let expected_hint_row_rows = setup.num_cols * setup.record_size;
        assert_eq!(
            setup.hint_row.rows, expected_hint_row_rows,
            "hint_row rows ({}) must equal num_cols × record_size ({})",
            setup.hint_row.rows, expected_hint_row_rows
        );
        assert_eq!(
            setup.hint_row.cols, params.n,
            "hint_row cols ({}) must equal LWE dimension ({})",
            setup.hint_row.cols, params.n
        );

        // Validate hint_cross dimensions: record_size × n × n
        let expected_hint_cross_len = setup.record_size * params.n * params.n;
        assert_eq!(
            setup.hint_cross.len(), expected_hint_cross_len,
            "hint_cross length ({}) must equal record_size × n² ({})",
            setup.hint_cross.len(), expected_hint_cross_len
        );

        // Regenerate matrices from seeds
        let a_col = LweMatrix::from_seed(&setup.seed_col, setup.num_cols, setup.lwe_dim);
        let a_row = LweMatrix::from_seed(&setup.seed_row, setup.num_rows, setup.lwe_dim);

        Self {
            a_col,
            a_row,
            hint_col: setup.hint_col,
            hint_row: setup.hint_row,
            hint_cross: setup.hint_cross,
            params,
            num_cols: setup.num_cols,
            num_rows: setup.num_rows,
            record_size: setup.record_size,
            num_records: setup.num_records,
        }
    }

    /// Generate query for a record index
    ///
    /// The first query (column selection) uses standard Regev encryption with Δ scaling.
    /// The second query (row selection) uses unscaled encryption to avoid Δ² overflow.
    pub fn query(&self, record_idx: usize, rng: &mut impl Rng) -> (DoublePirQueryState, DoublePirQuery) {
        assert!(record_idx < self.num_records, "Record index out of bounds");

        // Convert record index to (row, col) in the record grid
        let col_idx = record_idx % self.num_cols;
        let row_idx = record_idx / self.num_cols;

        // Generate fresh secrets
        let secret_col: Vec<u32> = (0..self.params.n).map(|_| rng.random()).collect();
        let secret_row: Vec<u32> = (0..self.params.n).map(|_| rng.random()).collect();

        // First query: Encrypt unit vector for column selection (standard Regev with Δ)
        // query_col[col] = A₁[col,:]·s₁ + e₁ + Δ·u_col[col]
        let query_col: Vec<u32> = (0..self.num_cols)
            .map(|i| {
                let msg = if i == col_idx { 1 } else { 0 };
                encrypt(
                    &self.params,
                    self.a_col.row(i),
                    &SecretKey { s: &secret_col },
                    msg,
                    rng,
                )
            })
            .collect();

        // Second query: Encrypt unit vector for row selection WITHOUT Δ scaling
        // query_row[row] = A₂[row,:]·s₂ + e₂ + u_row[row]
        // This avoids the Δ² issue: final signal is Δ×target instead of Δ²×target
        let query_row: Vec<u32> = (0..self.num_rows)
            .map(|i| {
                let a_row_i = self.a_row.row(i);
                let e = crate::regev::sample_noise(self.params.noise_stddev, rng);
                let msg = if i == row_idx { 1u32 } else { 0u32 };

                // c = a·s + e + msg (no Δ scaling!)
                crate::regev::dot_product(a_row_i, &secret_row)
                    .wrapping_add(e)
                    .wrapping_add(msg)
            })
            .collect();

        let state = DoublePirQueryState {
            col_idx,
            row_idx,
            secret_col,
            secret_row,
        };

        let query = DoublePirQuery { query_col, query_row };

        (state, query)
    }

    /// Recover the record from the answer
    ///
    /// The answer contains encrypted bytes of the target record.
    /// We need to decrypt each byte using all three hints.
    ///
    /// ## Math Background
    ///
    /// The server computes:
    /// ```text
    /// answer[byte] = Σ_row Σ_col DB[row][col][byte] × q_col[col] × q_row[row]
    /// ```
    ///
    /// With our encoding (unscaled second query):
    /// - q_col[col] = A₁[col,:]·s₁ + e₁ + Δ·u_col[col]
    /// - q_row[row] = A₂[row,:]·s₂ + e₂ + u_row[row]  (NO Δ!)
    ///
    /// The signal term is: `Δ × DB[target_row][target_col][byte]`
    /// The hint terms to remove are:
    /// 1. `hint_col[target_row, byte, :] · s_col` (from (A₁·s₁) selected by u_row)
    /// 2. `Δ × hint_row[target_col, byte, :] · s_row` (from Δ·DB × (A₂·s₂))
    /// 3. Cross term: `Σ_j Σ_k hint_cross[byte, j, k] × s_col[j] × s_row[k]`
    pub fn recover(&self, state: &DoublePirQueryState, answer: &DoublePirAnswer) -> Vec<u8> {
        let delta = self.params.delta();
        let n = self.params.n;

        (0..self.record_size)
            .map(|byte_idx| {
                // Get the answer value for this byte
                let ans = answer.data[byte_idx];

                // 1. Remove hint_col contribution: hint_col[target_row * record_size + byte, :] · s_col
                let hint_col_idx = state.row_idx * self.record_size + byte_idx;
                let hint_col_contrib = crate::regev::dot_product(
                    self.hint_col.row(hint_col_idx),
                    &state.secret_col,
                );
                let after_col = ans.wrapping_sub(hint_col_contrib);

                // 2. Remove hint_row contribution: Δ × hint_row[target_col * record_size + byte, :] · s_row
                let hint_row_idx = state.col_idx * self.record_size + byte_idx;
                let hint_row_contrib = crate::regev::dot_product(
                    self.hint_row.row(hint_row_idx),
                    &state.secret_row,
                );
                let after_row = after_col.wrapping_sub(delta.wrapping_mul(hint_row_contrib));

                // 3. Remove cross term: Σ_j Σ_k hint_cross[byte, j, k] × s_col[j] × s_row[k]
                // hint_cross is stored as [byte][j][k] flattened
                let cross_base = byte_idx * n * n;
                let mut cross_contrib = 0u32;
                for j in 0..n {
                    for k in 0..n {
                        let h = self.hint_cross[cross_base + j * n + k];
                        cross_contrib = cross_contrib.wrapping_add(
                            h.wrapping_mul(state.secret_col[j])
                             .wrapping_mul(state.secret_row[k])
                        );
                    }
                }
                let after_cross = after_row.wrapping_sub(cross_contrib);

                // The remaining value is approximately Δ × plaintext + noise
                crate::regev::round_decode(after_cross, &self.params) as u8
            })
            .collect()
    }

    /// Number of records in the database
    pub fn num_records(&self) -> usize {
        self.num_records
    }

    /// Size of each record in bytes
    pub fn record_size(&self) -> usize {
        self.record_size
    }
}

// ============================================================================
// DoublePIR Server
// ============================================================================

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
        assert!(db.num_cols > 0, "Database must have positive number of columns");
        assert!(db.num_rows > 0, "Database must have positive number of rows");
        assert!(db.record_size > 0, "Record size must be positive");

        // Generate seeds for both matrices
        let seed_col = LweMatrix::generate_seed(rng);
        let seed_row = LweMatrix::generate_seed(rng);

        // Generate matrices from seeds
        let a_col = LweMatrix::from_seed(&seed_col, db.num_cols, params.n);
        let a_row = LweMatrix::from_seed(&seed_row, db.num_rows, params.n);

        // Compute hints
        let hint_col = Self::compute_hint_col(&db, &a_col);
        let hint_row = Self::compute_hint_row(&db, &a_row);
        let hint_cross = Self::compute_hint_cross(&db, &hint_col, &a_row, params.n);

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

    /// Compute first hint: for each (row, byte), compute sum over cols of DB[row][col][byte] * A₁[col, :]
    ///
    /// This allows the client to remove the contribution of secret_col from the answer.
    /// Result shape: (num_rows * record_size) × lwe_dim
    fn compute_hint_col(db: &DoublePirDatabase, a_col: &LweMatrix) -> ClientHint {
        let rows = db.num_rows * db.record_size;
        let cols = a_col.cols; // lwe_dim

        // Parallel computation over output rows
        let row_results: Vec<Vec<u32>> = (0..rows)
            .into_par_iter()
            .map(|out_row| {
                let record_row = out_row / db.record_size;
                let byte_idx = out_row % db.record_size;

                (0..cols)
                    .map(|j| {
                        let mut sum = 0u32;
                        for col in 0..db.num_cols {
                            // DB[record_row][col][byte_idx] * A₁[col, j]
                            let db_val = db.get(record_row, col, byte_idx);
                            let a_val = a_col.get(col, j);
                            sum = sum.wrapping_add(db_val.wrapping_mul(a_val));
                        }
                        sum
                    })
                    .collect()
            })
            .collect();

        let data: Vec<u32> = row_results.into_iter().flatten().collect();
        ClientHint { data, rows, cols }
    }

    /// Compute second hint: for each (col, byte), compute sum over rows of DB[row][col][byte] * A₂[row, :]
    ///
    /// This allows the client to remove the contribution of secret_row from the answer.
    /// Result shape: (num_cols × record_size) × lwe_dim
    fn compute_hint_row(db: &DoublePirDatabase, a_row: &LweMatrix) -> ClientHint {
        let rows = db.num_cols * db.record_size;
        let cols = a_row.cols; // lwe_dim

        // For each (col, byte) and LWE dimension
        let row_results: Vec<Vec<u32>> = (0..rows)
            .into_par_iter()
            .map(|out_row| {
                let col = out_row / db.record_size;
                let byte_idx = out_row % db.record_size;

                (0..cols)
                    .map(|j| {
                        let mut sum = 0u32;
                        for row in 0..db.num_rows {
                            // hint_row[col, byte, j] = Σ_row DB[row][col][byte] × A₂[row, j]
                            let db_val = db.get(row, col, byte_idx);
                            let a_val = a_row.get(row, j);
                            sum = sum.wrapping_add(db_val.wrapping_mul(a_val));
                        }
                        sum
                    })
                    .collect()
            })
            .collect();

        let data: Vec<u32> = row_results.into_iter().flatten().collect();
        ClientHint { data, rows, cols }
    }

    /// Compute cross hint: for each (byte, j, k), compute Σ_row H_col[row, byte, j] × A₂[row, k]
    ///
    /// This cancels the cross term (H_col · s₁) × (A₂ · s₂) in recovery.
    /// Result shape: record_size × lwe_dim × lwe_dim (flattened)
    fn compute_hint_cross(
        db: &DoublePirDatabase,
        hint_col: &ClientHint,
        a_row: &LweMatrix,
        lwe_dim: usize,
    ) -> Vec<u32> {
        let record_size = db.record_size;

        // hint_cross[byte][j][k] = Σ_row H_col[row, byte, j] × A₂[row, k]
        // H_col is stored as [(row * record_size + byte)][j]
        let results: Vec<Vec<u32>> = (0..record_size)
            .into_par_iter()
            .map(|byte_idx| {
                let mut byte_result = vec![0u32; lwe_dim * lwe_dim];
                for j in 0..lwe_dim {
                    for k in 0..lwe_dim {
                        let mut sum = 0u32;
                        for row in 0..db.num_rows {
                            // H_col[row, byte_idx, j]
                            let h_col_idx = row * record_size + byte_idx;
                            let h_col_val = hint_col.data[h_col_idx * lwe_dim + j];
                            // A₂[row, k]
                            let a_val = a_row.get(row, k);
                            sum = sum.wrapping_add(h_col_val.wrapping_mul(a_val));
                        }
                        byte_result[j * lwe_dim + k] = sum;
                    }
                }
                byte_result
            })
            .collect();

        results.into_iter().flatten().collect()
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
            query.query_col.len(), self.db.num_cols,
            "query_col length ({}) must match database columns ({})",
            query.query_col.len(), self.db.num_cols
        );
        assert_eq!(
            query.query_row.len(), self.db.num_rows,
            "query_row length ({}) must match database rows ({})",
            query.query_row.len(), self.db.num_rows
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
// Trait Implementations
// ============================================================================

impl PirClientTrait for DoublePirClient {
    type Protocol = DoublePir;

    fn from_setup(setup: DoublePirSetup, params: LweParams) -> Self {
        DoublePirClient::new(setup, params)
    }

    fn query(&self, record_idx: usize, rng: &mut impl Rng) -> (DoublePirQueryState, DoublePirQuery) {
        self.query(record_idx, rng)
    }

    fn recover(&self, state: &DoublePirQueryState, answer: &DoublePirAnswer) -> Vec<u8> {
        self.recover(state, answer)
    }

    fn num_records(&self) -> usize {
        self.num_records()
    }

    fn record_size(&self) -> usize {
        self.record_size()
    }
}

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

// ============================================================================
// Communication Cost Implementations
// ============================================================================

impl CommunicationCost for DoublePirQuery {
    fn size_bytes(&self) -> usize {
        (self.query_col.len() + self.query_row.len()) * std::mem::size_of::<u32>()
    }
}

impl CommunicationCost for DoublePirAnswer {
    fn size_bytes(&self) -> usize {
        self.data.len() * std::mem::size_of::<u32>()
    }
}

impl CommunicationCost for DoublePirSetup {
    fn size_bytes(&self) -> usize {
        // Two seeds: 64 bytes
        // hint_col: (num_rows * record_size) * lwe_dim * 4 bytes
        // hint_row: (num_cols * record_size) * lwe_dim * 4 bytes
        // hint_cross: record_size * lwe_dim * lwe_dim * 4 bytes
        64 + (self.hint_col.data.len() + self.hint_row.data.len() + self.hint_cross.len())
            * std::mem::size_of::<u32>()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix_database::DoublePirDatabase;

    fn create_test_records(n: usize, record_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| (0..record_size).map(|j| ((i * record_size + j) % 256) as u8).collect())
            .collect()
    }

    /// Test with zero A matrices to verify basic PIR structure without A·s terms
    #[test]
    fn test_double_pir_zero_matrices() {
        use crate::pir::{ClientHint, LweMatrix};

        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let n = 4;
        let params = LweParams {
            n,
            p: 256,
            noise_stddev: 0.0,
        };

        // Create client with zero A matrices (eliminates A·s terms)
        let a_col = LweMatrix { data: vec![0u32; 3 * n], rows: 3, cols: n };
        let a_row = LweMatrix { data: vec![0u32; 3 * n], rows: 3, cols: n };
        let hint_col = ClientHint { data: vec![0u32; 6 * n], rows: 6, cols: n };
        let hint_row = ClientHint { data: vec![0u32; 6 * n], rows: 6, cols: n };
        let hint_cross = vec![0u32; 2 * n * n]; // record_size × n × n

        let client = DoublePirClient {
            a_col,
            a_row,
            hint_col,
            hint_row,
            hint_cross,
            params,
            num_cols: 3,
            num_rows: 3,
            record_size: 2,
            num_records: 9,
        };

        let mut rng = rand::rng();
        let target_idx = 4; // R4 = [8, 9] at (row=1, col=1)
        let (state, query) = client.query(target_idx, &mut rng);

        // With A=0, queries should be:
        // query_col[col] = 0 + Δ·u_col[col]
        // query_row[row] = 0 + u_row[row]
        let delta = params.delta();
        
        // Check query_col has Δ at target column
        assert_eq!(query.query_col[0], 0);
        assert_eq!(query.query_col[1], delta);
        assert_eq!(query.query_col[2], 0);

        // Check query_row has 1 at target row
        assert_eq!(query.query_row[0], 0);
        assert_eq!(query.query_row[1], 1);
        assert_eq!(query.query_row[2], 0);

        // Compute answer manually
        let answer = DoublePirAnswer { data: db.multiply_double(&query.query_col, &query.query_row) };

        // With zero hints, recovery should just be round_decode of the answer
        println!("Delta = {}", delta);
        println!("Answer = {:?}", answer.data);
        println!("Expected: Δ × [8, 9] = [{}, {}]", delta * 8, delta * 9);

        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, vec![8, 9], "Failed to recover with zero matrices");
    }

    /// Basic DoublePIR correctness test.
    ///
    /// The cross-term `(A₁·s₁) × (A₂·s₂)` is correctly canceled by `hint_cross`.
    /// With zero noise, recovery should be exact.
    #[test]
    fn test_double_pir_basic() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0, // Zero noise for deterministic correctness test
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
        use crate::pir_trait::{PirClient, PirServer};

        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        // Use zero noise for testing trait interface
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

        // Compare with SimplePIR answer size would be: √100 × record_size × 4 = 10 × 32 × 4 = 1280 bytes
        // DoublePIR answer is 10× smaller!
        println!("DoublePIR answer size: {} bytes", answer_size);
        println!("SimplePIR answer would be: {} bytes", 10 * 32 * 4);
    }

    #[test]
    fn test_double_pir_imperfect_square() {
        // 10 records (not a perfect square)
        let records = create_test_records(10, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        // Use zero noise for testing
        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = DoublePirClient::new(setup, params);

        // Test all 10 records
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
    fn test_query_state_indices() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0, // Zero noise for deterministic test
        };
        let mut rng = rand::rng();

        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = DoublePirClient::new(setup, params);

        // Record 4 should be at (row=1, col=1) in a 3×3 grid
        let (state, _) = client.query(4, &mut rng);
        assert_eq!(state.col_idx, 1);
        assert_eq!(state.row_idx, 1);

        // Record 7 should be at (row=2, col=1)
        let (state, _) = client.query(7, &mut rng);
        assert_eq!(state.col_idx, 1);
        assert_eq!(state.row_idx, 2);
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
            n: 128, // Different from setup.lwe_dim (64)
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

        // Create a malformed query with wrong query_col size
        let bad_query = DoublePirQuery {
            query_col: vec![0u32; 5], // Wrong size (should be 3)
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

        // Create a malformed query with wrong query_row size
        let bad_query = DoublePirQuery {
            query_col: vec![0u32; 3],
            query_row: vec![0u32; 5], // Wrong size (should be 3)
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
        let answer = DoublePirAnswer {
            data: vec![100, 200, 300, 400],
        };
        let encoded = bincode::serialize(&answer).unwrap();
        let decoded: DoublePirAnswer = bincode::deserialize(&encoded).unwrap();
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

        // Serialize and deserialize
        let encoded = bincode::serialize(&setup).unwrap();
        let decoded: DoublePirSetup = bincode::deserialize(&encoded).unwrap();

        // Verify all fields
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
        // Test full protocol with serialization at each step
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        // Server creates setup
        let server = DoublePirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        // Simulate network: serialize setup
        let setup_bytes = bincode::serialize(&setup).unwrap();
        let setup_received: DoublePirSetup = bincode::deserialize(&setup_bytes).unwrap();

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
        let answer_received: DoublePirAnswer = bincode::deserialize(&answer_bytes).unwrap();

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

        // Check that serialized sizes roughly match CommunicationCost estimates
        let query_bytes = bincode::serialize(&query).unwrap();
        let answer_bytes = bincode::serialize(&answer).unwrap();
        let setup_bytes = bincode::serialize(&setup).unwrap();

        // The CommunicationCost trait gives the data payload size
        // bincode adds a small overhead (8 bytes per Vec for length prefix)
        let query_cost = query.size_bytes();
        let answer_cost = answer.size_bytes();
        let setup_cost = setup.size_bytes();

        // Serialized size should be close to estimated cost (within 5% for large messages)
        println!("Query: serialized={}, estimated={}", query_bytes.len(), query_cost);
        println!("Answer: serialized={}, estimated={}", answer_bytes.len(), answer_cost);
        println!("Setup: serialized={}, estimated={}", setup_bytes.len(), setup_cost);

        // Allow some overhead for bincode length prefixes
        assert!(query_bytes.len() <= query_cost + 32);
        assert!(answer_bytes.len() <= answer_cost + 16);
        assert!(setup_bytes.len() <= setup_cost + 128);
    }
}


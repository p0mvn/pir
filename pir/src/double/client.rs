//! DoublePIR client implementation.

use rand::Rng;

use crate::{
    double::{DoublePir, DoublePirAnswer, DoublePirQuery, DoublePirSetup},
    params::LweParams,
    pir::{ClientHint, LweMatrix},
    pir_trait::PirClient as PirClientTrait,
    regev::SecretKey,
};

// ============================================================================
// Cross-term Computation
// ============================================================================

/// Compute cross term: Σ_j Σ_k H[j,k] × s_col[j] × s_row[k]
///
/// Simple loop implementation - allows LLVM to auto-vectorize the inner loop.
#[inline]
fn compute_cross_term(h_matrix: &[u32], s_col: &[u32], s_row: &[u32], n: usize) -> u32 {
    let mut result = 0u32;
    for j in 0..n {
        let row_start = j * n;
        let mut row_dot = 0u32;
        for k in 0..n {
            row_dot = row_dot.wrapping_add(h_matrix[row_start + k].wrapping_mul(s_row[k]));
        }
        result = result.wrapping_add(s_col[j].wrapping_mul(row_dot));
    }
    result
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
            setup.hint_cross.len(),
            expected_hint_cross_len,
            "hint_cross length ({}) must equal record_size × n² ({})",
            setup.hint_cross.len(),
            expected_hint_cross_len
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
    pub fn query(
        &self,
        record_idx: usize,
        rng: &mut impl Rng,
    ) -> (DoublePirQueryState, DoublePirQuery) {
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
                crate::regev::encrypt(
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

        let query = DoublePirQuery {
            query_col,
            query_row,
        };

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
                let hint_col_contrib =
                    crate::regev::dot_product(self.hint_col.row(hint_col_idx), &state.secret_col);
                let after_col = ans.wrapping_sub(hint_col_contrib);

                // 2. Remove hint_row contribution: Δ × hint_row[target_col * record_size + byte, :] · s_row
                let hint_row_idx = state.col_idx * self.record_size + byte_idx;
                let hint_row_contrib =
                    crate::regev::dot_product(self.hint_row.row(hint_row_idx), &state.secret_row);
                let after_row = after_col.wrapping_sub(delta.wrapping_mul(hint_row_contrib));

                // 3. Remove cross term: Σ_j Σ_k hint_cross[byte, j, k] × s_col[j] × s_row[k]
                // Optimized as s_col · (H · s_row) using matrix factorization:
                //   Step 1: v = H · s_row (matrix-vector product)
                //   Step 2: result = s_col · v (dot product)
                // This has better cache locality than the naive O(n²) loop.
                let cross_base = byte_idx * n * n;
                let cross_contrib = compute_cross_term(
                    &self.hint_cross[cross_base..cross_base + n * n],
                    &state.secret_col,
                    &state.secret_row,
                    n,
                );
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

    /// Debug: Get the first few elements of A_col matrix
    pub fn get_a_col_data(&self) -> &[u32] {
        &self.a_col.data
    }

    /// Debug: Get the first few elements of A_row matrix
    pub fn get_a_row_data(&self) -> &[u32] {
        &self.a_row.data
    }

    /// Debug: Get hint_col dimensions
    pub fn hint_col_rows(&self) -> usize {
        self.hint_col.rows
    }

    /// Debug: Get hint_row dimensions
    pub fn hint_row_rows(&self) -> usize {
        self.hint_row.rows
    }

    /// Debug: Get first few hint_col values
    pub fn get_hint_col_data(&self) -> &[u32] {
        &self.hint_col.data
    }

    /// Debug: Get hint_row data
    pub fn get_hint_row_data(&self) -> &[u32] {
        &self.hint_row.data
    }

    /// Debug: Get hint_cross data
    pub fn get_hint_cross(&self) -> &[u32] {
        &self.hint_cross
    }

    /// Debug: Get hint_col cols dimension
    pub fn hint_col_cols(&self) -> usize {
        self.hint_col.cols
    }

    /// Debug: Get hint_row cols dimension
    pub fn hint_row_cols(&self) -> usize {
        self.hint_row.cols
    }

    /// Debug: Get delta value
    pub fn delta(&self) -> u32 {
        self.params.delta()
    }

    /// Debug: Get n (LWE dimension)
    pub fn lwe_n(&self) -> usize {
        self.params.n
    }

    /// Debug: Get p (plaintext modulus)
    pub fn lwe_p(&self) -> u32 {
        self.params.p
    }
}

// ============================================================================
// Trait Implementation
// ============================================================================

impl PirClientTrait for DoublePirClient {
    type Protocol = DoublePir;

    fn from_setup(setup: DoublePirSetup, params: LweParams) -> Self {
        DoublePirClient::new(setup, params)
    }

    fn query(
        &self,
        record_idx: usize,
        rng: &mut impl Rng,
    ) -> (DoublePirQueryState, DoublePirQuery) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::double::DoublePirAnswer;
    use crate::matrix_database::DoublePirDatabase;

    fn create_test_records(n: usize, record_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                (0..record_size)
                    .map(|j| ((i * record_size + j) % 256) as u8)
                    .collect()
            })
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
        let a_col = LweMatrix {
            data: vec![0u32; 3 * n],
            rows: 3,
            cols: n,
        };
        let a_row = LweMatrix {
            data: vec![0u32; 3 * n],
            rows: 3,
            cols: n,
        };
        let hint_col = ClientHint {
            data: vec![0u32; 6 * n],
            rows: 6,
            cols: n,
        };
        let hint_row = ClientHint {
            data: vec![0u32; 6 * n],
            rows: 6,
            cols: n,
        };
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
        let answer = DoublePirAnswer {
            data: db.multiply_double(&query.query_col, &query.query_row),
        };

        // With zero hints, recovery should just be round_decode of the answer
        println!("Delta = {}", delta);
        println!("Answer = {:?}", answer.data);
        println!("Expected: Δ × [8, 9] = [{}, {}]", delta * 8, delta * 9);

        let recovered = client.recover(&state, &answer);
        assert_eq!(
            recovered,
            vec![8, 9],
            "Failed to recover with zero matrices"
        );
    }

    #[test]
    fn test_query_state_indices() {
        let records = create_test_records(9, 2);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        let params = LweParams {
            n: 64,
            p: 256,
            noise_stddev: 0.0,
        };
        let mut rng = rand::rng();

        let server = crate::double::DoublePirServer::new(db, &params, &mut rng);
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
}

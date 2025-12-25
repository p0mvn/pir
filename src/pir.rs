use rand::Rng;

/// LWE public matrix A (shared between client and server)
#[derive(Clone)]
pub struct LweMatrix {
    pub data: Vec<u64>, // row-major: A[i][j] = data[i * cols + j]
    pub rows: usize,    // √N (db.cols)
    pub cols: usize,    // n (LWE dimension)
}

/// Client hint: preprocessed db · A
pub struct ClientHint {
    pub data: Vec<u64>, // row-major: hint_c[i][j]
    pub rows: usize,    // db.rows
    pub cols: usize,    // n
}

impl LweMatrix {
    /// Generate random A matrix
    pub fn random(rows: usize, cols: usize, rng: &mut impl Rng) -> Self {
        let data: Vec<u64> = (0..rows * cols)
            .map(|_| rng.random()) // uniform in ℤ_q (q = 2^64 with wrapping)
            .collect();
        Self { data, rows, cols }
    }

    /// Get element A[row, col]
    #[inline]
    pub fn get(&self, row: usize, col: usize) -> u64 {
        self.data[row * self.cols + col]
    }

    /// Get row slice A[row, :]
    #[inline]
    pub fn row(&self, row: usize) -> &[u64] {
        let start = row * self.cols;
        &self.data[start..start + self.cols]
    }
}

impl ClientHint {
    /// Get row slice hint_c[row, :]
    #[inline]
    pub fn row(&self, row: usize) -> &[u64] {
        let start = row * self.cols;
        &self.data[start..start + self.cols]
    }
}

// ============================================================================
// Protocol Messages (what travels between client & server)
// ============================================================================

/// Sent from server to client during setup
pub struct SetupMessage {
    pub a: LweMatrix,
    pub hint_c: ClientHint,
    pub db_cols: usize,     // √N - needed for query generation
    pub db_rows: usize,     // needed for answer interpretation
    pub record_size: usize, // bytes per record
}

/// Client's query (sent to server)
pub struct Query(pub Vec<u64>); // √N elements

/// Server's answer (sent to client)
pub struct Answer(pub Vec<u64>); // db.rows elements

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// 256-bit seed for PRG-based matrix generation
/// Using ChaCha20 for portability, constant-time operation, and strong security
pub type MatrixSeed = [u8; 32];

/// LWE public matrix A (shared between client and server)
/// Can be generated deterministically from a seed using ChaCha20 PRG
#[derive(Clone)]
pub struct LweMatrix {
    pub data: Vec<u32>, // row-major: A[i][j] = data[i * cols + j]
    pub rows: usize,    // √N (db.cols)
    pub cols: usize,    // n (LWE dimension)
}

/// Client hint: preprocessed db · A
pub struct ClientHint {
    pub data: Vec<u32>, // row-major: hint_c[i][j]
    pub rows: usize,    // db.rows
    pub cols: usize,    // n
}

impl LweMatrix {
    /// Generate random A matrix (legacy method, generates fresh randomness)
    pub fn random(rows: usize, cols: usize, rng: &mut impl Rng) -> Self {
        let data: Vec<u32> = (0..rows * cols)
            .map(|_| rng.random()) // uniform in ℤ_q (q = 2^32 with wrapping)
            .collect();
        Self { data, rows, cols }
    }

    /// Generate A matrix deterministically from a seed using ChaCha20 PRG
    /// Both client and server can regenerate the same A from the seed,
    /// eliminating the need to store/transmit the full matrix
    pub fn from_seed(seed: &MatrixSeed, rows: usize, cols: usize) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let data: Vec<u32> = (0..rows * cols)
            .map(|_| rng.random()) // uniform in ℤ_q (q = 2^32 with wrapping)
            .collect();
        Self { data, rows, cols }
    }

    /// Generate a new random seed for matrix generation
    pub fn generate_seed(rng: &mut impl Rng) -> MatrixSeed {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        seed
    }

    /// Get element A[row, col]
    #[inline]
    pub fn get(&self, row: usize, col: usize) -> u32 {
        self.data[row * self.cols + col]
    }

    /// Get row slice A[row, :]
    #[inline]
    pub fn row(&self, row: usize) -> &[u32] {
        let start = row * self.cols;
        &self.data[start..start + self.cols]
    }
}

impl ClientHint {
    /// Get row slice hint_c[row, :]
    #[inline]
    pub fn row(&self, row: usize) -> &[u32] {
        let start = row * self.cols;
        &self.data[start..start + self.cols]
    }
}

// ============================================================================
// Protocol Messages (what travels between client & server)
// ============================================================================

/// Sent from server to client during setup
/// Uses a 32-byte seed instead of full matrix A to save bandwidth
/// Client regenerates A locally from the seed using ChaCha20 PRG
pub struct SetupMessage {
    pub matrix_seed: MatrixSeed, // 32 bytes instead of full A matrix
    pub hint_c: ClientHint,
    pub db_cols: usize,     // √N - needed for query generation (also rows of A)
    pub db_rows: usize,     // needed for answer interpretation
    pub record_size: usize, // bytes per record
    pub lwe_dim: usize,     // n - LWE dimension (cols of A)
}

/// Client's query (sent to server)
pub struct Query(pub Vec<u32>); // √N elements

/// Server's answer (sent to client)
pub struct Answer(pub Vec<u32>); // db.rows elements

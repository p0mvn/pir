use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// 256-bit seed for PRG-based matrix generation
/// Using ChaCha20 for portability, constant-time operation, and strong security
pub type MatrixSeed = [u8; 32];

/// LWE public matrix A (shared between client and server)
/// Can be generated deterministically from a seed using ChaCha20 PRG
#[derive(Clone, Serialize, Deserialize)]
pub struct LweMatrix {
    pub data: Vec<u32>, // row-major: A[i][j] = data[i * cols + j]
    pub rows: usize,    // √N (db.cols)
    pub cols: usize,    // n (LWE dimension)
}

/// Client hint: preprocessed db · A
#[derive(Clone, Serialize, Deserialize)]
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
#[derive(Clone, Serialize, Deserialize)]
pub struct SetupMessage {
    pub matrix_seed: MatrixSeed, // 32 bytes instead of full A matrix
    pub hint_c: ClientHint,
    pub db_cols: usize,     // √N - needed for query generation (also rows of A)
    pub db_rows: usize,     // needed for answer interpretation
    pub record_size: usize, // bytes per record
    pub lwe_dim: usize,     // n - LWE dimension (cols of A)
}

/// Client's query (sent to server)
#[derive(Clone, Serialize, Deserialize)]
pub struct Query(pub Vec<u32>); // √N elements

/// Server's answer (sent to client)
#[derive(Clone, Serialize, Deserialize)]
pub struct Answer(pub Vec<u32>); // db.rows elements

// ============================================================================
// Serialization Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_serialization_roundtrip() {
        let query = Query(vec![1, 2, 3, 4, 5]);
        let encoded = bincode::serialize(&query).unwrap();
        let decoded: Query = bincode::deserialize(&encoded).unwrap();
        assert_eq!(query.0, decoded.0);
    }

    #[test]
    fn test_answer_serialization_roundtrip() {
        let answer = Answer(vec![100, 200, 300]);
        let encoded = bincode::serialize(&answer).unwrap();
        let decoded: Answer = bincode::deserialize(&encoded).unwrap();
        assert_eq!(answer.0, decoded.0);
    }

    #[test]
    fn test_client_hint_serialization_roundtrip() {
        let hint = ClientHint {
            data: vec![1, 2, 3, 4, 5, 6],
            rows: 2,
            cols: 3,
        };
        let encoded = bincode::serialize(&hint).unwrap();
        let decoded: ClientHint = bincode::deserialize(&encoded).unwrap();
        assert_eq!(hint.data, decoded.data);
        assert_eq!(hint.rows, decoded.rows);
        assert_eq!(hint.cols, decoded.cols);
    }

    #[test]
    fn test_setup_message_serialization_roundtrip() {
        let setup = SetupMessage {
            matrix_seed: [42u8; 32],
            hint_c: ClientHint {
                data: vec![1, 2, 3, 4],
                rows: 2,
                cols: 2,
            },
            db_cols: 10,
            db_rows: 20,
            record_size: 32,
            lwe_dim: 1024,
        };
        let encoded = bincode::serialize(&setup).unwrap();
        let decoded: SetupMessage = bincode::deserialize(&encoded).unwrap();
        assert_eq!(setup.matrix_seed, decoded.matrix_seed);
        assert_eq!(setup.hint_c.data, decoded.hint_c.data);
        assert_eq!(setup.db_cols, decoded.db_cols);
        assert_eq!(setup.db_rows, decoded.db_rows);
        assert_eq!(setup.record_size, decoded.record_size);
        assert_eq!(setup.lwe_dim, decoded.lwe_dim);
    }

    #[test]
    fn test_query_serialization_size() {
        // Query with √N = 100 elements should be ~400 bytes + overhead
        let query = Query(vec![0u32; 100]);
        let encoded = bincode::serialize(&query).unwrap();
        // bincode: 8 bytes for length prefix + 400 bytes for data
        assert_eq!(encoded.len(), 8 + 100 * 4);
    }

    #[test]
    fn test_answer_serialization_size() {
        // Answer with 320 elements (√N × record_size for SimplePIR)
        let answer = Answer(vec![0u32; 320]);
        let encoded = bincode::serialize(&answer).unwrap();
        assert_eq!(encoded.len(), 8 + 320 * 4);
    }

    #[test]
    fn test_lwe_matrix_serialization_roundtrip() {
        let matrix = LweMatrix {
            data: vec![1, 2, 3, 4, 5, 6],
            rows: 2,
            cols: 3,
        };
        let encoded = bincode::serialize(&matrix).unwrap();
        let decoded: LweMatrix = bincode::deserialize(&encoded).unwrap();
        assert_eq!(matrix.data, decoded.data);
        assert_eq!(matrix.rows, decoded.rows);
        assert_eq!(matrix.cols, decoded.cols);
    }
}

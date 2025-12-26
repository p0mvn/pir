use rand::Rng;
use rayon::prelude::*;

use crate::{
    matrix_database::MatrixDatabase,
    params::LweParams,
    pir::{Answer, ClientHint, LweMatrix, MatrixSeed, Query},
};

/// Server state
pub struct PirServer {
    db: MatrixDatabase,
    matrix_seed: MatrixSeed,
    a: LweMatrix,
    lwe_dim: usize,
}

impl PirServer {
    /// Create a new server with the given database
    /// Generates a seed and derives matrix A from it using ChaCha20 PRG
    pub fn new(db: MatrixDatabase, params: &LweParams, rng: &mut impl Rng) -> Self {
        let matrix_seed = LweMatrix::generate_seed(rng);
        let a = LweMatrix::from_seed(&matrix_seed, db.cols, params.n);
        Self {
            db,
            matrix_seed,
            a,
            lwe_dim: params.n,
        }
    }

    /// Get the setup message to send to the client
    /// Contains seed (32 bytes) instead of full A matrix, plus hint_c = DB · A
    pub fn setup_message(&self) -> crate::pir::SetupMessage {
        let hint_c = self.compute_hint();
        crate::pir::SetupMessage {
            matrix_seed: self.matrix_seed,
            hint_c,
            db_cols: self.db.cols,
            db_rows: self.db.rows,
            record_size: self.db.record_size,
            lwe_dim: self.lwe_dim,
        }
    }

    /// Matrix multiplication: DB · A
    /// (db.rows × db.cols) · (db.cols × n) → (db.rows × n)
    /// Parallelized over rows using rayon
    pub fn compute_hint(&self) -> ClientHint {
        assert_eq!(self.db.cols, self.a.rows, "Inner dimensions must match");

        let rows = self.db.rows;
        let cols = self.a.cols; // n
        let inner = self.db.cols; // √N

        // Parallel computation: each row is independent
        // Compute all rows in parallel, then flatten
        let row_results: Vec<Vec<u32>> = (0..rows)
            .into_par_iter()
            .map(|i| {
                (0..cols)
                    .map(|j| {
                        let mut sum = 0u32;
                        for k in 0..inner {
                            // hint_c[i,j] += db[i,k] * A[k,j]
                            let db_val = self.db.data[i * self.db.cols + k] as u32;
                            let a_val = self.a.get(k, j);
                            sum = sum.wrapping_add(db_val.wrapping_mul(a_val));
                        }
                        sum
                    })
                    .collect()
            })
            .collect();

        // Flatten row vectors into single data vector
        let data: Vec<u32> = row_results.into_iter().flatten().collect();

        ClientHint { data, rows, cols }
    }

    /// Answer: compute DB · query
    pub fn answer(&self, query: &Query) -> Answer {
        let mut out = vec![0u32; self.db.rows];
        self.answer_into(query, &mut out);
        Answer(out)
    }

    /// Answer into a caller-provided buffer (avoids allocation; useful for throughput benchmarks).
    pub fn answer_into(&self, query: &Query, out: &mut [u32]) {
        self.db.multiply_vec_into(&query.0, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix_database::MatrixDatabase;

    /// Helper to create a server with a specific A matrix (for testing)
    fn test_server_with_matrix(db: MatrixDatabase, a: LweMatrix) -> PirServer {
        PirServer {
            db,
            matrix_seed: [0u8; 32], // dummy seed for tests
            a,
            lwe_dim: 2,
        }
    }

    #[test]
    fn test_compute_hint_small_matrix() {
        // Create a 2×2 database (4 records of 1 byte each)
        // Layout:
        //   col0  col1
        //   1     2
        //   3     4
        let records: Vec<Vec<u8>> = vec![vec![1], vec![2], vec![3], vec![4]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        assert_eq!(db.rows, 2);
        assert_eq!(db.cols, 2);

        // Create A matrix (2×2 for n=2)
        // A = [[5, 6],
        //      [7, 8]]
        let a = LweMatrix {
            data: vec![5, 6, 7, 8],
            rows: 2,
            cols: 2,
        };

        let server = test_server_with_matrix(db, a);

        let hint = server.compute_hint();

        // hint_c = DB · A
        // [[1, 2],    [[5, 6],     [[1*5+2*7, 1*6+2*8],     [[19, 22],
        //  [3, 4]]  ·  [7, 8]]  =   [3*5+4*7, 3*6+4*8]]  =   [43, 50]]

        assert_eq!(hint.rows, 2);
        assert_eq!(hint.cols, 2);
        assert_eq!(hint.data, vec![19, 22, 43, 50]);
    }

    #[test]
    fn test_compute_hint_identity_matrix() {
        // When A is identity, hint_c should equal DB (useful sanity check)
        let records: Vec<Vec<u8>> = vec![vec![10], vec![20], vec![30], vec![40]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        // Identity matrix A = I₂
        let a = LweMatrix {
            data: vec![1, 0, 0, 1],
            rows: 2,
            cols: 2,
        };

        let server = test_server_with_matrix(db, a);

        let hint = server.compute_hint();

        // DB · I = DB
        // DB layout: [[10, 20], [30, 40]]
        assert_eq!(hint.data, vec![10, 20, 30, 40]);
    }

    #[test]
    fn test_compute_hint_rectangular() {
        // DB: 2×2, A: 2×3 → hint_c: 2×3
        // Tests non-square output (realistic case where n ≠ √N)
        let records: Vec<Vec<u8>> = vec![vec![1], vec![2], vec![3], vec![4]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        // A: 2×3
        // [[1, 2, 3],
        //  [4, 5, 6]]
        let a = LweMatrix {
            data: vec![1, 2, 3, 4, 5, 6],
            rows: 2,
            cols: 3,
        };

        let server = test_server_with_matrix(db, a);

        let hint = server.compute_hint();

        // [[1, 2],    [[1, 2, 3],     [[1*1+2*4, 1*2+2*5, 1*3+2*6],     [[9, 12, 15],
        //  [3, 4]]  ·  [4, 5, 6]]  =   [3*1+4*4, 3*2+4*5, 3*3+4*6]]  =   [19, 26, 33]]

        assert_eq!(hint.rows, 2);
        assert_eq!(hint.cols, 3);
        assert_eq!(hint.data, vec![9, 12, 15, 19, 26, 33]);
    }

    #[test]
    fn test_answer_unit_vector_selects_column() {
        // Database layout (4 records of 2 bytes each):
        //        col0  col1
        // row 0:  10    20    (byte 0 of records 0,1)
        // row 1:  11    21    (byte 1 of records 0,1)
        // row 2:  30    40    (byte 0 of records 2,3)
        // row 3:  31    41    (byte 1 of records 2,3)
        let records: Vec<Vec<u8>> = vec![
            vec![10, 11], // record 0
            vec![20, 21], // record 1
            vec![30, 31], // record 2
            vec![40, 41], // record 3
        ];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 2);

        // Dummy A (not used by answer)
        let a = LweMatrix {
            data: vec![0; db.cols * 2],
            rows: db.cols,
            cols: 2,
        };

        let server = test_server_with_matrix(db, a);

        // Unit vector selecting column 1: [0, 1]
        // NOTE: this query is in plaintext.
        // Actual protocol obfuscates the query with encryption
        // and multiplies the encrypted query with the database
        let query = Query(vec![0, 1]);
        let answer = server.answer(&query);

        // Should return column 1: [20, 21, 40, 41]
        assert_eq!(answer.0, vec![20, 21, 40, 41]);
    }

    #[test]
    fn test_seeded_matrix_generation() {
        // Verify that the same seed produces the same matrix
        let seed: MatrixSeed = [42u8; 32];
        let a1 = LweMatrix::from_seed(&seed, 10, 8);
        let a2 = LweMatrix::from_seed(&seed, 10, 8);
        assert_eq!(
            a1.data, a2.data,
            "Same seed should produce identical matrix"
        );

        // Different seeds should produce different matrices
        let seed2: MatrixSeed = [43u8; 32];
        let a3 = LweMatrix::from_seed(&seed2, 10, 8);
        assert_ne!(
            a1.data, a3.data,
            "Different seeds should produce different matrices"
        );
    }
}

//! Hint computation for DoublePIR.
//!
//! DoublePIR requires three hints for correct decryption:
//! - hint_col: for canceling the H_col · s_col term
//! - hint_row: for canceling the Δ × H_row · s_row term
//! - hint_cross: for canceling the (H_col · s_col) × (A₂ · s_row) cross term

use rayon::prelude::*;

use crate::{
    matrix_database::DoublePirDatabase,
    pir::{ClientHint, LweMatrix},
};

/// Trait for hint computation operations.
///
/// This allows for potential alternative implementations (e.g., GPU-accelerated).
pub trait HintComputation {
    /// Compute first hint: for each (row, byte), compute sum over cols of DB[row][col][byte] * A₁[col, :]
    fn compute_hint_col(db: &DoublePirDatabase, a_col: &LweMatrix) -> ClientHint;

    /// Compute second hint: for each (col, byte), compute sum over rows of DB[row][col][byte] * A₂[row, :]
    fn compute_hint_row(db: &DoublePirDatabase, a_row: &LweMatrix) -> ClientHint;

    /// Compute cross hint: for each (byte, j, k), compute Σ_row H_col[row, byte, j] × A₂[row, k]
    fn compute_hint_cross(
        db: &DoublePirDatabase,
        hint_col: &ClientHint,
        a_row: &LweMatrix,
        lwe_dim: usize,
    ) -> Vec<u32>;
}

/// Default CPU-based parallel hint computation using rayon.
pub struct CpuHintComputation;

impl HintComputation for CpuHintComputation {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_records(n: usize, record_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                (0..record_size)
                    .map(|j| ((i * record_size + j) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn test_hint_col_dimensions() {
        let records = create_test_records(9, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        let lwe_dim = 64;
        let a_col = LweMatrix {
            data: vec![1u32; db.num_cols * lwe_dim],
            rows: db.num_cols,
            cols: lwe_dim,
        };

        let hint_col = CpuHintComputation::compute_hint_col(&db, &a_col);

        // hint_col: (num_rows * record_size) × lwe_dim = (3 * 4) × 64 = 12 × 64
        assert_eq!(hint_col.rows, 3 * 4);
        assert_eq!(hint_col.cols, 64);
    }

    #[test]
    fn test_hint_row_dimensions() {
        let records = create_test_records(9, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        let lwe_dim = 64;
        let a_row = LweMatrix {
            data: vec![1u32; db.num_rows * lwe_dim],
            rows: db.num_rows,
            cols: lwe_dim,
        };

        let hint_row = CpuHintComputation::compute_hint_row(&db, &a_row);

        // hint_row: (num_cols * record_size) × lwe_dim = (3 * 4) × 64 = 12 × 64
        assert_eq!(hint_row.rows, 3 * 4);
        assert_eq!(hint_row.cols, 64);
    }

    #[test]
    fn test_hint_cross_dimensions() {
        let records = create_test_records(9, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        let lwe_dim = 8; // Small for testing
        let a_col = LweMatrix {
            data: vec![1u32; db.num_cols * lwe_dim],
            rows: db.num_cols,
            cols: lwe_dim,
        };
        let a_row = LweMatrix {
            data: vec![1u32; db.num_rows * lwe_dim],
            rows: db.num_rows,
            cols: lwe_dim,
        };

        let hint_col = CpuHintComputation::compute_hint_col(&db, &a_col);
        let hint_cross = CpuHintComputation::compute_hint_cross(&db, &hint_col, &a_row, lwe_dim);

        // hint_cross: record_size × lwe_dim × lwe_dim = 4 × 8 × 8 = 256
        assert_eq!(hint_cross.len(), 4 * 8 * 8);
    }
}

#[derive(Clone)]
pub struct MatrixDatabase {
    /// Database payload stored compactly (one byte per plaintext element).
    ///
    /// This is critical for paper-comparable throughput: for "1-bit entries" we
    /// pack 8 bits into one byte-sized plaintext element (p≈256 regime), so a
    /// 1GiB database is actually ~1GiB in memory, not 4GiB.
    pub data: Vec<u8>,
    pub rows: usize,
    pub cols: usize,
    /// Bytes per record
    pub record_size: usize,
    /// Number of record columns (√N)
    pub records_per_group: usize,
    /// Original number of records
    pub num_records: usize,
}

/// Matrix database structure designed for Private Information Retrieval (PIR)
/// using the "square root trick" to reduce communication complexity.
/// Instead of storing N records in a linear array (which would require O(N) query size),
/// records are arranged in a √N × √N matrix. This enables PIR queries with only O(√N) communication.
///
/// Visual example with 9 records (3 bytes each):
///          col 0    col 1    col 2
//         ┌────────┬────────┬────────┐
// group 0 │ R0[0]  │ R1[0]  │ R2[0]  │  row (byte) 0
//         │ R0[1]  │ R1[1]  │ R2[1]  │  row (byte) 1
//         │ R0[2]  │ R1[2]  │ R2[2]  │  row (byte) 2
//         ├────────┼────────┼────────┤
// group 1 │ R3[0]  │ R4[0]  │ R5[0]  │  row (byte) 3
//         │ R3[1]  │ R4[1]  │ R5[1]  │  row (byte) 4
//         │ R3[2]  │ R4[2]  │ R5[2]  │  row (byte) 5
//         ├────────┼────────┼────────┤
// group 2 │ R6[0]  │ R7[0]  │ R8[0]  │  row (byte) 6
//         │ R6[1]  │ R7[1]  │ R8[1]  │  row (byte) 7
//         │ R6[2]  │ R7[2]  │ R8[2]  │  row (byte) 8
//         └────────┴────────┴────────┘
impl MatrixDatabase {
    /// Create database with configurable record size
    pub fn new(records: &[&[u8]], record_size: usize) -> Self {
        let num_records = records.len();

        // √N columns (one per record in a group)
        let records_per_group = (num_records as f64).sqrt().ceil() as usize;

        // Number of row "bands"
        // It can differ from the number of columns when N is not a perfect square.
        let num_groups = (num_records + records_per_group - 1) / records_per_group;

        let cols = records_per_group;
        let rows = record_size * num_groups;

        let mut data = vec![0u8; rows * cols];

        for (rec_idx, record) in records.iter().enumerate() {
            let group = rec_idx / records_per_group;
            let col = rec_idx % records_per_group;

            for (byte_idx, &byte) in record.iter().take(record_size).enumerate() {
                let row = group * record_size + byte_idx;
                data[row * cols + col] = byte;
            }
        }

        Self {
            data,
            rows,
            cols,
            record_size,
            records_per_group,
            num_records,
        }
    }

    /// Create a database of `num_records` records (each `record_size` bytes),
    /// filling values deterministically from a seed without constructing a giant
    /// `Vec<Vec<u8>>`.
    ///
    /// This exists primarily to support paper-like benchmarks at 1GiB scale.
    pub fn new_generated(num_records: usize, record_size: usize, seed: u64) -> Self {
        use rand::Rng;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let records_per_group = (num_records as f64).sqrt().ceil() as usize;
        let num_groups = (num_records + records_per_group - 1) / records_per_group;

        let cols = records_per_group;
        let rows = record_size * num_groups;

        let mut rng = {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&seed.to_le_bytes());
            ChaCha20Rng::from_seed(s)
        };

        // Fill row-major; for record_size==1 this matches record index ordering.
        let mut data = vec![0u8; rows * cols];
        for idx in 0..rows * cols {
            data[idx] = rng.random();
        }

        Self {
            data,
            rows,
            cols,
            record_size,
            records_per_group,
            num_records,
        }
    }

    /// Convert record index to (row_band_start, col)
    pub fn record_to_coords(&self, record_idx: usize) -> (usize, usize) {
        assert!(record_idx < self.num_records, "Record index out of bounds");
        let group = record_idx / self.records_per_group;
        let col = record_idx % self.records_per_group;
        let row_start = group * self.record_size;
        (row_start, col)
    }

    /// Extract a full record from the answer column
    pub fn extract_record(&self, answer: &[u32], record_idx: usize) -> Vec<u8> {
        assert!(record_idx < self.num_records, "Record index out of bounds");
        let (row_start, _) = self.record_to_coords(record_idx);
        answer[row_start..row_start + self.record_size]
            .iter()
            .map(|&x| x as u8)
            .collect()
    }

    /// Matrix-vector multiply
    /// Note: NOT parallelized — rayon overhead exceeds benefit for µs-scale operations
    pub fn multiply_vec(&self, query: &[u32]) -> Vec<u32> {
        let mut out = vec![0u32; self.rows];
        self.multiply_vec_into(query, &mut out);
        out
    }

    /// Matrix-vector multiply into a caller-provided buffer (to avoid per-call allocation).
    pub fn multiply_vec_into(&self, query: &[u32], out: &mut [u32]) {
        assert_eq!(query.len(), self.cols, "Query length must match columns");
        assert_eq!(out.len(), self.rows, "Output length must match rows");

        for row in 0..self.rows {
            let base = row * self.cols;
            let mut sum = 0u32;
            for col in 0..self.cols {
                let db_val = self.data[base + col] as u32;
                sum = sum.wrapping_add(db_val.wrapping_mul(query[col]));
            }
            out[row] = sum;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_square_9_records() {
        // 9 records of 2 bytes each: [0,1], [2,3], [4,5], ...
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = MatrixDatabase::new(&record_refs, 2);

        // √9 = 3, so 3 columns, 3 groups
        assert_eq!(db.cols, 3, "should have 3 columns");
        assert_eq!(db.records_per_group, 3);
        assert_eq!(db.rows, 6, "3 groups × 2 bytes = 6 rows");
        assert_eq!(db.num_records, 9);

        // Verify layout:
        //          col0   col1   col2
        // group 0: R0     R1     R2      (rows 0-1)
        // group 1: R3     R4     R5      (rows 2-3)
        // group 2: R6     R7     R8      (rows 4-5)

        // R0 = [0,1] at column 0, rows 0-1
        assert_eq!(db.data[0 * 3 + 0], 0); // row 0, col 0
        assert_eq!(db.data[1 * 3 + 0], 1); // row 1, col 0

        // R4 = [8,9] at column 1, rows 2-3 (group 1)
        assert_eq!(db.data[2 * 3 + 1], 8); // row 2, col 1
        assert_eq!(db.data[3 * 3 + 1], 9); // row 3, col 1

        // R8 = [16,17] at column 2, rows 4-5 (group 2)
        assert_eq!(db.data[4 * 3 + 2], 16); // row 4, col 2
        assert_eq!(db.data[5 * 3 + 2], 17); // row 5, col 2
    }

    #[test]
    fn test_imperfect_square_10_records() {
        // 10 records of 2 bytes each
        let records: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = MatrixDatabase::new(&record_refs, 2);

        // √10 ≈ 3.16, ceil = 4 columns
        // num_groups = ceil(10/4) = 3 groups
        assert_eq!(db.cols, 4, "ceil(√10) = 4 columns");
        assert_eq!(db.records_per_group, 4);
        assert_eq!(db.rows, 6, "3 groups × 2 bytes = 6 rows");
        assert_eq!(db.num_records, 10);

        // Verify layout:
        //          col0   col1   col2   col3
        // group 0: R0     R1     R2     R3      (rows 0-1)
        // group 1: R4     R5     R6     R7      (rows 2-3)
        // group 2: R8     R9     (0)    (0)     (rows 4-5)

        // R0 = [0,1] at column 0
        assert_eq!(db.data[0 * 4 + 0], 0);
        assert_eq!(db.data[1 * 4 + 0], 1);

        // R7 = [14,15] at column 3, group 1 (rows 2-3)
        assert_eq!(db.data[2 * 4 + 3], 14);
        assert_eq!(db.data[3 * 4 + 3], 15);

        // R9 = [18,19] at column 1, group 2 (rows 4-5)
        assert_eq!(db.data[4 * 4 + 1], 18);
        assert_eq!(db.data[5 * 4 + 1], 19);

        // Empty slots (col 2,3 in group 2) should be 0
        assert_eq!(db.data[4 * 4 + 2], 0);
        assert_eq!(db.data[4 * 4 + 3], 0);
    }

    #[test]
    fn test_record_to_coords() {
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = MatrixDatabase::new(&record_refs, 2);

        assert_eq!(db.record_to_coords(0), (0, 0));
        assert_eq!(db.record_to_coords(1), (0, 1));
        assert_eq!(db.record_to_coords(2), (0, 2));
        assert_eq!(db.record_to_coords(3), (2, 0));
        assert_eq!(db.record_to_coords(4), (2, 1));
        assert_eq!(db.record_to_coords(5), (2, 2));
        assert_eq!(db.record_to_coords(6), (4, 0));
        assert_eq!(db.record_to_coords(7), (4, 1));
        assert_eq!(db.record_to_coords(8), (4, 2));
    }

    #[test]
    fn test_extract_record() {
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = MatrixDatabase::new(&record_refs, 2);

        let answer = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(db.extract_record(&answer, 0), vec![0, 1]);

        // group = 7 / 2 (index / records per group)
        // index = 2 * 2 = 4 (row start)
        assert_eq!(db.extract_record(&answer, 7), vec![4, 5]);
    }

    #[test]
    fn test_multiply_vec_unit_vector_selects_column() {
        // This is THE core PIR operation: unit vector selects a column
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 2);

        // Layout (2 bytes per record, 3 cols):
        //          col0   col1   col2
        // row 0:   0      2      4      (byte 0 of R0, R1, R2)
        // row 1:   1      3      5      (byte 1 of R0, R1, R2)
        // row 2:   6      8      10     (byte 0 of R3, R4, R5)
        // row 3:   7      9      11     (byte 1 of R3, R4, R5)
        // row 4:   12     14     16     (byte 0 of R6, R7, R8)
        // row 5:   13     15     17     (byte 1 of R6, R7, R8)

        // Select column 0 with unit vector [1, 0, 0]
        let query_col0 = vec![1u32, 0, 0];
        let result = db.multiply_vec(&query_col0);
        assert_eq!(result, vec![0, 1, 6, 7, 12, 13]);

        // Select column 1 with unit vector [0, 1, 0]
        let query_col1 = vec![0u32, 1, 0];
        let result = db.multiply_vec(&query_col1);
        assert_eq!(result, vec![2, 3, 8, 9, 14, 15]);

        // Select column 2 with unit vector [0, 0, 1]
        let query_col2 = vec![0u32, 0, 1];
        let result = db.multiply_vec(&query_col2);
        assert_eq!(result, vec![4, 5, 10, 11, 16, 17]);
    }

    #[test]
    fn test_multiply_vec_zero_vector() {
        let records: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8]).collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        let zero_query = vec![0u32; db.cols];
        let result = db.multiply_vec(&zero_query);

        assert!(result.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_multiply_vec_all_ones() {
        // All-ones vector sums each row
        let records: Vec<Vec<u8>> = vec![vec![1], vec![2], vec![3], vec![4]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        // 4 records → 2×2 matrix:
        //   col0  col1
        //   1     2      → row sum = 3
        //   3     4      → row sum = 7

        let ones = vec![1u32; db.cols];
        let result = db.multiply_vec(&ones);

        assert_eq!(result, vec![3, 7]);
    }

    #[test]
    fn test_multiply_vec_scaled_selection() {
        // Selecting column with scalar > 1 scales the result
        let records: Vec<Vec<u8>> = vec![vec![10], vec![20], vec![30], vec![40]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        // Matrix:
        //   10    20
        //   30    40

        // Select col 0, scaled by 3
        let query = vec![3u32, 0];
        let result = db.multiply_vec(&query);
        assert_eq!(result, vec![30, 90]); // [10*3, 30*3]

        // Select col 1, scaled by 2
        let query = vec![0u32, 2];
        let result = db.multiply_vec(&query);
        assert_eq!(result, vec![40, 80]); // [20*2, 40*2]
    }

    #[test]
    fn test_multiply_vec_wrapping_arithmetic() {
        // Verify wrapping behavior for large values
        let records: Vec<Vec<u8>> = vec![vec![255], vec![255], vec![255], vec![255]];
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        // Large multiplier that would overflow without wrapping
        let large = u32::MAX / 2;
        let query = vec![large, 0];
        let result = db.multiply_vec(&query);

        // Should wrap correctly: 255 * (u32::MAX/2)
        let expected = 255u32.wrapping_mul(large);
        assert_eq!(result[0], expected);
    }

    #[test]
    fn test_multiply_vec_dimensions() {
        let records: Vec<Vec<u8>> = (0..16).map(|i| vec![i as u8, i as u8]).collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 2);

        let query = vec![1u32; db.cols];
        let result = db.multiply_vec(&query);

        // Result should have `rows` elements
        assert_eq!(result.len(), db.rows);
    }

    #[test]
    #[should_panic]
    fn test_multiply_vec_wrong_query_size() {
        let records: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8]).collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 1);

        // Wrong size query should panic
        let bad_query = vec![1u32; db.cols + 1];
        db.multiply_vec(&bad_query);
    }
}

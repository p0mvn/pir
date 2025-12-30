// ============================================================================
// SimplePIR Database Layout
// ============================================================================

#[derive(Clone)]
pub struct MatrixDatabase {
    pub data: Vec<u32>,
    pub rows: usize,
    pub cols: usize,
    /// Bytes per record
    pub record_size: usize,
    /// Number of record columns (√N)
    pub records_per_group: usize,
    /// Original number of records
    pub num_records: usize,
}

// ============================================================================
// DoublePIR Database Layout
// ============================================================================

/// Database layout optimized for DoublePIR.
///
/// DoublePIR reduces answer size by applying PIR twice:
/// 1. First query selects a "column" of records → intermediate result
/// 2. Second query selects a "row" from that → final record
///
/// ## Layout
///
/// Records are arranged in a √N × √N grid. Each cell contains one record.
/// Physically stored as a 3D array flattened to 1D:
///   `data[row][col][byte]` where:
///   - `row` ∈ [0, √N) — which row of records
///   - `col` ∈ [0, √N) — which column of records  
///   - `byte` ∈ [0, record_size) — byte within record
///
/// ## Visual Example (9 records, 2 bytes each)
///
/// Logical √N × √N grid of records:
/// ```text
///          col 0    col 1    col 2
///        ┌────────┬────────┬────────┐
/// row 0  │  R0    │  R1    │  R2    │
///        ├────────┼────────┼────────┤
/// row 1  │  R3    │  R4    │  R5    │
///        ├────────┼────────┼────────┤
/// row 2  │  R6    │  R7    │  R8    │
///        └────────┴────────┴────────┘
/// ```
///
/// Physical storage (row-major, bytes interleaved):
/// For each row of records, store all bytes consecutively:
/// ```text
/// Row 0: [R0[0], R0[1], R1[0], R1[1], R2[0], R2[1]]
/// Row 1: [R3[0], R3[1], R4[0], R4[1], R5[0], R5[1]]
/// Row 2: [R6[0], R6[1], R7[0], R7[1], R8[0], R8[1]]
/// ```
///
/// ## DoublePIR Operations
///
/// **First multiplication** (query1 selects column):
/// - query1 = encrypted unit vector of length √N (selects column c)
/// - For each (row, byte): result[row][byte] = Σ_col data[row][col][byte] × query1[col]
/// - Result: √N × record_size values (one column of records)
///
/// **Second multiplication** (query2 selects row):
/// - query2 = encrypted unit vector of length √N (selects row r)
/// - For each byte: result[byte] = Σ_row intermediate[row][byte] × query2[row]
/// - Result: record_size values (one record)
///
/// ## Comparison with SimplePIR
///
/// | Aspect | SimplePIR | DoublePIR |
/// |--------|-----------|-----------|
/// | Query size | √N | 2×√N |
/// | Answer size | √N × record_size | ~n (LWE dimension) |
/// | Server work | 1 matmul | 2 matmuls |
///
#[derive(Clone)]
pub struct DoublePirDatabase {
    /// Flattened 3D data: data[row * cols * record_size + col * record_size + byte]
    pub data: Vec<u32>,
    /// √N — number of record rows
    pub num_rows: usize,
    /// √N — number of record columns
    pub num_cols: usize,
    /// Bytes per record
    pub record_size: usize,
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

        let mut data = vec![0u32; rows * cols];

        for (rec_idx, record) in records.iter().enumerate() {
            let group = rec_idx / records_per_group;
            let col = rec_idx % records_per_group;

            for (byte_idx, &byte) in record.iter().take(record_size).enumerate() {
                let row = group * record_size + byte_idx;
                data[row * cols + col] = byte as u32;
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

    /// Convert record index to (row_band_start, col)
    pub fn record_to_coords(&self, record_idx: usize) -> (usize, usize) {
        assert!(record_idx < self.num_records, "Record index out of bounds");
        let group = record_idx / self.records_per_group;
        let col = record_idx % self.records_per_group;
        let row_start = group * self.record_size;
        (row_start, col)
    }

    /// Extract a full record from the answer column
    pub fn extract_record(&self, answer: &[u32], record_idx: usize) -> Vec<u32> {
        assert!(record_idx < self.num_records, "Record index out of bounds");
        let (row_start, _) = self.record_to_coords(record_idx);
        answer[row_start..row_start + self.record_size].to_vec()
    }

    /// Matrix-vector multiply
    /// Note: NOT parallelized — rayon overhead exceeds benefit for µs-scale operations
    pub fn multiply_vec(&self, query: &[u32]) -> Vec<u32> {
        assert_eq!(query.len(), self.cols, "Query length must match columns");
        let mut result = vec![0u32; self.rows];
        for row in 0..self.rows {
            let mut sum = 0u32;
            for col in 0..self.cols {
                sum = sum.wrapping_add(self.data[row * self.cols + col].wrapping_mul(query[col]));
            }
            result[row] = sum;
        }
        result
    }

    /// Convert to DoublePIR database layout
    /// This reinterprets the same data for DoublePIR's two-stage query
    pub fn to_double_pir(&self) -> DoublePirDatabase {
        DoublePirDatabase::from_simple_pir(self)
    }
}

// ============================================================================
// DoublePIR Database Implementation
// ============================================================================

impl DoublePirDatabase {
    /// Create database from raw records.
    ///
    /// Records are arranged in a √N × √N grid.
    pub fn new(records: &[&[u8]], record_size: usize) -> Self {
        let num_records = records.len();

        // √N for both dimensions
        let sqrt_n = (num_records as f64).sqrt().ceil() as usize;
        let num_rows = (num_records + sqrt_n - 1) / sqrt_n; // ceil(N / √N)
        let num_cols = sqrt_n;

        // Storage: num_rows × num_cols × record_size
        let mut data = vec![0u32; num_rows * num_cols * record_size];

        for (rec_idx, record) in records.iter().enumerate() {
            let row = rec_idx / num_cols;
            let col = rec_idx % num_cols;

            for (byte_idx, &byte) in record.iter().take(record_size).enumerate() {
                let idx = row * num_cols * record_size + col * record_size + byte_idx;
                data[idx] = byte as u32;
            }
        }

        Self {
            data,
            num_rows,
            num_cols,
            record_size,
            num_records,
        }
    }

    /// Convert from SimplePIR database layout.
    ///
    /// SimplePIR stores: (groups × record_size) rows × √N cols
    /// DoublePIR stores: √N rows × √N cols × record_size bytes
    pub fn from_simple_pir(simple: &MatrixDatabase) -> Self {
        let num_records = simple.num_records;
        let record_size = simple.record_size;
        let num_cols = simple.cols; // √N
        let num_groups = simple.rows / record_size;
        let num_rows = num_groups;

        let mut data = vec![0u32; num_rows * num_cols * record_size];

        // SimplePIR: data[group * record_size + byte_idx][col]
        // DoublePIR: data[row][col][byte_idx]
        for row in 0..num_rows {
            for col in 0..num_cols {
                for byte_idx in 0..record_size {
                    let simple_row = row * record_size + byte_idx;
                    let simple_idx = simple_row * simple.cols + col;
                    let double_idx = row * num_cols * record_size + col * record_size + byte_idx;
                    data[double_idx] = simple.data[simple_idx];
                }
            }
        }

        Self {
            data,
            num_rows,
            num_cols,
            record_size,
            num_records,
        }
    }

    /// Convert record index to (row, col) in the record grid.
    pub fn record_to_coords(&self, record_idx: usize) -> (usize, usize) {
        assert!(record_idx < self.num_records, "Record index out of bounds");
        let row = record_idx / self.num_cols;
        let col = record_idx % self.num_cols;
        (row, col)
    }

    /// Get a single byte from the database.
    #[inline]
    pub fn get(&self, row: usize, col: usize, byte_idx: usize) -> u32 {
        debug_assert!(row < self.num_rows);
        debug_assert!(col < self.num_cols);
        debug_assert!(byte_idx < self.record_size);
        self.data[row * self.num_cols * self.record_size + col * self.record_size + byte_idx]
    }

    /// Get an entire record at (row, col).
    pub fn get_record(&self, row: usize, col: usize) -> &[u32] {
        let start = row * self.num_cols * self.record_size + col * self.record_size;
        &self.data[start..start + self.record_size]
    }

    /// First-level multiplication for DoublePIR.
    ///
    /// Computes: for each (row, byte): result[row][byte] = Σ_col data[row][col][byte] × query[col]
    ///
    /// # Arguments
    /// * `query` - Encrypted unit vector of length √N selecting a column
    ///
    /// # Returns
    /// Intermediate matrix of shape (√N rows) × (record_size bytes)
    /// Flattened as: result[row * record_size + byte]
    pub fn multiply_first(&self, query: &[u32]) -> Vec<u32> {
        assert_eq!(
            query.len(),
            self.num_cols,
            "Query length must match number of columns"
        );

        let mut result = vec![0u32; self.num_rows * self.record_size];

        for row in 0..self.num_rows {
            for byte_idx in 0..self.record_size {
                let mut sum = 0u32;
                for col in 0..self.num_cols {
                    let val = self.get(row, col, byte_idx);
                    sum = sum.wrapping_add(val.wrapping_mul(query[col]));
                }
                result[row * self.record_size + byte_idx] = sum;
            }
        }

        result
    }

    /// Second-level multiplication for DoublePIR.
    ///
    /// Computes: for each byte: result[byte] = Σ_row intermediate[row][byte] × query[row]
    ///
    /// # Arguments
    /// * `intermediate` - Result from first multiplication, shape (√N) × record_size
    /// * `query` - Encrypted unit vector of length √N selecting a row
    ///
    /// # Returns
    /// Final result of shape record_size (one record's worth of bytes)
    pub fn multiply_second(&self, intermediate: &[u32], query: &[u32]) -> Vec<u32> {
        assert_eq!(
            intermediate.len(),
            self.num_rows * self.record_size,
            "Intermediate size mismatch"
        );
        assert_eq!(
            query.len(),
            self.num_rows,
            "Query length must match number of rows"
        );

        let mut result = vec![0u32; self.record_size];

        for byte_idx in 0..self.record_size {
            let mut sum = 0u32;
            for row in 0..self.num_rows {
                let val = intermediate[row * self.record_size + byte_idx];
                sum = sum.wrapping_add(val.wrapping_mul(query[row]));
            }
            result[byte_idx] = sum;
        }

        result
    }

    /// Combined two-stage multiplication (for testing/comparison).
    ///
    /// Equivalent to multiply_second(multiply_first(query_col), query_row)
    pub fn multiply_double(&self, query_col: &[u32], query_row: &[u32]) -> Vec<u32> {
        let intermediate = self.multiply_first(query_col);
        self.multiply_second(&intermediate, query_row)
    }

    /// Dimensions for DoublePIR queries and hints.
    pub fn dimensions(&self) -> DoublePirDimensions {
        DoublePirDimensions {
            num_rows: self.num_rows,
            num_cols: self.num_cols,
            record_size: self.record_size,
            num_records: self.num_records,
        }
    }
}

/// Dimension information for DoublePIR setup.
#[derive(Debug, Clone, Copy)]
pub struct DoublePirDimensions {
    /// √N — number of record rows
    pub num_rows: usize,
    /// √N — number of record columns
    pub num_cols: usize,
    /// Bytes per record
    pub record_size: usize,
    /// Total number of records
    pub num_records: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // SimplePIR Database Tests
    // ========================================================================

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

    // ========================================================================
    // DoublePIR Database Tests
    // ========================================================================

    #[test]
    fn test_double_pir_layout_9_records() {
        // 9 records of 2 bytes each
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = DoublePirDatabase::new(&record_refs, 2);

        // √9 = 3, so 3×3 grid
        assert_eq!(db.num_rows, 3);
        assert_eq!(db.num_cols, 3);
        assert_eq!(db.record_size, 2);
        assert_eq!(db.num_records, 9);

        // Verify layout:
        //          col 0    col 1    col 2
        // row 0:   R0       R1       R2
        // row 1:   R3       R4       R5
        // row 2:   R6       R7       R8

        // R0 = [0, 1] at (row=0, col=0)
        assert_eq!(db.get(0, 0, 0), 0);
        assert_eq!(db.get(0, 0, 1), 1);

        // R4 = [8, 9] at (row=1, col=1)
        assert_eq!(db.get(1, 1, 0), 8);
        assert_eq!(db.get(1, 1, 1), 9);

        // R8 = [16, 17] at (row=2, col=2)
        assert_eq!(db.get(2, 2, 0), 16);
        assert_eq!(db.get(2, 2, 1), 17);
    }

    #[test]
    fn test_double_pir_get_record() {
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = DoublePirDatabase::new(&record_refs, 2);

        // R4 = [8, 9] at (row=1, col=1)
        let record = db.get_record(1, 1);
        assert_eq!(record, &[8, 9]);

        // R0 = [0, 1] at (row=0, col=0)
        let record = db.get_record(0, 0);
        assert_eq!(record, &[0, 1]);
    }

    #[test]
    fn test_double_pir_record_to_coords() {
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = DoublePirDatabase::new(&record_refs, 2);

        // Record 0 → (row=0, col=0)
        assert_eq!(db.record_to_coords(0), (0, 0));
        // Record 4 → (row=1, col=1)
        assert_eq!(db.record_to_coords(4), (1, 1));
        // Record 8 → (row=2, col=2)
        assert_eq!(db.record_to_coords(8), (2, 2));
        // Record 5 → (row=1, col=2)
        assert_eq!(db.record_to_coords(5), (1, 2));
    }

    #[test]
    fn test_double_pir_multiply_first_selects_column() {
        // 9 records of 2 bytes each
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = DoublePirDatabase::new(&record_refs, 2);

        // Select column 1 (contains R1, R4, R7)
        // R1 = [2, 3], R4 = [8, 9], R7 = [14, 15]
        let query_col1 = vec![0u32, 1, 0];
        let intermediate = db.multiply_first(&query_col1);

        // Result should be [R1, R4, R7] flattened = [2, 3, 8, 9, 14, 15]
        assert_eq!(intermediate.len(), 3 * 2); // 3 rows × 2 bytes
        assert_eq!(intermediate, vec![2, 3, 8, 9, 14, 15]);
    }

    #[test]
    fn test_double_pir_multiply_second_selects_row() {
        // Intermediate: [R1, R4, R7] = [[2, 3], [8, 9], [14, 15]]
        // Flattened: [2, 3, 8, 9, 14, 15]
        let intermediate = vec![2u32, 3, 8, 9, 14, 15];

        // Create dummy database just to call multiply_second
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 2);

        // Select row 1 (which is R4 = [8, 9] in our intermediate)
        let query_row1 = vec![0u32, 1, 0];
        let result = db.multiply_second(&intermediate, &query_row1);

        assert_eq!(result, vec![8, 9]);
    }

    #[test]
    fn test_double_pir_multiply_double_end_to_end() {
        // 9 records of 2 bytes each
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = DoublePirDatabase::new(&record_refs, 2);

        // Query for R4 at (row=1, col=1)
        // query_col selects column 1
        // query_row selects row 1
        let query_col = vec![0u32, 1, 0]; // select col 1
        let query_row = vec![0u32, 1, 0]; // select row 1

        let result = db.multiply_double(&query_col, &query_row);

        // R4 = [8, 9]
        assert_eq!(result, vec![8, 9]);
    }

    #[test]
    fn test_double_pir_all_records() {
        // Test that we can retrieve any record using unit vectors
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = DoublePirDatabase::new(&record_refs, 2);

        for rec_idx in 0..9 {
            let (row, col) = db.record_to_coords(rec_idx);

            // Create unit vectors
            let mut query_col = vec![0u32; 3];
            query_col[col] = 1;
            let mut query_row = vec![0u32; 3];
            query_row[row] = 1;

            let result = db.multiply_double(&query_col, &query_row);
            let expected = records[rec_idx].iter().map(|&b| b as u32).collect::<Vec<_>>();

            assert_eq!(
                result, expected,
                "Failed for record {rec_idx} at ({row}, {col})"
            );
        }
    }

    #[test]
    fn test_double_pir_from_simple_pir() {
        // Create SimplePIR database
        let records: Vec<Vec<u8>> = (0..9)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let simple_db = MatrixDatabase::new(&record_refs, 2);
        let double_db = simple_db.to_double_pir();

        // Both should have same dimensions
        assert_eq!(double_db.num_cols, simple_db.cols);
        assert_eq!(double_db.record_size, simple_db.record_size);
        assert_eq!(double_db.num_records, simple_db.num_records);

        // Both should retrieve the same records
        for rec_idx in 0..9 {
            let (row, col) = double_db.record_to_coords(rec_idx);

            let mut query_col = vec![0u32; 3];
            query_col[col] = 1;
            let mut query_row = vec![0u32; 3];
            query_row[row] = 1;

            let double_result = double_db.multiply_double(&query_col, &query_row);
            let expected = records[rec_idx].iter().map(|&b| b as u32).collect::<Vec<_>>();

            assert_eq!(double_result, expected);
        }
    }

    #[test]
    fn test_double_pir_dimensions() {
        let records: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 32]).collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = DoublePirDatabase::new(&record_refs, 32);
        let dims = db.dimensions();

        // √100 = 10
        assert_eq!(dims.num_rows, 10);
        assert_eq!(dims.num_cols, 10);
        assert_eq!(dims.record_size, 32);
        assert_eq!(dims.num_records, 100);
    }

    #[test]
    fn test_double_pir_imperfect_square() {
        // 10 records (not a perfect square)
        let records: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();

        let db = DoublePirDatabase::new(&record_refs, 2);

        // √10 ≈ 3.16 → ceil = 4 columns
        // rows = ceil(10/4) = 3 rows
        assert_eq!(db.num_cols, 4);
        assert_eq!(db.num_rows, 3);

        // Can still retrieve all 10 records
        for rec_idx in 0..10 {
            let (row, col) = db.record_to_coords(rec_idx);

            let mut query_col = vec![0u32; db.num_cols];
            query_col[col] = 1;
            let mut query_row = vec![0u32; db.num_rows];
            query_row[row] = 1;

            let result = db.multiply_double(&query_col, &query_row);
            let expected = records[rec_idx].iter().map(|&b| b as u32).collect::<Vec<_>>();

            assert_eq!(result, expected, "Failed for record {rec_idx}");
        }
    }
}

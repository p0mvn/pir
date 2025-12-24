
pub struct MatrixDatabase {
    pub data: Vec<u64>,
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

        let mut data = vec![0u64; rows * cols];

        for (rec_idx, record) in records.iter().enumerate() {
            let group = rec_idx / records_per_group;
            let col = rec_idx % records_per_group;
            
            for (byte_idx, &byte) in record.iter().take(record_size).enumerate() {
                let row = group * record_size + byte_idx;
                data[row * cols + col] = byte as u64;
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
        assert_eq!(db.data[0 * 3 + 0], 0);  // row 0, col 0
        assert_eq!(db.data[1 * 3 + 0], 1);  // row 1, col 0
        
        // R4 = [8,9] at column 1, rows 2-3 (group 1)
        assert_eq!(db.data[2 * 3 + 1], 8);  // row 2, col 1
        assert_eq!(db.data[3 * 3 + 1], 9);  // row 3, col 1
        
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
}
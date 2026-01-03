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

mod client;
mod hint;
mod server;

pub use client::{DoublePirClient, DoublePirQueryState};
pub use hint::HintComputation;
pub use server::DoublePirServer;

use serde::{Deserialize, Serialize};

use crate::{
    pir::{ClientHint, MatrixSeed},
    pir_trait::{CommunicationCost, PirProtocol},
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

//! Trait-based PIR interface for composable Simple/Double PIR modes.
//!
//! This module defines the common interface that both SimplePIR and DoublePIR
//! implementations must satisfy, enabling:
//! - Compile-time mode selection via generics
//! - Runtime mode selection via trait objects
//! - Easy benchmarking and comparison between modes

use rand::Rng;

use crate::params::LweParams;

/// Core PIR protocol trait.
///
/// Both SimplePIR and DoublePIR implement this trait, allowing code to be
/// generic over the PIR mode while maintaining type safety.
///
/// # Type Parameters
/// - `Query`: The query type sent from client to server
/// - `Answer`: The answer type sent from server to client
/// - `QueryState`: Client-side state needed for recovery (contains secrets)
/// - `SetupData`: Server-to-client setup information (hints, dimensions, etc.)
pub trait PirProtocol {
    /// Query sent from client to server
    type Query;
    /// Answer sent from server to client
    type Answer;
    /// Client state for recovery (kept secret)
    type QueryState;
    /// Setup data from server to client
    type SetupData;
}

/// Client-side PIR operations.
///
/// Handles query generation and answer recovery.
pub trait PirClient: Sized {
    /// The protocol this client implements
    type Protocol: PirProtocol;

    /// Initialize client from server's setup data
    fn from_setup(setup: <Self::Protocol as PirProtocol>::SetupData, params: LweParams) -> Self;

    /// Generate a query for the given record index.
    ///
    /// Returns:
    /// - `QueryState`: Secret state needed for recovery
    /// - `Query`: The query to send to the server
    fn query(
        &self,
        record_idx: usize,
        rng: &mut impl Rng,
    ) -> (
        <Self::Protocol as PirProtocol>::QueryState,
        <Self::Protocol as PirProtocol>::Query,
    );

    /// Recover the requested record from the server's answer.
    fn recover(
        &self,
        state: &<Self::Protocol as PirProtocol>::QueryState,
        answer: &<Self::Protocol as PirProtocol>::Answer,
    ) -> Vec<u8>;

    /// Number of records in the database
    fn num_records(&self) -> usize;

    /// Size of each record in bytes
    fn record_size(&self) -> usize;
}

/// Server-side PIR operations.
///
/// Handles setup and query answering.
pub trait PirServer: Sized {
    /// The protocol this server implements
    type Protocol: PirProtocol;

    /// Generate the setup data to send to clients.
    ///
    /// This typically includes:
    /// - Matrix seeds (for regenerating A)
    /// - Precomputed hints (DB · A)
    /// - Database dimensions
    fn setup(&self) -> <Self::Protocol as PirProtocol>::SetupData;

    /// Answer a client's query.
    ///
    /// Computes the PIR response (typically DB · query or similar).
    fn answer(
        &self,
        query: &<Self::Protocol as PirProtocol>::Query,
    ) -> <Self::Protocol as PirProtocol>::Answer;

    /// Number of records in the database
    fn num_records(&self) -> usize;

    /// Size of each record in bytes
    fn record_size(&self) -> usize;
}

// ============================================================================
// Communication cost estimation
// ============================================================================

/// Trait for estimating communication costs.
///
/// Useful for benchmarking and comparing PIR modes.
pub trait CommunicationCost {
    /// Size in bytes when serialized
    fn size_bytes(&self) -> usize;
}

/// Summary of communication costs for a PIR scheme
#[derive(Debug, Clone, Copy)]
pub struct PirCosts {
    /// Setup data size (server → client, one-time)
    pub setup_bytes: usize,
    /// Query size (client → server, per-query)
    pub query_bytes: usize,
    /// Answer size (server → client, per-query)
    pub answer_bytes: usize,
}

impl PirCosts {
    /// Total per-query communication (both directions)
    pub fn per_query_bytes(&self) -> usize {
        self.query_bytes + self.answer_bytes
    }
}

// ============================================================================
// Mode selection helpers
// ============================================================================

/// PIR mode selector for runtime dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PirMode {
    /// SimplePIR: O(√N) query, O(√N × record_size) answer
    Simple,
    /// DoublePIR: O(√N) query (×2), O(n) answer
    Double,
}

impl PirMode {
    /// Human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            PirMode::Simple => "SimplePIR",
            PirMode::Double => "DoublePIR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pir_mode_names() {
        assert_eq!(PirMode::Simple.name(), "SimplePIR");
        assert_eq!(PirMode::Double.name(), "DoublePIR");
    }

    #[test]
    fn test_pir_costs() {
        let costs = PirCosts {
            setup_bytes: 1024,
            query_bytes: 256,
            answer_bytes: 512,
        };
        assert_eq!(costs.per_query_bytes(), 768);
    }

    /// Test that SimplePIR works through the trait interface
    #[test]
    fn test_simple_pir_via_trait() {
        use crate::matrix_database::MatrixDatabase;
        use crate::params::LweParams;
        use crate::simple::PirClient as SimplePirClient;
        use crate::simple::PirServer as SimplePirServer;

        // Create test database
        let records: Vec<Vec<u8>> = (0..16)
            .map(|i| vec![(i * 2) as u8, (i * 2 + 1) as u8])
            .collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 2);

        // Use trait interface
        let params = LweParams::default_128bit();
        let mut rng = rand::rng();

        // Server setup via trait
        let server = SimplePirServer::new(db, &params, &mut rng);
        let setup_data = <SimplePirServer as PirServer>::setup(&server);

        // Client setup via trait
        let client = <SimplePirClient as PirClient>::from_setup(setup_data, params);

        // Query via trait
        let target_idx = 7;
        let (state, query) = <SimplePirClient as PirClient>::query(&client, target_idx, &mut rng);

        // Answer via trait
        let answer = <SimplePirServer as PirServer>::answer(&server, &query);

        // Recover via trait
        let recovered = <SimplePirClient as PirClient>::recover(&client, &state, &answer);

        // Verify
        assert_eq!(recovered, records[target_idx]);
    }

    /// Test communication cost estimation
    #[test]
    fn test_communication_cost_estimation() {
        use crate::matrix_database::MatrixDatabase;
        use crate::params::LweParams;
        use crate::pir::{Answer, Query, SetupMessage};
        use crate::simple::PirServer as SimplePirServer;

        let records: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 32]).collect();
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = MatrixDatabase::new(&record_refs, 32);

        let params = LweParams::default_128bit();
        let mut rng = rand::rng();
        let server = SimplePirServer::new(db, &params, &mut rng);
        let setup = server.setup_message();

        // Check setup message size
        let setup_size = <SetupMessage as CommunicationCost>::size_bytes(&setup);
        assert!(setup_size > 32); // At least seed + some hint data

        // Check query size (√N × 4 bytes)
        let sqrt_n = 10; // √100 = 10
        let query = Query(vec![0u32; sqrt_n]);
        let query_size = <Query as CommunicationCost>::size_bytes(&query);
        assert_eq!(query_size, sqrt_n * 4);

        // Check answer size (√N × record_size × 4 bytes for SimplePIR)
        // Actually it's db.rows × 4 bytes
        let answer = Answer(vec![0u32; setup.db_rows]);
        let answer_size = <Answer as CommunicationCost>::size_bytes(&answer);
        assert_eq!(answer_size, setup.db_rows * 4);
    }
}

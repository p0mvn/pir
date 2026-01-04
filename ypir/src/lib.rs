//! YPIR: DoublePIR with LWE-to-RLWE packing for compressed responses
//!
//! YPIR combines the DoublePIR protocol with LWE-to-RLWE packing to achieve
//! significantly smaller response sizes while maintaining high throughput.
//!
//! # Architecture
//!
//! The protocol works as follows:
//! 1. Client generates a DoublePIR query plus a packing key
//! 2. Server computes DoublePIR answer (LWE ciphertexts)
//! 3. Server packs LWE ciphertexts into compact RLWE ciphertexts using packing key
//! 4. Client decrypts RLWE response to recover plaintext
//!
//! # Compression Benefit
//!
//! DoublePIR answer: `record_size × (n + 1)` elements
//! YPIR answer: `record_size / d × 2d` elements (after packing d LWE → 1 RLWE)
//!
//! For typical parameters (n = d = 2048, record_size = 256 KB):
//! - DoublePIR: 256K × 2049 × 4 bytes ≈ 2 GB
//! - YPIR: 256K / 2048 × 4096 × 4 bytes ≈ 2 MB (1000× compression)
//!
//! # Parameters
//!
//! YPIR uses two parameter sets (see [`params`] module):
//! - **SimplePIR pass**: d₁ = 2^10, q₁ = 2^32 (high-throughput database scan)
//! - **Packing pass**: d₂ = 2^11, q₂ ≈ 2^32 (response compression via RLWE)

pub mod client;
pub mod params;
pub mod server;

pub use client::YpirClient;
pub use params::{LweParams, PackingParams, YpirParams};
pub use server::YpirServer;

use pir::double::{DoublePirQuery, DoublePirQueryState, DoublePirSetup};
use pir::lwe_to_rlwe::PackingKey;
use pir::pir_trait::{CommunicationCost, PirProtocol};
use pir::ring::RingElement;
use pir::ring_regev::RLWECiphertextOwned;

// ============================================================================
// Protocol Types
// ============================================================================

/// Marker type for YPIR protocol.
///
/// YPIR = DoublePIR + LWE-to-RLWE packing.
pub struct Ypir;

impl PirProtocol for Ypir {
    type Query = YpirQuery;
    type Answer = YpirAnswer;
    type QueryState = YpirQueryState;
    type SetupData = YpirSetup;
}

/// YPIR query: DoublePIR query plus a packing key.
///
/// The packing key allows the server to pack the LWE response into
/// a compact RLWE ciphertext that only the client can decrypt.
///
/// # Communication Cost
///
/// - DoublePIR query: `2 × √N × (n + 1) × 4` bytes
/// - Packing key: `d × d × NUM_DIGITS × 2d × 4` bytes
///
/// The packing key is the dominant cost, but it enables massive
/// response compression (typically 1000×).
pub struct YpirQuery {
    /// The underlying DoublePIR query (encrypted unit vectors)
    pub double_query: DoublePirQuery,
    /// Packing key for LWE-to-RLWE conversion (allows server to compress response)
    pub packing_key: PackingKey,
}

/// YPIR answer: packed RLWE ciphertexts.
///
/// The server packs every `d` LWE ciphertexts from the DoublePIR answer
/// into a single RLWE ciphertext, achieving `~d/2` compression ratio.
///
/// For a record of `record_size` bytes:
/// - DoublePIR produces `record_size` LWE ciphertexts
/// - These are packed into `ceil(record_size / d)` RLWE ciphertexts
///
/// # Communication Cost
///
/// - DoublePIR answer: `record_size × (n + 1) × 4` bytes
/// - YPIR answer: `ceil(record_size / d) × 2d × 4` bytes
pub struct YpirAnswer {
    /// Packed RLWE ciphertexts, each encrypting up to d coefficients
    pub packed_cts: Vec<RLWECiphertextOwned>,
}

/// Setup data sent from server to client.
///
/// YPIR reuses the DoublePIR setup data entirely. The packing-related
/// setup (RLWE parameters) is implicit in the ring dimension.
pub struct YpirSetup {
    /// Underlying DoublePIR setup (seeds, hints, dimensions)
    pub double_setup: DoublePirSetup,
    /// Ring dimension for RLWE packing (typically equal to LWE dimension)
    pub ring_dim: usize,
}

/// Client-side state needed to decrypt the YPIR response.
///
/// Contains both the DoublePIR query state (for hint subtraction) and
/// the RLWE secret key (for decrypting the packed response).
pub struct YpirQueryState {
    /// DoublePIR query state (secrets s₁, s₂ for hint computation)
    pub double_state: DoublePirQueryState,
    /// RLWE secret key for decrypting packed response
    /// This is typically derived from the LWE secret s₁
    pub rlwe_secret: RingElement,
}

// ============================================================================
// Communication Cost Implementations
// ============================================================================

impl CommunicationCost for YpirQuery {
    fn size_bytes(&self) -> usize {
        // DoublePIR query size
        let double_query_size = self.double_query.size_bytes();

        // Packing key size: d keys × d positions × NUM_DIGITS × 2d coefficients × 4 bytes
        // Each KeySwitchKey has d × NUM_DIGITS RLWE ciphertexts
        // Each RLWE ciphertext has 2d coefficients (a and c polynomials)
        let d = self.packing_key.d;
        let num_digits = pir::lwe_to_rlwe::NUM_DIGITS;
        let packing_key_size = d * d * num_digits * 2 * d * std::mem::size_of::<u32>();

        double_query_size + packing_key_size
    }
}

impl CommunicationCost for YpirAnswer {
    fn size_bytes(&self) -> usize {
        // Each RLWE ciphertext has 2d coefficients (a and c polynomials)
        self.packed_cts
            .iter()
            .map(|ct| (ct.a.coeffs.len() + ct.c.coeffs.len()) * std::mem::size_of::<u32>())
            .sum()
    }
}

impl CommunicationCost for YpirSetup {
    fn size_bytes(&self) -> usize {
        // Same as DoublePIR setup
        self.double_setup.size_bytes()
    }
}

// ============================================================================
// Helper Implementations
// ============================================================================

impl YpirSetup {
    /// Number of records in the database
    pub fn num_records(&self) -> usize {
        self.double_setup.num_records
    }

    /// Size of each record in bytes
    pub fn record_size(&self) -> usize {
        self.double_setup.record_size
    }

    /// LWE dimension
    pub fn lwe_dim(&self) -> usize {
        self.double_setup.lwe_dim
    }
}

impl YpirAnswer {
    /// Number of packed RLWE ciphertexts
    pub fn num_ciphertexts(&self) -> usize {
        self.packed_cts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir::ring::RingElement;

    #[test]
    fn test_ypir_protocol_types() {
        // Verify the protocol trait is correctly implemented
        fn assert_protocol<P: PirProtocol>() {}
        assert_protocol::<Ypir>();
    }

    #[test]
    fn test_communication_cost_answer() {
        // Create a mock RLWE ciphertext with d=4
        let d = 4;
        let ct = RLWECiphertextOwned {
            a: RingElement {
                coeffs: vec![0u32; d],
            },
            c: RingElement {
                coeffs: vec![0u32; d],
            },
        };

        let answer = YpirAnswer {
            packed_cts: vec![ct],
        };

        // Size should be 2d × 4 bytes = 32 bytes
        assert_eq!(answer.size_bytes(), 2 * d * std::mem::size_of::<u32>());
    }

    #[test]
    fn test_communication_cost_answer_multiple_cts() {
        let d = 8;

        // Multiple ciphertexts
        let cts: Vec<RLWECiphertextOwned> = (0..3)
            .map(|_| RLWECiphertextOwned {
                a: RingElement {
                    coeffs: vec![0u32; d],
                },
                c: RingElement {
                    coeffs: vec![0u32; d],
                },
            })
            .collect();

        let answer = YpirAnswer { packed_cts: cts };

        // 3 ciphertexts × 2d × 4 bytes = 3 × 16 × 4 = 192 bytes
        assert_eq!(answer.size_bytes(), 3 * 2 * d * std::mem::size_of::<u32>());
    }

    #[test]
    fn test_communication_cost_empty_answer() {
        let answer = YpirAnswer {
            packed_cts: vec![],
        };
        assert_eq!(answer.size_bytes(), 0);
    }

    #[test]
    fn test_ypir_answer_num_ciphertexts() {
        let d = 4;

        // Zero ciphertexts
        let answer_empty = YpirAnswer {
            packed_cts: vec![],
        };
        assert_eq!(answer_empty.num_ciphertexts(), 0);

        // One ciphertext
        let ct = RLWECiphertextOwned {
            a: RingElement {
                coeffs: vec![0u32; d],
            },
            c: RingElement {
                coeffs: vec![0u32; d],
            },
        };
        let answer_one = YpirAnswer {
            packed_cts: vec![ct],
        };
        assert_eq!(answer_one.num_ciphertexts(), 1);

        // Multiple ciphertexts
        let cts: Vec<RLWECiphertextOwned> = (0..5)
            .map(|_| RLWECiphertextOwned {
                a: RingElement {
                    coeffs: vec![0u32; d],
                },
                c: RingElement {
                    coeffs: vec![0u32; d],
                },
            })
            .collect();
        let answer_many = YpirAnswer { packed_cts: cts };
        assert_eq!(answer_many.num_ciphertexts(), 5);
    }

    #[test]
    fn test_ypir_protocol_associated_types() {
        // Verify associated types compile and are correct
        fn check_types<P: PirProtocol>()
        where
            P::Query: Sized,
            P::Answer: Sized,
            P::QueryState: Sized,
            P::SetupData: Sized,
        {
        }
        check_types::<Ypir>();
    }
}

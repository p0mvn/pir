//! YPIR client implementation.
//!
//! The YPIR client wraps DoublePIR with LWE-to-RLWE packing support.
//! It generates packing keys alongside queries and decrypts packed RLWE responses.

use rand::Rng;

use pir::double::DoublePirClient;
use pir::lwe_to_rlwe::{decode_packed_result, decrypt_raw, gen_packing_key};
use pir::params::LweParams;
use pir::pir_trait::PirClient as PirClientTrait;
use pir::ring::RingElement;

use crate::{Ypir, YpirAnswer, YpirParams, YpirQuery, YpirQueryState, YpirSetup};

/// YPIR client: DoublePIR client with LWE-to-RLWE packing support.
///
/// The client wraps a `DoublePirClient` and adds:
/// - Packing key generation alongside queries
/// - RLWE decryption for packed responses
///
/// # Query Flow
///
/// ```text
/// 1. Generate DoublePIR query (encrypted unit vectors)
/// 2. Generate packing key (allows server to pack response)
/// 3. Send both to server as YpirQuery
/// ```
///
/// # Recovery Flow
///
/// ```text
/// 1. Receive packed RLWE ciphertexts from server
/// 2. Decrypt each RLWE ciphertext using stored RLWE secret
/// 3. Decode coefficients to recover plaintext bytes
/// ```
pub struct YpirClient {
    /// Underlying DoublePIR client
    inner: DoublePirClient,
    /// YPIR parameters (LWE + packing)
    params: YpirParams,
    /// Ring dimension for RLWE packing
    ring_dim: usize,
}

impl YpirClient {
    /// Create a new YPIR client from setup data.
    ///
    /// # Arguments
    /// * `setup` - Setup data from the YPIR server
    /// * `params` - YPIR parameters (LWE + packing)
    ///
    /// # Panics
    ///
    /// Panics if setup data is inconsistent with parameters.
    pub fn new(setup: YpirSetup, params: YpirParams) -> Self {
        let inner = DoublePirClient::new(setup.double_setup, params.lwe);
        let ring_dim = setup.ring_dim;

        Self {
            inner,
            params,
            ring_dim,
        }
    }

    /// Generate a YPIR query for the given record index.
    ///
    /// This generates:
    /// 1. A DoublePIR query (two encrypted unit vectors)
    /// 2. A packing key (allows server to pack LWE → RLWE)
    ///
    /// The packing key allows the server to compress the DoublePIR response
    /// from `record_size × (n+1)` elements to `ceil(record_size/d) × 2d` elements.
    ///
    /// # Arguments
    /// * `record_idx` - Index of the record to retrieve (0-indexed)
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// * `YpirQueryState` - Secret state needed for recovery (kept by client)
    /// * `YpirQuery` - Query to send to server (DoublePIR query + packing key)
    ///
    /// # Panics
    ///
    /// Panics if `record_idx` is out of bounds.
    pub fn query(&self, record_idx: usize, rng: &mut impl Rng) -> (YpirQueryState, YpirQuery) {
        // Generate DoublePIR query
        let (double_state, double_query) = self.inner.query(record_idx, rng);

        // Generate RLWE secret key for packing
        // We use the DoublePIR column secret as the LWE secret for packing,
        // and generate a fresh RLWE secret for decryption.
        let d = self.ring_dim;
        let lwe_secret = &double_state.secret_col;

        // Generate RLWE secret key (random polynomial)
        let rlwe_secret = RingElement::random(d, rng);

        // Generate packing key: allows server to convert LWE → RLWE
        let packing_key = gen_packing_key(
            lwe_secret,
            &rlwe_secret,
            self.params.packing.noise_stddev,
            rng,
        );

        let state = YpirQueryState {
            double_state,
            rlwe_secret,
        };

        let query = YpirQuery {
            double_query,
            packing_key,
        };

        (state, query)
    }

    /// Recover the requested record from a YPIR answer.
    ///
    /// The answer contains packed RLWE ciphertexts. Each ciphertext encrypts
    /// up to `d` plaintext coefficients (database bytes).
    ///
    /// # Decryption Process
    ///
    /// For each RLWE ciphertext:
    /// 1. Compute raw decryption: `c - a·s` (noisy plaintext polynomial)
    /// 2. Decode each coefficient: `round(coeff/Δ) mod p`
    /// 3. Concatenate to form the recovered record
    ///
    /// # Arguments
    /// * `state` - Secret state from query generation
    /// * `answer` - Packed RLWE ciphertexts from server
    ///
    /// # Returns
    ///
    /// The recovered record as a byte vector.
    pub fn recover(&self, state: &YpirQueryState, answer: &YpirAnswer) -> Vec<u8> {
        let p = self.params.packing.plaintext_modulus;
        let delta = self.params.packing.delta();

        let mut result = Vec::new();

        // Decrypt each packed RLWE ciphertext
        for ct in &answer.packed_cts {
            // Raw decryption: c - a·s ≈ Δ·m + noise
            let noisy = decrypt_raw(&state.rlwe_secret, ct);

            // Decode: round(coeff/Δ) mod p
            let decoded = decode_packed_result(&noisy, delta, p);

            // Each decoded value is a plaintext coefficient (0-255 for p=256)
            // These are the database bytes
            for &coeff in &decoded {
                result.push(coeff as u8);
            }
        }

        // Trim to actual record size (last ciphertext may have padding)
        let record_size = self.inner.record_size();
        result.truncate(record_size);

        result
    }

    /// Number of records in the database.
    pub fn num_records(&self) -> usize {
        self.inner.num_records()
    }

    /// Size of each record in bytes.
    pub fn record_size(&self) -> usize {
        self.inner.record_size()
    }

    /// Get the ring dimension used for RLWE packing.
    pub fn ring_dimension(&self) -> usize {
        self.ring_dim
    }

    /// Get the LWE dimension used for DoublePIR.
    pub fn lwe_dimension(&self) -> usize {
        self.params.lwe.n
    }

    /// Estimate the number of RLWE ciphertexts needed for a response.
    ///
    /// Each RLWE ciphertext can hold `d` plaintext coefficients (bytes).
    pub fn expected_num_ciphertexts(&self) -> usize {
        self.record_size().div_ceil(self.ring_dim)
    }
}

// ============================================================================
// Trait Implementation
// ============================================================================

impl PirClientTrait for YpirClient {
    type Protocol = Ypir;

    fn from_setup(setup: YpirSetup, params: LweParams) -> Self {
        // Convert LweParams to YpirParams (using matching packing params)
        let ypir_params = YpirParams::from_lwe(params);
        YpirClient::new(setup, ypir_params)
    }

    fn query(&self, record_idx: usize, rng: &mut impl Rng) -> (YpirQueryState, YpirQuery) {
        self.query(record_idx, rng)
    }

    fn recover(&self, state: &YpirQueryState, answer: &YpirAnswer) -> Vec<u8> {
        self.recover(state, answer)
    }

    fn num_records(&self) -> usize {
        self.num_records()
    }

    fn record_size(&self) -> usize {
        self.record_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir::lwe_to_rlwe::pack_with_key_switching;
    use pir::regev::{self, CiphertextOwned, SecretKey};

    /// Test that packing key generation works correctly
    #[test]
    fn test_packing_key_generation() {
        let d = 4;
        let noise_stddev = 2.0;
        let mut rng = rand::rng();

        // Generate secrets
        let lwe_secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement::random(d, &mut rng);

        // Generate packing key
        let packing_key = gen_packing_key(&lwe_secret, &rlwe_secret, noise_stddev, &mut rng);

        // Verify structure
        assert_eq!(packing_key.keys.len(), d);
        assert_eq!(packing_key.d, d);
    }

    /// Test full pack-decrypt cycle with mock LWE ciphertexts
    #[test]
    fn test_pack_decrypt_cycle() {
        let d = 4;
        let p = 256u32;
        let noise_stddev = 2.0;
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        // Generate secrets (same for LWE and packing for simplicity)
        let lwe_secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement::random(d, &mut rng);

        // Messages to encrypt
        let messages: Vec<u32> = vec![10, 20, 30, 40];

        // Create LWE ciphertexts (simulating DoublePIR output)
        let lwe_cts: Vec<CiphertextOwned> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
                let c = regev::encrypt(&params, &a, &SecretKey { s: &lwe_secret }, msg, &mut rng);
                CiphertextOwned { a, c }
            })
            .collect();

        // Generate packing key
        let packing_key = gen_packing_key(&lwe_secret, &rlwe_secret, noise_stddev, &mut rng);

        // Pack into RLWE
        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let packed = pack_with_key_switching(&lwe_refs, &packing_key);

        // Decrypt RLWE
        let noisy = decrypt_raw(&rlwe_secret, &packed);

        // Decode
        let delta = params.delta();
        let decoded = decode_packed_result(&noisy, delta, p);

        // Verify
        assert_eq!(decoded, messages);
    }

    /// Test that decoding handles larger ring dimensions
    #[test]
    fn test_decode_with_larger_d() {
        let d = 8;
        let p = 256u32;
        let noise_stddev = 1.5;
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        let lwe_secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement::random(d, &mut rng);

        // Random messages
        let messages: Vec<u32> = (0..d).map(|_| rng.random_range(0..p)).collect();

        let lwe_cts: Vec<CiphertextOwned> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
                let c = regev::encrypt(&params, &a, &SecretKey { s: &lwe_secret }, msg, &mut rng);
                CiphertextOwned { a, c }
            })
            .collect();

        let packing_key = gen_packing_key(&lwe_secret, &rlwe_secret, noise_stddev, &mut rng);
        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let packed = pack_with_key_switching(&lwe_refs, &packing_key);
        let noisy = decrypt_raw(&rlwe_secret, &packed);
        let delta = params.delta();
        let decoded = decode_packed_result(&noisy, delta, p);

        assert_eq!(decoded, messages);
    }

    /// Test expected ciphertext count calculation
    #[test]
    fn test_expected_ciphertexts() {
        // For record_size = 10, ring_dim = 4: ceil(10/4) = 3
        assert_eq!(10usize.div_ceil(4), 3);

        // For record_size = 8, ring_dim = 4: ceil(8/4) = 2
        assert_eq!(8usize.div_ceil(4), 2);

        // For record_size = 2048, ring_dim = 2048: ceil(2048/2048) = 1
        assert_eq!(2048usize.div_ceil(2048), 1);
    }
}

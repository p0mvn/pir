//! LWE-to-RLWE packing transformation
//!
//! Takes d LWE ciphertexts and packs them into 1 RLWE ciphertext.
//! This is the core technique YPIR uses to compress responses.
//!
//! ## Key Switching Overview
//!
//! The naive packing only works when LWE ciphertexts have specially-structured
//! `a` vectors (negacyclic rotations). For arbitrary LWE ciphertexts, we need
//! **key switching**.
//!
//! Key switching works by:
//! 1. Decomposing each element of the LWE `a` vector into bits
//! 2. Using pre-computed RLWE encryptions of `s_i · 2^k · x^j` to reconstruct
//!    an RLWE ciphertext that encrypts `μ · x^j`
//!
//! The "packing key" is the collection of these pre-computed RLWE ciphertexts.

use rand::Rng;

use crate::regev::Ciphertext;
use crate::ring::RingElement;
use crate::ring_regev::{RLWECiphertextOwned, RlweParams};

/// Given a d×d matrix M (stored row-major as Vec<Vec<u32>>),
/// extract the polynomial A such that rot(A) = M.
/// 
/// For this to be valid, M must actually BE a negacyclic matrix.
/// In the general case (arbitrary LWE ciphertexts), M won't be negacyclic,
/// so we need a different approach (key switching).
fn matrix_to_ring_element(first_column: &[u32], d: usize) -> RingElement {
    // First column of rot(A):
    // [A₀, -A_(d-1), -A_(d-2), ..., -A₁]
    let mut coeffs = vec![0u32; d];
    coeffs[0] = first_column[0];
    for i in 1..d {
        // first_column[i] = -A_(d-i)
        // So A_(d-i) = -first_column[i]
        coeffs[d - i] = first_column[i].wrapping_neg();
    }
    RingElement { coeffs }
}

/// Pack d LWE ciphertexts into 1 RLWE ciphertext.
/// 
/// CAVEAT: This naive version only works if the a_i vectors form
/// a negacyclic matrix. For arbitrary LWE ciphertexts, we need
/// key switching (see pack_with_key_switching).
/// 
/// The key insight: LWE computes c_i = ⟨a_i, s⟩ where a_i = x^i·A (rotation).
/// This means c = rot(A)·s (matrix-vector product).
/// 
/// RLWE decryption computes C - A'·S (polynomial multiplication).
/// For A'·S to equal rot(A)·s, we must use A' = first_column directly
/// (NOT the recovered original polynomial A).
pub fn pack_naive(
    lwe_cts: &[Ciphertext],  // d ciphertexts, each with a.len() == d
    d: usize,
) -> RLWECiphertextOwned {
    assert_eq!(lwe_cts.len(), d);
    
    // Extract first column of the matrix formed by stacking a_i as rows.
    // This IS the polynomial we need for RLWE (not the original A that
    // generated these rotations). The first column [a_0, -a_{d-1}, ..., -a_1]
    // when used directly makes polynomial multiplication A'·S equal the
    // matrix-vector product rot(A)·s that LWE encryption computed.
    let first_column: Vec<u32> = lwe_cts.iter().map(|ct| ct.a[0]).collect();
    
    let a_poly = RingElement { coeffs: first_column };
    
    // Stack the c values into a polynomial
    let c_poly = RingElement {
        coeffs: lwe_cts.iter().map(|ct| ct.c).collect(),
    };
    
    RLWECiphertextOwned {
        a: a_poly,
        c: c_poly,
    }
}

// ============================================================================
// Key Switching Implementation
// ============================================================================

/// Number of bits to decompose each coefficient into.
/// Using base-2 decomposition (each bit separately).
/// For q = 2^32, we have 32 bits per coefficient.
const LOG_Q: usize = 32;

/// A key-switching key for a single position j.
///
/// This allows converting an LWE ciphertext (under secret s) to an RLWE
/// ciphertext (under secret S) that encrypts `μ · x^j`.
///
/// Structure: `ks[i][k]` is an RLWE encryption of `s_i · 2^k · x^j`
/// where:
/// - i ∈ {0, ..., d-1} indexes the LWE secret component
/// - k ∈ {0, ..., 31} indexes the bit position
pub struct KeySwitchKey {
    /// ks[i][k] encrypts s_i · 2^k · x^j under the RLWE secret
    /// Dimensions: [d][LOG_Q]
    pub ks: Vec<Vec<RLWECiphertextOwned>>,
    /// The target position j (encrypts μ · x^j)
    pub target_position: usize,
}

/// Generate a key-switching key for position j.
///
/// This creates RLWE encryptions of `s_i · 2^k · x^j` for all i, k.
///
/// # Arguments
/// * `lwe_secret` - The LWE secret key s (vector of d elements)
/// * `rlwe_secret` - The RLWE secret key S (polynomial with d coefficients)
/// * `j` - Target position: the result will encrypt μ · x^j
/// * `params` - RLWE parameters
/// * `rng` - Random number generator
pub fn gen_key_switch_key(
    lwe_secret: &[u32],
    rlwe_secret: &RingElement,
    j: usize,
    params: &RlweParams,
    rng: &mut impl Rng,
) -> KeySwitchKey {
    let d = params.d;
    assert_eq!(lwe_secret.len(), d);
    assert_eq!(rlwe_secret.coeffs.len(), d);
    assert!(j < d);

    let mut ks = Vec::with_capacity(d);

    for i in 0..d {
        let mut ks_i = Vec::with_capacity(LOG_Q);
        for k in 0..LOG_Q {
            // We want to encrypt: s_i · 2^k · x^j
            //
            // Create the message polynomial: scalar · x^j
            // where scalar = s_i · 2^k
            let scalar = lwe_secret[i].wrapping_mul(1u32 << k);

            let mut msg_coeffs = vec![0u32; d];
            msg_coeffs[j] = scalar;
            let msg = RingElement { coeffs: msg_coeffs };

            // Encrypt under RLWE secret
            let rlwe_sk = crate::regev::SecretKey {
                s: &rlwe_secret.coeffs,
            };
            let ct = crate::ring_regev::encrypt(params, &rlwe_sk, &msg, rng);
            ks_i.push(ct);
        }
        ks.push(ks_i);
    }

    KeySwitchKey {
        ks,
        target_position: j,
    }
}

/// Add two RLWE ciphertexts homomorphically.
///
/// If ct1 encrypts m1 and ct2 encrypts m2, the result encrypts m1 + m2.
pub fn add_rlwe_ciphertexts(
    ct1: &RLWECiphertextOwned,
    ct2: &RLWECiphertextOwned,
) -> RLWECiphertextOwned {
    RLWECiphertextOwned {
        a: ct1.a.add(&ct2.a),
        c: ct1.c.add(&ct2.c),
    }
}

/// Create a "zero" RLWE ciphertext (encrypts zero with no noise).
///
/// This is used as the starting point for accumulating key-switch results.
fn zero_rlwe_ciphertext(d: usize) -> RLWECiphertextOwned {
    RLWECiphertextOwned {
        a: RingElement::zero(d),
        c: RingElement::zero(d),
    }
}

/// Apply key switching to convert a single LWE ciphertext to RLWE.
///
/// Given an LWE ciphertext (a, c) encrypting μ under secret s,
/// produces an RLWE ciphertext encrypting μ · x^j under secret S.
///
/// # How it works
///
/// LWE ciphertext: c = ⟨a, s⟩ + e + Δμ
///
/// We want to compute an RLWE ciphertext (A', C') such that:
///   C' - A'·S ≈ Δμ · x^j
///
/// The key insight: we can "absorb" the ⟨a, s⟩ term using the key-switch key.
///
/// For each a_i, decompose it into bits: a_i = Σ_k a_i,k · 2^k
///
/// Then: ⟨a, s⟩ = Σ_i a_i · s_i = Σ_i Σ_k a_i,k · 2^k · s_i
///
/// The key-switch key contains RLWE encryptions of s_i · 2^k · x^j.
/// By summing the appropriate ciphertexts (weighted by the bits a_i,k),
/// we get an RLWE encryption of ⟨a, s⟩ · x^j.
///
/// Final result:
///   C' = c · x^j - Σ_i Σ_k a_i,k · KS[i][k]
///
/// which decrypts to: c · x^j - ⟨a, s⟩ · x^j = (e + Δμ) · x^j ≈ Δμ · x^j
pub fn key_switch(
    lwe_ct: &Ciphertext,
    ks_key: &KeySwitchKey,
    d: usize,
) -> RLWECiphertextOwned {
    assert_eq!(lwe_ct.a.len(), d);
    let j = ks_key.target_position;

    // Start with the "c" part: we need c · x^j as a polynomial
    // This will be the C component of our RLWE ciphertext
    let mut c_poly_coeffs = vec![0u32; d];
    c_poly_coeffs[j] = lwe_ct.c;
    let c_poly = RingElement {
        coeffs: c_poly_coeffs,
    };

    // Now we need to subtract the key-switched ⟨a, s⟩ term
    // Accumulate: Σ_i Σ_k a_i,k · KS[i][k]
    let mut accumulated = zero_rlwe_ciphertext(d);

    for i in 0..d {
        let a_i = lwe_ct.a[i];

        // Decompose a_i into bits and accumulate
        for k in 0..LOG_Q {
            // Extract bit k of a_i
            let bit = (a_i >> k) & 1;

            if bit == 1 {
                // Add KS[i][k] to the accumulator
                accumulated = add_rlwe_ciphertexts(&accumulated, &ks_key.ks[i][k]);
            }
        }
    }

    // The accumulated ciphertext is a "raw" RLWE encryption of ⟨a, s⟩ · x^j:
    //   accumulated.c - accumulated.a · S ≈ ⟨a, s⟩ · x^j + noise
    //
    // The original LWE ciphertext has: c = ⟨a, s⟩ + e + Δμ
    //
    // We want an RLWE ciphertext that decrypts to (e + Δμ) · x^j.
    //
    // Setting A' = -accumulated.a and C' = c·x^j - accumulated.c gives:
    //   C' - A'·S = c·x^j - accumulated.c + accumulated.a·S
    //             = c·x^j - (accumulated.c - accumulated.a·S)
    //             ≈ c·x^j - ⟨a, s⟩·x^j
    //             = (c - ⟨a, s⟩)·x^j
    //             = (e + Δμ)·x^j  ✓
    //
    // Note: This requires "raw" KS keys (no Δ scaling) - see gen_key_switch_key_raw().

    RLWECiphertextOwned {
        a: accumulated.a.neg(), // Negate to get correct sign
        c: c_poly.sub(&accumulated.c),
    }
}

/// Generate a key-switching key for position j (RAW version).
///
/// This creates RLWE encryptions of `s_i · 2^k · x^j` WITHOUT the Δ scaling.
/// This is necessary because the ⟨a, s⟩ term in LWE is not Δ-scaled.
///
/// The ciphertext structure is:
///   KS[i][k].c = KS[i][k].a · S + e + s_i · 2^k · x^j
///
/// Note: This bypasses the plaintext modulus p entirely.
pub fn gen_key_switch_key_raw(
    lwe_secret: &[u32],
    rlwe_secret: &RingElement,
    j: usize,
    d: usize,
    noise_stddev: f64,
    rng: &mut impl Rng,
) -> KeySwitchKey {
    assert_eq!(lwe_secret.len(), d);
    assert_eq!(rlwe_secret.coeffs.len(), d);
    assert!(j < d);

    let mut ks = Vec::with_capacity(d);

    for i in 0..d {
        let mut ks_i = Vec::with_capacity(LOG_Q);
        for k in 0..LOG_Q {
            // Create raw RLWE encryption of s_i · 2^k · x^j
            // c = a · S + e + s_i · 2^k · x^j (NO Δ scaling!)

            let a = RingElement::random(d, rng);
            let e = RingElement::random_small(d, noise_stddev as i32, rng);

            // Message: s_i · 2^k · x^j
            let scalar = lwe_secret[i].wrapping_mul(1u32 << k);
            let mut msg_coeffs = vec![0u32; d];
            msg_coeffs[j] = scalar;
            let msg = RingElement { coeffs: msg_coeffs };

            // c = a · S + e + msg (raw, no Δ)
            let c = a.mul(rlwe_secret).add(&e).add(&msg);

            ks_i.push(RLWECiphertextOwned { a, c });
        }
        ks.push(ks_i);
    }

    KeySwitchKey {
        ks,
        target_position: j,
    }
}

/// Decrypt a "raw" RLWE ciphertext (no Δ scaling was used).
///
/// Returns the noisy plaintext: c - a·s ≈ msg + e
/// The caller must handle rounding/decoding.
pub fn decrypt_raw(rlwe_secret: &RingElement, ct: &RLWECiphertextOwned) -> RingElement {
    ct.c.sub(&ct.a.mul(rlwe_secret))
}

// ============================================================================
// Full Packing with Key Switching
// ============================================================================

/// A packing key contains d key-switching keys, one for each position.
///
/// This allows packing d arbitrary LWE ciphertexts into a single RLWE ciphertext.
///
/// ```text
/// LWE(μ₀) --[KS to pos 0]--> RLWE(μ₀)      \
/// LWE(μ₁) --[KS to pos 1]--> RLWE(μ₁·x)     \
/// LWE(μ₂) --[KS to pos 2]--> RLWE(μ₂·x²)    --> SUM --> RLWE(μ₀ + μ₁x + μ₂x² + ...)
/// LWE(μ₃) --[KS to pos 3]--> RLWE(μ₃·x³)    /
/// ```
///
/// Size: d × d × LOG_Q × 2d coefficients = O(d³ log q) storage
/// For d=4, LOG_Q=32: 4 × 4 × 32 × 2 × 4 = 4096 u32 values
pub struct PackingKey {
    /// keys[j] is the key-switching key for position j
    pub keys: Vec<KeySwitchKey>,
    /// Ring dimension
    pub d: usize,
}

/// Generate a packing key for converting d LWE ciphertexts to 1 RLWE ciphertext.
///
/// # Arguments
/// * `lwe_secret` - The LWE secret key (vector of d elements)
/// * `rlwe_secret` - The RLWE secret key (polynomial with d coefficients)
/// * `d` - Ring dimension
/// * `noise_stddev` - Standard deviation for RLWE encryption noise
/// * `rng` - Random number generator
pub fn gen_packing_key(
    lwe_secret: &[u32],
    rlwe_secret: &RingElement,
    d: usize,
    noise_stddev: f64,
    rng: &mut impl Rng,
) -> PackingKey {
    let keys = (0..d)
        .map(|j| gen_key_switch_key_raw(lwe_secret, rlwe_secret, j, d, noise_stddev, rng))
        .collect();

    PackingKey { keys, d }
}

/// Pack d LWE ciphertexts into 1 RLWE ciphertext using key switching.
///
/// This is the core YPIR packing transformation that works for **arbitrary**
/// LWE ciphertexts (not just those with negacyclic structure).
///
/// # Arguments
/// * `lwe_cts` - Exactly d LWE ciphertexts encrypting μ₀, μ₁, ..., μ_{d-1}
/// * `packing_key` - Pre-computed packing key
///
/// # Returns
/// An RLWE ciphertext encrypting the polynomial μ(x) = μ₀ + μ₁x + μ₂x² + ... + μ_{d-1}x^{d-1}
///
/// # Compression
/// - Input: d LWE ciphertexts, each with (d+1) elements = d(d+1) total
/// - Output: 1 RLWE ciphertext with 2d elements
/// - Compression ratio: (d+1)/2 ≈ d/2 for large d
pub fn pack_with_key_switching(
    lwe_cts: &[Ciphertext],
    packing_key: &PackingKey,
) -> RLWECiphertextOwned {
    let d = packing_key.d;
    assert_eq!(lwe_cts.len(), d, "Must provide exactly d LWE ciphertexts");

    // Start with zero RLWE ciphertext
    let mut result = zero_rlwe_ciphertext(d);

    // Key-switch each LWE ciphertext to its position and accumulate
    for (j, lwe_ct) in lwe_cts.iter().enumerate() {
        // Key-switch ct_j to position j: produces RLWE encrypting μ_j · x^j
        let rlwe_j = key_switch(lwe_ct, &packing_key.keys[j], d);

        // Add to accumulator
        result = add_rlwe_ciphertexts(&result, &rlwe_j);
    }

    // Result encrypts: Σ_j μ_j · x^j = μ₀ + μ₁x + μ₂x² + ... + μ_{d-1}x^{d-1}
    result
}

/// Decode a raw RLWE decryption result to plaintext coefficients.
///
/// After raw decryption, each coefficient contains (noise + Δ·μ).
/// This function rounds to recover the original μ values.
pub fn decode_packed_result(noisy: &RingElement, delta: u32, p: u32) -> Vec<u32> {
    let half_delta = delta / 2;
    noisy
        .coeffs
        .iter()
        .map(|&coeff| (coeff.wrapping_add(half_delta) / delta) % p)
        .collect()
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use crate::{
        params::LweParams,
        regev::{self, CiphertextOwned},
    };

    use super::*;

    // ========================================================================
    // Helper functions
    // ========================================================================

    /// Create d LWE ciphertexts where the a-vectors form a negacyclic matrix
    /// (i.e., they're rotations of a single polynomial)
    fn create_negacyclic_lwe_ciphertexts(
        d: usize,
        secret: &[u32],
        messages: &[u32],
        params: &LweParams,
        rng: &mut impl rand::Rng,
    ) -> Vec<CiphertextOwned> {
        // Generate a random polynomial
        let base_poly = RingElement::random(d, rng);
        
        let mut cts = Vec::with_capacity(d);
        for i in 0..d {
            // Create the i-th rotation of base_poly
            let a = rotate_negacyclic(&base_poly.coeffs, i);
            
            // Encrypt: c = ⟨a, s⟩ + e + Δ·μ
            let c = regev::encrypt(params, &a, &regev::SecretKey { s: secret }, messages[i], rng);
            
            cts.push(regev::CiphertextOwned { a, c });
        }
        cts
    }

        /// Rotate polynomial coefficients negacyclically by k positions
    /// x^k · (a₀ + a₁x + ...) mod (x^d + 1)
    fn rotate_negacyclic(coeffs: &[u32], k: usize) -> Vec<u32> {
        let d = coeffs.len();
        let mut result = vec![0u32; d];
        for i in 0..d {
            let new_idx = (i + k) % d;
            if i + k >= d {
                // Wrapped around: multiply by -1
                result[new_idx] = coeffs[i].wrapping_neg();
            } else {
                result[new_idx] = coeffs[i];
            }
        }
        result
    }

    #[test]
    fn test_matrix_to_ring_element_happy_path() {
        // Given polynomial A = [1, 2, 3, 4] (coefficients A₀=1, A₁=2, A₂=3, A₃=4)
        // The first column of its negacyclic rotation matrix rot(A) is:
        //   [A₀, -A₃, -A₂, -A₁] = [1, -4, -3, -2]
        //
        // In u32 wrapping arithmetic:
        //   -4 = 0xFFFF_FFFC
        //   -3 = 0xFFFF_FFFD
        //   -2 = 0xFFFF_FFFE
        let d = 4;
        let first_column: Vec<u32> = vec![
            1,                    // A₀
            0u32.wrapping_sub(4), // -A₃ = -4
            0u32.wrapping_sub(3), // -A₂ = -3
            0u32.wrapping_sub(2), // -A₁ = -2
        ];

        // The function should recover the original polynomial A = [1, 2, 3, 4]
        let result = matrix_to_ring_element(&first_column, d);

        assert_eq!(result.coeffs, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_pack_naive_d4() {
        let d = 4;
        let params = LweParams { n: d, p: 256, noise_stddev: 3.2 };
        let mut rng = rand::rng();
        
        // Generate secret (same for LWE and RLWE)
        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        
        // Messages to pack
        let messages: Vec<u32> = (0..d).map(|_| rng.random_range(0..params.p)).collect();
        
        // Create LWE ciphertexts with negacyclic structure
        let lwe_cts = create_negacyclic_lwe_ciphertexts(d, &secret, &messages, &params, &mut rng);
        
        // Pack into RLWE
        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let rlwe_ct = pack_naive(&lwe_refs, d);
        
        // Decrypt RLWE
        let rlwe_params = RlweParams::new(d, params.p, params.noise_stddev);
        let decrypted = crate::ring_regev::decrypt(
            &rlwe_params,
            &regev::SecretKey { s: &secret },
            &rlwe_ct,
        );
        
        // Check that we recovered the packed message
        assert_eq!(decrypted.coeffs, messages);
    }

    // ========================================================================
    // Key Switching Tests
    // ========================================================================

    /// Test key-switch key generation creates the right structure
    #[test]
    fn test_gen_key_switch_key_structure() {
        let d = 4;
        let noise_stddev = 3.2;
        let mut rng = rand::rng();

        // Generate secrets
        let lwe_secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: lwe_secret.clone(), // Same secret for simplicity
        };

        let j = 2; // Target position
        let ks_key = gen_key_switch_key_raw(&lwe_secret, &rlwe_secret, j, d, noise_stddev, &mut rng);

        // Check dimensions
        assert_eq!(ks_key.ks.len(), d);
        for i in 0..d {
            assert_eq!(ks_key.ks[i].len(), LOG_Q);
        }
        assert_eq!(ks_key.target_position, j);
    }

    /// Test that KS key entries decrypt to the correct values
    #[test]
    fn test_key_switch_key_decryption() {
        let d = 4;
        let noise_stddev = 3.2;
        let mut rng = rand::rng();

        // Use small secret values so we can verify exactly
        let lwe_secret: Vec<u32> = vec![5, 3, 7, 2];
        let rlwe_secret = RingElement {
            coeffs: lwe_secret.clone(),
        };

        let j = 1; // Target position x^1
        let ks_key = gen_key_switch_key_raw(&lwe_secret, &rlwe_secret, j, d, noise_stddev, &mut rng);

        // Check a few entries: KS[i][k] should decrypt to s_i · 2^k · x^j
        // Let's check KS[0][0]: should be s_0 · 2^0 · x^1 = 5 · 1 · x = 5x
        let decrypted_00 = decrypt_raw(&rlwe_secret, &ks_key.ks[0][0]);

        // The decrypted polynomial should have coefficient 5 at position j=1
        // (plus small noise)
        let coeff_at_j = decrypted_00.coeffs[j] as i64;
        let expected = 5i64;
        let diff = (coeff_at_j - expected).abs();
        // Allow for noise (should be small, ~3σ ≈ 10)
        assert!(
            diff < 100,
            "KS[0][0] decryption error too large: got {}, expected ~{}",
            coeff_at_j,
            expected
        );

        // Other coefficients should be ~0 (just noise)
        for idx in 0..d {
            if idx != j {
                let coeff = decrypted_00.coeffs[idx] as i32;
                // Should be close to 0 (small noise)
                assert!(
                    coeff.abs() < 100 || coeff > (u32::MAX - 100) as i32,
                    "Non-target coefficient should be ~0, got {}",
                    coeff
                );
            }
        }

        // Check KS[2][3]: should be s_2 · 2^3 · x^1 = 7 · 8 · x = 56x
        let decrypted_23 = decrypt_raw(&rlwe_secret, &ks_key.ks[2][3]);
        let coeff_at_j_23 = decrypted_23.coeffs[j] as i64;
        let expected_23 = 7i64 * 8; // 56
        let diff_23 = (coeff_at_j_23 - expected_23).abs();
        assert!(
            diff_23 < 100,
            "KS[2][3] decryption error too large: got {}, expected ~{}",
            coeff_at_j_23,
            expected_23
        );
    }

    /// Test key switching a single LWE ciphertext
    #[test]
    fn test_key_switch_single_ciphertext() {
        let d = 4;
        let p = 256u32;
        let noise_stddev = 3.2;
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        // Generate secrets (use same for LWE and RLWE for simplicity)
        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: secret.clone(),
        };

        // Create a random LWE ciphertext
        let message = 42u32;
        let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let c = regev::encrypt(&params, &a, &regev::SecretKey { s: &secret }, message, &mut rng);
        let lwe_ct = CiphertextOwned { a: a.clone(), c };

        // Verify LWE decryption works
        let lwe_decrypted = regev::decrypt(&params, &regev::SecretKey { s: &secret }, &lwe_ct.as_ref());
        assert_eq!(lwe_decrypted, message);

        // Generate key-switch key for position j=0
        let j = 0;
        let ks_key = gen_key_switch_key_raw(&secret, &rlwe_secret, j, d, noise_stddev, &mut rng);

        // Apply key switching
        let rlwe_ct = key_switch(&lwe_ct.as_ref(), &ks_key, d);

        // Decrypt the RLWE ciphertext (raw decryption)
        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);

        // The result should be (e + Δμ) · x^j at position j
        // Since j=0, we expect coefficient 0 to be ≈ Δ·message
        let delta = params.delta();

        // Decode: round(coeff / Δ) mod p
        let half_delta = delta / 2;
        let decoded = (decrypted_poly.coeffs[j].wrapping_add(half_delta) / delta) % p;

        assert_eq!(
            decoded, message,
            "Key-switched ciphertext decryption failed: got {}, expected {}",
            decoded, message
        );

        // Other positions should decode to ~0
        for idx in 1..d {
            let decoded_other = (decrypted_poly.coeffs[idx].wrapping_add(half_delta) / delta) % p;
            assert!(
                decoded_other == 0 || decoded_other == p - 1 || decoded_other == 1,
                "Non-target position {} should decode to ~0, got {}",
                idx,
                decoded_other
            );
        }
    }

    /// Test key switching to different positions
    #[test]
    fn test_key_switch_different_positions() {
        let d = 4;
        let p = 256u32;
        let noise_stddev = 3.2;
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: secret.clone(),
        };

        let message = 100u32;
        let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let c = regev::encrypt(&params, &a, &regev::SecretKey { s: &secret }, message, &mut rng);
        let lwe_ct = CiphertextOwned { a: a.clone(), c };

        // Test each position
        for j in 0..d {
            let ks_key = gen_key_switch_key_raw(&secret, &rlwe_secret, j, d, noise_stddev, &mut rng);
            let rlwe_ct = key_switch(&lwe_ct.as_ref(), &ks_key, d);
            let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);

            let delta = params.delta();
            let half_delta = delta / 2;
            let decoded = (decrypted_poly.coeffs[j].wrapping_add(half_delta) / delta) % p;

            assert_eq!(
                decoded, message,
                "Position {}: got {}, expected {}",
                j, decoded, message
            );
        }
    }

    /// Test that key switching preserves homomorphic properties
    /// If we key-switch two ciphertexts and add the RLWE results,
    /// we should get an encryption of the sum of messages.
    #[test]
    fn test_key_switch_homomorphic_addition() {
        let d = 4;
        let p = 256u32;
        let noise_stddev = 2.0; // Lower noise for this test
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: secret.clone(),
        };

        // Two messages
        let msg1 = 30u32;
        let msg2 = 50u32;

        // Create two LWE ciphertexts
        let a1: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let c1 = regev::encrypt(&params, &a1, &regev::SecretKey { s: &secret }, msg1, &mut rng);
        let lwe_ct1 = CiphertextOwned { a: a1, c: c1 };

        let a2: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let c2 = regev::encrypt(&params, &a2, &regev::SecretKey { s: &secret }, msg2, &mut rng);
        let lwe_ct2 = CiphertextOwned { a: a2, c: c2 };

        // Key-switch both to position 0
        let j = 0;
        let ks_key = gen_key_switch_key_raw(&secret, &rlwe_secret, j, d, noise_stddev, &mut rng);

        let rlwe_ct1 = key_switch(&lwe_ct1.as_ref(), &ks_key, d);
        let rlwe_ct2 = key_switch(&lwe_ct2.as_ref(), &ks_key, d);

        // Add RLWE ciphertexts
        let rlwe_sum = add_rlwe_ciphertexts(&rlwe_ct1, &rlwe_ct2);

        // Decrypt and decode
        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_sum);
        let delta = params.delta();
        let half_delta = delta / 2;
        let decoded = (decrypted_poly.coeffs[j].wrapping_add(half_delta) / delta) % p;

        assert_eq!(
            decoded,
            (msg1 + msg2) % p,
            "Homomorphic addition failed: got {}, expected {}",
            decoded,
            (msg1 + msg2) % p
        );
    }

    // ========================================================================
    // Full Packing Tests
    // ========================================================================

    /// Test packing key generation creates the right structure
    #[test]
    fn test_gen_packing_key_structure() {
        let d = 4;
        let noise_stddev = 3.2;
        let mut rng = rand::rng();

        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: secret.clone(),
        };

        let packing_key = gen_packing_key(&secret, &rlwe_secret, d, noise_stddev, &mut rng);

        // Should have d key-switching keys
        assert_eq!(packing_key.keys.len(), d);
        assert_eq!(packing_key.d, d);

        // Each key should target its position
        for j in 0..d {
            assert_eq!(packing_key.keys[j].target_position, j);
        }
    }

    /// Test full packing of d=4 arbitrary LWE ciphertexts
    #[test]
    fn test_pack_with_key_switching_d4() {
        let d = 4;
        let p = 256u32;
        let noise_stddev = 2.0; // Lower noise for reliable decryption
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        // Generate secrets (same for LWE and RLWE)
        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: secret.clone(),
        };

        // Messages to pack
        let messages: Vec<u32> = vec![42, 17, 99, 5];
        assert_eq!(messages.len(), d);

        // Create d ARBITRARY LWE ciphertexts (random a vectors, not negacyclic!)
        let lwe_cts: Vec<CiphertextOwned> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
                let c = regev::encrypt(&params, &a, &regev::SecretKey { s: &secret }, msg, &mut rng);
                CiphertextOwned { a, c }
            })
            .collect();

        // Verify each LWE ciphertext decrypts correctly
        for (i, ct) in lwe_cts.iter().enumerate() {
            let dec = regev::decrypt(&params, &regev::SecretKey { s: &secret }, &ct.as_ref());
            assert_eq!(dec, messages[i], "LWE ciphertext {} failed to decrypt", i);
        }

        // Generate packing key
        let packing_key = gen_packing_key(&secret, &rlwe_secret, d, noise_stddev, &mut rng);

        // Pack into RLWE
        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let rlwe_ct = pack_with_key_switching(&lwe_refs, &packing_key);

        // Decrypt RLWE (raw)
        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);

        // Decode to recover messages
        let decoded = decode_packed_result(&decrypted_poly, params.delta(), p);

        assert_eq!(
            decoded, messages,
            "Packing failed: got {:?}, expected {:?}",
            decoded, messages
        );
    }

    /// Test packing with random messages
    #[test]
    fn test_pack_with_key_switching_random_messages() {
        let d = 4;
        let p = 256u32;
        let noise_stddev = 2.0;
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: secret.clone(),
        };

        // Random messages
        let messages: Vec<u32> = (0..d).map(|_| rng.random_range(0..p)).collect();

        // Create arbitrary LWE ciphertexts
        let lwe_cts: Vec<CiphertextOwned> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
                let c = regev::encrypt(&params, &a, &regev::SecretKey { s: &secret }, msg, &mut rng);
                CiphertextOwned { a, c }
            })
            .collect();

        let packing_key = gen_packing_key(&secret, &rlwe_secret, d, noise_stddev, &mut rng);
        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let rlwe_ct = pack_with_key_switching(&lwe_refs, &packing_key);
        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);
        let decoded = decode_packed_result(&decrypted_poly, params.delta(), p);

        assert_eq!(decoded, messages);
    }

    /// Test packing with d=8 to verify scaling
    #[test]
    fn test_pack_with_key_switching_d8() {
        let d = 8;
        let p = 256u32;
        let noise_stddev = 1.5; // Even lower noise for larger d
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: secret.clone(),
        };

        let messages: Vec<u32> = (0..d).map(|_| rng.random_range(0..p)).collect();

        let lwe_cts: Vec<CiphertextOwned> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
                let c = regev::encrypt(&params, &a, &regev::SecretKey { s: &secret }, msg, &mut rng);
                CiphertextOwned { a, c }
            })
            .collect();

        let packing_key = gen_packing_key(&secret, &rlwe_secret, d, noise_stddev, &mut rng);
        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let rlwe_ct = pack_with_key_switching(&lwe_refs, &packing_key);
        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);
        let decoded = decode_packed_result(&decrypted_poly, params.delta(), p);

        assert_eq!(decoded, messages);
    }

    /// Test that packing achieves the expected compression ratio
    #[test]
    fn test_packing_compression_ratio() {
        let d = 4;

        // Input: d LWE ciphertexts, each with (d+1) elements
        let lwe_size = d * (d + 1); // 4 * 5 = 20 elements

        // Output: 1 RLWE ciphertext with 2d elements
        let rlwe_size = 2 * d; // 2 * 4 = 8 elements

        let compression_ratio = lwe_size as f64 / rlwe_size as f64;

        // Expected: (d+1)/2 = 5/2 = 2.5
        let expected_ratio = (d + 1) as f64 / 2.0;

        assert!(
            (compression_ratio - expected_ratio).abs() < 0.01,
            "Compression ratio mismatch: got {}, expected {}",
            compression_ratio,
            expected_ratio
        );

        println!("Compression ratio for d={}: {}x", d, compression_ratio);
    }

    /// Test packing key size
    #[test]
    fn test_packing_key_size() {
        let d = 4;
        let noise_stddev = 3.2;
        let mut rng = rand::rng();

        let secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement {
            coeffs: secret.clone(),
        };

        let packing_key = gen_packing_key(&secret, &rlwe_secret, d, noise_stddev, &mut rng);

        // Count total RLWE ciphertexts in packing key
        let total_rlwe_cts: usize = packing_key.keys.iter().map(|k| k.ks.len() * LOG_Q).sum();

        // Expected: d positions × d secret components × LOG_Q bits = d² × LOG_Q
        let expected = d * d * LOG_Q;
        assert_eq!(total_rlwe_cts, expected);

        // Each RLWE ciphertext has 2d coefficients
        let total_coefficients = total_rlwe_cts * 2 * d;
        println!(
            "Packing key size for d={}: {} RLWE ciphertexts, {} u32 coefficients ({} KB)",
            d,
            total_rlwe_cts,
            total_coefficients,
            total_coefficients * 4 / 1024
        );
    }
}

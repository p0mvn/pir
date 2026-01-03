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

use crate::ntt::CrtParams;
use crate::regev::Ciphertext;
use crate::ring::RingElement;
use crate::ring_regev::RLWECiphertextOwned;

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
    lwe_cts: &[Ciphertext], // d ciphertexts, each with a.len() == d
    d: usize,
) -> RLWECiphertextOwned {
    assert_eq!(lwe_cts.len(), d);

    // Extract first column of the matrix formed by stacking a_i as rows.
    // This IS the polynomial we need for RLWE (not the original A that
    // generated these rotations). The first column [a_0, -a_{d-1}, ..., -a_1]
    // when used directly makes polynomial multiplication A'·S equal the
    // matrix-vector product rot(A)·s that LWE encryption computed.
    let first_column: Vec<u32> = lwe_cts.iter().map(|ct| ct.a[0]).collect();

    let a_poly = RingElement {
        coeffs: first_column,
    };

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

/// Gadget decomposition parameters.
///
/// Instead of base-2 decomposition (32 bits → 32 RLWE ciphertexts per position),
/// we use a larger base to reduce the number of ciphertexts.
///
/// With base B = 2^LOG_BASE:
/// - Each coefficient is decomposed into NUM_DIGITS digits in base B
/// - KS[i][k] encrypts s_i · B^k · x^j
/// - During key switching, we multiply by the digit value (not just 0/1)
///
/// Example with base 256 (LOG_BASE = 8):
/// - NUM_DIGITS = 32/8 = 4 (instead of 32)
/// - Each digit is in range [0, 255]
/// - 8x reduction in packing key size
///
///   Number of bits per digit in gadget decomposition.
///   LOG_BASE = 8 means base 256.
pub const LOG_BASE: usize = 8;

/// The decomposition base: B = 2^LOG_BASE = 256
pub const GADGET_BASE: u32 = 1 << LOG_BASE;

/// Number of digits needed to represent a 32-bit coefficient in base B.
/// NUM_DIGITS = 32 / LOG_BASE = 4 for base 256
pub const NUM_DIGITS: usize = 32 / LOG_BASE;

/// A key-switching key for a single position j.
///
/// This allows converting an LWE ciphertext (under secret s) to an RLWE
/// ciphertext (under secret S) that encrypts `μ · x^j`.
///
/// Structure: `ks[i][k]` is an RLWE encryption of `s_i · B^k · x^j`
/// where:
/// - i ∈ {0, ..., d-1} indexes the LWE secret component
/// - k ∈ {0, ..., NUM_DIGITS-1} indexes the digit position
/// - B = GADGET_BASE = 2^LOG_BASE (e.g., 256 for LOG_BASE=8)
///
/// With base 256, we have 4 ciphertexts per position instead of 32:
///   KS[i][0] = RLWE.Enc(s_i · 1 · x^j)
///   KS[i][1] = RLWE.Enc(s_i · 256 · x^j)
///   KS[i][2] = RLWE.Enc(s_i · 256² · x^j)
///   KS[i][3] = RLWE.Enc(s_i · 256³ · x^j)
pub struct KeySwitchKey {
    /// ks[i][k] encrypts s_i · B^k · x^j under the RLWE secret
    /// Dimensions: [d][NUM_DIGITS]
    pub ks: Vec<Vec<RLWECiphertextOwned>>,
    /// The target position j (encrypts μ · x^j)
    pub target_position: usize,
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

/// Multiply an RLWE ciphertext by a scalar homomorphically.
///
/// If ct encrypts m, the result encrypts scalar · m.
///
/// This is used in gadget decomposition with larger bases (e.g., base 256).
/// Instead of just adding ciphertexts when a bit is 1, we multiply by the
/// digit value (0-255) and add.
pub fn scalar_mul_rlwe_ciphertext(scalar: u32, ct: &RLWECiphertextOwned) -> RLWECiphertextOwned {
    RLWECiphertextOwned {
        a: ct.a.scalar_mul(scalar),
        c: ct.c.scalar_mul(scalar),
    }
}

/// Add scalar multiple of ct2 to ct1: ct1 + scalar * ct2
///
/// More efficient than separate scalar_mul and add operations when
/// accumulating many scaled ciphertexts.
#[allow(dead_code)]
pub fn add_scaled_rlwe_ciphertext(
    ct1: &RLWECiphertextOwned,
    scalar: u32,
    ct2: &RLWECiphertextOwned,
) -> RLWECiphertextOwned {
    RLWECiphertextOwned {
        a: ct1.a.add(&ct2.a.scalar_mul(scalar)),
        c: ct1.c.add(&ct2.c.scalar_mul(scalar)),
    }
}

/// Add scalar multiple of ct2 to ct1 in-place: ct1 += scalar * ct2
///
/// This avoids allocating new vectors on each accumulation, which is
/// critical for performance in the key_switch inner loop.
#[inline]
fn add_scaled_rlwe_ciphertext_inplace(ct1: &mut RLWECiphertextOwned, scalar: u32, ct2: &RLWECiphertextOwned) {
    for (a1, a2) in ct1.a.coeffs.iter_mut().zip(&ct2.a.coeffs) {
        *a1 = a1.wrapping_add(a2.wrapping_mul(scalar));
    }
    for (c1, c2) in ct1.c.coeffs.iter_mut().zip(&ct2.c.coeffs) {
        *c1 = c1.wrapping_add(c2.wrapping_mul(scalar));
    }
}

/// Add ct2 to ct1 in-place: ct1 += ct2
#[inline]
fn add_rlwe_ciphertext_inplace(ct1: &mut RLWECiphertextOwned, ct2: &RLWECiphertextOwned) {
    for (a1, a2) in ct1.a.coeffs.iter_mut().zip(&ct2.a.coeffs) {
        *a1 = a1.wrapping_add(*a2);
    }
    for (c1, c2) in ct1.c.coeffs.iter_mut().zip(&ct2.c.coeffs) {
        *c1 = c1.wrapping_add(*c2);
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
/// For each a_i, decompose it into base-B digits: a_i = Σ_k d_k · B^k
/// where B = GADGET_BASE and d_k ∈ [0, B-1].
///
/// Then: ⟨a, s⟩ = Σ_i a_i · s_i = Σ_i Σ_k d_k · B^k · s_i
///
/// The key-switch key contains RLWE encryptions of s_i · B^k · x^j.
/// By summing the appropriate ciphertexts (weighted by digits d_k),
/// we get an RLWE encryption of ⟨a, s⟩ · x^j.
///
/// Final result:
///   C' = c · x^j - Σ_i Σ_k d_k · KS[i][k]
///
/// which decrypts to: c · x^j - ⟨a, s⟩ · x^j = (e + Δμ) · x^j ≈ Δμ · x^j
///
/// # Dimensions
///
/// This function supports both homogeneous (n = d) and heterogeneous (n ≠ d) cases:
/// - LWE dimension n is inferred from `lwe_ct.a.len()`
/// - RLWE ring dimension d is inferred from `ks_key`
///
/// The key-switch key must be generated with matching dimensions.
pub fn key_switch(lwe_ct: &Ciphertext, ks_key: &KeySwitchKey) -> RLWECiphertextOwned {
    // Infer dimensions from inputs
    let lwe_dim = lwe_ct.a.len();
    let ring_dim = ks_key.ks[0][0].a.coeffs.len();
    let j = ks_key.target_position;

    assert_eq!(
        ks_key.ks.len(),
        lwe_dim,
        "KS key has {} components but LWE ciphertext has dimension {}",
        ks_key.ks.len(),
        lwe_dim
    );
    assert!(
        j < ring_dim,
        "Target position {} >= ring dimension {}",
        j,
        ring_dim
    );

    // c · x^j as a polynomial (ring_dim coefficients)
    let mut c_poly_coeffs = vec![0u32; ring_dim];
    c_poly_coeffs[j] = lwe_ct.c;
    let c_poly = RingElement {
        coeffs: c_poly_coeffs,
    };

    // Accumulate: Σ_i Σ_k d_k · KS[i][k]
    // Use in-place accumulation to avoid repeated allocations
    let mut accumulated = zero_rlwe_ciphertext(ring_dim);
    let digit_mask = GADGET_BASE - 1;

    // Iterate over LWE dimension (n)
    for i in 0..lwe_dim {
        let mut a_i = lwe_ct.a[i];

        // Decompose a_i into base-B digits and accumulate
        for k in 0..NUM_DIGITS {
            // Extract digit k (lowest LOG_BASE bits of current a_i)
            let digit = a_i & digit_mask;

            if digit != 0 {
                // Add digit · KS[i][k] to the accumulator (in-place)
                add_scaled_rlwe_ciphertext_inplace(&mut accumulated, digit, &ks_key.ks[i][k]);
            }

            // Shift right by LOG_BASE bits to get next digit
            a_i >>= LOG_BASE;
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
/// This creates RLWE encryptions of `s_i · B^k · x^j` WITHOUT the Δ scaling,
/// where B = GADGET_BASE = 2^LOG_BASE (e.g., 256).
///
/// The ciphertext structure is:
///   KS[i][k].c = KS[i][k].a · S + e + s_i · B^k · x^j
///
/// With base 256:
///   KS[i][0] = RLWE.Enc(s_i · 1 · x^j)
///   KS[i][1] = RLWE.Enc(s_i · 256 · x^j)
///   KS[i][2] = RLWE.Enc(s_i · 256² · x^j)
///   KS[i][3] = RLWE.Enc(s_i · 256³ · x^j)
///
/// Note: This bypasses the plaintext modulus p entirely.
///
/// # Performance
///
/// Uses CRT-based NTT for O(n log n) polynomial multiplication.
/// The CRT parameters are precomputed once and reused for all encryptions.
///
/// # Dimensions
///
/// - LWE dimension n is inferred from `lwe_secret.len()`
/// - RLWE ring dimension d is inferred from `rlwe_secret.coeffs.len()`
/// - These can be different (heterogeneous case)
pub fn gen_key_switch_key_raw(
    lwe_secret: &[u32],
    rlwe_secret: &RingElement,
    j: usize,
    noise_stddev: f64,
    rng: &mut impl Rng,
) -> KeySwitchKey {
    let lwe_dim = lwe_secret.len();
    let ring_dim = rlwe_secret.coeffs.len();
    assert!(
        j < ring_dim,
        "Target position {} >= ring dimension {}",
        j,
        ring_dim
    );

    // Precompute CRT parameters for O(n log n) multiplication
    let crt = CrtParams::new(ring_dim);

    let mut ks = Vec::with_capacity(lwe_dim);

    for i in 0..lwe_dim {
        let mut ks_i = Vec::with_capacity(NUM_DIGITS);
        for k in 0..NUM_DIGITS {
            // Create raw RLWE encryption of s_i · B^k · x^j
            // c = a · S + e + s_i · B^k · x^j (NO Δ scaling!)

            let a = RingElement::random(ring_dim, rng);
            let e = RingElement::random_small(ring_dim, noise_stddev as i32, rng);

            // Message: s_i · B^k · x^j
            // B^k = (2^LOG_BASE)^k = 2^(LOG_BASE * k)
            let power = (LOG_BASE * k) as u32;
            let scalar = lwe_secret[i].wrapping_mul(1u32 << power);
            let mut msg_coeffs = vec![0u32; ring_dim];
            msg_coeffs[j] = scalar;
            let msg = RingElement { coeffs: msg_coeffs };

            // c = a · S + e + msg (raw, no Δ)
            // Use CRT-based NTT for O(n log n) polynomial multiplication
            let c = a.mul_crt(rlwe_secret, &crt).add(&e).add(&msg);

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
///
/// # Performance
///
/// Uses CRT-based NTT for O(n log n) polynomial multiplication.
/// For multiple decryptions, consider using `decrypt_raw_with_crt` with
/// precomputed CRT parameters.
pub fn decrypt_raw(rlwe_secret: &RingElement, ct: &RLWECiphertextOwned) -> RingElement {
    let ring_dim = rlwe_secret.coeffs.len();
    let crt = CrtParams::new(ring_dim);
    ct.c.sub(&ct.a.mul_crt(rlwe_secret, &crt))
}

/// Decrypt a "raw" RLWE ciphertext with precomputed CRT parameters.
///
/// This is more efficient when decrypting multiple ciphertexts as the
/// CRT parameters are computed once and reused.
pub fn decrypt_raw_with_crt(
    rlwe_secret: &RingElement,
    ct: &RLWECiphertextOwned,
    crt: &CrtParams,
) -> RingElement {
    ct.c.sub(&ct.a.mul_crt(rlwe_secret, crt))
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
/// ## Homogeneous Case (n = d)
///
/// Size: d × d × NUM_DIGITS × 2d coefficients = O(d³ · log_B(q)) storage
/// where B = GADGET_BASE = 256 and NUM_DIGITS = 32/LOG_BASE = 4.
///
/// For d=4, NUM_DIGITS=4: 4 × 4 × 4 × 2 × 4 = 512 u32 values
/// (8x smaller than base-2 decomposition with LOG_Q=32)
///
/// ## Heterogeneous Case (n ≠ d)
///
/// When LWE dimension n differs from RLWE ring dimension d:
/// - Size: d × n × NUM_DIGITS × 2d coefficients
/// - Each KS key has n components (one per LWE secret element)
/// - Result has d positions (ring dimension)
pub struct PackingKey {
    /// keys[j] is the key-switching key for position j
    pub keys: Vec<KeySwitchKey>,
    /// RLWE ring dimension (number of positions to pack into)
    pub d: usize,
    /// LWE dimension (length of LWE secret)
    pub n: usize,
}

/// Generate a packing key for converting LWE ciphertexts to RLWE ciphertexts.
///
/// # Arguments
/// * `lwe_secret` - The LWE secret key (length determines LWE dimension n)
/// * `rlwe_secret` - The RLWE secret key (length determines ring dimension d)
/// * `noise_stddev` - Standard deviation for RLWE encryption noise
/// * `rng` - Random number generator
///
/// # Dimensions
///
/// - LWE dimension n is inferred from `lwe_secret.len()`
/// - RLWE ring dimension d is inferred from `rlwe_secret.coeffs.len()`
/// - These can be the same (homogeneous) or different (heterogeneous)
///
/// # Packing Capacity
///
/// Each call to `pack_with_key_switching` packs exactly `d` LWE ciphertexts
/// into one RLWE ciphertext. If you have more LWE ciphertexts, call packing multiple times.
///
/// # Size
///
/// The packing key size is `d × n × NUM_DIGITS × 2d × sizeof(u32)` bytes.
/// For n=1024, d=2048, NUM_DIGITS=4: 2048 × 1024 × 4 × 4096 × 4 ≈ 137 GB
/// (This is why YPIR queries are larger than DoublePIR queries.)
pub fn gen_packing_key(
    lwe_secret: &[u32],
    rlwe_secret: &RingElement,
    noise_stddev: f64,
    rng: &mut impl Rng,
) -> PackingKey {
    let lwe_dim = lwe_secret.len();
    let ring_dim = rlwe_secret.coeffs.len();

    let keys = (0..ring_dim)
        .map(|j| gen_key_switch_key_raw(lwe_secret, rlwe_secret, j, noise_stddev, rng))
        .collect();

    PackingKey {
        keys,
        d: ring_dim,
        n: lwe_dim,
    }
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
/// - Input: d LWE ciphertexts, each with (n+1) elements = d(n+1) total
/// - Output: 1 RLWE ciphertext with 2d elements
/// - Compression ratio: (n+1)/2 for homogeneous case (n=d), varies for heterogeneous
///
/// # Dimension Handling
///
/// - Homogeneous (n = d): Each LWE ciphertext has d-element `a` vector
/// - Heterogeneous (n ≠ d): Each LWE ciphertext has n-element `a` vector,
///   result has d-coefficient polynomials
pub fn pack_with_key_switching(
    lwe_cts: &[Ciphertext],
    packing_key: &PackingKey,
) -> RLWECiphertextOwned {
    let d = packing_key.d;
    let n = packing_key.n;
    assert_eq!(lwe_cts.len(), d, "Must provide exactly d LWE ciphertexts");

    // Start with zero RLWE ciphertext
    let mut result = zero_rlwe_ciphertext(d);

    // Key-switch each LWE ciphertext to its position and accumulate (in-place)
    for (j, lwe_ct) in lwe_cts.iter().enumerate() {
        assert_eq!(
            lwe_ct.a.len(),
            n,
            "LWE ciphertext {} has wrong dimension: expected {}, got {}",
            j,
            n,
            lwe_ct.a.len()
        );

        // Key-switch ct_j to position j: produces RLWE encrypting μ_j · x^j
        let rlwe_j = key_switch(lwe_ct, &packing_key.keys[j]);

        // Add to accumulator (in-place to avoid allocation)
        add_rlwe_ciphertext_inplace(&mut result, &rlwe_j);
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
        ring_regev::RlweParams,
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
            let c = regev::encrypt(
                params,
                &a,
                &regev::SecretKey { s: secret },
                messages[i],
                rng,
            );

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
    fn test_pack_naive_d4() {
        let d = 4;
        let params = LweParams {
            n: d,
            p: 256,
            noise_stddev: 3.2,
        };
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
        let decrypted =
            crate::ring_regev::decrypt(&rlwe_params, &regev::SecretKey { s: &secret }, &rlwe_ct);

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
        let ks_key = gen_key_switch_key_raw(&lwe_secret, &rlwe_secret, j, noise_stddev, &mut rng);

        // Check dimensions - now using NUM_DIGITS instead of LOG_Q (32)
        assert_eq!(ks_key.ks.len(), d);
        for i in 0..d {
            assert_eq!(ks_key.ks[i].len(), NUM_DIGITS); // 4 instead of 32
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
        let ks_key = gen_key_switch_key_raw(&lwe_secret, &rlwe_secret, j, noise_stddev, &mut rng);

        // Check a few entries: KS[i][k] should decrypt to s_i · B^k · x^j
        // where B = GADGET_BASE = 256

        // KS[0][0]: should be s_0 · B^0 · x^1 = 5 · 1 · x = 5x
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

        // KS[2][1]: should be s_2 · B^1 · x^1 = 7 · 256 · x = 1792x
        let decrypted_21 = decrypt_raw(&rlwe_secret, &ks_key.ks[2][1]);
        let coeff_at_j_21 = decrypted_21.coeffs[j] as i64;
        let expected_21 = 7i64 * GADGET_BASE as i64; // 7 * 256 = 1792
        let diff_21 = (coeff_at_j_21 - expected_21).abs();
        assert!(
            diff_21 < 100,
            "KS[2][1] decryption error too large: got {}, expected ~{}",
            coeff_at_j_21,
            expected_21
        );

        // KS[1][2]: should be s_1 · B^2 · x^1 = 3 · 65536 · x = 196608x
        let decrypted_12 = decrypt_raw(&rlwe_secret, &ks_key.ks[1][2]);
        let coeff_at_j_12 = decrypted_12.coeffs[j] as i64;
        let expected_12 = 3i64 * (GADGET_BASE as i64 * GADGET_BASE as i64); // 3 * 256^2 = 196608
        let diff_12 = (coeff_at_j_12 - expected_12).abs();
        assert!(
            diff_12 < 100,
            "KS[1][2] decryption error too large: got {}, expected ~{}",
            coeff_at_j_12,
            expected_12
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
        let c = regev::encrypt(
            &params,
            &a,
            &regev::SecretKey { s: &secret },
            message,
            &mut rng,
        );
        let lwe_ct = CiphertextOwned { a: a.clone(), c };

        // Verify LWE decryption works
        let lwe_decrypted =
            regev::decrypt(&params, &regev::SecretKey { s: &secret }, &lwe_ct.as_ref());
        assert_eq!(lwe_decrypted, message);

        // Generate key-switch key for position j=0
        let j = 0;
        let ks_key = gen_key_switch_key_raw(&secret, &rlwe_secret, j, noise_stddev, &mut rng);

        // Apply key switching
        let rlwe_ct = key_switch(&lwe_ct.as_ref(), &ks_key);

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
        let c = regev::encrypt(
            &params,
            &a,
            &regev::SecretKey { s: &secret },
            message,
            &mut rng,
        );
        let lwe_ct = CiphertextOwned { a: a.clone(), c };

        // Test each position
        for j in 0..d {
            let ks_key = gen_key_switch_key_raw(&secret, &rlwe_secret, j, noise_stddev, &mut rng);
            let rlwe_ct = key_switch(&lwe_ct.as_ref(), &ks_key);
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
        let c1 = regev::encrypt(
            &params,
            &a1,
            &regev::SecretKey { s: &secret },
            msg1,
            &mut rng,
        );
        let lwe_ct1 = CiphertextOwned { a: a1, c: c1 };

        let a2: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let c2 = regev::encrypt(
            &params,
            &a2,
            &regev::SecretKey { s: &secret },
            msg2,
            &mut rng,
        );
        let lwe_ct2 = CiphertextOwned { a: a2, c: c2 };

        // Key-switch both to position 0
        let j = 0;
        let ks_key = gen_key_switch_key_raw(&secret, &rlwe_secret, j, noise_stddev, &mut rng);

        let rlwe_ct1 = key_switch(&lwe_ct1.as_ref(), &ks_key);
        let rlwe_ct2 = key_switch(&lwe_ct2.as_ref(), &ks_key);

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

        let packing_key = gen_packing_key(&secret, &rlwe_secret, noise_stddev, &mut rng);

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
                let c =
                    regev::encrypt(&params, &a, &regev::SecretKey { s: &secret }, msg, &mut rng);
                CiphertextOwned { a, c }
            })
            .collect();

        // Verify each LWE ciphertext decrypts correctly
        for (i, ct) in lwe_cts.iter().enumerate() {
            let dec = regev::decrypt(&params, &regev::SecretKey { s: &secret }, &ct.as_ref());
            assert_eq!(dec, messages[i], "LWE ciphertext {} failed to decrypt", i);
        }

        // Generate packing key
        let packing_key = gen_packing_key(&secret, &rlwe_secret, noise_stddev, &mut rng);

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
                let c =
                    regev::encrypt(&params, &a, &regev::SecretKey { s: &secret }, msg, &mut rng);
                CiphertextOwned { a, c }
            })
            .collect();

        let packing_key = gen_packing_key(&secret, &rlwe_secret, noise_stddev, &mut rng);
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
                let c =
                    regev::encrypt(&params, &a, &regev::SecretKey { s: &secret }, msg, &mut rng);
                CiphertextOwned { a, c }
            })
            .collect();

        let packing_key = gen_packing_key(&secret, &rlwe_secret, noise_stddev, &mut rng);
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

        let packing_key = gen_packing_key(&secret, &rlwe_secret, noise_stddev, &mut rng);

        // Count total RLWE ciphertexts in packing key
        let total_rlwe_cts: usize = packing_key
            .keys
            .iter()
            .map(|k| k.ks.len() * NUM_DIGITS)
            .sum();

        // Expected: d positions × d secret components × NUM_DIGITS = d² × NUM_DIGITS
        // With base 256 (NUM_DIGITS=4), this is 8x smaller than base-2 (LOG_Q=32)
        let expected = d * d * NUM_DIGITS;
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
        println!(
            "  Using base {} (LOG_BASE={}), NUM_DIGITS={}",
            GADGET_BASE, LOG_BASE, NUM_DIGITS
        );
        println!(
            "  Reduction from base-2: {}x fewer ciphertexts",
            32 / NUM_DIGITS
        );
    }

    /// Test that the optimized gadget decomposition produces correct results
    #[test]
    fn test_gadget_decomposition_correctness() {
        // Verify that base-B decomposition correctly reconstructs values
        let test_values: Vec<u32> = vec![
            0,
            1,
            255,
            256,
            257,
            65535,
            65536,
            0x12345678,
            0xDEADBEEF,
            u32::MAX,
        ];

        for &val in &test_values {
            // Decompose into base-B digits
            let mut digits = [0u32; NUM_DIGITS];
            let mut v = val;
            for k in 0..NUM_DIGITS {
                digits[k] = v & (GADGET_BASE - 1);
                v >>= LOG_BASE;
            }

            // Reconstruct: sum of digit[k] * B^k
            let mut reconstructed = 0u32;
            for k in 0..NUM_DIGITS {
                let power = (LOG_BASE * k) as u32;
                reconstructed = reconstructed.wrapping_add(digits[k].wrapping_mul(1u32 << power));
            }

            assert_eq!(
                reconstructed, val,
                "Failed to reconstruct {}: got {}",
                val, reconstructed
            );
        }
    }

    /// Verify the noise growth with base-256 is acceptable
    #[test]
    fn test_base256_noise_growth() {
        // With base-256, each digit can be up to 255, so we multiply ciphertexts
        // by larger values. This increases noise by factor of ~B/2 = 128 per digit.
        //
        // Total noise growth compared to base-2:
        // - Base-2: 32 additions (each adds ~e noise) → ~32e total
        // - Base-256: 4 additions with scalar ~128 each → ~4*128e = 512e total
        //
        // However, we have 8x fewer ciphertexts and operations, which can be
        // worth the noise tradeoff for many applications.

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

        // Test with multiple random messages to ensure decryption works
        for _ in 0..10 {
            let messages: Vec<u32> = (0..d).map(|_| rng.random_range(0..p)).collect();

            let lwe_cts: Vec<CiphertextOwned> = messages
                .iter()
                .map(|&msg| {
                    let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
                    let c = regev::encrypt(
                        &params,
                        &a,
                        &regev::SecretKey { s: &secret },
                        msg,
                        &mut rng,
                    );
                    CiphertextOwned { a, c }
                })
                .collect();

            let packing_key = gen_packing_key(&secret, &rlwe_secret, noise_stddev, &mut rng);
            let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
            let rlwe_ct = pack_with_key_switching(&lwe_refs, &packing_key);
            let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);
            let decoded = decode_packed_result(&decrypted_poly, params.delta(), p);

            assert_eq!(
                decoded, messages,
                "Base-256 packing failed: got {:?}, expected {:?}",
                decoded, messages
            );
        }
    }

    // ========================================================================
    // Heterogeneous Dimension Tests (LWE dim n ≠ RLWE dim d)
    // ========================================================================

    /// Test packing with different LWE and RLWE dimensions
    #[test]
    fn test_heterogeneous_packing_n_less_than_d() {
        // LWE dimension n = 4, RLWE ring dimension d = 8
        let n = 4;
        let d = 8;
        let p = 256u32;
        let noise_stddev = 2.0;
        let lwe_params = LweParams { n, p, noise_stddev };
        let mut rng = rand::rng();

        // Independent secrets!
        let lwe_secret: Vec<u32> = (0..n).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement::random_ternary(d, &mut rng);

        // Messages to pack (d messages)
        let messages: Vec<u32> = (0..d).map(|_| rng.random_range(0..p)).collect();

        // Create d LWE ciphertexts with n-dimensional a vectors
        let lwe_cts: Vec<CiphertextOwned> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u32> = (0..n).map(|_| rng.random()).collect();
                let c = regev::encrypt(
                    &lwe_params,
                    &a,
                    &regev::SecretKey { s: &lwe_secret },
                    msg,
                    &mut rng,
                );
                CiphertextOwned { a, c }
            })
            .collect();

        // Generate packing key (dimensions inferred from secrets)
        let packing_key = gen_packing_key(&lwe_secret, &rlwe_secret, noise_stddev, &mut rng);

        assert_eq!(packing_key.n, n);
        assert_eq!(packing_key.d, d);

        // Pack
        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let rlwe_ct = pack_with_key_switching(&lwe_refs, &packing_key);

        // Verify RLWE ciphertext has correct dimension
        assert_eq!(rlwe_ct.a.coeffs.len(), d);
        assert_eq!(rlwe_ct.c.coeffs.len(), d);

        // Decrypt and decode
        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);
        let decoded = decode_packed_result(&decrypted_poly, lwe_params.delta(), p);

        assert_eq!(
            decoded, messages,
            "Heterogeneous packing failed: got {:?}, expected {:?}",
            decoded, messages
        );
    }

    /// Test with completely independent secrets (uniform LWE, ternary RLWE)
    #[test]
    fn test_independent_secrets() {
        let d = 4;
        let p = 256u32;
        let noise_stddev = 2.0;
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        // LWE: uniform random secret
        let lwe_secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();

        // RLWE: ternary secret (completely different!)
        let rlwe_secret = RingElement::random_ternary(d, &mut rng);

        // Verify secrets are actually different
        assert_ne!(
            lwe_secret, rlwe_secret.coeffs,
            "Secrets should be different for this test"
        );

        let messages: Vec<u32> = vec![42, 17, 99, 5];

        let lwe_cts: Vec<CiphertextOwned> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
                let c = regev::encrypt(
                    &params,
                    &a,
                    &regev::SecretKey { s: &lwe_secret },
                    msg,
                    &mut rng,
                );
                CiphertextOwned { a, c }
            })
            .collect();

        // Packing key bridges the two secrets
        let packing_key = gen_packing_key(&lwe_secret, &rlwe_secret, noise_stddev, &mut rng);

        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let rlwe_ct = pack_with_key_switching(&lwe_refs, &packing_key);

        // Decrypt with RLWE secret (not LWE secret!)
        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);
        let decoded = decode_packed_result(&decrypted_poly, params.delta(), p);

        assert_eq!(
            decoded, messages,
            "Independent secrets packing failed: got {:?}, expected {:?}",
            decoded, messages
        );
    }

    /// Test with ternary RLWE secret of specific Hamming weight
    #[test]
    fn test_ternary_hw_secret() {
        let d = 8;
        let p = 256u32;
        let noise_stddev = 2.0;
        let params = LweParams {
            n: d,
            p,
            noise_stddev,
        };
        let mut rng = rand::rng();

        // LWE: uniform random
        let lwe_secret: Vec<u32> = (0..d).map(|_| rng.random()).collect();

        // RLWE: ternary with specific Hamming weight (half the dimension)
        let rlwe_secret = RingElement::random_ternary_hw(d, d / 2, &mut rng);

        // Verify Hamming weight
        let hw: usize = rlwe_secret.coeffs.iter().filter(|&&c| c != 0).count();
        assert_eq!(hw, d / 2);

        let messages: Vec<u32> = (0..d).map(|_| rng.random_range(0..p)).collect();

        let lwe_cts: Vec<CiphertextOwned> = messages
            .iter()
            .map(|&msg| {
                let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
                let c = regev::encrypt(
                    &params,
                    &a,
                    &regev::SecretKey { s: &lwe_secret },
                    msg,
                    &mut rng,
                );
                CiphertextOwned { a, c }
            })
            .collect();

        let packing_key = gen_packing_key(&lwe_secret, &rlwe_secret, noise_stddev, &mut rng);
        let lwe_refs: Vec<_> = lwe_cts.iter().map(|ct| ct.as_ref()).collect();
        let rlwe_ct = pack_with_key_switching(&lwe_refs, &packing_key);

        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);
        let decoded = decode_packed_result(&decrypted_poly, params.delta(), p);

        assert_eq!(decoded, messages);
    }

    /// Test that heterogeneous packing key has correct structure
    #[test]
    fn test_heterogeneous_packing_key_structure() {
        let n = 4; // LWE dimension
        let d = 8; // RLWE ring dimension
        let noise_stddev = 3.2;
        let mut rng = rand::rng();

        let lwe_secret: Vec<u32> = (0..n).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement::random_ternary(d, &mut rng);

        let packing_key = gen_packing_key(&lwe_secret, &rlwe_secret, noise_stddev, &mut rng);

        // Should have d key-switching keys (one per position)
        assert_eq!(packing_key.keys.len(), d);
        assert_eq!(packing_key.d, d);
        assert_eq!(packing_key.n, n);

        // Each key should have n components (one per LWE secret element)
        for (j, ks_key) in packing_key.keys.iter().enumerate() {
            assert_eq!(
                ks_key.ks.len(),
                n,
                "KS key {} should have {} components",
                j,
                n
            );
            assert_eq!(ks_key.target_position, j);

            // Each component should have NUM_DIGITS RLWE ciphertexts
            for ks_component in &ks_key.ks {
                assert_eq!(ks_component.len(), NUM_DIGITS);

                // Each RLWE ciphertext should have d-dimensional polynomials
                for ct in ks_component {
                    assert_eq!(ct.a.coeffs.len(), d);
                    assert_eq!(ct.c.coeffs.len(), d);
                }
            }
        }
    }

    /// Test key switching with different LWE/RLWE dimensions (n < d)
    #[test]
    fn test_key_switch_different_dimensions() {
        let n = 4; // LWE dimension
        let d = 8; // RLWE ring dimension (different!)
        let p = 256u32;
        let noise_stddev = 2.0;
        let lwe_params = LweParams { n, p, noise_stddev };
        let mut rng = rand::rng();

        let lwe_secret: Vec<u32> = (0..n).map(|_| rng.random()).collect();
        let rlwe_secret = RingElement::random_ternary(d, &mut rng);

        let message = 42u32;
        let a: Vec<u32> = (0..n).map(|_| rng.random()).collect();
        let c = regev::encrypt(
            &lwe_params,
            &a,
            &regev::SecretKey { s: &lwe_secret },
            message,
            &mut rng,
        );
        let lwe_ct = CiphertextOwned { a: a.clone(), c };

        // Generate KS key for position 0
        let j = 0;
        let ks_key = gen_key_switch_key_raw(&lwe_secret, &rlwe_secret, j, noise_stddev, &mut rng);

        // Apply key switching (unified function handles both cases)
        let rlwe_ct = key_switch(&lwe_ct.as_ref(), &ks_key);

        // Verify dimensions match ring dimension
        assert_eq!(rlwe_ct.a.coeffs.len(), d);
        assert_eq!(rlwe_ct.c.coeffs.len(), d);

        // Decrypt and decode
        let decrypted_poly = decrypt_raw(&rlwe_secret, &rlwe_ct);
        let decoded = (decrypted_poly.coeffs[j].wrapping_add(lwe_params.delta() / 2)
            / lwe_params.delta())
            % p;

        assert_eq!(
            decoded, message,
            "Key switch with n={}, d={} failed: got {}, expected {}",
            n, d, decoded, message
        );
    }
}

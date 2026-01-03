//! Number Theoretic Transform (NTT) for fast polynomial multiplication.
//!
//! NTT is the finite field equivalent of FFT. It transforms polynomial multiplication
//! from O(n²) to O(n log n) by:
//! 1. Converting polynomials to NTT domain (O(n log n))
//! 2. Point-wise multiplication in NTT domain (O(n))
//! 3. Converting back to coefficient domain (O(n log n))
//!
//! For the ring R_q = Z_q[x]/(x^d + 1), we use the "negative wrapped convolution"
//! technique with a 2d-th root of unity.
//!
//! ## NTT-Friendly Prime
//!
//! We use q = 2013265921 = 15 × 2^27 + 1, which:
//! - Fits in u32 (max ~4 billion)
//! - Has 2^27-th roots of unity (supports d up to 2^26 = 67 million)
//! - Allows efficient modular arithmetic

/// NTT-friendly prime: q = 2013265921 = 15 × 2^27 + 1
pub const NTT_PRIME: u64 = 2013265921;

/// Primitive root of unity modulo NTT_PRIME
/// g = 31 is a primitive root mod 2013265921
const PRIMITIVE_ROOT: u64 = 31;

/// Precomputed NTT parameters for a specific ring dimension.
#[derive(Clone)]
pub struct NttParams {
    /// Ring dimension (must be power of 2)
    pub d: usize,
    /// ψ powers: ψ^i for i = 0..d (for negacyclic pre-multiplication)
    psi_powers: Vec<u64>,
    /// ψ^(-i) for i = 0..d (for negacyclic post-multiplication)
    psi_inv_powers: Vec<u64>,
    /// ω powers in bit-reversed order for forward NTT (ω = ψ²)
    omega_table: Vec<u64>,
    /// ω^(-1) powers in bit-reversed order for inverse NTT
    omega_inv_table: Vec<u64>,
    /// n^(-1) mod q for scaling in inverse NTT
    pub n_inv: u64,
}

impl NttParams {
    /// Create NTT parameters for ring dimension d.
    ///
    /// # Panics
    /// Panics if d is not a power of 2 or if d is too large.
    pub fn new(d: usize) -> Self {
        assert!(d > 0 && d.is_power_of_two(), "d must be a power of 2");
        assert!(d <= (1 << 26), "d must be at most 2^26 for this prime");

        // ψ = g^((q-1)/(2d)) is a primitive 2d-th root of unity
        let psi = mod_pow(PRIMITIVE_ROOT, (NTT_PRIME - 1) / (2 * d as u64), NTT_PRIME);
        let psi_inv = mod_inv(psi, NTT_PRIME);

        // ω = ψ² is a primitive d-th root of unity
        let omega = mod_mul(psi, psi, NTT_PRIME);
        let omega_inv = mod_inv(omega, NTT_PRIME);

        // Precompute ψ^i for negacyclic twist
        let psi_powers = precompute_powers(psi, d);
        let psi_inv_powers = precompute_powers(psi_inv, d);

        // Precompute ω^i in bit-reversed order for NTT butterflies
        let omega_table = precompute_omega_table(omega, d);
        let omega_inv_table = precompute_omega_table(omega_inv, d);

        // n^(-1) mod q
        let n_inv = mod_inv(d as u64, NTT_PRIME);

        Self {
            d,
            psi_powers,
            psi_inv_powers,
            omega_table,
            omega_inv_table,
            n_inv,
        }
    }
}

/// Precompute powers of base: [base^0, base^1, ..., base^(n-1)]
fn precompute_powers(base: u64, n: usize) -> Vec<u64> {
    let mut powers = vec![1u64; n];
    for i in 1..n {
        powers[i] = mod_mul(powers[i - 1], base, NTT_PRIME);
    }
    powers
}

/// Precompute omega table for NTT butterflies.
/// Returns [ω^0, ω^1, ω^2, ..., ω^(d-1)]
fn precompute_omega_table(omega: u64, d: usize) -> Vec<u64> {
    precompute_powers(omega, d)
}

/// Bit-reverse an index.
#[inline]
fn bit_reverse(mut x: usize, bits: usize) -> usize {
    let mut result = 0;
    for _ in 0..bits {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// Forward NTT: coefficient domain → NTT domain.
///
/// For negacyclic convolution (mod x^d + 1):
/// 1. Multiply coefficient i by ψ^i (twist)
/// 2. Apply standard NTT
pub fn ntt_forward(coeffs: &mut [u64], params: &NttParams) {
    let n = params.d;
    assert_eq!(coeffs.len(), n);

    // Step 1: Apply negacyclic twist (multiply by ψ^i)
    for i in 0..n {
        coeffs[i] = mod_mul(coeffs[i], params.psi_powers[i], NTT_PRIME);
    }

    // Step 2: Standard Cooley-Tukey NTT
    cooley_tukey_ntt(coeffs, &params.omega_table);
}

/// Inverse NTT: NTT domain → coefficient domain.
///
/// For negacyclic convolution:
/// 1. Apply standard INTT
/// 2. Multiply coefficient i by ψ^(-i) and scale by n^(-1) (untwist)
pub fn ntt_inverse(coeffs: &mut [u64], params: &NttParams) {
    let n = params.d;
    assert_eq!(coeffs.len(), n);

    // Step 1: Standard Gentleman-Sande INTT
    gentleman_sande_intt(coeffs, &params.omega_inv_table);

    // Step 2: Apply inverse negacyclic twist and scale by n^(-1)
    for i in 0..n {
        coeffs[i] = mod_mul(coeffs[i], params.psi_inv_powers[i], NTT_PRIME);
        coeffs[i] = mod_mul(coeffs[i], params.n_inv, NTT_PRIME);
    }
}

/// Cooley-Tukey radix-2 DIT NTT (in-place).
///
/// Uses bit-reversal permutation followed by butterfly operations.
fn cooley_tukey_ntt(a: &mut [u64], omega_table: &[u64]) {
    let n = a.len();
    let log_n = n.trailing_zeros() as usize;

    // Bit-reversal permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            a.swap(i, j);
        }
    }

    // Butterfly operations
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let step = n / len;

        for start in (0..n).step_by(len) {
            for j in 0..half {
                let omega = omega_table[j * step];
                let u = a[start + j];
                let v = mod_mul(a[start + j + half], omega, NTT_PRIME);
                a[start + j] = mod_add(u, v, NTT_PRIME);
                a[start + j + half] = mod_sub(u, v, NTT_PRIME);
            }
        }
        len *= 2;
    }
}

/// Gentleman-Sande radix-2 DIF inverse NTT (in-place).
///
/// Uses butterfly operations followed by bit-reversal permutation.
fn gentleman_sande_intt(a: &mut [u64], omega_inv_table: &[u64]) {
    let n = a.len();
    let log_n = n.trailing_zeros() as usize;

    // Butterfly operations (reverse of forward NTT)
    let mut len = n;
    while len >= 2 {
        let half = len / 2;
        let step = n / len;

        for start in (0..n).step_by(len) {
            for j in 0..half {
                let omega_inv = omega_inv_table[j * step];
                let u = a[start + j];
                let v = a[start + j + half];
                a[start + j] = mod_add(u, v, NTT_PRIME);
                a[start + j + half] = mod_mul(mod_sub(u, v, NTT_PRIME), omega_inv, NTT_PRIME);
            }
        }
        len /= 2;
    }

    // Bit-reversal permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            a.swap(i, j);
        }
    }
}

/// Point-wise multiplication of two polynomials in NTT domain.
///
/// If a and b are in NTT domain, their point-wise product gives
/// the NTT of (a * b mod x^d + 1).
pub fn ntt_mul(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| mod_mul(x, y, NTT_PRIME))
        .collect()
}

/// Point-wise addition of two polynomials in NTT domain.
pub fn ntt_add(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| mod_add(x, y, NTT_PRIME))
        .collect()
}

/// Point-wise subtraction of two polynomials in NTT domain.
pub fn ntt_sub(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| mod_sub(x, y, NTT_PRIME))
        .collect()
}

/// Scalar multiplication in NTT domain.
pub fn ntt_scalar_mul(a: &[u64], scalar: u64) -> Vec<u64> {
    let scalar_mod = scalar % NTT_PRIME;
    a.iter()
        .map(|&x| mod_mul(x, scalar_mod, NTT_PRIME))
        .collect()
}

// ============================================================================
// Modular Arithmetic
// ============================================================================

/// Modular addition: (a + b) mod p
#[inline]
pub fn mod_add(a: u64, b: u64, p: u64) -> u64 {
    let sum = a + b;
    if sum >= p {
        sum - p
    } else {
        sum
    }
}

/// Modular subtraction: (a - b) mod p
#[inline]
pub fn mod_sub(a: u64, b: u64, p: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        p - b + a
    }
}

/// Modular multiplication: (a * b) mod p
/// Uses u128 to avoid overflow.
#[inline]
pub fn mod_mul(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 * b as u128) % p as u128) as u64
}

/// Modular exponentiation: base^exp mod p
pub fn mod_pow(mut base: u64, mut exp: u64, p: u64) -> u64 {
    let mut result = 1u64;
    base %= p;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, p);
        }
        exp >>= 1;
        base = mod_mul(base, base, p);
    }
    result
}

/// Modular inverse using extended Euclidean algorithm.
/// Returns a^(-1) mod p.
pub fn mod_inv(a: u64, p: u64) -> u64 {
    // Using Fermat's little theorem: a^(-1) = a^(p-2) mod p (for prime p)
    mod_pow(a, p - 2, p)
}

// ============================================================================
// Conversion between u32 (wrapping) and NTT domain
// ============================================================================

/// Convert u32 coefficients (wrapping arithmetic) to u64 mod NTT_PRIME.
///
/// Since NTT_PRIME < 2^32, we just take the coefficient mod NTT_PRIME.
/// This may lose precision for very large coefficients.
pub fn u32_to_ntt_coeffs(coeffs: &[u32]) -> Vec<u64> {
    coeffs.iter().map(|&c| (c as u64) % NTT_PRIME).collect()
}

/// Convert NTT domain coefficients back to u32.
///
/// Assumes coefficients are already reduced mod NTT_PRIME.
pub fn ntt_coeffs_to_u32(coeffs: &[u64]) -> Vec<u32> {
    coeffs.iter().map(|&c| c as u32).collect()
}

// ============================================================================
// High-level polynomial operations
// ============================================================================

/// Multiply two polynomials using NTT.
///
/// This is the main entry point for NTT-based polynomial multiplication.
/// Complexity: O(n log n) instead of O(n²).
pub fn poly_mul_ntt(a: &[u64], b: &[u64], params: &NttParams) -> Vec<u64> {
    let d = params.d;
    assert_eq!(a.len(), d);
    assert_eq!(b.len(), d);

    // Convert to NTT domain
    let mut a_ntt = a.to_vec();
    let mut b_ntt = b.to_vec();
    ntt_forward(&mut a_ntt, params);
    ntt_forward(&mut b_ntt, params);

    // Point-wise multiplication
    let mut c_ntt = ntt_mul(&a_ntt, &b_ntt);

    // Convert back to coefficient domain
    ntt_inverse(&mut c_ntt, params);

    c_ntt
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_arithmetic() {
        let p = NTT_PRIME;

        // Addition
        assert_eq!(mod_add(p - 1, 1, p), 0);
        assert_eq!(mod_add(p - 1, 2, p), 1);
        assert_eq!(mod_add(100, 200, p), 300);

        // Subtraction
        assert_eq!(mod_sub(100, 50, p), 50);
        assert_eq!(mod_sub(50, 100, p), p - 50);
        assert_eq!(mod_sub(0, 1, p), p - 1);

        // Multiplication
        assert_eq!(mod_mul(2, 3, p), 6);
        assert_eq!(mod_mul(p - 1, p - 1, p), 1); // (-1) * (-1) = 1

        // Exponentiation
        assert_eq!(mod_pow(2, 10, p), 1024);
        assert_eq!(mod_pow(2, 0, p), 1);

        // Inverse
        let a = 12345u64;
        let a_inv = mod_inv(a, p);
        assert_eq!(mod_mul(a, a_inv, p), 1);
    }

    #[test]
    fn test_bit_reverse() {
        assert_eq!(bit_reverse(0b000, 3), 0b000);
        assert_eq!(bit_reverse(0b001, 3), 0b100);
        assert_eq!(bit_reverse(0b010, 3), 0b010);
        assert_eq!(bit_reverse(0b011, 3), 0b110);
        assert_eq!(bit_reverse(0b100, 3), 0b001);
        assert_eq!(bit_reverse(0b101, 3), 0b101);
        assert_eq!(bit_reverse(0b110, 3), 0b011);
        assert_eq!(bit_reverse(0b111, 3), 0b111);
    }

    #[test]
    fn test_ntt_roundtrip() {
        let d = 8;
        let params = NttParams::new(d);

        let original: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut coeffs = original.clone();

        // Forward NTT
        ntt_forward(&mut coeffs, &params);

        // Values should have changed
        assert_ne!(coeffs, original);

        // Inverse NTT
        ntt_inverse(&mut coeffs, &params);

        // Should recover original
        assert_eq!(coeffs, original);
    }

    #[test]
    fn test_ntt_roundtrip_larger() {
        for log_d in [4, 5, 6, 7, 8, 10] {
            let d = 1 << log_d;
            let params = NttParams::new(d);

            let original: Vec<u64> = (0..d as u64).collect();
            let mut coeffs = original.clone();

            ntt_forward(&mut coeffs, &params);
            ntt_inverse(&mut coeffs, &params);

            assert_eq!(coeffs, original, "Failed for d={}", d);
        }
    }

    #[test]
    fn test_ntt_mul_simple() {
        let d = 4;
        let params = NttParams::new(d);

        // Multiply (1 + x) by (1 + x) = 1 + 2x + x²
        // In ring Z_q[x]/(x^4 + 1): result is [1, 2, 1, 0]
        let a: Vec<u64> = vec![1, 1, 0, 0]; // 1 + x
        let b: Vec<u64> = vec![1, 1, 0, 0]; // 1 + x

        let result = poly_mul_ntt(&a, &b, &params);

        assert_eq!(result, vec![1, 2, 1, 0]);
    }

    #[test]
    fn test_ntt_mul_negacyclic() {
        let d = 4;
        let params = NttParams::new(d);

        // x³ * x = x⁴ = -1 (mod x⁴ + 1)
        // So result should be [-1, 0, 0, 0] = [q-1, 0, 0, 0]
        let a: Vec<u64> = vec![0, 0, 0, 1]; // x³
        let b: Vec<u64> = vec![0, 1, 0, 0]; // x

        let result = poly_mul_ntt(&a, &b, &params);

        assert_eq!(result, vec![NTT_PRIME - 1, 0, 0, 0]);
    }

    #[test]
    fn test_ntt_mul_identity() {
        let d = 8;
        let params = NttParams::new(d);

        // Multiply by 1 (identity)
        let a: Vec<u64> = vec![3, 1, 4, 1, 5, 9, 2, 6];
        let one: Vec<u64> = vec![1, 0, 0, 0, 0, 0, 0, 0];

        let result = poly_mul_ntt(&a, &one, &params);

        assert_eq!(result, a);
    }

    #[test]
    fn test_ntt_mul_commutative() {
        let d = 8;
        let params = NttParams::new(d);

        let a: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let b: Vec<u64> = vec![8, 7, 6, 5, 4, 3, 2, 1];

        let ab = poly_mul_ntt(&a, &b, &params);
        let ba = poly_mul_ntt(&b, &a, &params);

        assert_eq!(ab, ba);
    }

    #[test]
    fn test_ntt_mul_vs_schoolbook() {
        // Verify NTT multiplication matches schoolbook multiplication
        let d = 4;
        let params = NttParams::new(d);

        let a: Vec<u64> = vec![1, 2, 3, 4];
        let b: Vec<u64> = vec![5, 6, 7, 8];

        // NTT multiplication
        let ntt_result = poly_mul_ntt(&a, &b, &params);

        // Schoolbook multiplication with reduction mod (x^d + 1)
        let schoolbook_result = poly_mul_schoolbook_mod(&a, &b, d);

        assert_eq!(ntt_result, schoolbook_result);
    }

    /// Schoolbook polynomial multiplication mod (x^d + 1) for testing.
    fn poly_mul_schoolbook_mod(a: &[u64], b: &[u64], d: usize) -> Vec<u64> {
        let mut result = vec![0u64; d];
        for i in 0..d {
            for j in 0..d {
                let idx = i + j;
                let coeff = mod_mul(a[i], b[j], NTT_PRIME);
                if idx < d {
                    result[idx] = mod_add(result[idx], coeff, NTT_PRIME);
                } else {
                    // x^d = -1, so x^(d+k) = -x^k
                    result[idx - d] = mod_sub(result[idx - d], coeff, NTT_PRIME);
                }
            }
        }
        result
    }

    #[test]
    fn test_ntt_mul_random() {
        use rand::Rng;
        let mut rng = rand::rng();

        for log_d in [2, 3, 4, 5, 6] {
            let d = 1 << log_d;
            let params = NttParams::new(d);

            let a: Vec<u64> = (0..d).map(|_| rng.random::<u64>() % NTT_PRIME).collect();
            let b: Vec<u64> = (0..d).map(|_| rng.random::<u64>() % NTT_PRIME).collect();

            let ntt_result = poly_mul_ntt(&a, &b, &params);
            let schoolbook_result = poly_mul_schoolbook_mod(&a, &b, d);

            assert_eq!(ntt_result, schoolbook_result, "Failed for d={}", d);
        }
    }

    #[test]
    fn test_primitive_root() {
        // Verify that PRIMITIVE_ROOT is indeed a primitive root mod NTT_PRIME
        // It should have order q-1
        let order = NTT_PRIME - 1;

        // g^(order) should be 1
        assert_eq!(mod_pow(PRIMITIVE_ROOT, order, NTT_PRIME), 1);

        // g^(order/2) should NOT be 1 (proving it's primitive)
        assert_ne!(mod_pow(PRIMITIVE_ROOT, order / 2, NTT_PRIME), 1);
    }

    #[test]
    fn test_roots_of_unity() {
        // For d=8, ψ = g^((q-1)/16) should be a 16th root of unity
        let d = 8;
        let psi = mod_pow(PRIMITIVE_ROOT, (NTT_PRIME - 1) / (2 * d as u64), NTT_PRIME);

        // ψ^(2d) = 1
        assert_eq!(mod_pow(psi, 2 * d as u64, NTT_PRIME), 1);

        // ψ^d = -1 (for negacyclic convolution)
        assert_eq!(mod_pow(psi, d as u64, NTT_PRIME), NTT_PRIME - 1);
    }

    #[test]
    fn test_u32_conversion() {
        let u32_coeffs: Vec<u32> = vec![0, 1, 100, 1000, u32::MAX];
        let ntt_coeffs = u32_to_ntt_coeffs(&u32_coeffs);

        // Values should be reduced mod NTT_PRIME
        assert_eq!(ntt_coeffs[0], 0);
        assert_eq!(ntt_coeffs[1], 1);
        assert_eq!(ntt_coeffs[2], 100);
        assert_eq!(ntt_coeffs[3], 1000);
        assert_eq!(ntt_coeffs[4], (u32::MAX as u64) % NTT_PRIME);
    }
}

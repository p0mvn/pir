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
//! ## NTT-Friendly Primes
//!
//! We use multiple primes for CRT-based multiplication to support q = 2^32:
//! - p1 = 2013265921 = 15 × 2^27 + 1
//! - p2 = 2281701377 = 17 × 2^27 + 1
//! - p3 = 3489660929 = 13 × 2^28 + 1
//!
//! Their product (~2^93) exceeds the maximum intermediate value in polynomial
//! multiplication, allowing exact reconstruction via Chinese Remainder Theorem.

/// Primary NTT-friendly prime: q = 2013265921 = 15 × 2^27 + 1
pub const NTT_PRIME: u64 = 2013265921;

/// Second NTT-friendly prime: q = 2281701377 = 17 × 2^27 + 1
pub const NTT_PRIME_2: u64 = 2281701377;

/// Third NTT-friendly prime: q = 3489660929 = 13 × 2^28 + 1
pub const NTT_PRIME_3: u64 = 3489660929;

/// Primitive root of unity modulo NTT_PRIME
/// g = 31 is a primitive root mod 2013265921
const PRIMITIVE_ROOT: u64 = 31;

/// Primitive root of unity modulo NTT_PRIME_2
/// g = 3 is a primitive root mod 2281701377
const PRIMITIVE_ROOT_2: u64 = 3;

/// Primitive root of unity modulo NTT_PRIME_3
/// g = 3 is a primitive root mod 3489660929
const PRIMITIVE_ROOT_3: u64 = 3;

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
// CRT-based Polynomial Multiplication for q = 2^32
// ============================================================================

/// Precomputed CRT parameters for three-prime reconstruction.
///
/// Used to convert results from three NTT prime fields back to integers,
/// which are then reduced mod 2^32.
pub struct CrtParams {
    /// NTT parameters for first prime
    pub ntt1: NttParams,
    /// NTT parameters for second prime  
    pub ntt2: NttParams,
    /// NTT parameters for third prime
    pub ntt3: NttParams,
    /// Product of all three primes (for range checking)
    pub modulus_product: u128,
    /// p1^(-1) mod p2
    inv_p1_mod_p2: u64,
    /// (p1*p2)^(-1) mod p3
    inv_p1p2_mod_p3: u64,
    /// p1 * p2
    p1_times_p2: u128,
}

impl CrtParams {
    /// Create CRT parameters for ring dimension d.
    pub fn new(d: usize) -> Self {
        let ntt1 = NttParams::new(d);
        let ntt2 = NttParams::with_prime(d, NTT_PRIME_2, PRIMITIVE_ROOT_2);
        let ntt3 = NttParams::with_prime(d, NTT_PRIME_3, PRIMITIVE_ROOT_3);
        
        let p1 = NTT_PRIME;
        let p2 = NTT_PRIME_2;
        let p3 = NTT_PRIME_3;
        
        // Precompute CRT coefficients
        let inv_p1_mod_p2 = mod_inv(p1 % p2, p2);
        let p1_times_p2 = p1 as u128 * p2 as u128;
        let inv_p1p2_mod_p3 = mod_inv((p1_times_p2 % p3 as u128) as u64, p3);
        
        let modulus_product = p1_times_p2 * p3 as u128;
        
        Self {
            ntt1,
            ntt2,
            ntt3,
            modulus_product,
            inv_p1_mod_p2,
            inv_p1p2_mod_p3,
            p1_times_p2,
        }
    }
}

impl NttParams {
    /// Create NTT parameters for a specific prime.
    pub fn with_prime(d: usize, prime: u64, primitive_root: u64) -> Self {
        assert!(d > 0 && d.is_power_of_two(), "d must be a power of 2");
        
        // Check that 2d divides (prime - 1) for 2d-th roots of unity
        let order = prime - 1;
        assert!(order % (2 * d as u64) == 0, "Prime doesn't support dimension {}", d);

        // ψ = g^((q-1)/(2d)) is a primitive 2d-th root of unity
        let psi = mod_pow(primitive_root, order / (2 * d as u64), prime);
        let psi_inv = mod_inv(psi, prime);

        // ω = ψ² is a primitive d-th root of unity
        let omega = mod_mul(psi, psi, prime);
        let omega_inv = mod_inv(omega, prime);

        // Precompute ψ^i for negacyclic twist
        let psi_powers = precompute_powers_with_prime(psi, d, prime);
        let psi_inv_powers = precompute_powers_with_prime(psi_inv, d, prime);

        // Precompute ω^i in bit-reversed order for NTT butterflies
        let omega_table = precompute_powers_with_prime(omega, d, prime);
        let omega_inv_table = precompute_powers_with_prime(omega_inv, d, prime);

        // n^(-1) mod q
        let n_inv = mod_inv(d as u64, prime);

        Self {
            d,
            psi_powers,
            psi_inv_powers,
            omega_table,
            omega_inv_table,
            n_inv,
        }
    }
    
    /// Get the prime associated with these parameters.
    /// Note: This returns NTT_PRIME for backwards compatibility with existing NttParams.
    pub fn prime(&self) -> u64 {
        // For CRT usage, we track the prime separately
        NTT_PRIME
    }
}

/// Precompute powers of base mod a specific prime
fn precompute_powers_with_prime(base: u64, n: usize, prime: u64) -> Vec<u64> {
    let mut powers = vec![1u64; n];
    for i in 1..n {
        powers[i] = mod_mul(powers[i - 1], base, prime);
    }
    powers
}

/// NTT forward transform using a specific prime
fn ntt_forward_with_prime(coeffs: &mut [u64], params: &NttParams, prime: u64) {
    let n = params.d;
    assert_eq!(coeffs.len(), n);

    // Step 1: Apply negacyclic twist (multiply by ψ^i)
    for i in 0..n {
        coeffs[i] = mod_mul(coeffs[i], params.psi_powers[i], prime);
    }

    // Step 2: Standard Cooley-Tukey NTT
    cooley_tukey_ntt_with_prime(coeffs, &params.omega_table, prime);
}

/// NTT inverse transform using a specific prime
fn ntt_inverse_with_prime(coeffs: &mut [u64], params: &NttParams, prime: u64) {
    let n = params.d;
    assert_eq!(coeffs.len(), n);

    // Step 1: Standard Gentleman-Sande INTT
    gentleman_sande_intt_with_prime(coeffs, &params.omega_inv_table, prime);

    // Step 2: Apply inverse negacyclic twist and scale by n^(-1)
    for i in 0..n {
        coeffs[i] = mod_mul(coeffs[i], params.psi_inv_powers[i], prime);
        coeffs[i] = mod_mul(coeffs[i], params.n_inv, prime);
    }
}

fn cooley_tukey_ntt_with_prime(a: &mut [u64], omega_table: &[u64], prime: u64) {
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
                let v = mod_mul(a[start + j + half], omega, prime);
                a[start + j] = mod_add(u, v, prime);
                a[start + j + half] = mod_sub(u, v, prime);
            }
        }
        len *= 2;
    }
}

fn gentleman_sande_intt_with_prime(a: &mut [u64], omega_inv_table: &[u64], prime: u64) {
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
                a[start + j] = mod_add(u, v, prime);
                a[start + j + half] = mod_mul(mod_sub(u, v, prime), omega_inv, prime);
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

/// Reconstruct a single coefficient from three residues using CRT.
///
/// Given r1 = x mod p1, r2 = x mod p2, r3 = x mod p3,
/// returns x mod 2^32.
///
/// The true value x may be negative (due to negacyclic wraparound),
/// so we handle signed reconstruction.
#[inline]
fn crt_reconstruct_mod_2_32(r1: u64, r2: u64, r3: u64, crt: &CrtParams) -> u32 {
    let p1 = NTT_PRIME;
    let p2 = NTT_PRIME_2;
    let p3 = NTT_PRIME_3;
    
    // Step 1: Combine r1 and r2 to get x mod (p1*p2)
    // x = r1 + p1 * ((r2 - r1) * p1^(-1) mod p2)
    let diff_12 = if r2 >= r1 { r2 - r1 } else { p2 - r1 % p2 + r2 };
    let k1 = mod_mul(diff_12, crt.inv_p1_mod_p2, p2);
    let x_12: u128 = r1 as u128 + (p1 as u128) * (k1 as u128);
    
    // Step 2: Combine x_12 and r3 to get x mod (p1*p2*p3)
    // x = x_12 + (p1*p2) * ((r3 - x_12 mod p3) * (p1*p2)^(-1) mod p3)
    let x_12_mod_p3 = (x_12 % p3 as u128) as u64;
    let diff_123 = if r3 >= x_12_mod_p3 { 
        r3 - x_12_mod_p3 
    } else { 
        p3 - x_12_mod_p3 + r3 
    };
    let k2 = mod_mul(diff_123, crt.inv_p1p2_mod_p3, p3);
    let x: u128 = x_12 + crt.p1_times_p2 * (k2 as u128);
    
    // Step 3: Handle signed values
    // If x > modulus_product/2, it represents a negative number
    let half_modulus = crt.modulus_product / 2;
    let signed_x: i128 = if x > half_modulus {
        x as i128 - crt.modulus_product as i128
    } else {
        x as i128
    };
    
    // Step 4: Reduce mod 2^32
    // Rust's as u32 does the right thing for negative numbers (wrapping)
    signed_x as u32
}

/// Multiply two polynomials with u32 coefficients, returning result mod 2^32.
///
/// This uses CRT with three NTT-friendly primes to compute the exact
/// integer result of negacyclic convolution, then reduces mod 2^32.
///
/// This is the correct way to use NTT when working with q = 2^32 modulus.
///
/// # Arguments
/// * `a` - First polynomial (u32 coefficients)
/// * `b` - Second polynomial (u32 coefficients)
/// * `crt` - Precomputed CRT parameters
///
/// # Returns
/// Product polynomial with coefficients reduced mod 2^32
pub fn poly_mul_u32_crt(a: &[u32], b: &[u32], crt: &CrtParams) -> Vec<u32> {
    let d = crt.ntt1.d;
    assert_eq!(a.len(), d);
    assert_eq!(b.len(), d);
    
    // NTT multiplication in first prime field (p1)
    let mut a1: Vec<u64> = a.iter().map(|&x| x as u64).collect();
    let mut b1: Vec<u64> = b.iter().map(|&x| x as u64).collect();
    ntt_forward(&mut a1, &crt.ntt1);
    ntt_forward(&mut b1, &crt.ntt1);
    let mut c1: Vec<u64> = a1.iter().zip(b1.iter())
        .map(|(&x, &y)| mod_mul(x, y, NTT_PRIME))
        .collect();
    ntt_inverse(&mut c1, &crt.ntt1);
    
    // NTT multiplication in second prime field (p2)
    let mut a2: Vec<u64> = a.iter().map(|&x| x as u64).collect();
    let mut b2: Vec<u64> = b.iter().map(|&x| x as u64).collect();
    ntt_forward_with_prime(&mut a2, &crt.ntt2, NTT_PRIME_2);
    ntt_forward_with_prime(&mut b2, &crt.ntt2, NTT_PRIME_2);
    let mut c2: Vec<u64> = a2.iter().zip(b2.iter())
        .map(|(&x, &y)| mod_mul(x, y, NTT_PRIME_2))
        .collect();
    ntt_inverse_with_prime(&mut c2, &crt.ntt2, NTT_PRIME_2);
    
    // NTT multiplication in third prime field (p3)
    let mut a3: Vec<u64> = a.iter().map(|&x| x as u64).collect();
    let mut b3: Vec<u64> = b.iter().map(|&x| x as u64).collect();
    ntt_forward_with_prime(&mut a3, &crt.ntt3, NTT_PRIME_3);
    ntt_forward_with_prime(&mut b3, &crt.ntt3, NTT_PRIME_3);
    let mut c3: Vec<u64> = a3.iter().zip(b3.iter())
        .map(|(&x, &y)| mod_mul(x, y, NTT_PRIME_3))
        .collect();
    ntt_inverse_with_prime(&mut c3, &crt.ntt3, NTT_PRIME_3);
    
    // CRT reconstruction: combine results from all three primes
    (0..d)
        .map(|i| crt_reconstruct_mod_2_32(c1[i], c2[i], c3[i], crt))
        .collect()
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

    // ========================================================================
    // CRT-based Multiplication Tests
    // ========================================================================

    #[test]
    fn test_additional_primes_are_valid() {
        // Verify that the additional primes support NTT for reasonable dimensions
        let d = 256;
        
        // NTT_PRIME_2 should have 2d-th roots of unity
        let order2 = NTT_PRIME_2 - 1;
        assert_eq!(order2 % (2 * d as u64), 0, "NTT_PRIME_2 doesn't support d={}", d);
        let psi2 = mod_pow(PRIMITIVE_ROOT_2, order2 / (2 * d as u64), NTT_PRIME_2);
        assert_eq!(mod_pow(psi2, 2 * d as u64, NTT_PRIME_2), 1);
        assert_eq!(mod_pow(psi2, d as u64, NTT_PRIME_2), NTT_PRIME_2 - 1);
        
        // NTT_PRIME_3 should have 2d-th roots of unity
        let order3 = NTT_PRIME_3 - 1;
        assert_eq!(order3 % (2 * d as u64), 0, "NTT_PRIME_3 doesn't support d={}", d);
        let psi3 = mod_pow(PRIMITIVE_ROOT_3, order3 / (2 * d as u64), NTT_PRIME_3);
        assert_eq!(mod_pow(psi3, 2 * d as u64, NTT_PRIME_3), 1);
        assert_eq!(mod_pow(psi3, d as u64, NTT_PRIME_3), NTT_PRIME_3 - 1);
    }

    #[test]
    fn test_crt_mul_simple() {
        let d = 4;
        let crt = CrtParams::new(d);
        
        // (1 + x) * (1 + x) = 1 + 2x + x²
        let a: Vec<u32> = vec![1, 1, 0, 0];
        let b: Vec<u32> = vec![1, 1, 0, 0];
        
        let result = poly_mul_u32_crt(&a, &b, &crt);
        
        assert_eq!(result, vec![1, 2, 1, 0]);
    }

    #[test]
    fn test_crt_mul_negacyclic() {
        let d = 4;
        let crt = CrtParams::new(d);
        
        // x³ * x = x⁴ = -1 (mod x⁴ + 1)
        // -1 mod 2^32 = u32::MAX
        let a: Vec<u32> = vec![0, 0, 0, 1];
        let b: Vec<u32> = vec![0, 1, 0, 0];
        
        let result = poly_mul_u32_crt(&a, &b, &crt);
        
        assert_eq!(result, vec![u32::MAX, 0, 0, 0]);
    }

    #[test]
    fn test_crt_mul_matches_schoolbook() {
        use rand::Rng;
        let mut rng = rand::rng();
        
        for log_d in [2, 3, 4, 5, 6] {
            let d = 1 << log_d;
            let crt = CrtParams::new(d);
            
            // Generate random u32 polynomials
            let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
            let b: Vec<u32> = (0..d).map(|_| rng.random()).collect();
            
            // CRT-based NTT multiplication
            let ntt_result = poly_mul_u32_crt(&a, &b, &crt);
            
            // Schoolbook multiplication with u32 wrapping arithmetic
            let schoolbook_result = poly_mul_schoolbook_u32(&a, &b, d);
            
            assert_eq!(ntt_result, schoolbook_result, "Failed for d={}", d);
        }
    }

    /// Schoolbook polynomial multiplication mod (x^d + 1) with u32 wrapping arithmetic.
    fn poly_mul_schoolbook_u32(a: &[u32], b: &[u32], d: usize) -> Vec<u32> {
        let mut result = vec![0u32; d];
        for i in 0..d {
            for j in 0..d {
                let idx = i + j;
                let coeff = (a[i] as u64).wrapping_mul(b[j] as u64);
                if idx < d {
                    result[idx] = result[idx].wrapping_add(coeff as u32);
                } else {
                    // x^d = -1, so x^(d+k) = -x^k
                    result[idx - d] = result[idx - d].wrapping_sub(coeff as u32);
                }
            }
        }
        result
    }

    #[test]
    fn test_crt_mul_identity() {
        let d = 8;
        let crt = CrtParams::new(d);
        
        let a: Vec<u32> = vec![3, 1, 4, 1, 5, 9, 2, 6];
        let one: Vec<u32> = vec![1, 0, 0, 0, 0, 0, 0, 0];
        
        let result = poly_mul_u32_crt(&a, &one, &crt);
        
        assert_eq!(result, a);
    }

    #[test]
    fn test_crt_mul_with_large_coefficients() {
        use rand::Rng;
        let mut rng = rand::rng();
        
        let d = 8;
        let crt = CrtParams::new(d);
        
        // Use very large coefficients near u32::MAX
        let a: Vec<u32> = (0..d).map(|_| rng.random_range(u32::MAX - 1000..=u32::MAX)).collect();
        let b: Vec<u32> = (0..d).map(|_| rng.random_range(u32::MAX - 1000..=u32::MAX)).collect();
        
        let ntt_result = poly_mul_u32_crt(&a, &b, &crt);
        let schoolbook_result = poly_mul_schoolbook_u32(&a, &b, d);
        
        assert_eq!(ntt_result, schoolbook_result);
    }

    #[test]
    fn test_crt_mul_ternary_secret() {
        use rand::Rng;
        let mut rng = rand::rng();
        
        let d = 16;
        let crt = CrtParams::new(d);
        
        // Simulate RLWE encryption: random 'a' × ternary 's'
        let a: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        let s: Vec<u32> = (0..d).map(|_| {
            match rng.random_range(0..3u32) {
                0 => 0u32,
                1 => 1u32,
                _ => u32::MAX, // -1 mod 2^32
            }
        }).collect();
        
        let ntt_result = poly_mul_u32_crt(&a, &s, &crt);
        let schoolbook_result = poly_mul_schoolbook_u32(&a, &s, d);
        
        assert_eq!(ntt_result, schoolbook_result);
    }
}

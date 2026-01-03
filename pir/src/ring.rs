use std::sync::Arc;

use crate::ntt::{self, NttParams};

/// Parameters for the polynomial ring R_q = Z_q[x]/(x^d + 1)
#[derive(Clone, Copy)]
pub struct RingParams {
    pub d: usize, // Ring dimension (must be power of 2)
                  // q = 2^32 implicitly (using wrapping u32 arithmetic, similar to LWE code)
}

impl RingParams {
    pub fn new(d: usize) -> Self {
        assert!(d > 0 && d.is_power_of_two(), "d must be a power of 2");
        Self { d }
    }
}

// ============================================================================
// NTT-Accelerated Ring Element
// ============================================================================

/// A polynomial stored in NTT domain for O(n) multiplication.
///
/// This type keeps polynomials in NTT representation, where:
/// - Multiplication is O(n) coefficient-wise products
/// - Addition/subtraction is O(n) coefficient-wise
/// - Conversion to/from coefficient domain is O(n log n)
///
/// ## Usage Pattern
///
/// For operations involving many multiplications with the same operand:
/// ```ignore
/// let params = Arc::new(NttParams::new(1024));
///
/// // Convert to NTT domain once
/// let a_ntt = NttRingElement::from_coeffs(&a.coeffs, params.clone());
/// let b_ntt = NttRingElement::from_coeffs(&b.coeffs, params.clone());
///
/// // Fast multiplication in NTT domain
/// let c_ntt = a_ntt.mul(&b_ntt);
///
/// // Convert back only when needed
/// let c = c_ntt.to_ring_element();
/// ```
///
/// ## Modular Arithmetic
///
/// This uses the NTT-friendly prime q = 2013265921 instead of 2^32.
/// Results may differ slightly from wrapping u32 arithmetic for large values.
#[derive(Clone)]
pub struct NttRingElement {
    /// Coefficients in NTT domain
    pub ntt_coeffs: Vec<u64>,
    /// Shared NTT parameters
    pub params: Arc<NttParams>,
}

impl NttRingElement {
    /// Create from coefficient domain (performs forward NTT).
    ///
    /// Complexity: O(n log n)
    pub fn from_coeffs(coeffs: &[u32], params: Arc<NttParams>) -> Self {
        assert_eq!(coeffs.len(), params.d);

        // Convert u32 → u64 mod NTT_PRIME
        let mut ntt_coeffs = ntt::u32_to_ntt_coeffs(coeffs);

        // Forward NTT
        ntt::ntt_forward(&mut ntt_coeffs, &params);

        Self { ntt_coeffs, params }
    }

    /// Create from existing NTT coefficients (no transform needed).
    pub fn from_ntt_coeffs(ntt_coeffs: Vec<u64>, params: Arc<NttParams>) -> Self {
        assert_eq!(ntt_coeffs.len(), params.d);
        Self { ntt_coeffs, params }
    }

    /// Convert back to coefficient domain (performs inverse NTT).
    ///
    /// Complexity: O(n log n)
    pub fn to_coeffs(&self) -> Vec<u64> {
        let mut coeffs = self.ntt_coeffs.clone();
        ntt::ntt_inverse(&mut coeffs, &self.params);
        coeffs
    }

    /// Convert to a RingElement (coefficient domain, u32).
    ///
    /// Complexity: O(n log n)
    pub fn to_ring_element(&self) -> RingElement {
        let coeffs = self.to_coeffs();
        RingElement {
            coeffs: ntt::ntt_coeffs_to_u32(&coeffs),
        }
    }

    /// Zero polynomial in NTT domain.
    pub fn zero(params: Arc<NttParams>) -> Self {
        Self {
            ntt_coeffs: vec![0u64; params.d],
            params,
        }
    }

    /// One (multiplicative identity) in NTT domain.
    ///
    /// In NTT domain, the constant 1 transforms to [1, 1, 1, ..., 1].
    pub fn one(params: Arc<NttParams>) -> Self {
        // The constant polynomial 1 = [1, 0, 0, ..., 0] in coefficient domain
        // After NTT with negacyclic twist, it becomes [ψ⁰, ψ¹, ψ², ...] evaluated at roots
        // For simplicity, we compute it properly:
        let mut coeffs = vec![0u32; params.d];
        coeffs[0] = 1;
        Self::from_coeffs(&coeffs, params)
    }

    /// Add two polynomials in NTT domain.
    ///
    /// Complexity: O(n)
    pub fn add(&self, other: &Self) -> Self {
        debug_assert!(Arc::ptr_eq(&self.params, &other.params));
        Self {
            ntt_coeffs: ntt::ntt_add(&self.ntt_coeffs, &other.ntt_coeffs),
            params: self.params.clone(),
        }
    }

    /// Subtract two polynomials in NTT domain.
    ///
    /// Complexity: O(n)
    pub fn sub(&self, other: &Self) -> Self {
        debug_assert!(Arc::ptr_eq(&self.params, &other.params));
        Self {
            ntt_coeffs: ntt::ntt_sub(&self.ntt_coeffs, &other.ntt_coeffs),
            params: self.params.clone(),
        }
    }

    /// Multiply two polynomials in NTT domain.
    ///
    /// This is the key operation that NTT accelerates:
    /// **O(n) instead of O(n²)** for schoolbook multiplication.
    ///
    /// Complexity: O(n)
    pub fn mul(&self, other: &Self) -> Self {
        debug_assert!(Arc::ptr_eq(&self.params, &other.params));
        Self {
            ntt_coeffs: ntt::ntt_mul(&self.ntt_coeffs, &other.ntt_coeffs),
            params: self.params.clone(),
        }
    }

    /// Negate a polynomial in NTT domain.
    ///
    /// Complexity: O(n)
    pub fn neg(&self) -> Self {
        Self {
            ntt_coeffs: self
                .ntt_coeffs
                .iter()
                .map(|&c| if c == 0 { 0 } else { ntt::NTT_PRIME - c })
                .collect(),
            params: self.params.clone(),
        }
    }

    /// Scalar multiplication in NTT domain.
    ///
    /// Complexity: O(n)
    pub fn scalar_mul(&self, scalar: u32) -> Self {
        Self {
            ntt_coeffs: ntt::ntt_scalar_mul(&self.ntt_coeffs, scalar as u64),
            params: self.params.clone(),
        }
    }

    /// Generate a random polynomial in NTT domain.
    pub fn random(params: Arc<NttParams>, rng: &mut impl rand::Rng) -> Self {
        let coeffs: Vec<u32> = (0..params.d).map(|_| rng.random()).collect();
        Self::from_coeffs(&coeffs, params)
    }

    /// Generate a small random polynomial in NTT domain.
    pub fn random_small(params: Arc<NttParams>, bound: i32, rng: &mut impl rand::Rng) -> Self {
        let coeffs: Vec<u32> = (0..params.d)
            .map(|_| {
                let val = rng.random_range(0..=2 * bound) - bound;
                val as u32
            })
            .collect();
        Self::from_coeffs(&coeffs, params)
    }
}

/// A polynomial in Z_q[x]/(x^d + 1)
/// coeffs[i] is the coefficient of x^i
/// When we write Z_q[x]/(x^d + 1), we are saying:
/// "Take all polynomials with coefficients mod q but treat x^d + 1 as 0"
/// If x^d + 1 = 0, then x^d = -1.
/// We then generalize this rule to all polynomials with greater degree.
#[derive(Clone)]
pub struct RingElement {
    pub coeffs: Vec<u32>,
}

impl RingElement {
    /// Zero polynomial
    pub fn zero(d: usize) -> Self {
        Self { coeffs: vec![0; d] }
    }

    /// One (multiplicative identity)  
    pub fn one(d: usize) -> Self {
        let mut coeffs = vec![0; d];
        coeffs[0] = 1;
        Self { coeffs }
    }

    /// Monomial x^k (useful for testing)
    pub fn monomial(d: usize, k: usize) -> Self {
        let mut coeffs = vec![0; d];
        coeffs[k] = 1;
        Self { coeffs }
    }

    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        // Hint: use .wrapping_add() like in your regev.rs
        let mut result = self.coeffs.clone();
        for (i, coeff) in other.coeffs.iter().enumerate() {
            result[i] = result[i].wrapping_add(*coeff);
        }
        Self { coeffs: result }
    }

    /// Returns polynomial of length 2d - 1 (d is the degree of the polynomials)
    /// Multiply two polynomials (no modular reduction yet)
    fn poly_mul_schoolbook(a: &[u32], b: &[u32]) -> Vec<u32> {
        let d = a.len();
        let mut result = vec![0u32; 2 * d - 1];
        for i in 0..d {
            for j in 0..d {
                result[i + j] = result[i + j].wrapping_add(a[i].wrapping_mul(b[j]));
            }
        }
        result
    }

    /// Reduce polynomial mod (x^d + 1)
    /// Input: polynomial of length 2d - 1
    /// Output: polynomial of length d
    fn reduce_mod_xd_plus_1(poly: &[u32], d: usize) -> Vec<u32> {
        let mut result = vec![0u32; d];

        for (i, &coeff) in poly.iter().enumerate() {
            let target_idx = i % d;
            if i < d {
                // No wraparound needed
                result[target_idx] = result[target_idx].wrapping_add(coeff);
            } else {
                // Wraparound: x^d = -1, so we SUBTRACT
                result[target_idx] = result[target_idx].wrapping_sub(coeff);
            }
        }

        result
    }

    /// Multiply two polynomials and reduce mod (x^d + 1)
    pub fn mul(&self, other: &Self) -> Self {
        let d = self.coeffs.len();
        let product = Self::poly_mul_schoolbook(&self.coeffs, &other.coeffs);
        // Note: in polynomial multiplication of two degree-(d-1) polynomials, the maximum
        // degree is 2d - 2.
        // So, you never reach index 2d. This implies, that there is a cycle with
        // positive coefficients and then there is a cycle with negative coefficients.
        // However, flipping of the negative sign back to positive never occurs.
        let reduced = Self::reduce_mod_xd_plus_1(&product, d);
        Self { coeffs: reduced }
    }

    /// Negate a polynomial
    pub fn neg(&self) -> Self {
        Self {
            coeffs: self.coeffs.iter().map(|&c| c.wrapping_neg()).collect(),
        }
    }

    /// Subtract other polynomial from self
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = self.coeffs.clone();
        for (i, coeff) in other.coeffs.iter().enumerate() {
            result[i] = result[i].wrapping_sub(*coeff);
        }
        Self { coeffs: result }
    }

    /// Multiply a polynomial by a scalar
    pub fn scalar_mul(&self, scalar: u32) -> Self {
        Self {
            coeffs: self
                .coeffs
                .iter()
                .map(|&c| c.wrapping_mul(scalar))
                .collect(),
        }
    }

    /// Uniformly random polynomial
    pub fn random(d: usize, rng: &mut impl rand::Rng) -> Self {
        let coeffs: Vec<u32> = (0..d).map(|_| rng.random()).collect();
        Self { coeffs }
    }

    /// Small polynomial (for secrets/errors in RLWE)
    /// Coefficients in {-bound, ..., bound}
    pub fn random_small(d: usize, bound: i32, rng: &mut impl rand::Rng) -> Self {
        let coeffs: Vec<u32> = (0..d)
            .map(|_| {
                // Generate uniform in [0, 2*bound], then shift to [-bound, bound]
                let val = rng.random_range(0..=2 * bound) - bound;
                val as u32 // Negative values wrap correctly (e.g., -1 → u32::MAX)
            })
            .collect();
        Self { coeffs }
    }

    /// Ternary polynomial: coefficients uniformly sampled from {-1, 0, 1}.
    ///
    /// Used for RLWE secret keys in YPIR. Ternary secrets provide:
    /// - Better noise growth during polynomial multiplication
    /// - Faster operations (sparse structure can be exploited)
    /// - Standard security assumption for Ring-LWE
    ///
    /// # Arguments
    /// * `d` - Ring dimension (number of coefficients)
    /// * `rng` - Random number generator
    pub fn random_ternary(d: usize, rng: &mut impl rand::Rng) -> Self {
        let coeffs: Vec<u32> = (0..d)
            .map(|_| {
                match rng.random_range(0..3u32) {
                    0 => 0u32,
                    1 => 1u32,
                    _ => u32::MAX, // -1 mod 2^32
                }
            })
            .collect();
        Self { coeffs }
    }

    /// Ternary polynomial with specified Hamming weight.
    ///
    /// Creates a polynomial with exactly `weight` non-zero coefficients,
    /// each uniformly chosen to be +1 or -1. Remaining coefficients are 0.
    ///
    /// This is useful for RLWE secrets where you want precise control
    /// over the number of non-zero elements (affects security/noise tradeoff).
    ///
    /// # Arguments
    /// * `d` - Ring dimension
    /// * `weight` - Number of non-zero coefficients (must be ≤ d)
    /// * `rng` - Random number generator
    pub fn random_ternary_hw(d: usize, weight: usize, rng: &mut impl rand::Rng) -> Self {
        use rand::seq::SliceRandom;

        assert!(weight <= d, "Hamming weight cannot exceed dimension");

        let mut coeffs = vec![0u32; d];

        // Select `weight` random positions
        let mut positions: Vec<usize> = (0..d).collect();
        positions.shuffle(rng);

        for &pos in positions.iter().take(weight) {
            // Randomly +1 or -1
            coeffs[pos] = if rng.random_bool(0.5) {
                1u32
            } else {
                u32::MAX // -1 mod 2^32
            };
        }

        Self { coeffs }
    }

    /// Multiply using NTT (O(n log n) instead of O(n²)).
    ///
    /// **Note**: This uses the NTT-friendly prime q = 2013265921 instead of 2^32.
    /// For most cryptographic applications with reasonable coefficient sizes,
    /// this gives identical results. For very large coefficients that wrap
    /// around 2^32, results may differ.
    ///
    /// # Arguments
    /// * `other` - The polynomial to multiply with
    /// * `params` - Precomputed NTT parameters (reuse for efficiency)
    pub fn mul_ntt(&self, other: &Self, params: &NttParams) -> Self {
        let d = self.coeffs.len();
        assert_eq!(d, other.coeffs.len());
        assert_eq!(d, params.d);

        // Convert to u64 mod NTT_PRIME
        let mut a_ntt = ntt::u32_to_ntt_coeffs(&self.coeffs);
        let mut b_ntt = ntt::u32_to_ntt_coeffs(&other.coeffs);

        // Forward NTT
        ntt::ntt_forward(&mut a_ntt, params);
        ntt::ntt_forward(&mut b_ntt, params);

        // Point-wise multiplication
        let mut c_ntt = ntt::ntt_mul(&a_ntt, &b_ntt);

        // Inverse NTT
        ntt::ntt_inverse(&mut c_ntt, params);

        // Convert back to u32
        Self {
            coeffs: ntt::ntt_coeffs_to_u32(&c_ntt),
        }
    }

    /// Convert to NTT domain for repeated operations.
    ///
    /// Use this when you need to perform many multiplications with the same
    /// polynomial. Store the result and use `NttRingElement::mul()` for O(n)
    /// multiplication.
    pub fn to_ntt(&self, params: Arc<NttParams>) -> NttRingElement {
        NttRingElement::from_coeffs(&self.coeffs, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };
        let b = RingElement {
            coeffs: vec![5, 6, 7, 8],
        };
        let c = a.add(&b);
        assert_eq!(c.coeffs, vec![6, 8, 10, 12]);
    }

    #[test]
    fn test_poly_mul_schoolbook() {
        let a = vec![1, 2, 3];
        let b = vec![4, 5, 6];
        let c = RingElement::poly_mul_schoolbook(&a, &b);
        assert_eq!(c, vec![4, 13, 28, 27, 18]);
    }

    #[test]
    fn test_reduce_mod_xd_plus_1() {
        let poly = vec![0, 0, 0, 0, 0, 1, 0];
        let d = 4;
        let reduced = RingElement::reduce_mod_xd_plus_1(&poly, d);
        assert_eq!(reduced, vec![0, u32::MAX, 0, 0]);
    }

    #[test]
    fn test_xd_equals_minus_one() {
        let d = 4;
        // x^3 * x = x^4 should equal -1
        let x_cubed = RingElement::monomial(d, 3); // [0, 0, 0, 1]
        let x = RingElement::monomial(d, 1); // [0, 1, 0, 0]

        // [0, 0, 0, 0, 1, 0, 0]
        let result = x_cubed.mul(&x);

        // -1 in wrapping u32 is u32::MAX
        assert_eq!(result.coeffs, vec![u32::MAX, 0, 0, 0]);
    }

    /// Test that the maximum coefficient is wrapped around to the negative side
    /// This is the highest degree term you can get from multiplying two polynomials in the ring.
    // For d = 4:
    // x³ × x³ = x⁶
    // x⁶ = x⁴ · x² = (-1) · x² = -x²
    #[test]
    fn test_max_wraparound() {
        let d = 4;
        // x^(d-1) * x^(d-1) = x^(2d-2)
        // x^3 * x^3 = x^6 = x^4 * x^2 = (-1) * x^2 = -x^2
        let x_cubed = RingElement::monomial(d, 3);

        let result = x_cubed.mul(&x_cubed);

        // -x^2 means coefficient at index 2 is -1 = u32::MAX
        assert_eq!(result.coeffs, vec![0, 0, u32::MAX, 0]);
    }

    #[test]
    fn test_multiple_terms_wrap() {
        // d = 4 for this test
        // (x^2 + x^3) * (x^2 + x^3)
        // = x^4 + x^5 + x^5 + x^6
        // = x^4 + 2x^5 + x^6
        //
        // x^4 = -1           → -1 at index 0
        // 2x^5 = -2x         → -2 at index 1
        // x^6 = -x^2         → -1 at index 2

        let poly = RingElement {
            coeffs: vec![0, 0, 1, 1], // x^2 + x^3
        };

        let result = poly.mul(&poly);

        // Expected: -1 - 2x - x^2
        // In u32: [u32::MAX, u32::MAX - 1, u32::MAX, 0]
        // Which is: [-1, -2, -1, 0] in wrapping arithmetic
        assert_eq!(
            result.coeffs,
            vec![
                u32::MAX,     // -1
                u32::MAX - 1, // -2
                u32::MAX,     // -1
                0
            ]
        );
    }

    #[test]
    fn test_mul_identity() {
        // a * 1 = a
        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };
        let one = RingElement::one(4);
        let result = a.mul(&one);
        assert_eq!(result.coeffs, a.coeffs);
    }

    #[test]
    fn test_mul_commutative() {
        // a * b = b * a
        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };
        let b = RingElement {
            coeffs: vec![5, 6, 7, 8],
        };
        let result_ab = a.mul(&b);
        let result_ba = b.mul(&a);
        assert_eq!(result_ab.coeffs, result_ba.coeffs);
    }

    #[test]
    fn test_mul_distributive() {
        // a * (b + c) = a*b + a*c
        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };
        let b = RingElement {
            coeffs: vec![5, 6, 7, 8],
        };
        let c = RingElement {
            coeffs: vec![9, 10, 11, 12],
        };
        let result_ab = a.mul(&b);
        let result_ac = a.mul(&c);

        let rhs = result_ab.add(&result_ac);
        let lhs = a.mul(&b.add(&c));

        assert_eq!(lhs.coeffs, rhs.coeffs);
    }

    #[test]
    fn test_neg() {
        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };
        let result = a.neg();
        assert_eq!(
            result.coeffs,
            vec![u32::MAX, u32::MAX - 1, u32::MAX - 2, u32::MAX - 3]
        );
    }

    #[test]
    fn test_sub() {
        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };
        let b = RingElement {
            coeffs: vec![5, 6, 7, 8],
        };
        let result = a.sub(&b);
        assert_eq!(
            result.coeffs,
            vec![u32::MAX - 3, u32::MAX - 3, u32::MAX - 3, u32::MAX - 3]
        );
    }

    #[test]
    fn test_scalar_mul() {
        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };
        let result = a.scalar_mul(2);
        assert_eq!(result.coeffs, vec![2, 4, 6, 8]);
    }

    #[test]
    fn random_identity() {
        let d = 4;
        let rng = &mut rand::rng();
        let a = RingElement::random(d, rng);
        let one = RingElement::one(d);
        let result = a.mul(&one);
        assert_eq!(result.coeffs, a.coeffs);
    }

    // ========================================================================
    // NTT-Accelerated Tests
    // ========================================================================

    #[test]
    fn test_ntt_mul_matches_schoolbook() {
        // Note: NTT uses q = 2013265921, schoolbook uses q = 2^32
        // Results match for small positive values
        let d = 4;
        let params = NttParams::new(d);

        // Use values that produce small positive results
        let a = RingElement {
            coeffs: vec![1, 1, 0, 0], // 1 + x
        };
        let b = RingElement {
            coeffs: vec![1, 1, 0, 0], // 1 + x
        };

        let schoolbook = a.mul(&b);
        let ntt_result = a.mul_ntt(&b, &params);

        // (1+x)² = 1 + 2x + x² → [1, 2, 1, 0]
        assert_eq!(schoolbook.coeffs, ntt_result.coeffs);
        assert_eq!(ntt_result.coeffs, vec![1, 2, 1, 0]);
    }

    #[test]
    fn test_ntt_mul_identity() {
        let d = 8;
        let params = NttParams::new(d);

        let a = RingElement {
            coeffs: vec![3, 1, 4, 1, 5, 9, 2, 6],
        };
        let one = RingElement::one(d);

        let result = a.mul_ntt(&one, &params);
        assert_eq!(result.coeffs, a.coeffs);
    }

    #[test]
    fn test_ntt_mul_negacyclic() {
        let d = 4;
        let params = NttParams::new(d);

        // x³ × x = x⁴ = -1 (mod x⁴ + 1)
        let x_cubed = RingElement::monomial(d, 3);
        let x = RingElement::monomial(d, 1);

        let ntt_result = x_cubed.mul_ntt(&x, &params);

        // NTT gives -1 mod NTT_PRIME = 2013265920
        // This is correct negacyclic behavior
        assert_eq!(ntt_result.coeffs[0], (ntt::NTT_PRIME - 1) as u32);
        assert_eq!(ntt_result.coeffs[1], 0);
        assert_eq!(ntt_result.coeffs[2], 0);
        assert_eq!(ntt_result.coeffs[3], 0);
    }

    #[test]
    fn test_ntt_ring_element_roundtrip() {
        let d = 8;
        let params = Arc::new(NttParams::new(d));

        let original = RingElement {
            coeffs: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        // Convert to NTT domain and back
        let ntt_elem = original.to_ntt(params);
        let recovered = ntt_elem.to_ring_element();

        assert_eq!(original.coeffs, recovered.coeffs);
    }

    #[test]
    fn test_ntt_ring_element_mul() {
        let d = 4;
        let params = Arc::new(NttParams::new(d));

        // Use values that produce small positive results
        let a = RingElement {
            coeffs: vec![1, 1, 0, 0], // 1 + x
        };
        let b = RingElement {
            coeffs: vec![1, 1, 0, 0], // 1 + x
        };

        // (1+x)² = 1 + 2x + x²
        let expected = vec![1u32, 2, 1, 0];

        // NTT multiplication
        let a_ntt = a.to_ntt(params.clone());
        let b_ntt = b.to_ntt(params.clone());
        let c_ntt = a_ntt.mul(&b_ntt);
        let result = c_ntt.to_ring_element();

        assert_eq!(expected, result.coeffs);
    }

    #[test]
    fn test_ntt_ring_element_add_sub() {
        let d = 4;
        let params = Arc::new(NttParams::new(d));

        let a = RingElement {
            coeffs: vec![10, 20, 30, 40],
        };
        let b = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };

        let a_ntt = a.to_ntt(params.clone());
        let b_ntt = b.to_ntt(params.clone());

        // Test addition
        let sum_ntt = a_ntt.add(&b_ntt);
        let sum = sum_ntt.to_ring_element();
        assert_eq!(sum.coeffs, vec![11, 22, 33, 44]);

        // Test subtraction
        let diff_ntt = a_ntt.sub(&b_ntt);
        let diff = diff_ntt.to_ring_element();
        assert_eq!(diff.coeffs, vec![9, 18, 27, 36]);
    }

    #[test]
    fn test_ntt_ring_element_scalar_mul() {
        let d = 4;
        let params = Arc::new(NttParams::new(d));

        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };

        let a_ntt = a.to_ntt(params);
        let scaled_ntt = a_ntt.scalar_mul(3);
        let scaled = scaled_ntt.to_ring_element();

        assert_eq!(scaled.coeffs, vec![3, 6, 9, 12]);
    }

    #[test]
    fn test_ntt_ring_element_neg() {
        let d = 4;
        let params = Arc::new(NttParams::new(d));

        let a = RingElement {
            coeffs: vec![1, 2, 3, 4],
        };

        let a_ntt = a.to_ntt(params.clone());
        let neg_ntt = a_ntt.neg();

        // a + (-a) should be zero
        let sum_ntt = a_ntt.add(&neg_ntt);
        let sum = sum_ntt.to_ring_element();

        assert_eq!(sum.coeffs, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_ntt_random_multiplications() {
        use rand::Rng;
        let mut rng = rand::rng();

        // Test that NTT multiplication is internally consistent
        // by verifying that NTT(a) * NTT(b) == NTT(a*b) via roundtrip
        for log_d in [2, 3, 4, 5, 6, 7, 8] {
            let d = 1 << log_d;
            let params = Arc::new(NttParams::new(d));

            // Random coefficients mod NTT_PRIME
            let a_coeffs: Vec<u32> = (0..d)
                .map(|_| (rng.random::<u64>() % ntt::NTT_PRIME) as u32)
                .collect();
            let b_coeffs: Vec<u32> = (0..d)
                .map(|_| (rng.random::<u64>() % ntt::NTT_PRIME) as u32)
                .collect();

            let a = RingElement { coeffs: a_coeffs };
            let b = RingElement { coeffs: b_coeffs };

            // NTT multiplication: convert to NTT, multiply, convert back
            let a_ntt = a.to_ntt(params.clone());
            let b_ntt = b.to_ntt(params.clone());
            let c_ntt = a_ntt.mul(&b_ntt);
            let result = c_ntt.to_ring_element();

            // Also test mul_ntt directly
            let result2 = a.mul_ntt(&b, &params);

            assert_eq!(
                result.coeffs, result2.coeffs,
                "NttRingElement.mul and RingElement.mul_ntt differ for d={}",
                d
            );
        }
    }

    #[test]
    fn test_ntt_repeated_mul_efficiency() {
        // This test demonstrates the pattern for efficient repeated multiplication
        let d = 256;
        let params = Arc::new(NttParams::new(d));
        let mut rng = rand::rng();

        // Generate a "key" that will be used in many multiplications
        let key = RingElement::random(d, &mut rng);
        let key_ntt = key.to_ntt(params.clone());

        // Multiple multiplications with the same key
        for _ in 0..10 {
            let input = RingElement::random(d, &mut rng);
            let input_ntt = input.to_ntt(params.clone());

            // O(n) multiplication in NTT domain!
            let result_ntt = key_ntt.mul(&input_ntt);
            let _result = result_ntt.to_ring_element();

            // Verify correctness
            let expected = key.mul_ntt(&input, &params);
            assert_eq!(_result.coeffs, expected.coeffs);
        }
    }

    // ========================================================================
    // Ternary Secret Tests
    // ========================================================================

    #[test]
    fn test_random_ternary_values() {
        let d = 64;
        let mut rng = rand::rng();
        let poly = RingElement::random_ternary(d, &mut rng);

        assert_eq!(poly.coeffs.len(), d);

        // Every coefficient should be 0, 1, or -1 (u32::MAX)
        for &coeff in &poly.coeffs {
            assert!(
                coeff == 0 || coeff == 1 || coeff == u32::MAX,
                "Coefficient {} is not ternary",
                coeff
            );
        }
    }

    #[test]
    fn test_random_ternary_distribution() {
        let d = 1000usize;
        let mut rng = rand::rng();
        let poly = RingElement::random_ternary(d, &mut rng);

        // Count occurrences
        let mut count_zero: usize = 0;
        let mut count_plus: usize = 0;
        let mut count_minus: usize = 0;

        for &coeff in &poly.coeffs {
            match coeff {
                0 => count_zero += 1,
                1 => count_plus += 1,
                _ if coeff == u32::MAX => count_minus += 1,
                _ => panic!("Non-ternary coefficient"),
            }
        }

        // Each should be roughly 1/3 of total (allow 10% tolerance)
        let expected = d / 3;
        let tolerance = d / 10;

        assert!(
            count_zero.abs_diff(expected) < tolerance,
            "Zero count {} too far from expected {}",
            count_zero,
            expected
        );
        assert!(
            count_plus.abs_diff(expected) < tolerance,
            "Plus count {} too far from expected {}",
            count_plus,
            expected
        );
        assert!(
            count_minus.abs_diff(expected) < tolerance,
            "Minus count {} too far from expected {}",
            count_minus,
            expected
        );
    }

    #[test]
    fn test_random_ternary_hw_exact_weight() {
        let d = 64;
        let weight = 20;
        let mut rng = rand::rng();

        let poly = RingElement::random_ternary_hw(d, weight, &mut rng);

        assert_eq!(poly.coeffs.len(), d);

        // Count non-zero coefficients
        let nonzero_count = poly.coeffs.iter().filter(|&&c| c != 0).count();
        assert_eq!(nonzero_count, weight);

        // All non-zero should be +1 or -1
        for &coeff in &poly.coeffs {
            assert!(
                coeff == 0 || coeff == 1 || coeff == u32::MAX,
                "Coefficient {} is not ternary",
                coeff
            );
        }
    }

    #[test]
    fn test_random_ternary_hw_edge_cases() {
        let d = 16;
        let mut rng = rand::rng();

        // All zeros
        let poly_zero = RingElement::random_ternary_hw(d, 0, &mut rng);
        assert!(poly_zero.coeffs.iter().all(|&c| c == 0));

        // All non-zero
        let poly_full = RingElement::random_ternary_hw(d, d, &mut rng);
        assert!(poly_full.coeffs.iter().all(|&c| c == 1 || c == u32::MAX));
    }

    #[test]
    fn test_ternary_mul_produces_small_coeffs() {
        // Multiplying two ternary polynomials should produce coefficients
        // bounded by d (the ring dimension)
        let d = 8;
        let mut rng = rand::rng();

        let a = RingElement::random_ternary(d, &mut rng);
        let b = RingElement::random_ternary(d, &mut rng);

        let c = a.mul(&b);

        // Each coefficient is a sum of at most d products of ±1 or 0
        // So |c_i| ≤ d
        for &coeff in &c.coeffs {
            let signed = coeff as i32;
            // Handle wraparound: if > 2^31, it's negative
            let abs_val = if signed < 0 { -signed } else { signed };
            assert!(
                (abs_val as usize) <= d,
                "Coefficient {} exceeds bound {}",
                signed,
                d
            );
        }
    }
}

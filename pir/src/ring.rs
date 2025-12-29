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

/// A polynomial in Z_q[x]/(x^d + 1)
/// coeffs[i] is the coefficient of x^i
/// When we write Z_q[x]/(x^d + 1), we are saying:
/// "Take all polynomials with coefficients mod q but treat x^d + 1 as 0"
/// If x^d + 1 = 0, then x^d = -1.
/// We then generalize this rule to all polynomials with greater degree.
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
        let d = 4;
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
}

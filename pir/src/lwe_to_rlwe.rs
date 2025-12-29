//! LWE-to-RLWE packing transformation
//! 
//! Takes d LWE ciphertexts and packs them into 1 RLWE ciphertext.
//! This is the core technique YPIR uses to compress responses.

use crate::ring::RingElement;
use crate::ring_regev::{RlweParams, RLWECiphertextOwned};
use crate::regev::Ciphertext;

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

#[cfg(test)]
mod tests {
    use rand::Rng;

    use crate::{params::LweParams, regev::{self, CiphertextOwned}};

    use super::*;

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
}

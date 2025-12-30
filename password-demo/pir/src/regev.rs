use crate::params::LweParams;
use rand::Rng;
use rand_distr::{Distribution, Normal};

// ============================================================================
// Reusable primitives (used by both Regev and PIR)
// ============================================================================

/// Compute dot product: a·s mod q (wrapping arithmetic)
pub fn dot_product(a: &[u32], s: &[u32]) -> u32 {
    a.iter()
        .zip(s.iter())
        .map(|(&ai, &si)| ai.wrapping_mul(si))
        .fold(0u32, |acc, x| acc.wrapping_add(x))
}

/// Round and decode: converts noisy value to plaintext
/// noisy = e + Δ·μ → μ
pub fn round_decode(noisy: u32, params: &LweParams) -> u32 {
    let delta = params.delta();
    let half_delta = delta / 2;
    (noisy.wrapping_add(half_delta) / delta) % params.p
}

/// Sample noise from centered discrete Gaussian distribution.
///
/// LWE security requires noise centered at 0 with appropriate tail bounds.
/// We sample from N(0, σ²), round to nearest integer, then cast to u32.
/// Negative values wrap around mod 2³² which is correct for ℤ_q arithmetic.
pub fn sample_noise(stddev: f64, rng: &mut impl Rng) -> u32 {
    if stddev == 0.0 {
        return 0;
    }
    let normal = Normal::new(0.0, stddev).expect("stddev must be finite and positive");
    let sample: f64 = normal.sample(rng);
    // Round to nearest integer, then cast to u32
    // Negative values wrap correctly: -1 becomes u32::MAX (≡ -1 mod 2³²)
    sample.round() as i64 as u32
}

// ============================================================================
// Regev encryption scheme
// ============================================================================

/// Secret key
pub struct SecretKey<'a> {
    pub s: &'a [u32],
}

/// Ciphertext
pub struct Ciphertext<'a> {
    pub a: &'a [u32],
    pub c: u32,
}

/// Decrypt a ciphertext using the secret key
pub fn decrypt(params: &LweParams, sk: &SecretKey, ct: &Ciphertext) -> u32 {
    let noisy = ct.c.wrapping_sub(dot_product(ct.a, sk.s));
    round_decode(noisy, params)
}

// ============================================================================
// Regev encryption scheme - owned types (for keygen/encrypt)
// ============================================================================

/// Secret key (owned) - returned by keygen
pub struct SecretKeyOwned {
    pub s: Vec<u32>,
}

impl SecretKeyOwned {
    /// Borrow as SecretKey for use with decrypt
    pub fn as_ref(&self) -> SecretKey<'_> {
        SecretKey { s: &self.s }
    }
}

/// Ciphertext (owned) - returned by encrypt
pub struct CiphertextOwned {
    pub a: Vec<u32>,
    pub c: u32,
}

impl CiphertextOwned {
    /// Borrow as Ciphertext for use with decrypt
    pub fn as_ref(&self) -> Ciphertext<'_> {
        Ciphertext {
            a: &self.a,
            c: self.c,
        }
    }
}

/// Generates a random secret key
pub fn keygen(params: &LweParams, rng: &mut impl Rng) -> SecretKeyOwned {
    let s: Vec<u32> = (0..params.n).map(|_| rng.random()).collect();
    SecretKeyOwned { s }
}

/// Encrypt a message using the secret key
pub fn encrypt(params: &LweParams, a: &[u32], sk: &SecretKey, msg: u32, rng: &mut impl Rng) -> u32 {
    let e = sample_noise(params.noise_stddev, rng);

    // c = aᵀs + e + Δμ mod q
    dot_product(&a, sk.s)
        .wrapping_add(e)
        .wrapping_add(params.delta().wrapping_mul(msg))
}

/// Add two ciphertexts homomorphically
pub fn add_ciphertexts(ct1: &Ciphertext, ct2: &Ciphertext) -> CiphertextOwned {
    CiphertextOwned {
        a: ct1
            .a
            .iter()
            .zip(ct2.a.iter())
            .map(|(&a1, &a2)| a1.wrapping_add(a2))
            .collect(),
        c: ct1.c.wrapping_add(ct2.c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let params = LweParams::default_128bit();
        let mut rng = rand::rng();
        let sk = keygen(&params, &mut rng);
        let msg = 123;

        let a: Vec<u32> = (0..params.n).map(|_| rng.random()).collect();

        let ct = encrypt(&params, &a, &sk.as_ref(), msg, &mut rng);
        let dec = decrypt(&params, &sk.as_ref(), &Ciphertext { a: &a, c: ct });
        assert_eq!(dec, msg);
    }

    #[test]
    fn test_encrypt_decrypt_homomorphic() {
        let params = LweParams::default_128bit();
        let mut rng = rand::rng();
        let sk = keygen(&params, &mut rng);
        let msg = 123;

        let a1: Vec<u32> = (0..params.n).map(|_| rng.random()).collect();

        let ct1 = encrypt(&params, &a1, &sk.as_ref(), msg, &mut rng);

        let a2: Vec<u32> = (0..params.n).map(|_| rng.random()).collect();

        let ct2 = encrypt(&params, &a2, &sk.as_ref(), msg, &mut rng);

        // Add the two ciphertexts homomorphically
        let c_combined = add_ciphertexts(
            &Ciphertext { a: &a1, c: ct1 },
            &Ciphertext { a: &a2, c: ct2 },
        );

        // Decrypt the combined ciphertext
        let dec = decrypt(&params, &sk.as_ref(), &c_combined.as_ref());

        // Assert that the decrypted value is the sum of the two messages
        assert_eq!(dec, msg + msg);
    }
}

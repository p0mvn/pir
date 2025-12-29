use rand::Rng;

use crate::{
    regev::{SecretKey, SecretKeyOwned},
    ring::RingElement,
};

pub struct RlweParams {
    pub d: usize, // Ring dimension (power of 2, e.g., 1024, 2048)
    pub p: u32,   // Plaintext modulus
    pub noise_stddev: f64, // Standard deviation for error sampling
                  // q = 2^32 implicitly
}

impl RlweParams {
    pub fn new(d: usize, p: u32, noise_stddev: f64) -> Self {
        assert!(d > 0 && d.is_power_of_two(), "d must be a power of 2");
        Self { d, p, noise_stddev }
    }

    /// Scaling factor Δ = ⌊q/p⌋ where q = 2^32
    pub fn delta(&self) -> u32 {
        (2_u64.pow(32) / self.p as u64) as u32
    }
}

pub struct RLWECiphertextOwned {
    pub a: RingElement,
    pub c: RingElement,
}

// Generates a random secret key
pub fn keygen(params: &RlweParams, rng: &mut impl Rng) -> SecretKeyOwned {
    let s = RingElement::random_small(params.d, params.noise_stddev as i32, rng);
    SecretKeyOwned {
        s: s.coeffs.clone(),
    }
}

/// Encrypt a message polynomial using the secret key
/// c = a·s + e + Δ·μ
pub fn encrypt(params: &RlweParams, s: &SecretKey, m: &RingElement, rng: &mut impl Rng) -> RLWECiphertextOwned {
    let a = RingElement::random(params.d, rng);
    let e = RingElement::random_small(params.d, params.noise_stddev as i32, rng);

    let s_ring = RingElement {
        coeffs: s.s.to_vec(),
    };

    // Scale each coefficient of the message by Δ
    let delta_m = m.scalar_mul(params.delta());

    let c = a.mul(&s_ring).add(&e).add(&delta_m);
    RLWECiphertextOwned {
        a: a,
        c: c,
    }
}


/// Decrypt: recover plaintext polynomial from ciphertext
/// For each coefficient: μ_i = round_decode(c_i - (a·s)_i)
pub fn decrypt(params: &RlweParams, s: &SecretKey, ct: &RLWECiphertextOwned) -> RingElement {
    let secret_key = RingElement {
        coeffs: s.s.to_vec(),
    };

    // Compute noisy = c - a·s = e + Δ·μ
    let noisy = ct.c.sub(&ct.a.mul(&secret_key));

    // Decode each coefficient using round_decode
    let delta = params.delta();
    let half_delta = delta / 2;

    let decoded_coeffs: Vec<u32> = noisy
        .coeffs
        .iter()
        .map(|&coeff| {
            // Same logic as round_decode from regev.rs
            (coeff.wrapping_add(half_delta) / delta) % params.p
        })
        .collect();

    RingElement {
        coeffs: decoded_coeffs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> RlweParams {
        RlweParams::new(64, 256, 3.2)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let params = test_params();
        let mut rng = rand::rng();
        let sk = keygen(&params, &mut rng);

        // Random message polynomial with coefficients in [0, p)
        let msg = RingElement {
            coeffs: (0..params.d).map(|_| rng.random_range(0..params.p)).collect(),
        };

        let ct = encrypt(&params, &sk.as_ref(), &msg, &mut rng);
        let decrypted = decrypt(&params, &sk.as_ref(), &ct);

        assert_eq!(msg.coeffs, decrypted.coeffs);
    }

    #[test]
    fn test_encrypt_decrypt_zero() {
        let params = test_params();
        let mut rng = rand::rng();
        let sk = keygen(&params, &mut rng);

        let msg = RingElement::zero(params.d);
        let ct = encrypt(&params, &sk.as_ref(), &msg, &mut rng);
        let decrypted = decrypt(&params, &sk.as_ref(), &ct);

        assert_eq!(msg.coeffs, decrypted.coeffs);
    }

    #[test]
    fn test_encrypt_decrypt_max_values() {
        let params = test_params();
        let mut rng = rand::rng();
        let sk = keygen(&params, &mut rng);

        // All coefficients at max plaintext value (p-1)
        let msg = RingElement {
            coeffs: vec![params.p - 1; params.d],
        };

        let ct = encrypt(&params, &sk.as_ref(), &msg, &mut rng);
        let decrypted = decrypt(&params, &sk.as_ref(), &ct);

        assert_eq!(msg.coeffs, decrypted.coeffs);
    }
}
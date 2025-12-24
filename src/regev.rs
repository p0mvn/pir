use crate::params::LweParams;
use rand::Rng;
use rand::distr::StandardUniform;

pub struct SecretKey {
    pub s: Vec<u64>, // Secret vector in ℤ_q^n
}

pub struct Ciphertext {
    pub a: Vec<u64>, // Random vector
    pub c: u64,      // aᵀs + e + Δμ
}

/// Generates a random secret key
pub fn keygen(params: &LweParams, rng: &mut impl Rng) -> SecretKey {
    let s: Vec<u64> = (0..params.n)
        .map(|_| rng.random_range(0..params.q))
        .collect();
    SecretKey { s }
}

/// Encrypt a message using the secret key
pub fn encrypt(params: &LweParams, sk: &SecretKey, msg: u64, rng: &mut impl Rng) -> Ciphertext {
    let a: Vec<u64> = (0..params.n)
        .map(|_| rng.random_range(0..params.q))
        .collect();

    let e = sample_noise(params.noise_stddev, rng);

    // aᵀs mod q
    let dot: u64 = a
        .iter()
        .zip(sk.s.iter())
        .map(|(&ai, &si)| ai.wrapping_mul(si))
        .fold(0u64, |acc, x| acc.wrapping_add(x));

    // c = aᵀs + e + Δμ mod q
    let c = dot
        .wrapping_add(e as u64)
        .wrapping_add(params.delta() * msg);

    Ciphertext { a, c }
}

// Sample noise from the standard normal distribution
// This is used to add noise to the ciphertext
pub fn sample_noise(stddev: f64, rng: &mut impl Rng) -> u64 {
    let noise: f64 = rng.sample(StandardUniform);
    (noise * stddev) as u64
}

// Decrypt a ciphertext using the secret key
pub fn decrypt(params: &LweParams, sk: &SecretKey, ct: &Ciphertext) -> u64 {
    // c - aᵀs
    let dot: u64 =
        ct.a.iter()
            .zip(sk.s.iter())
            .map(|(&ai, &si)| ai.wrapping_mul(si))
            .fold(0u64, |acc, x| acc.wrapping_add(x));

    let noisy = ct.c.wrapping_sub(dot);

    // Round to nearest multiple of Δ
    let delta = params.delta();
    let half_delta = delta / 2;
    ((noisy + half_delta) / delta) % params.p
}

// Add two ciphertexts homomorphically
pub fn add_ciphertexts(ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
    Ciphertext {
        a: ct1
            .a
            .iter()
            .zip(ct2.a.iter())
            .map(|(&a1, &a2)| a1.wrapping_add(a2))
            .collect(),
        c: ct1.c.wrapping_add(ct2.c),
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let params = LweParams::default_128bit();
        let mut rng = rand::rng();
        let sk = keygen(&params, &mut rng);
        let msg = 123;
        let ct = encrypt(&params, &sk, msg, &mut rng);
        let dec = decrypt(&params, &sk, &ct);
        assert_eq!(dec, msg);
    }

    #[test]
    fn test_encrypt_decrypt_homomorphic() {
        let params = LweParams::default_128bit();
        let mut rng = rand::rng();
        let sk = keygen(&params, &mut rng);
        let msg = 123;
        let ct1 = encrypt(&params, &sk, msg, &mut rng);
        let ct2 = encrypt(&params, &sk, msg, &mut rng);

        // Add the two ciphertexts homomorphically
        let c_combined = add_ciphertexts(&ct1, &ct2);

        // Decrypt the combined ciphertext
        let dec = decrypt(&params, &sk, &c_combined);

        // Assert that the decrypted value is the sum of the two messages
        assert_eq!(dec, msg + msg);
    }
}

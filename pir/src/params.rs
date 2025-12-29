#[derive(Clone, Copy)]
pub struct LweParams {
    pub n: usize,          // LWE dimension (e.g., 1024)
    pub p: u32,            // Plaintext modulus (e.g., 256 for bytes)
    pub noise_stddev: f64, // Noise parameter
}

impl LweParams {
    pub fn default_128bit() -> Self {
        Self {
            n: 1024,
            p: 256,
            noise_stddev: 6.4,
        }
    }

    /// Scaling factor Δ = ⌊q/p⌋ where q = 2^32
    /// For p = 256: Δ = 2^32 / 256 = 2^24 = 16777216
    pub fn delta(&self) -> u32 {
        // q = 2^32, using wrapping division via bit shift
        // 2^32 / p = 2^(32 - log2(p))
        // For p = 256 = 2^8: delta = 2^24
        (1u32 << 24) * (256 / self.p)
    }
}

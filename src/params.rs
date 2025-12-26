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
        assert!(self.p >= 2, "plaintext modulus p must be >= 2");

        // q = 2^32 does not fit in u32, so compute in u64 then cast back.
        // Δ = floor(q / p)
        let q: u64 = 1u64 << 32;
        (q / (self.p as u64)) as u32
    }
}

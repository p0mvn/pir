
pub struct LweParams {
    pub n: usize,           // LWE dimension (e.g., 1024)
    pub q: u64,             // Modulus (e.g., 2^32)
    pub p: u64,             // Plaintext modulus (e.g., 256 for bytes)
    pub noise_stddev: f64,  // Noise parameter
}

impl LweParams {
    pub fn default_128bit() -> Self {
        Self {
            n: 1024,
            q: 1u64 << 32,
            p: 256,
            noise_stddev: 6.4,
        }
    }
    
    /// Scaling factor Δ = ⌊q/p⌋
    pub fn delta(&self) -> u64 {
        self.q / self.p
    }
}
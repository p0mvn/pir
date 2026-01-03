//! YPIR: DoublePIR with LWE-to-RLWE packing for compressed responses
//!
//! YPIR combines the DoublePIR protocol with LWE-to-RLWE packing to achieve
//! significantly smaller response sizes while maintaining high throughput.
//!
//! # Architecture
//!
//! The protocol works as follows:
//! 1. Client generates a DoublePIR query plus a packing key
//! 2. Server computes DoublePIR answer (LWE ciphertexts)
//! 3. Server packs LWE ciphertexts into compact RLWE ciphertexts using packing key
//! 4. Client decrypts RLWE response to recover plaintext

// TODO: Implement protocol types (YpirQuery, YpirAnswer, YpirSetup)
// TODO: Implement YpirClient with packing key generation
// TODO: Implement YpirServer with response packing

//! YPIR server implementation.
//!
//! The YPIR server wraps DoublePIR with LWE-to-RLWE packing for compressed responses.
//!
//! # Implementation Note
//!
//! This implementation packs the **first-pass SimplePIR result** rather than the
//! full DoublePIR answer. This is because our DoublePIR answer involves both
//! secrets (s_col and s_row), which is incompatible with single-secret LWE packing.
//!
//! The first-pass intermediate result is a proper LWE ciphertext under s_col,
//! which can be packed using the client's packing key (generated from s_col).
//!
//! The client then performs the row selection locally after unpacking.

use rand::Rng;

use crate::double::DoublePirServer;
use crate::lwe_to_rlwe::pack_with_key_switching;
use crate::matrix_database::DoublePirDatabase;
use crate::pir::{LweMatrix, MatrixSeed};
use crate::pir_trait::PirServer as PirServerTrait;
use crate::regev::Ciphertext;

use super::{Ypir, YpirAnswer, YpirParams, YpirQuery, YpirSetup};

/// YPIR server: DoublePIR server with LWE-to-RLWE response packing.
///
/// The server wraps a `DoublePirServer` and adds response compression by
/// packing the first-pass SimplePIR result into compact RLWE ciphertexts.
///
/// # Protocol Flow
///
/// 1. Compute first-pass: intermediate = DB × query_col
/// 2. For each (row, byte), this is an LWE ciphertext under s_col
/// 3. Pack batches of d LWE ciphertexts into RLWE ciphertexts
/// 4. Client unpacks and selects target row
///
/// # Compression Benefit
///
/// For num_rows rows, record_size bytes, and ring dimension d:
/// - Without packing: num_rows × record_size × (n + 1) × 4 bytes
/// - With packing: ⌈(num_rows × record_size) / d⌉ × 2d × 4 bytes
pub struct YpirServer {
    /// Underlying DoublePIR server (used for setup/hints only)
    inner: DoublePirServer,
    /// Ring dimension for RLWE packing
    ring_dim: usize,
    /// Seed for the column matrix A_col (needed for computing `a` vectors)
    seed_col: MatrixSeed,
    /// Database for computing effective `a` vectors
    db: DoublePirDatabase,
    /// LWE dimension
    lwe_dim: usize,
}

impl YpirServer {
    /// Create a new YPIR server.
    ///
    /// # Arguments
    /// * `db` - The database in DoublePIR layout
    /// * `params` - YPIR parameters (LWE + packing)
    /// * `rng` - Random number generator for seed generation
    ///
    /// # Panics
    ///
    /// Panics if parameters are invalid (see `DoublePirServer::new`).
    pub fn new(db: DoublePirDatabase, params: &YpirParams, rng: &mut impl Rng) -> Self {
        // Clone the database since DoublePirServer takes ownership
        let db_clone = db.clone();

        // Create the underlying DoublePIR server
        let inner = DoublePirServer::new(db_clone, &params.lwe, rng);

        // Get the column seed from the setup (needed for computing `a` vectors)
        let setup = inner.setup();
        let seed_col = setup.seed_col;

        Self {
            inner,
            ring_dim: params.packing.ring_dimension,
            seed_col,
            db,
            lwe_dim: params.lwe.n,
        }
    }

    /// Get setup data to send to client.
    ///
    /// The setup includes DoublePIR setup data plus the ring dimension
    /// for RLWE packing.
    pub fn setup(&self) -> YpirSetup {
        YpirSetup {
            double_setup: self.inner.setup(),
            ring_dim: self.ring_dim,
        }
    }

    /// Answer a YPIR query.
    ///
    /// This performs:
    /// 1. First-pass SimplePIR: intermediate = DB × query_col
    /// 2. Compute `a` vectors for each (row, byte) LWE ciphertext
    /// 3. Pack LWE ciphertexts into RLWE ciphertexts using client's packing key
    ///
    /// # Arguments
    /// * `query` - YPIR query containing DoublePIR query + packing key
    ///
    /// # Returns
    /// YPIR answer containing packed RLWE ciphertexts
    ///
    /// The answer contains the packed first-pass result. The client unpacks
    /// and performs row selection locally.
    pub fn answer(&self, query: &YpirQuery) -> YpirAnswer {
        let num_rows = self.db.num_rows;
        let num_cols = self.db.num_cols;
        let record_size = self.db.record_size;
        let n = self.lwe_dim;
        let d = self.ring_dim;

        // Regenerate A_col from seed
        let a_col = LweMatrix::from_seed(&self.seed_col, num_cols, n);

        // Step 1: Compute first-pass SimplePIR result
        // intermediate[row, byte] = Σ_col DB[row, col, byte] × query_col[col]
        let intermediate = self.db.multiply_first(&query.double_query.query_col);

        // Step 2: Compute `a` vectors for each (row, byte) pair
        // The first-pass result is an LWE ciphertext under s_col:
        // intermediate[row, byte] = <a_eff, s_col> + noise + Δ × DB[row, target_col, byte]
        // where a_eff[k] = Σ_col DB[row, col, byte] × A_col[col, k]
        let total_ciphertexts = num_rows * record_size;
        let mut a_vectors: Vec<Vec<u32>> = Vec::with_capacity(total_ciphertexts);
        let mut c_values: Vec<u32> = Vec::with_capacity(total_ciphertexts);

        for row in 0..num_rows {
            for byte_idx in 0..record_size {
                // Compute a_eff for this (row, byte)
                let mut a_eff = vec![0u32; n];
                for col in 0..num_cols {
                    let db_val = self.db.get(row, col, byte_idx);
                    if db_val != 0 {
                        for k in 0..n {
                            a_eff[k] =
                                a_eff[k].wrapping_add(db_val.wrapping_mul(a_col.get(col, k)));
                        }
                    }
                }
                a_vectors.push(a_eff);

                // The c value is the intermediate result for this (row, byte)
                let intermediate_idx = row * record_size + byte_idx;
                c_values.push(intermediate[intermediate_idx]);
            }
        }

        // Step 3: Pack batches of d LWE ciphertexts into RLWE ciphertexts
        let num_packed = total_ciphertexts.div_ceil(d);
        let mut packed_cts = Vec::with_capacity(num_packed);

        for chunk_idx in 0..num_packed {
            let start = chunk_idx * d;
            let end = (start + d).min(total_ciphertexts);
            let chunk_size = end - start;

            // Create LWE ciphertexts for this chunk
            let mut lwe_cts: Vec<Ciphertext> = Vec::with_capacity(d);

            for j in 0..d {
                if j < chunk_size {
                    let idx = start + j;
                    lwe_cts.push(Ciphertext {
                        a: &a_vectors[idx],
                        c: c_values[idx],
                    });
                } else {
                    // Padding: zero ciphertext
                    lwe_cts.push(Ciphertext {
                        a: &a_vectors[0], // Dummy a vector for padding
                        c: 0,
                    });
                }
            }

            // Pack into RLWE
            let packed = pack_with_key_switching(&lwe_cts, &query.packing_key);
            packed_cts.push(packed);
        }

        YpirAnswer { packed_cts }
    }

    /// Number of records in the database.
    pub fn num_records(&self) -> usize {
        self.inner.num_records()
    }

    /// Size of each record in bytes.
    pub fn record_size(&self) -> usize {
        self.inner.record_size()
    }

    /// Get the ring dimension used for RLWE packing.
    pub fn ring_dimension(&self) -> usize {
        self.ring_dim
    }

    /// Get the LWE dimension used for DoublePIR.
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_dim
    }

    /// Get the number of database rows.
    pub fn num_rows(&self) -> usize {
        self.db.num_rows
    }
}

// ============================================================================
// Trait Implementation
// ============================================================================

impl PirServerTrait for YpirServer {
    type Protocol = Ypir;

    fn setup(&self) -> YpirSetup {
        self.setup()
    }

    fn answer(&self, query: &YpirQuery) -> YpirAnswer {
        self.answer(query)
    }

    fn num_records(&self) -> usize {
        self.num_records()
    }

    fn record_size(&self) -> usize {
        self.record_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{LweParams, PackingParams, YpirClient, YpirParams};
    use crate::matrix_database::DoublePirDatabase;
    use crate::pir_trait::CommunicationCost;

    fn create_test_records(n: usize, record_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                (0..record_size)
                    .map(|j| ((i * record_size + j) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    /// Test YpirServer creation
    #[test]
    fn test_ypir_server_creation() {
        let records = create_test_records(9, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        let params = YpirParams::test();
        let mut rng = rand::rng();

        let server = YpirServer::new(db, &params, &mut rng);

        assert_eq!(server.num_records(), 9);
        assert_eq!(server.record_size(), 4);
        assert_eq!(server.ring_dimension(), params.packing.ring_dimension);
    }

    /// Test YpirServer setup generation
    #[test]
    fn test_ypir_server_setup() {
        let records = create_test_records(9, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        let params = YpirParams::test();
        let mut rng = rand::rng();

        let server = YpirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        assert_eq!(setup.num_records(), 9);
        assert_eq!(setup.record_size(), 4);
        assert_eq!(setup.ring_dim, params.packing.ring_dimension);
    }

    /// Test basic YPIR end-to-end correctness (small parameters)
    #[test]
    fn test_ypir_end_to_end_basic() {
        // Use very small parameters for fast testing
        let record_size = 4; // 4 bytes per record
        let num_records = 9;

        let records = create_test_records(num_records, record_size);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, record_size);

        // Use test parameters with matching dimensions for packing to work
        // The LWE dimension and ring dimension must match for the packing key
        let params = YpirParams {
            lwe: LweParams {
                n: 4, // Small LWE dimension
                p: 256,
                noise_stddev: 0.0, // Zero noise for deterministic testing
            },
            packing: PackingParams {
                ring_dimension: 4, // Must match LWE dimension for homogeneous packing
                plaintext_modulus: 256,
                noise_stddev: 0.0,
            },
        };

        let mut rng = rand::rng();

        let server = YpirServer::new(db, &params, &mut rng);
        let setup = server.setup();

        let client = YpirClient::new(setup, params);

        // Test retrieving a record
        let target_idx = 4;
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);

        // Verify answer structure
        assert!(
            !answer.packed_cts.is_empty(),
            "Answer should contain packed ciphertexts"
        );

        // Recover the record
        let recovered = client.recover(&state, &answer);

        assert_eq!(
            recovered, records[target_idx],
            "Failed to recover record {}: expected {:?}, got {:?}",
            target_idx, records[target_idx], recovered
        );
    }

    /// Test YPIR with all records
    #[test]
    fn test_ypir_all_records() {
        let record_size = 4;
        let num_records = 9;

        let records = create_test_records(num_records, record_size);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, record_size);

        let params = YpirParams {
            lwe: LweParams {
                n: 4,
                p: 256,
                noise_stddev: 0.0,
            },
            packing: PackingParams {
                ring_dimension: 4,
                plaintext_modulus: 256,
                noise_stddev: 0.0,
            },
        };

        let mut rng = rand::rng();

        let server = YpirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = YpirClient::new(setup, params);

        for target_idx in 0..num_records {
            let (state, query) = client.query(target_idx, &mut rng);
            let answer = server.answer(&query);
            let recovered = client.recover(&state, &answer);

            assert_eq!(
                recovered, records[target_idx],
                "Failed to recover record {}: expected {:?}, got {:?}",
                target_idx, records[target_idx], recovered
            );
        }
    }

    /// Test YPIR via trait interface
    #[test]
    fn test_ypir_via_trait() {
        use crate::pir_trait::{PirClient, PirServer};

        let records = create_test_records(9, 4);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, 4);

        let params = YpirParams {
            lwe: LweParams {
                n: 4,
                p: 256,
                noise_stddev: 0.0,
            },
            packing: PackingParams {
                ring_dimension: 4,
                plaintext_modulus: 256,
                noise_stddev: 0.0,
            },
        };

        let mut rng = rand::rng();

        // Use trait interface
        let server = YpirServer::new(db, &params, &mut rng);
        let setup = <YpirServer as PirServer>::setup(&server);
        let client = <YpirClient as PirClient>::from_setup(setup, params.lwe);

        let target_idx = 4;
        let (state, query) = <YpirClient as PirClient>::query(&client, target_idx, &mut rng);
        let answer = <YpirServer as PirServer>::answer(&server, &query);
        let recovered = <YpirClient as PirClient>::recover(&client, &state, &answer);

        assert_eq!(recovered, records[target_idx]);
    }

    /// Test compression: YPIR answer should pack intermediate results
    #[test]
    fn test_ypir_compression() {
        let record_size = 16;
        let num_records = 16;

        let records = create_test_records(num_records, record_size);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, record_size);

        let params = YpirParams {
            lwe: LweParams {
                n: 16, // Larger for meaningful compression test
                p: 256,
                noise_stddev: 0.0,
            },
            packing: PackingParams {
                ring_dimension: 16,
                plaintext_modulus: 256,
                noise_stddev: 0.0,
            },
        };

        let mut rng = rand::rng();

        let server = YpirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = YpirClient::new(setup, params);

        let target_idx = 5;
        let (_, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);

        // Calculate sizes
        let ypir_answer_size = answer.size_bytes();

        // The answer should contain packed intermediate results
        // num_rows × record_size ciphertexts packed into RLWE
        let num_rows = 4; // sqrt(16) = 4
        let total_cts = num_rows * record_size;
        let num_packed = total_cts.div_ceil(16);
        let expected_ypir_size = num_packed * 2 * 16 * 4;

        println!(
            "YPIR answer: {} bytes, expected: {} bytes, num_packed: {}",
            ypir_answer_size, expected_ypir_size, num_packed
        );

        assert_eq!(ypir_answer_size, expected_ypir_size);
    }

    /// Test with larger records to verify packing works at scale
    #[test]
    fn test_ypir_larger_records() {
        let record_size = 8;
        let num_records = 16;

        let records = create_test_records(num_records, record_size);
        let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
        let db = DoublePirDatabase::new(&record_refs, record_size);

        let params = YpirParams {
            lwe: LweParams {
                n: 8,
                p: 256,
                noise_stddev: 0.0,
            },
            packing: PackingParams {
                ring_dimension: 8,
                plaintext_modulus: 256,
                noise_stddev: 0.0,
            },
        };

        let mut rng = rand::rng();

        let server = YpirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = YpirClient::new(setup, params);

        // Test a few indices
        for target_idx in [0, 7, 15] {
            let (state, query) = client.query(target_idx, &mut rng);
            let answer = server.answer(&query);
            let recovered = client.recover(&state, &answer);

            assert_eq!(
                recovered, records[target_idx],
                "Failed to recover record {}: expected {:?}, got {:?}",
                target_idx, records[target_idx], recovered
            );
        }
    }
}

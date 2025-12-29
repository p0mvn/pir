use crate::{
    params::LweParams,
    pir::{Answer, ClientHint, LweMatrix, Query, SetupMessage},
    regev::{Ciphertext, SecretKey, decrypt, encrypt},
};
use rand::Rng;

/// Client state (reusable across queries)
pub struct PirClient {
    a: LweMatrix, // Regenerated from seed, not stored/transmitted
    hint_c: ClientHint,
    params: LweParams,
    db_cols: usize,
    db_rows: usize,
    record_size: usize,
}

/// Per-query secret state (needed for recovery)
pub struct QueryState {
    pub row_start: usize,
    pub secret: Vec<u32>,
}

impl PirClient {
    /// Initialize client from setup message
    /// Regenerates matrix A locally from the seed using ChaCha20 PRG
    pub fn new(msg: SetupMessage, params: LweParams) -> Self {
        // Regenerate A from the seed - same PRG produces identical matrix
        let a = LweMatrix::from_seed(&msg.matrix_seed, msg.db_cols, msg.lwe_dim);
        Self {
            a,
            hint_c: msg.hint_c,
            params,
            db_cols: msg.db_cols,
            db_rows: msg.db_rows,
            record_size: msg.record_size,
        }
    }

    /// Query: generate encrypted unit vector for record index
    pub fn query(&self, record_idx: usize, rng: &mut impl Rng) -> (QueryState, Query) {
        // Parse index as (row_start, col)
        let records_per_group = self.db_cols;
        let group = record_idx / records_per_group;
        let col = record_idx % records_per_group;
        let row_start = group * self.record_size;

        // Fresh secret s ∈ ℤ_q^n
        let secret: Vec<u32> = (0..self.params.n).map(|_| rng.random()).collect();

        // qu = A·s + e + Δ·u_col
        // Encrypt unit vector: query[i] = Enc(1) if i == col, else Enc(0)
        let query_data: Vec<u32> = (0..self.db_cols)
            .map(|i| {
                let msg = if i == col { 1 } else { 0 };
                encrypt(
                    &self.params,
                    self.a.row(i),
                    &SecretKey { s: &secret },
                    msg,
                    rng,
                )
            })
            .collect();

        let state = QueryState { row_start, secret };
        (state, Query(query_data))
    }

    /// Recover: decrypt the target record from the answer
    ///
    /// Each byte is recovered by Regev-decrypting (hint_c[row,:], ans[row])
    /// where hint_c[row,:] acts as 'a' and ans[row] acts as 'c'
    pub fn recover(&self, state: &QueryState, answer: &Answer) -> Vec<u8> {
        let sk = SecretKey { s: &state.secret };

        (0..self.record_size)
            .map(|byte_idx| {
                let row = state.row_start + byte_idx;
                let ct = Ciphertext {
                    a: self.hint_c.row(row),
                    c: answer.0[row],
                };
                decrypt(&self.params, &sk, &ct) as u8
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pir::{ClientHint, LweMatrix, MatrixSeed, SetupMessage};

    /// Create a test client with a seeded matrix A
    /// For deterministic tests, we use a fixed seed
    fn test_client(db_cols: usize, record_size: usize) -> PirClient {
        let n = 4; // small LWE dimension for testing
        let params = LweParams {
            n,
            p: 256,
            noise_stddev: 0.0, // zero noise for deterministic tests
        };

        // Use a fixed seed for deterministic tests
        let matrix_seed: MatrixSeed = [0u8; 32];

        // Dummy hint (not used in query)
        let hint_c = ClientHint {
            data: vec![0u32; db_cols * n],
            rows: db_cols,
            cols: n,
        };

        let msg = SetupMessage {
            matrix_seed,
            hint_c,
            db_cols,
            db_rows: db_cols * record_size,
            record_size,
            lwe_dim: n,
        };

        PirClient::new(msg, params)
    }

    /// Create a test client with zero matrix A (makes A·s = 0)
    /// Uses a custom A matrix directly for specific test scenarios
    fn test_client_with_zero_a(db_cols: usize, record_size: usize) -> PirClient {
        let n = 4;
        let params = LweParams {
            n,
            p: 256,
            noise_stddev: 0.0,
        };

        // Zero matrix A: makes A·s = 0, so query = 0 + 0 + Δ·u_col = Δ·u_col
        let a = LweMatrix {
            data: vec![0u32; db_cols * n],
            rows: db_cols,
            cols: n,
        };

        // Dummy hint (not used in query)
        let hint_c = ClientHint {
            data: vec![0u32; db_cols * n],
            rows: db_cols,
            cols: n,
        };

        PirClient {
            a,
            hint_c,
            params,
            db_cols,
            db_rows: db_cols * record_size,
            record_size,
        }
    }

    #[test]
    fn test_query_dimensions() {
        let client = test_client(4, 2); // 4 columns, 2-byte records
        let mut rng = rand::rng();

        let (state, query) = client.query(0, &mut rng);

        assert_eq!(query.0.len(), 4, "Query should have db_cols elements");
        assert_eq!(
            state.secret.len(),
            client.params.n,
            "Secret should have n elements"
        );
    }

    #[test]
    fn test_query_unit_vector_structure() {
        // With A = 0 and noise = 0, query should be exactly Δ·u_col
        let client = test_client_with_zero_a(4, 1);
        let mut rng = rand::rng();
        let delta = client.params.delta();

        // Query for record 2 (col = 2)
        let (_, query) = client.query(2, &mut rng);

        // Should be [0, 0, Δ, 0]
        assert_eq!(query.0[0], 0);
        assert_eq!(query.0[1], 0);
        assert_eq!(query.0[2], delta);
        assert_eq!(query.0[3], 0);
    }

    #[test]
    fn test_query_selects_correct_column() {
        let client = test_client_with_zero_a(5, 1);
        let mut rng = rand::rng();
        let delta = client.params.delta();

        // Test all columns
        for col in 0..5 {
            let (_, query) = client.query(col, &mut rng);

            for i in 0..5 {
                if i == col {
                    assert_eq!(
                        query.0[i], delta,
                        "Position {i} should be Δ for record {col}"
                    );
                } else {
                    assert_eq!(query.0[i], 0, "Position {i} should be 0 for record {col}");
                }
            }
        }
    }

    #[test]
    fn test_query_fresh_secret_each_time() {
        let client = test_client(4, 1);
        let mut rng = rand::rng();

        let (state1, _) = client.query(0, &mut rng);
        let (state2, _) = client.query(0, &mut rng);

        // Secrets should be different (with overwhelming probability)
        assert_ne!(
            state1.secret, state2.secret,
            "Each query should have a fresh secret"
        );
    }

    #[test]
    fn test_recover_with_zero_hint() {
        // With hint_c = 0, recovery simplifies to just rounding ans/Δ
        let n = 4;
        let record_size = 2;
        let db_cols = 2;

        let params = LweParams {
            n,
            p: 256,
            noise_stddev: 0.0,
        };
        let delta = params.delta();

        // Zero hint means hint_c[row,:] · s = 0
        let hint_c = ClientHint {
            data: vec![0u32; 4 * n], // 4 rows (2 groups × 2 bytes)
            rows: 4,
            cols: n,
        };

        // Build client directly for testing (bypass SetupMessage)
        let client = PirClient {
            a: LweMatrix {
                data: vec![0; db_cols * n],
                rows: db_cols,
                cols: n,
            },
            hint_c,
            params,
            db_cols,
            db_rows: 4,
            record_size,
        };

        // Simulate answer for record in group 0: bytes [42, 99]
        // answer[0] = 42 * Δ, answer[1] = 99 * Δ
        let answer = Answer(vec![42 * delta, 99 * delta, 0, 0]);

        let state = QueryState {
            row_start: 0,
            secret: vec![12345; n], // any secret, hint is zero
        };

        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, vec![42, 99]);
    }

    #[test]
    fn test_recover_with_nonzero_hint() {
        // Verifies hint_c · s is correctly subtracted
        let n = 2;
        let record_size = 1;
        let db_cols = 2;

        let params = LweParams {
            n,
            p: 256,
            noise_stddev: 0.0,
        };
        let delta = params.delta();

        // hint_c[0,:] = [1, 2] (for row 0)
        // hint_c[1,:] = [3, 4] (for row 1)
        let hint_c = ClientHint {
            data: vec![1, 2, 3, 4],
            rows: 2,
            cols: n,
        };

        // Build client directly for testing (bypass SetupMessage)
        let client = PirClient {
            a: LweMatrix {
                data: vec![0; db_cols * n],
                rows: db_cols,
                cols: n,
            },
            hint_c,
            params,
            db_cols,
            db_rows: 2,
            record_size,
        };

        // secret = [10, 20]
        // hint_c[0,:] · s = 1*10 + 2*20 = 50
        let secret = vec![10u32, 20];
        let hint_dot = 1 * 10 + 2 * 20; // = 50

        // For plaintext = 77:
        // answer[0] = 77*Δ + hint_dot (so after subtracting hint_dot, we get 77*Δ)
        let plaintext = 77u32;
        let answer = Answer(vec![
            (plaintext * delta).wrapping_add(hint_dot),
            0, // unused
        ]);

        let state = QueryState {
            row_start: 0,
            secret,
        };

        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, vec![77]);
    }

    #[test]
    fn test_recover_second_group() {
        // Test recovering a record from group 1 (not group 0)
        let n = 2;
        let record_size = 2;
        let db_cols = 2;

        let params = LweParams {
            n,
            p: 256,
            noise_stddev: 0.0,
        };
        let delta = params.delta();

        let hint_c = ClientHint {
            data: vec![0u32; 4 * n], // 4 rows
            rows: 4,
            cols: n,
        };

        // Build client directly for testing (bypass SetupMessage)
        let client = PirClient {
            a: LweMatrix {
                data: vec![0; db_cols * n],
                rows: db_cols,
                cols: n,
            },
            hint_c,
            params,
            db_cols,
            db_rows: 4,
            record_size,
        };

        // Record in group 1 starts at row 2 (group * record_size = 1 * 2)
        // Bytes: [200, 201]
        let answer = Answer(vec![
            0,
            0, // group 0 (rows 0-1)
            200 * delta,
            201 * delta, // group 1 (rows 2-3) ← target
        ]);

        let state = QueryState {
            row_start: 2, // group 1
            secret: vec![0; n],
        };

        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, vec![200, 201]);
    }

    #[test]
    fn test_client_from_seed() {
        // Verify client correctly regenerates A from seed
        let params = LweParams {
            n: 4,
            p: 256,
            noise_stddev: 0.0,
        };

        let seed: MatrixSeed = [42u8; 32];
        let db_cols = 3;
        let db_rows = 6;

        let msg = SetupMessage {
            matrix_seed: seed,
            hint_c: ClientHint {
                data: vec![0u32; db_rows * params.n],
                rows: db_rows,
                cols: params.n,
            },
            db_cols,
            db_rows,
            record_size: 2,
            lwe_dim: params.n,
        };

        let client = PirClient::new(msg, params);

        // Verify the regenerated A matches what we'd get from the seed directly
        let expected_a = LweMatrix::from_seed(&seed, db_cols, params.n);
        assert_eq!(client.a.data, expected_a.data);
    }
}

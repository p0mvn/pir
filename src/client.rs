use crate::{
    params::LweParams,
    pir::{ClientHint, LweMatrix, Query, SetupMessage},
    regev::sample_noise,
};
use rand::Rng;

/// Client state (reusable across queries)
pub struct PirClient {
    a: LweMatrix,
    hint_c: ClientHint,
    params: LweParams,
    db_cols: usize,
    db_rows: usize,
    record_size: usize,
}

/// Per-query secret state (needed for recovery)
pub struct QueryState {
    pub row_start: usize,
    pub secret: Vec<u64>,
}

impl PirClient {
    /// Initialize client from setup message
    pub fn new(msg: SetupMessage, params: LweParams) -> Self {
        Self {
            a: msg.a,
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
        let secret: Vec<u64> = (0..self.params.n).map(|_| rng.random()).collect();

        // qu = A·s + e + Δ·u_col
        let mut query_data = vec![0u64; self.db_cols];

        for i in 0..self.db_cols {
            // A[i,:] · s
            let mut dot = 0u64;
            for j in 0..self.params.n {
                dot = dot.wrapping_add(self.a.get(i, j).wrapping_mul(secret[j]));
            }

            // + e (noise)
            let noise = sample_noise(self.params.noise_stddev, rng);
            dot = dot.wrapping_add(noise);

            // + Δ·u_col (unit vector scaled by Δ)
            // This selects the column of the unit vector
            // when matrix-multiplied against the database
            // server side.
            if i == col {
                dot = dot.wrapping_add(self.params.delta());
            }

            query_data[i] = dot;
        }

        let state = QueryState { row_start, secret };
        (state, Query(query_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pir::{ClientHint, LweMatrix, SetupMessage};

    /// Create a test client with zero matrix A (makes A·s = 0)
    fn test_client(db_cols: usize, record_size: usize) -> PirClient {
        let n = 4; // small LWE dimension for testing
        let params = LweParams {
            n,
            q: 1u64 << 32,
            p: 256,
            noise_stddev: 0.0, // zero noise for deterministic tests
        };

        // Zero matrix A: makes A·s = 0, so query = 0 + 0 + Δ·u_col = Δ·u_col
        let a = LweMatrix {
            data: vec![0u64; db_cols * n],
            rows: db_cols,
            cols: n,
        };

        // Dummy hint (not used in query)
        let hint_c = ClientHint {
            data: vec![0u64; db_cols * n],
            rows: db_cols,
            cols: n,
        };

        let msg = SetupMessage {
            a,
            hint_c,
            db_cols,
            db_rows: db_cols * record_size,
            record_size,
        };

        PirClient::new(msg, params)
    }

    #[test]
    fn test_query_dimensions() {
        let client = test_client(4, 2); // 4 columns, 2-byte records
        let mut rng = rand::rng();

        let (state, query) = client.query(0, &mut rng);

        assert_eq!(query.0.len(), 4, "Query should have db_cols elements");
        assert_eq!(state.secret.len(), client.params.n, "Secret should have n elements");
    }

    #[test]
    fn test_query_unit_vector_structure() {
        // With A = 0 and noise = 0, query should be exactly Δ·u_col
        let client = test_client(4, 1);
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
        let client = test_client(5, 1);
        let mut rng = rand::rng();
        let delta = client.params.delta();

        // Test all columns
        for col in 0..5 {
            let (_, query) = client.query(col, &mut rng);

            for i in 0..5 {
                if i == col {
                    assert_eq!(query.0[i], delta, "Position {i} should be Δ for record {col}");
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
        assert_ne!(state1.secret, state2.secret, "Each query should have a fresh secret");
    }
}

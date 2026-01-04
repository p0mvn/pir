//! WebAssembly bindings for YPIR + Binary Fuse Filter
//!
//! This crate provides WASM-compatible bindings for the client-side
//! operations of keyword PIR using YPIR and Binary Fuse Filters.
//!
//! YPIR = DoublePIR + LWE-to-RLWE packing for ~1000× response compression.

use pir::binary_fuse::{BinaryFuseParams, KeywordQuery};
use pir::double::{DoublePirQuery, DoublePirQueryState, DoublePirSetup};
use pir::lwe_to_rlwe::{KeySwitchKey, PackingKey};
use pir::params::LweParams;
use pir::pir::ClientHint;
use pir::ring::RingElement;
use pir::ring_regev::RLWECiphertextOwned;
use pir::ypir::{
    PackingParams, YpirAnswer, YpirClient, YpirParams, YpirQuery, YpirQueryState, YpirSetup,
};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use wasm_bindgen::prelude::*;

// Initialize panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ============================================================================
// Serializable types for JavaScript interop
// ============================================================================

/// Binary Fuse Filter parameters (sent from server to client)
/// Note: seed is serialized as string to avoid JavaScript precision loss for large u64 values
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsBinaryFuseParams {
    pub seed: String, // String to preserve u64 precision in JS
    pub segment_size: usize,
    pub filter_size: usize,
    pub value_size: usize,
    pub segment_length_mask: u32,
}

impl From<BinaryFuseParams> for JsBinaryFuseParams {
    fn from(p: BinaryFuseParams) -> Self {
        Self {
            seed: p.seed.to_string(),
            segment_size: p.segment_size,
            filter_size: p.filter_size,
            value_size: p.value_size,
            segment_length_mask: p.segment_length_mask,
        }
    }
}

impl From<JsBinaryFuseParams> for BinaryFuseParams {
    fn from(p: JsBinaryFuseParams) -> Self {
        Self {
            seed: p.seed.parse().expect("Invalid seed string"),
            segment_size: p.segment_size,
            filter_size: p.filter_size,
            value_size: p.value_size,
            segment_length_mask: p.segment_length_mask,
        }
    }
}

/// LWE parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsLweParams {
    pub n: usize,
    pub p: u32,
    pub noise_stddev: f64,
}

impl From<LweParams> for JsLweParams {
    fn from(p: LweParams) -> Self {
        Self {
            n: p.n,
            p: p.p,
            noise_stddev: p.noise_stddev,
        }
    }
}

impl From<JsLweParams> for LweParams {
    fn from(p: JsLweParams) -> Self {
        Self {
            n: p.n,
            p: p.p,
            noise_stddev: p.noise_stddev,
        }
    }
}

/// Packing parameters for RLWE
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsPackingParams {
    pub ring_dimension: usize,
    pub plaintext_modulus: u32,
    pub noise_stddev: f64,
}

impl From<PackingParams> for JsPackingParams {
    fn from(p: PackingParams) -> Self {
        Self {
            ring_dimension: p.ring_dimension,
            plaintext_modulus: p.plaintext_modulus,
            noise_stddev: p.noise_stddev,
        }
    }
}

impl From<JsPackingParams> for PackingParams {
    fn from(p: JsPackingParams) -> Self {
        Self {
            ring_dimension: p.ring_dimension,
            plaintext_modulus: p.plaintext_modulus,
            noise_stddev: p.noise_stddev,
        }
    }
}

/// Combined YPIR parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsYpirParams {
    pub lwe: JsLweParams,
    pub packing: JsPackingParams,
}

impl From<YpirParams> for JsYpirParams {
    fn from(p: YpirParams) -> Self {
        Self {
            lwe: p.lwe.into(),
            packing: p.packing.into(),
        }
    }
}

impl From<JsYpirParams> for YpirParams {
    fn from(p: JsYpirParams) -> Self {
        Self {
            lwe: p.lwe.into(),
            packing: p.packing.into(),
        }
    }
}

/// YPIR setup data (sent from server to client)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsYpirSetup {
    // DoublePIR setup fields
    pub seed_col: Vec<u8>,
    pub seed_row: Vec<u8>,
    pub hint_col_data: Vec<u32>,
    pub hint_col_rows: usize,
    pub hint_col_cols: usize,
    pub hint_row_data: Vec<u32>,
    pub hint_row_rows: usize,
    pub hint_row_cols: usize,
    pub hint_cross: Vec<u32>,
    pub num_cols: usize,
    pub num_rows: usize,
    pub record_size: usize,
    pub num_records: usize,
    pub lwe_dim: usize,
    // YPIR-specific field
    pub ring_dim: usize,
}

impl From<YpirSetup> for JsYpirSetup {
    fn from(s: YpirSetup) -> Self {
        Self {
            seed_col: s.double_setup.seed_col.to_vec(),
            seed_row: s.double_setup.seed_row.to_vec(),
            hint_col_data: s.double_setup.hint_col.data,
            hint_col_rows: s.double_setup.hint_col.rows,
            hint_col_cols: s.double_setup.hint_col.cols,
            hint_row_data: s.double_setup.hint_row.data,
            hint_row_rows: s.double_setup.hint_row.rows,
            hint_row_cols: s.double_setup.hint_row.cols,
            hint_cross: s.double_setup.hint_cross,
            num_cols: s.double_setup.num_cols,
            num_rows: s.double_setup.num_rows,
            record_size: s.double_setup.record_size,
            num_records: s.double_setup.num_records,
            lwe_dim: s.double_setup.lwe_dim,
            ring_dim: s.ring_dim,
        }
    }
}

impl From<JsYpirSetup> for YpirSetup {
    fn from(s: JsYpirSetup) -> Self {
        let mut seed_col = [0u8; 32];
        let mut seed_row = [0u8; 32];
        seed_col.copy_from_slice(&s.seed_col);
        seed_row.copy_from_slice(&s.seed_row);

        Self {
            double_setup: DoublePirSetup {
                seed_col,
                seed_row,
                hint_col: ClientHint {
                    data: s.hint_col_data,
                    rows: s.hint_col_rows,
                    cols: s.hint_col_cols,
                },
                hint_row: ClientHint {
                    data: s.hint_row_data,
                    rows: s.hint_row_rows,
                    cols: s.hint_row_cols,
                },
                hint_cross: s.hint_cross,
                num_cols: s.num_cols,
                num_rows: s.num_rows,
                record_size: s.record_size,
                num_records: s.num_records,
                lwe_dim: s.lwe_dim,
            },
            ring_dim: s.ring_dim,
        }
    }
}

/// RLWE ciphertext for JSON serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsRlweCiphertext {
    pub a: Vec<u32>,
    pub c: Vec<u32>,
}

impl From<RLWECiphertextOwned> for JsRlweCiphertext {
    fn from(ct: RLWECiphertextOwned) -> Self {
        Self {
            a: ct.a.coeffs,
            c: ct.c.coeffs,
        }
    }
}

impl From<JsRlweCiphertext> for RLWECiphertextOwned {
    fn from(ct: JsRlweCiphertext) -> Self {
        Self {
            a: RingElement { coeffs: ct.a },
            c: RingElement { coeffs: ct.c },
        }
    }
}

/// Key switch key for a single position
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsKeySwitchKey {
    /// ks[i][k] = RLWE encryption of s_i · B^k · x^j
    pub ks: Vec<Vec<JsRlweCiphertext>>,
    pub target_position: usize,
}

impl From<KeySwitchKey> for JsKeySwitchKey {
    fn from(k: KeySwitchKey) -> Self {
        Self {
            ks: k
                .ks
                .into_iter()
                .map(|inner| inner.into_iter().map(|ct| ct.into()).collect())
                .collect(),
            target_position: k.target_position,
        }
    }
}

impl From<JsKeySwitchKey> for KeySwitchKey {
    fn from(k: JsKeySwitchKey) -> Self {
        Self {
            ks: k
                .ks
                .into_iter()
                .map(|inner| inner.into_iter().map(|ct| ct.into()).collect())
                .collect(),
            target_position: k.target_position,
        }
    }
}

/// Packing key for YPIR (d key-switch keys, one per position)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsPackingKey {
    pub keys: Vec<JsKeySwitchKey>,
    pub d: usize,
    pub n: usize,
}

impl From<PackingKey> for JsPackingKey {
    fn from(k: PackingKey) -> Self {
        Self {
            keys: k.keys.into_iter().map(|k| k.into()).collect(),
            d: k.d,
            n: k.n,
        }
    }
}

impl From<JsPackingKey> for PackingKey {
    fn from(k: JsPackingKey) -> Self {
        Self {
            keys: k.keys.into_iter().map(|k| k.into()).collect(),
            d: k.d,
            n: k.n,
        }
    }
}

/// YPIR query (DoublePIR query + packing key)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsYpirQuery {
    pub query_col: Vec<u32>,
    pub query_row: Vec<u32>,
    pub packing_key: JsPackingKey,
}

impl From<YpirQuery> for JsYpirQuery {
    fn from(q: YpirQuery) -> Self {
        Self {
            query_col: q.double_query.query_col,
            query_row: q.double_query.query_row,
            packing_key: q.packing_key.into(),
        }
    }
}

impl From<JsYpirQuery> for YpirQuery {
    fn from(q: JsYpirQuery) -> Self {
        Self {
            double_query: DoublePirQuery {
                query_col: q.query_col,
                query_row: q.query_row,
            },
            packing_key: q.packing_key.into(),
        }
    }
}

/// YPIR answer (packed RLWE ciphertexts)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsYpirAnswer {
    pub packed_cts: Vec<JsRlweCiphertext>,
}

impl From<YpirAnswer> for JsYpirAnswer {
    fn from(a: YpirAnswer) -> Self {
        Self {
            packed_cts: a.packed_cts.into_iter().map(|ct| ct.into()).collect(),
        }
    }
}

impl From<JsYpirAnswer> for YpirAnswer {
    fn from(a: JsYpirAnswer) -> Self {
        Self {
            packed_cts: a.packed_cts.into_iter().map(|ct| ct.into()).collect(),
        }
    }
}

// ============================================================================
// Client state (kept in WASM memory)
// ============================================================================

/// Query state needed for decryption (not sent to server)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsQueryState {
    pub col_idx: usize,
    pub row_idx: usize,
    pub secret_col: Vec<u32>,
    pub secret_row: Vec<u32>,
    /// RLWE secret key coefficients
    pub rlwe_secret: Vec<u32>,
}

// ============================================================================
// WASM-exposed PIR Client
// ============================================================================

/// PIR Client that can be used from JavaScript
#[wasm_bindgen]
pub struct PirClient {
    inner: YpirClient,
    #[allow(dead_code)]
    params: YpirParams,
    filter_params: BinaryFuseParams,
    rng: rand::rngs::SmallRng,
}

#[wasm_bindgen]
impl PirClient {
    /// Create a new PIR client from setup data (JSON)
    #[wasm_bindgen(constructor)]
    pub fn new(
        setup_json: &str,
        ypir_params_json: &str,
        filter_params_json: &str,
    ) -> Result<PirClient, JsValue> {
        let setup: JsYpirSetup = serde_json::from_str(setup_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse setup: {}", e)))?;
        let ypir_params: JsYpirParams = serde_json::from_str(ypir_params_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse YPIR params: {}", e)))?;
        let filter_params: JsBinaryFuseParams = serde_json::from_str(filter_params_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse filter params: {}", e)))?;

        let params: YpirParams = ypir_params.into();
        let pir_setup: YpirSetup = setup.into();
        let filter_params_native: BinaryFuseParams = filter_params.clone().into();

        // Debug: log setup info
        web_sys::console::log_1(
            &format!(
                "YPIR setup: ring_dim={}, lwe_dim={}, num_records={}",
                pir_setup.ring_dim,
                pir_setup.lwe_dim(),
                pir_setup.num_records()
            )
            .into(),
        );
        web_sys::console::log_1(
            &format!(
                "Filter params: seed={}, segment_size={}, filter_size={}, value_size={}",
                filter_params_native.seed,
                filter_params_native.segment_size,
                filter_params_native.filter_size,
                filter_params_native.value_size
            )
            .into(),
        );

        let inner = YpirClient::new(pir_setup, params);

        // Create RNG from random seed
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;
        let rng = rand::rngs::SmallRng::from_seed(seed);

        Ok(PirClient {
            inner,
            params,
            filter_params: filter_params.into(),
            rng,
        })
    }

    /// Hash a password to SHA-1 (uppercase hex)
    #[wasm_bindgen]
    pub fn hash_password(password: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        hex::encode_upper(result)
    }

    /// Get the 3 record indices for a keyword (hash) query
    #[wasm_bindgen]
    pub fn get_keyword_indices(&self, keyword: &str) -> Vec<usize> {
        web_sys::console::log_1(
            &format!(
                "get_keyword_indices: keyword='{}', filter_seed={}",
                keyword, self.filter_params.seed
            )
            .into(),
        );
        let kw_query = KeywordQuery::new(&self.filter_params, &keyword);
        let positions = kw_query.record_indices();
        web_sys::console::log_1(
            &format!("get_keyword_indices: computed positions={:?}", positions).into(),
        );
        positions.to_vec()
    }

    /// Get the 3 record indices for a password (hashes it first)
    #[wasm_bindgen]
    pub fn get_password_indices(&self, password: &str) -> Vec<usize> {
        let hash = Self::hash_password(password);
        web_sys::console::log_1(
            &format!(
                "get_password_indices: password='{}' -> hash='{}'",
                password, hash
            )
            .into(),
        );
        self.get_keyword_indices(&hash)
    }

    /// Generate a PIR query for a specific record index
    /// Returns JSON: { state: JsQueryState, query: JsYpirQuery }
    #[wasm_bindgen]
    pub fn query(&mut self, record_idx: usize) -> Result<String, JsValue> {
        let (state, query) = self.inner.query(record_idx, &mut self.rng);

        let js_state = JsQueryState {
            col_idx: state.double_state.col_idx,
            row_idx: state.double_state.row_idx,
            secret_col: state.double_state.secret_col,
            secret_row: state.double_state.secret_row,
            rlwe_secret: state.rlwe_secret.coeffs,
        };

        let js_query: JsYpirQuery = query.into();

        let result = serde_json::json!({
            "state": js_state,
            "query": js_query,
        });

        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Recover a record from the server's answer
    /// Takes: state_json (JsQueryState), answer_json (JsYpirAnswer)
    /// Returns: the recovered bytes as a Uint8Array
    #[wasm_bindgen]
    pub fn recover(&self, state_json: &str, answer_json: &str) -> Result<Vec<u8>, JsValue> {
        // Debug: log raw JSON inputs
        web_sys::console::log_1(
            &format!(
                "State JSON (first 200 chars): {}",
                &state_json[..std::cmp::min(200, state_json.len())]
            )
            .into(),
        );
        web_sys::console::log_1(
            &format!(
                "Answer JSON (first 200 chars): {}",
                &answer_json[..std::cmp::min(200, answer_json.len())]
            )
            .into(),
        );

        let js_state: JsQueryState = serde_json::from_str(state_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse state: {}", e)))?;
        let js_answer: JsYpirAnswer = serde_json::from_str(answer_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse answer: {}", e)))?;

        // Debug: log answer info
        web_sys::console::log_1(
            &format!(
                "Answer: {} packed RLWE ciphertexts",
                js_answer.packed_cts.len()
            )
            .into(),
        );
        web_sys::console::log_1(
            &format!(
                "State: col_idx={}, row_idx={}",
                js_state.col_idx, js_state.row_idx,
            )
            .into(),
        );

        // Reconstruct the query state
        let state = YpirQueryState {
            double_state: DoublePirQueryState {
                col_idx: js_state.col_idx,
                row_idx: js_state.row_idx,
                secret_col: js_state.secret_col,
                secret_row: js_state.secret_row,
            },
            rlwe_secret: RingElement {
                coeffs: js_state.rlwe_secret,
            },
        };

        // Convert answer
        let answer: YpirAnswer = js_answer.into();

        // Use the YPIR client's recover method
        let result = self.inner.recover(&state, &answer);

        web_sys::console::log_1(&format!("Recovered result: {:?}", result).into());

        Ok(result)
    }

    /// XOR three records to decode the final value
    #[wasm_bindgen]
    pub fn decode_keyword(&self, rec0: &[u8], rec1: &[u8], rec2: &[u8]) -> Vec<u8> {
        rec0.iter()
            .zip(rec1.iter())
            .zip(rec2.iter())
            .map(|((&a, &b), &c)| a ^ b ^ c)
            .collect()
    }

    /// Get the number of records in the database
    #[wasm_bindgen]
    pub fn num_records(&self) -> usize {
        self.inner.num_records()
    }

    /// Get the record size in bytes
    #[wasm_bindgen]
    pub fn record_size(&self) -> usize {
        self.inner.record_size()
    }

    /// Get the ring dimension used for RLWE packing
    #[wasm_bindgen]
    pub fn ring_dimension(&self) -> usize {
        self.inner.ring_dimension()
    }

    /// Get the LWE dimension
    #[wasm_bindgen]
    pub fn lwe_dimension(&self) -> usize {
        self.inner.lwe_dimension()
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Get version info
#[wasm_bindgen]
pub fn version() -> String {
    "pir-wasm 0.2.0 (YPIR)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_roundtrip() {
        let params = JsBinaryFuseParams {
            seed: "12345".to_string(),
            segment_size: 128,
            filter_size: 384,
            value_size: 8,
            segment_length_mask: 127,
        };

        let json = serde_json::to_string(&params).unwrap();
        let decoded: JsBinaryFuseParams = serde_json::from_str(&json).unwrap();

        assert_eq!(params.seed, decoded.seed);
        assert_eq!(params.segment_size, decoded.segment_size);
    }

    #[test]
    fn test_ypir_params_roundtrip() {
        let params = JsYpirParams {
            lwe: JsLweParams {
                n: 64,
                p: 256,
                noise_stddev: 0.0,
            },
            packing: JsPackingParams {
                ring_dimension: 64,
                plaintext_modulus: 256,
                noise_stddev: 0.0,
            },
        };

        let json = serde_json::to_string(&params).unwrap();
        let decoded: JsYpirParams = serde_json::from_str(&json).unwrap();

        assert_eq!(params.lwe.n, decoded.lwe.n);
        assert_eq!(
            params.packing.ring_dimension,
            decoded.packing.ring_dimension
        );
    }
}

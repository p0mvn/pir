//! WebAssembly bindings for DoublePIR + Binary Fuse Filter
//!
//! This crate provides WASM-compatible bindings for the client-side
//! operations of keyword PIR using DoublePIR and Binary Fuse Filters.

use pir::binary_fuse::{BinaryFuseParams, KeywordQuery};
use pir::double::{DoublePirAnswer, DoublePirClient, DoublePirQuery, DoublePirSetup};
use pir::params::LweParams;
use pir::pir::ClientHint;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha1::{Sha1, Digest};
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

/// DoublePIR setup data (sent from server to client)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsDoublePirSetup {
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
}

impl From<DoublePirSetup> for JsDoublePirSetup {
    fn from(s: DoublePirSetup) -> Self {
        Self {
            seed_col: s.seed_col.to_vec(),
            seed_row: s.seed_row.to_vec(),
            hint_col_data: s.hint_col.data,
            hint_col_rows: s.hint_col.rows,
            hint_col_cols: s.hint_col.cols,
            hint_row_data: s.hint_row.data,
            hint_row_rows: s.hint_row.rows,
            hint_row_cols: s.hint_row.cols,
            hint_cross: s.hint_cross,
            num_cols: s.num_cols,
            num_rows: s.num_rows,
            record_size: s.record_size,
            num_records: s.num_records,
            lwe_dim: s.lwe_dim,
        }
    }
}

impl From<JsDoublePirSetup> for DoublePirSetup {
    fn from(s: JsDoublePirSetup) -> Self {
        let mut seed_col = [0u8; 32];
        let mut seed_row = [0u8; 32];
        seed_col.copy_from_slice(&s.seed_col);
        seed_row.copy_from_slice(&s.seed_row);

        Self {
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
        }
    }
}

/// DoublePIR query (sent from client to server)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsDoublePirQuery {
    pub query_col: Vec<u32>,
    pub query_row: Vec<u32>,
}

impl From<DoublePirQuery> for JsDoublePirQuery {
    fn from(q: DoublePirQuery) -> Self {
        Self {
            query_col: q.query_col,
            query_row: q.query_row,
        }
    }
}

impl From<JsDoublePirQuery> for DoublePirQuery {
    fn from(q: JsDoublePirQuery) -> Self {
        Self {
            query_col: q.query_col,
            query_row: q.query_row,
        }
    }
}

/// DoublePIR answer (sent from server to client)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsDoublePirAnswer {
    pub data: Vec<u32>,
}

impl From<DoublePirAnswer> for JsDoublePirAnswer {
    fn from(a: DoublePirAnswer) -> Self {
        Self { data: a.data }
    }
}

impl From<JsDoublePirAnswer> for DoublePirAnswer {
    fn from(a: JsDoublePirAnswer) -> Self {
        Self { data: a.data }
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
}

// ============================================================================
// WASM-exposed PIR Client
// ============================================================================

/// PIR Client that can be used from JavaScript
#[wasm_bindgen]
pub struct PirClient {
    inner: DoublePirClient,
    #[allow(dead_code)]
    params: LweParams,
    filter_params: BinaryFuseParams,
    rng: rand::rngs::SmallRng,
}

#[wasm_bindgen]
impl PirClient {
    /// Create a new PIR client from setup data (JSON)
    #[wasm_bindgen(constructor)]
    pub fn new(
        setup_json: &str,
        lwe_params_json: &str,
        filter_params_json: &str,
    ) -> Result<PirClient, JsValue> {
        let setup: JsDoublePirSetup = serde_json::from_str(setup_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse setup: {}", e)))?;
        let lwe_params: JsLweParams = serde_json::from_str(lwe_params_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse LWE params: {}", e)))?;
        let filter_params: JsBinaryFuseParams = serde_json::from_str(filter_params_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse filter params: {}", e)))?;

        let params: LweParams = lwe_params.into();
        let pir_setup: DoublePirSetup = setup.into();
        let filter_params_native: BinaryFuseParams = filter_params.clone().into();
        
        // Debug: log full seeds and filter params
        web_sys::console::log_1(&format!(
            "Full setup seeds: col={:?}, row={:?}",
            &pir_setup.seed_col,
            &pir_setup.seed_row
        ).into());
        web_sys::console::log_1(&format!(
            "Filter params: seed={}, segment_size={}, filter_size={}, value_size={}",
            filter_params_native.seed,
            filter_params_native.segment_size,
            filter_params_native.filter_size,
            filter_params_native.value_size
        ).into());
        
        let inner = DoublePirClient::new(pir_setup, params);
        
        // Debug: log A matrix data from client
        web_sys::console::log_1(&format!(
            "A_col first 8 elements: {:?}",
            inner.get_a_col_data().iter().take(8).collect::<Vec<_>>()
        ).into());
        web_sys::console::log_1(&format!(
            "A_row first 8 elements: {:?}",
            inner.get_a_row_data().iter().take(8).collect::<Vec<_>>()
        ).into());

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
        web_sys::console::log_1(&format!(
            "get_keyword_indices: keyword='{}', filter_seed={}",
            keyword, self.filter_params.seed
        ).into());
        let kw_query = KeywordQuery::new(&self.filter_params, &keyword);
        let positions = kw_query.record_indices();
        web_sys::console::log_1(&format!(
            "get_keyword_indices: computed positions={:?}",
            positions
        ).into());
        positions.to_vec()
    }

    /// Get the 3 record indices for a password (hashes it first)
    #[wasm_bindgen]
    pub fn get_password_indices(&self, password: &str) -> Vec<usize> {
        let hash = Self::hash_password(password);
        web_sys::console::log_1(&format!(
            "get_password_indices: password='{}' -> hash='{}'",
            password, hash
        ).into());
        self.get_keyword_indices(&hash)
    }

    /// Generate a PIR query for a specific record index
    /// Returns JSON: { state: JsQueryState, query: JsDoublePirQuery }
    #[wasm_bindgen]
    pub fn query(&mut self, record_idx: usize) -> Result<String, JsValue> {
        let (state, query) = self.inner.query(record_idx, &mut self.rng);

        let js_state = JsQueryState {
            col_idx: state.col_idx,
            row_idx: state.row_idx,
            secret_col: state.secret_col,
            secret_row: state.secret_row,
        };

        let js_query: JsDoublePirQuery = query.into();

        let result = serde_json::json!({
            "state": js_state,
            "query": js_query,
        });

        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Recover a record from the server's answer
    /// Takes: state_json (JsQueryState), answer_json (JsDoublePirAnswer)
    /// Returns: the recovered bytes as a Uint8Array
    #[wasm_bindgen]
    pub fn recover(&self, state_json: &str, answer_json: &str) -> Result<Vec<u8>, JsValue> {
        // Debug: log raw JSON inputs
        web_sys::console::log_1(&format!("State JSON (first 200 chars): {}", &state_json[..std::cmp::min(200, state_json.len())]).into());
        web_sys::console::log_1(&format!("Answer JSON: {}", answer_json).into());
        
        let js_state: JsQueryState = serde_json::from_str(state_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse state: {}", e)))?;
        let js_answer: JsDoublePirAnswer = serde_json::from_str(answer_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse answer: {}", e)))?;

        // Debug: log answer data and state
        web_sys::console::log_1(&format!(
            "Answer data: len={}, values={:?}",
            js_answer.data.len(),
            &js_answer.data
        ).into());
        web_sys::console::log_1(&format!(
            "State: col_idx={}, row_idx={}",
            js_state.col_idx,
            js_state.row_idx,
        ).into());
        web_sys::console::log_1(&format!(
            "Secret col first 4: {:?}",
            &js_state.secret_col[..std::cmp::min(4, js_state.secret_col.len())]
        ).into());
        web_sys::console::log_1(&format!(
            "Secret row first 4: {:?}",
            &js_state.secret_row[..std::cmp::min(4, js_state.secret_row.len())]
        ).into());

        // Manual debug recovery with detailed logging
        let delta = self.inner.delta();
        let n = self.inner.lwe_n();
        let p = self.inner.lwe_p();
        let record_size = self.inner.record_size();
        let hint_col_data = self.inner.get_hint_col_data();
        let hint_row_data = self.inner.get_hint_row_data();
        let hint_cross = self.inner.get_hint_cross();
        let hint_col_cols = self.inner.hint_col_cols();
        let hint_row_cols = self.inner.hint_row_cols();
        
        web_sys::console::log_1(&format!(
            "Recovery params: delta={}, n={}, p={}, record_size={}",
            delta, n, p, record_size
        ).into());
        web_sys::console::log_1(&format!(
            "Hint dims: hint_col_rows={}, hint_col_cols={}, hint_row_rows={}, hint_row_cols={}",
            self.inner.hint_col_rows(), hint_col_cols,
            self.inner.hint_row_rows(), hint_row_cols
        ).into());
        web_sys::console::log_1(&format!(
            "Hint data lens: hint_col={}, hint_row={}, hint_cross={}",
            hint_col_data.len(), hint_row_data.len(), hint_cross.len()
        ).into());

        let mut result = Vec::with_capacity(record_size);
        
        for byte_idx in 0..record_size {
            // Get the answer value for this byte
            let ans = js_answer.data[byte_idx];

            // 1. Remove hint_col contribution: hint_col[target_row * record_size + byte, :] · s_col
            let hint_col_idx = js_state.row_idx * record_size + byte_idx;
            let hint_col_row_start = hint_col_idx * hint_col_cols;
            let hint_col_row_end = hint_col_row_start + hint_col_cols;
            let hint_col_row = &hint_col_data[hint_col_row_start..hint_col_row_end];
            
            let hint_col_contrib: u32 = hint_col_row.iter()
                .zip(js_state.secret_col.iter())
                .map(|(&h, &s)| h.wrapping_mul(s))
                .fold(0u32, |acc, x| acc.wrapping_add(x));
            let after_col = ans.wrapping_sub(hint_col_contrib);

            // 2. Remove hint_row contribution: Δ × hint_row[target_col * record_size + byte, :] · s_row
            let hint_row_idx = js_state.col_idx * record_size + byte_idx;
            let hint_row_row_start = hint_row_idx * hint_row_cols;
            let hint_row_row_end = hint_row_row_start + hint_row_cols;
            let hint_row_row = &hint_row_data[hint_row_row_start..hint_row_row_end];
            
            let hint_row_contrib: u32 = hint_row_row.iter()
                .zip(js_state.secret_row.iter())
                .map(|(&h, &s)| h.wrapping_mul(s))
                .fold(0u32, |acc, x| acc.wrapping_add(x));
            let after_row = after_col.wrapping_sub(delta.wrapping_mul(hint_row_contrib));

            // 3. Remove cross term: Σ_j Σ_k hint_cross[byte, j, k] × s_col[j] × s_row[k]
            let cross_base = byte_idx * n * n;
            let mut cross_contrib = 0u32;
            for j in 0..n {
                for k in 0..n {
                    let h = hint_cross[cross_base + j * n + k];
                    cross_contrib = cross_contrib.wrapping_add(
                        h.wrapping_mul(js_state.secret_col[j])
                         .wrapping_mul(js_state.secret_row[k])
                    );
                }
            }
            let after_cross = after_row.wrapping_sub(cross_contrib);

            // Decode: The remaining value is approximately Δ × plaintext + noise
            // round_decode: output = round(value × p / 2^32) mod p
            let scaled = (after_cross as u64 * p as u64 + (1u64 << 31)) >> 32;
            let decoded = (scaled % p as u64) as u8;

            // Log details for first byte only
            if byte_idx == 0 {
                web_sys::console::log_1(&format!(
                    "Byte 0 recovery: ans={}, hint_col_contrib={}, after_col={}, hint_row_contrib={}, after_row={}, cross_contrib={}, after_cross={}, decoded={}",
                    ans, hint_col_contrib, after_col, hint_row_contrib, after_row, cross_contrib, after_cross, decoded
                ).into());
                
                // Also log hint values for byte 0
                web_sys::console::log_1(&format!(
                    "Byte 0 hints: hint_col_idx={}, hint_row_idx={}, cross_base={}",
                    hint_col_idx, hint_row_idx, cross_base
                ).into());
                web_sys::console::log_1(&format!(
                    "Byte 0 hint_col_row first 4: {:?}",
                    &hint_col_row[..std::cmp::min(4, hint_col_row.len())]
                ).into());
                web_sys::console::log_1(&format!(
                    "Byte 0 hint_row_row first 4: {:?}",
                    &hint_row_row[..std::cmp::min(4, hint_row_row.len())]
                ).into());
            }

            result.push(decoded);
        }

        // Debug: log result
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
    
    /// Debug: Get the first few elements of A_col matrix
    #[wasm_bindgen]
    pub fn get_a_col_data(&self) -> Vec<u32> {
        self.inner.get_a_col_data().iter().take(16).cloned().collect()
    }
    
    /// Debug: Get the first few elements of A_row matrix
    #[wasm_bindgen]
    pub fn get_a_row_data(&self) -> Vec<u32> {
        self.inner.get_a_row_data().iter().take(16).cloned().collect()
    }
}

// ============================================================================
// Utility functions
// ============================================================================

/// Get version info
#[wasm_bindgen]
pub fn version() -> String {
    "pir-wasm 0.1.0".to_string()
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
}


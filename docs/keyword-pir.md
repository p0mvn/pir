# Keyword PIR: From Key-to-Index Mappings

> Summary of "Practical Keyword Private Information Retrieval from Key-to-Index Mappings" (Hao et al.)

## Overview

**Problem**: Standard PIR assumes the client knows the *index* of the desired entry. In practice, databases are organized by *keywords* (key-value pairs), and indices aren't immediately available.

**Solution**: Encode the key-value database into an indexable format with a compact key-to-index mapping, then invoke standard PIR.

**Key Insight**: Reduce keyword PIR to standard PIR by:
1. Encoding the server's key-value database into an indexable database with a key-to-index mapping
2. Invoking standard PIR on the encoded database to retrieve specific positions based on the mapping

## Three Constructions

| Construction | # PIR Invocations | DB Expansion | Key Technique |
|-------------|-------------------|--------------|---------------|
| **KPIRkvs** | 3 (constant) | 1.15× | Binary Fuse Filters (sparse KVS) |
| **KPIRhash** | 1 | 1.87× | Hashing-to-bins + Row-KOPIR |
| **KPIRindex** | 1 | 1.03–1.36× | Approximate key-to-index mapping (PLA) |

### Comparison with ChalametPIR (State-of-the-Art)

- **Communication**: 15–178× reduction
- **Runtime**: 1.1–2.4× improvement
- **Example**: 1M entries × 32 bytes → 47ms execution

---

## Row-KOPIR: The Core Building Block

Row-KOPIR (Kushilevitz-Ostrovsky PIR) retrieves an *entire row* from a matrix database, not just a single element. This is crucial for keyword PIR constructions.

### Protocol (SimplePIR-based)

```
Parameters:
  - Database: D ∈ Z_p^{r×c} (r rows, c columns)
  - LWE params: (N, r, q, χ)
  - Random matrix: A ∈ Z_q^{N×r}
  - Scalar: Δ = ⌊q/p⌋

Setup(D):
  hint := A · D ∈ Z_q^{N×c}  // Client downloads once

Query(i):
  s ← Z_q^N, e ← χ^r
  qu := s·A + e + Δ·u_i   // u_i = unit vector with 1 at index i
  return (st := s, qu)

Answer(qu, D):
  return ans := qu · D ∈ Z_q^c

Recover(st, hint, ans):
  return Round_Δ(ans - st·hint mod q) ∈ Z_p^c  // Entire row!
```

**Key property**: Retrieves all c elements in row i with sublinear communication O(√n).

---

## Construction 1: KPIRkvs (Sparse Key-Value Store)

### Core Idea
Use Binary Fuse Filters (BFF) as an α-sparse KVS where decoding only accesses α=3 positions.

### α-Sparse KVS Definition

```
Encode(L) → (D, H):
  Input: key-value pairs L = {(k_i, v_i)}
  Output: vector D of size m, hash functions H = {h_1, h_2, h_3}

Decode(H, k, D[H(k)]) → v:
  Access only D[h_1(k)], D[h_2(k)], D[h_3(k)]
  Return v = D[h_1(k)] ⊕ D[h_2(k)] ⊕ D[h_3(k)]
```

### Protocol Flow

```
Setup:
  1. Encode key-value DB into vector D' using BFF
  2. Reshape D' into √m × √m matrix
  3. Compute hint := A·D'

Query(k):
  1. Compute h_1(k), h_2(k), h_3(k)
  2. For each position, invoke Row-KOPIR.Query

Answer:
  3 parallel Row-KOPIR.Answer calls

Recover:
  1. Recover 3 rows
  2. Extract D'[h_i(k)] from each row
  3. Return v = D'[h_1(k)] + D'[h_2(k)] + D'[h_3(k)]
```

### Parameters
- **Expansion**: m ≤ 1.156n
- **PIR invocations**: 3
- **Hash functions**: 3 (client stores)

---

## Construction 2: KPIRhash (Hashing-to-Bins)

### Core Idea
Hash key-value pairs into √n bins, then retrieve entire bin using Row-KOPIR.

### Protocol Flow

```
Setup:
  1. Initialize r = √n empty bins B_1, ..., B_r
  2. For each (k,v) ∈ D: append k||v to B_{h(k)}
  3. Combine bins as rows into matrix D' of size r × c
     where c = max bin size (padded with dummies)
  4. Compute hint := A·D'

Query(k):
  i := h(k) ∈ [r]
  (st', qu) ← Row-KOPIR.Query(i)

Answer(qu, D'):
  Row-KOPIR.Answer(qu, D')

Recover:
  1. Recover entire bin B_i = {k*_1||v*_1, ..., k*_c||v*_c}
  2. Linear scan: return v*_j if k = k*_j, else ⊥
```

### Parameters
- **Expansion**: m ≤ 1.873n (empirical max bin size ≈ 1.87√n)
- **PIR invocations**: 1
- **Hash functions**: 1 (client stores)

### Optimization: Permutation-based Hashing
Store only partial key in bins: split x into (x_1, x_2), store x_2 in bin x_1 ⊕ h(x_2). Saves log(r) bits per entry.

---

## Construction 3: KPIRindex (Approximate Key-to-Index Mapping) ⭐

**Most efficient construction** — single PIR invocation with minimal expansion.

### Core Idea
Build a compact approximate mapping from keys to positions (with error ε), then retrieve 2ε consecutive entries in one row.

### Approximate Key-to-Index Mapping

```
Map_ε(K) → map:
  Input: sorted key set K of size n
  Output: compact structure (e.g., piecewise linear approximation)

Extract_ε(k, map) → i_k:
  Output: approximate position i_k ∈ [pos(k) - ε, pos(k) + ε]
```

**Instantiation**: Piece-wise Linear Approximation (PLA)
- Segments: d ≤ n/2ε (sublinear when ε = O(√n))
- Practical: ε = 4, segments ≈ 1.3% of n

### Protocol Flow

```
Setup:
  1. Sort key-value pairs by key → {(k'_1, v'_1), ..., (k'_n, v'_n)}
  2. Compute map ← PLA(k'_1, ..., k'_n) with error ε
  3. Build matrix D' of size √n × (√n + 2ε):
     - Each row contains √n entries + ε overlap on each side
     - Row i: entries from (i-1)·c - ε + 1 to i·c + ε
  4. Compute hint := A·D'

Query(k):
  1. pos ← Extract_ε(map, k)
  2. row := ⌈pos/c⌉
  3. (st', qu) ← Row-KOPIR.Query(row)

Answer(qu, D'):
  Row-KOPIR.Answer(qu, D')

Recover:
  1. Recover row containing 2ε+c entries
  2. Linear scan: return v if k matches, else ⊥
```

### Repetition-Based Matrix Encoding

```
Original sorted entries: [D_1, D_2, ..., D_n]

Matrix with overlap (ε=2 example):
Row 1: [D_{-1}, D_0,   D_1, D_2, D_3, D_4,   D_5, D_6]
Row 2: [D_3,   D_4,   D_5, D_6, D_7, D_8,   D_9, D_10]
        ↑      ↑      ↑--------------↑      ↑      ↑
        overlap       original row          overlap
```

This ensures any 2ε consecutive entries are in the same row.

### Parameters
- **Expansion**: 1.03–1.36× (ε = 4)
- **PIR invocations**: 1
- **Client memory**: ~324 KB for 2^20 entries (the PLA mapping)

---

## Integration with YPIR

For your YPIR implementation, **KPIRindex is the recommended baseline**:

### Why KPIRindex?
1. **Single PIR invocation** — directly compatible with YPIR's response packing
2. **Minimal expansion** — 1.03–1.36× overhead
3. **Sublinear client storage** — PLA mapping is ~0.3 MB for 1M entries

### Integration Steps

```rust
// 1. Add key-to-index mapping module
pub mod pla;  // Piecewise Linear Approximation

// 2. Extend database encoding
impl MatrixDatabase {
    /// Encode key-value pairs with overlap for keyword PIR
    pub fn from_key_value_pairs(
        pairs: Vec<(Key, Value)>,
        epsilon: usize,
    ) -> (Self, PlaMapping) {
        // Sort by key
        // Build PLA mapping
        // Create matrix with row overlap
    }
}

// 3. Query modification
impl Client {
    pub fn keyword_query(&self, key: &Key, pla: &PlaMapping) -> Query {
        let approx_pos = pla.extract(key);
        let row = approx_pos / self.params.cols;
        self.query_row(row)  // Standard YPIR query
    }
}

// 4. Recovery modification
impl Client {
    pub fn keyword_recover(&self, key: &Key, response: Response) -> Option<Value> {
        let row_entries = self.recover_row(response);
        row_entries.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }
}
```

### Performance Expectations

For 2^20 entries × 32 bytes:
- **Setup**: ~24s (one-time)
- **Online communication**: ~50 KB (vs 4.5 MB for ChalametPIR)
- **Online runtime**: ~47 ms

---

## Security

All constructions inherit security from the underlying LWE-based PIR:

- **LWE parameters**: N=1024, q=2^32, σ=6.4 (Gaussian error)
- **Security**: 128-bit computational security
- **Query privacy**: Computationally indistinguishable queries for any two keys

---

## Key Takeaways

1. **Keyword PIR reduces to index PIR** via key-to-index mappings
2. **Row-KOPIR** (row retrieval) is the key primitive — retrieve √n elements at once
3. **KPIRindex** achieves best overall performance: 1 PIR call, ~1.1× expansion
4. **Trade-off**: Client stores compact mapping (~324 KB) to avoid linear communication
5. **Compatible with YPIR**: Just add sorting + PLA mapping + row overlap encoding

## References

- Paper: "Practical Keyword Private Information Retrieval from Key-to-Index Mappings"
- Code: https://github.com/alibaba-edu/mpc4j
- Binary Fuse Filters: https://github.com/FastFilter/fastfilter_java
- PGM-Index (PLA): https://github.com/gvinciguerra/PGM-index











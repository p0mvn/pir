# PIR Benchmark Results: SimplePIR vs DoublePIR

**Date:** December 29, 2025  
**Parameters:** n=1024, p=256, noise_stddev=6.4, record_size=3 bytes  
**System:** macOS (darwin 24.6.0)

## Summary

| Benchmark | 1,000 records | 10,000 records | 100,000 records |
|-----------|---------------|----------------|-----------------|
| **SimplePIR Setup** | ~1 ms | ~8.5 ms | ~77 ms |
| **SimplePIR Query** | ~10 µs | ~18 µs | ~62 µs |
| **DoublePIR Setup** | ~46 ms | ~282 ms | ~1.05 s |
| **DoublePIR Query** | ~290 µs | ~340 µs | ~530 µs |

## Key Trade-offs

### Computation vs Communication

| Metric | SimplePIR | DoublePIR | Winner |
|--------|-----------|-----------|--------|
| Server setup | Fast | 13-52x slower | SimplePIR |
| Query latency | ~10-60 µs | ~290-530 µs | SimplePIR |
| Answer size | O(√N × record_size) | O(record_size) | **DoublePIR** |

### Answer Size Comparison

| Records | SimplePIR Answer | DoublePIR Answer | Reduction |
|---------|------------------|------------------|-----------|
| 1,000 | 384 bytes | 12 bytes | **32x** |
| 10,000 | 1,200 bytes | 12 bytes | **100x** |
| 100,000 | 3,804 bytes | 12 bytes | **317x** |

## When to Use Each

### SimplePIR
- ✅ Low latency is critical (<100µs queries)
- ✅ Bandwidth is cheap/plentiful
- ✅ Fast server startup needed

### DoublePIR  
- ✅ Bandwidth is expensive (mobile, metered)
- ✅ Answer size must be minimal
- ✅ Can tolerate ~500µs query latency
- ✅ Server preprocessing can be done offline

## DoublePIR Performance Analysis

### Why DoublePIR Queries Are Slower

The bottleneck is the **cross-term computation** during recovery:

```
cross_term = Σ_j Σ_k H[j,k] × s_col[j] × s_row[k]
```

With n=1024:
- **~1 million operations per byte**
- For 3-byte records: **~3 million ops per query**

This is mathematically unavoidable — it cancels the `(A₁·s₁) × (A₂·s₂)` interaction term required for security.

### Optimization Attempts

| Approach | Result | Reason |
|----------|--------|--------|
| Rayon parallelization | ❌ Slower | Thread overhead > benefit |
| Manual SIMD unrolling | ❌ 5x slower | Breaks compiler auto-vectorization |
| Iterator chains | ⚠️ Inconsistent | High variance |
| Simple for-loop | ✅ Best | LLVM auto-vectorizes well |

### Future Optimization Opportunities

1. **GPU acceleration** — Matrix ops on GPU (cuBLAS, Metal)
2. **Explicit SIMD** — AVX2/AVX-512 intrinsics
3. **Ring-LWE** — Reduces n from 1024 to ~512
4. **Query batching** — Amortize costs across queries

## Raw Benchmark Data

```
simple_server_preprocessing/1000    time: [956.67 µs 999.84 µs 1.0550 ms]
simple_server_preprocessing/10000   time: [8.3759 ms 8.5423 ms 8.7184 ms]
simple_server_preprocessing/100000  time: [74.709 ms 76.787 ms 79.424 ms]

simple_end_to_end/1000              time: [10.299 µs 10.489 µs 10.738 µs]
simple_end_to_end/10000             time: [17.958 µs 18.192 µs 18.560 µs]
simple_end_to_end/100000            time: [61.981 µs 62.311 µs 62.685 µs]

double_server_preprocessing/1000    time: [45.135 ms 45.721 ms 46.445 ms]
double_server_preprocessing/10000   time: [279.13 ms 281.52 ms 284.18 ms]
double_server_preprocessing/100000  time: [1.0506 s 1.0969 s 1.1526 s]

double_end_to_end/1000              time: [280.88 µs 289.74 µs 301.72 µs]
double_end_to_end/10000             time: [316.60 µs 341.40 µs 376.85 µs]
double_end_to_end/100000            time: [512.94 µs 534.16 µs 559.73 µs]
```


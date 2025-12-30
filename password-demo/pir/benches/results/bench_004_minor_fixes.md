# Benchmark 004: Minor Fixes

**Date:** 2025-12-25  
**Commit:** Minor fixes / micro-optimizations after rayon  
**Hardware:** Apple M3 Pro, 36 GB RAM, macOS 15.6

## Configuration

- LWE dimension (n): 1024
- Modulus (q): 2³²
- Plaintext modulus (p): 256
- Record size: 3 bytes
- Data type: u32
- **Parallelization:** rayon for `compute_hint` only

## Results

### Server Preprocessing (parallelized with rayon)

| Records | Time | vs bench_003 | Speedup |
|---------|------|--------------|---------|
| 1,000 | 871 µs | **-8.6%** | **1.09×** |
| 10,000 | 8.08 ms | **-17.7%** | **1.21×** |
| 100,000 | 80.35 ms | **-3.9%** | **1.04×** |

### End-to-End Query (serial)

| Records | Time | Throughput | vs bench_003 |
|---------|------|------------|--------------|
| 1,000 | 9.98 µs | ~301 MB/s | **-25.9%** |
| 10,000 | 20.77 µs | ~1.44 GB/s | **-27.0%** |
| 100,000 | 65.73 µs | ~4.56 GB/s | **-32.7%** |

## Analysis

### What Changed vs bench_003

- **Preprocessing:** modest additional improvement (best at 10K: **~1.21×**).
- **End-to-end:** clear across-the-board improvement (**~1.35× → ~1.49×**), suggesting lower fixed overheads in the query/answer/recover path.

### Key Takeaway

Rayon continues to pay off for server preprocessing, while end-to-end stays serial; the gains here come from smaller constant-factor reductions rather than new parallelism.

### Cumulative Improvement (vs bench_001)

| Metric | bench_001 | bench_004 | Total Speedup |
|--------|-----------|-----------|---------------|
| Preprocessing (100K) | 455.6 ms | 80.35 ms | **5.7×** |
| End-to-end (100K) | 328 µs | 65.73 µs | **5.0×** |
| Throughput (100K) | 914 MB/s | 4.56 GB/s | **5.0×** |

## Next Optimization Ideas

- SIMD vectorization (explicit intrinsics)
- Cache tiling for better locality
- Batch query processing



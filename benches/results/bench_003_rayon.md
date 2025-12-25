# Benchmark 003: Rayon Parallelization

**Date:** 2024-12-25  
**Commit:** Add rayon for parallel hint computation  
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

| Records | Time | vs bench_002 | Speedup |
|---------|------|--------------|---------|
| 1,000 | 953 µs | -59.5% | **2.5×** |
| 10,000 | 9.81 ms | -77.0% | **4.3×** |
| 100,000 | 83.6 ms | -79.2% | **4.8×** |

### End-to-End Query (serial — rayon overhead not worth it)

| Records | Time | Throughput | vs bench_002 |
|---------|------|------------|--------------|
| 1,000 | 13.46 µs | ~223 MB/s | unchanged |
| 10,000 | 28.45 µs | ~1.05 GB/s | unchanged |
| 100,000 | 97.67 µs | ~3.07 GB/s | unchanged |

## Analysis

### What Worked

**Hint computation parallelizes beautifully:**
- Each row of `DB · A` is independent
- Large enough workload (300K+ operations) to amortize rayon overhead
- Nearly **5× speedup** on 10+ cores

### What Didn't Work

**End-to-end query parallelization hurt performance:**
- Initial attempt with rayon made queries **3-4× slower**
- Rayon overhead (~50µs) exceeds the operation itself (~28µs at 10K)
- Reverted to serial implementation

### Key Insight

```
Parallelization payoff = Work per thread > Thread overhead

compute_hint:  ~300K ops/row  →  Worth parallelizing ✓
multiply_vec:  ~300 ops/row   →  NOT worth parallelizing ✗
```

### Cumulative Improvement (vs bench_001)

| Metric | bench_001 | bench_003 | Total Speedup |
|--------|-----------|-----------|---------------|
| Preprocessing (100K) | 455.6 ms | 83.6 ms | **5.4×** |
| End-to-end (100K) | 328 µs | 97.7 µs | **3.4×** |
| Throughput (100K) | 914 MB/s | 3.07 GB/s | **3.4×** |

## Next Optimization Ideas

- SIMD vectorization (explicit intrinsics)
- Cache tiling for better locality
- Batch query processing


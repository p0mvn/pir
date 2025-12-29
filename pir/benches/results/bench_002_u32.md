# Benchmark 002: Switch to u32

**Date:** 2024-12-25  
**Commit:** Switch from u64 to u32 arithmetic  
**Hardware:** Apple M3 Pro, 36 GB RAM, macOS 15.6

## Configuration

- LWE dimension (n): 1024
- Modulus (q): 2³²
- Plaintext modulus (p): 256
- Record size: 3 bytes
- Data type: **u32** (changed from u64)

## Results

### Server Preprocessing

| Records | Time | vs bench_001 | Notes |
|---------|------|--------------|-------|
| 1,000 | 2.35 ms | -40.7% | ✓ improved |
| 10,000 | 42.6 ms | -3.2% | within noise |
| 100,000 | 401 ms | -14.7% | ✓ improved |

### End-to-End Query (client query → server answer → client recover)

| Records | Time | Throughput | vs bench_001 |
|---------|------|------------|--------------|
| 1,000 | 12.95 µs | ~232 MB/s | **-58.2%** |
| 10,000 | 28.71 µs | ~1.04 GB/s | **-65.0%** |
| 100,000 | 97.89 µs | ~3.06 GB/s | **-70.4%** |

## Analysis

### Improvements

- **End-to-end performance:** Massive improvement across all sizes (58-70% faster)
- **Server preprocessing:** Modest improvement (14-40% for most sizes)
- **Throughput at 100K:** Now at **3.06 GB/s** (up from 914 MB/s)

### Why u32 Helps

1. **Better cache utilization:** 2× more values fit in L1/L2 cache
2. **SIMD efficiency:** 2× more elements per vector register
3. **Memory bandwidth:** Half the data to move through memory hierarchy

### Gap vs Paper

- SimplePIR paper claims ~10 GB/s throughput
- Current best: 3.06 GB/s (~3× slower)
- Closing the gap! Was ~10× slower in bench_001

## Next Optimization Ideas

- Add rayon parallelization for server preprocessing
- SIMD vectorization (explicit AVX2/NEON intrinsics)
- Cache tiling for matrix operations
- Batch query processing



# Benchmark 001: Initial Implementation

**Date:** 2024-12-25  
**Commit:** Initial naive implementation  
**Hardware:** Apple M3 Pro, 36 GB RAM, macOS 15.6

## Configuration

- LWE dimension (n): 1024
- Modulus (q): 2³²
- Plaintext modulus (p): 256
- Record size: 3 bytes
- Data type: u64

## Results

### Server Preprocessing

| Records | Time | Notes |
|---------|------|-------|
| 1,000 | 3.57 ms | |
| 10,000 | 43.7 ms | |
| 100,000 | 455.6 ms | |

### End-to-End Query (client query → server answer → client recover)

| Records | Time | Throughput |
|---------|------|------------|
| 1,000 | 30.5 µs | ~98 MB/s |
| 10,000 | 78.9 µs | ~380 MB/s |
| 100,000 | 328 µs | ~914 MB/s |

## Analysis

- **Preprocessing scaling:** Linear with N ✓
- **Query scaling:** Sub-linear (√N structure) ✓
- **Gap vs paper:** ~10× slower than SimplePIR paper (10 GB/s)

## Optimization Ideas

- Switch from u64 to u32
- Add rayon parallelization
- SIMD vectorization
- Cache tiling


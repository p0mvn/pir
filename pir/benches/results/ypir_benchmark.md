# YPIR Benchmark Results

**Date**: January 3, 2026  
**Machine**: Apple Silicon (darwin 24.6.0)  
**Record Size**: 3 bytes

## Overview

YPIR = DoublePIR + LWE-to-RLWE packing for ~1000× response compression.

This benchmark compares three PIR protocols:
- **SimplePIR**: Fast single-server PIR, large responses
- **DoublePIR**: Compressed hints via nested PIR
- **YPIR**: DoublePIR + response compression via LWE-to-RLWE packing

## Parameters

| Protocol | LWE Dim (n) | Ring Dim (d) | Notes |
|----------|-------------|--------------|-------|
| SimplePIR | 1024 | - | 128-bit security |
| DoublePIR | 1024 | - | 128-bit security |
| YPIR (preprocess) | 1024 | 1024 | 128-bit security |
| YPIR (end-to-end) | 256 | 256 | Reduced for benchmarking |

## Server Preprocessing

Server preprocessing creates the hint matrix `H = DB × A`.

| Records | SimplePIR | DoublePIR | YPIR |
|---------|-----------|-----------|------|
| 1,000 | 1.10 ms | 55.3 ms | 48.9 ms |
| 10,000 | 10.8 ms | 317.7 ms | 321.4 ms |
| 100,000 | 127.0 ms | 1.21 s | 1.18 s |

**Analysis**:
- SimplePIR preprocessing is ~50× faster than DoublePIR/YPIR
- DoublePIR and YPIR have similar preprocessing times (both compute the same hints)
- All protocols scale linearly with database size

## End-to-End Latency (Query → Answer → Recover)

| Records | SimplePIR | DoublePIR | YPIR (n=256) |
|---------|-----------|-----------|--------------|
| 100 | ~10 µs* | ~300 µs* | ~33 s** |
| 1,000 | 13.6 µs | 333.3 µs | ~33 s** |
| 10,000 | 38.5 µs | 356.4 µs | ~33 s** |
| 100,000 | 93.2 µs | 634.4 µs | N/A |

*Extrapolated from benchmark data  
**Estimated from criterion warm-up (~33s per iteration, dominated by packing key generation)

**Analysis**:
- SimplePIR is the fastest for online operations (~10-100 µs)
- DoublePIR adds overhead for hint compression (~300-600 µs)
- YPIR's packing key generation dominates runtime: **O(d² × NUM_DIGITS) RLWE encryptions**
  - For d=256, NUM_DIGITS=4: ~262,144 RLWE encryptions per query
  - For d=1024, NUM_DIGITS=4: ~4.2 million RLWE encryptions per query

## Why YPIR End-to-End is Slow

The YPIR query includes a **packing key** that enables the server to compress LWE ciphertexts into RLWE ciphertexts. Generating this key requires:

```
Packing Key Size = d × d × NUM_DIGITS × 2d × 4 bytes
For d=256:  ~134 MB
For d=1024: ~34 GB (!)
```

Each position in the packing key requires `d × NUM_DIGITS` RLWE encryptions:
- d=256: 256 × 256 × 4 = 262,144 RLWE encryptions
- d=1024: 1024 × 1024 × 4 = 4,194,304 RLWE encryptions

This makes YPIR impractical for scenarios requiring frequent queries. However, YPIR excels when:
1. **Query amortization**: Reuse packing key across multiple queries
2. **Bandwidth-constrained**: ~1000× response compression justifies computation
3. **Large records**: Compression benefit increases with record size

## Response Size Comparison

For a 256 KB record:

| Protocol | Response Size | Compression |
|----------|---------------|-------------|
| SimplePIR | ~1 MB | 1× |
| DoublePIR | ~1 MB | 1× |
| YPIR | ~1 KB | ~1000× |

## Recommendations

| Use Case | Recommended Protocol |
|----------|---------------------|
| Low latency, any bandwidth | SimplePIR |
| Low latency, limited bandwidth | DoublePIR |
| Bandwidth-critical, amortized queries | YPIR |
| Single large record retrieval | YPIR |

## Raw Benchmark Output

### SimplePIR Preprocessing
```
simple_server_preprocessing/1000    time: [1.0485 ms 1.1015 ms 1.1669 ms]
simple_server_preprocessing/10000   time: [10.233 ms 10.775 ms 11.458 ms]
simple_server_preprocessing/100000  time: [117.08 ms 126.96 ms 138.02 ms]
```

### SimplePIR End-to-End
```
simple_end_to_end/1000    time: [11.301 µs 13.577 µs 16.736 µs]
simple_end_to_end/10000   time: [33.553 µs 38.540 µs 43.612 µs]
simple_end_to_end/100000  time: [80.281 µs 93.163 µs 109.40 µs]
```

### DoublePIR Preprocessing
```
double_server_preprocessing/1000    time: [50.975 ms 55.271 ms 60.741 ms]
double_server_preprocessing/10000   time: [307.38 ms 317.65 ms 330.30 ms]
double_server_preprocessing/100000  time: [1.1662 s 1.2065 s 1.2507 s]
```

### DoublePIR End-to-End
```
double_end_to_end/1000    time: [322.03 µs 333.27 µs 347.45 µs]
double_end_to_end/10000   time: [342.80 µs 356.37 µs 373.55 µs]
double_end_to_end/100000  time: [586.00 µs 634.35 µs 697.54 µs]
```

### YPIR Preprocessing (n=1024, d=1024)
```
ypir_server_preprocessing/1000    time: [47.255 ms 48.948 ms 51.077 ms]
ypir_server_preprocessing/10000   time: [313.02 ms 321.40 ms 331.03 ms]
ypir_server_preprocessing/100000  time: [1.1367 s 1.1770 s 1.2236 s]
```

### YPIR End-to-End (n=256, d=256)
```
ypir_end_to_end/100  time: ~33 s (estimated from criterion warm-up)
                     Dominated by packing key generation (262K RLWE encryptions)
```

## Future Optimizations

To make YPIR end-to-end competitive:

1. **Packing key caching**: Generate once, reuse across queries
2. **Smaller ring dimension**: Use d < n for faster key generation (trades compression)
3. **Parallelization**: Packing key generation is embarrassingly parallel
4. **Hardware acceleration**: NTT operations benefit from SIMD/GPU
5. **Alternative packing schemes**: Explore more efficient LWE-to-RLWE conversions

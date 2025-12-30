# PIR Benchmark Results

**Date:** December 29, 2025  
**Parameters:** n=1024, p=256, noise_stddev=6.4, record_size=3 bytes  
**System:** macOS (darwin 24.6.0)

## Summary Table

| Benchmark | 1,000 records | 10,000 records | 100,000 records |
|-----------|---------------|----------------|-----------------|
| **SimplePIR Server Setup** | 948 µs | 8.54 ms | 76.8 ms |
| **SimplePIR End-to-End** | 10.5 µs | 19.2 µs | 64.1 µs |
| **DoublePIR Server Setup** | 49.8 ms | 303 ms | 1.02 s |
| **DoublePIR End-to-End** | 298 µs | 323 µs | 502 µs |

## Detailed Results

### SimplePIR Server Preprocessing

Server setup includes matrix generation and hint computation (DB · A).

| Records | Time | Notes |
|---------|------|-------|
| 1,000 | 948.47 µs ± 27 µs | Fast setup |
| 10,000 | 8.54 ms ± 0.17 ms | Scales ~9x |
| 100,000 | 76.79 ms ± 2.4 ms | Scales ~9x |

### SimplePIR End-to-End Query

Full query cycle: client query → server answer → client recovery.

| Records | Time | Notes |
|---------|------|-------|
| 1,000 | 10.49 µs | √N ≈ 32 |
| 10,000 | 19.20 µs | √N ≈ 100 |
| 100,000 | 64.15 µs | √N ≈ 317 |

### DoublePIR Server Preprocessing

Server setup includes two matrix generations and three hint computations (col, row, cross).

| Records | Time | Notes |
|---------|------|-------|
| 1,000 | 49.81 ms | ~52x slower than SimplePIR |
| 10,000 | 303.03 ms | ~35x slower than SimplePIR |
| 100,000 | 1.017 s | ~13x slower than SimplePIR |

### DoublePIR End-to-End Query

Full query cycle with two-stage multiplication.

| Records | Time | Notes |
|---------|------|-------|
| 1,000 | 297.90 µs | ~28x slower than SimplePIR |
| 10,000 | 323.37 µs | ~17x slower than SimplePIR |
| 100,000 | 502.32 µs | ~8x slower than SimplePIR |

## Analysis

### Server Setup (Preprocessing)

- **SimplePIR** scales approximately as O(N × n) for the hint computation
- **DoublePIR** has significantly higher preprocessing cost due to computing three hints:
  - `hint_col`: O(√N × record_size × n)
  - `hint_row`: O(√N × record_size × n)  
  - `hint_cross`: O(√N × record_size × n²) — the dominant term

### Query Performance

| Metric | SimplePIR | DoublePIR | Ratio |
|--------|-----------|-----------|-------|
| Query scaling | O(√N) | O(√N) | Similar |
| Base overhead | Low | High (cross-term decryption) | ~28x at 1K |

DoublePIR's query overhead comes from:
1. Computing two encrypted queries instead of one
2. Removing the cross-term contribution during recovery (O(n²) per byte)

### Communication Trade-off

While DoublePIR is slower computationally, it significantly reduces answer size:

| Records | SimplePIR Answer | DoublePIR Answer | Reduction |
|---------|------------------|------------------|-----------|
| 1,000 | √N × 3 × 4 = 384 bytes | 3 × 4 = 12 bytes | 32x |
| 10,000 | √N × 3 × 4 = 1,200 bytes | 3 × 4 = 12 bytes | 100x |
| 100,000 | √N × 3 × 4 = 3,804 bytes | 3 × 4 = 12 bytes | 317x |

### Recommendations

1. **Use SimplePIR when:**
   - Low latency is critical
   - Bandwidth is not a concern
   - Database size is small to medium

2. **Use DoublePIR when:**
   - Bandwidth/answer size is the bottleneck
   - Can afford higher preprocessing time
   - Query latency of ~500µs is acceptable

## Raw Criterion Output

```
simple_server_preprocessing/1000    time: [928.04 µs 948.47 µs 975.40 µs]
simple_server_preprocessing/10000   time: [8.3759 ms 8.5423 ms 8.7184 ms]
simple_server_preprocessing/100000  time: [74.709 ms 76.787 ms 79.424 ms]

simple_end_to_end/1000              time: [10.299 µs 10.489 µs 10.738 µs]
simple_end_to_end/10000             time: [18.375 µs 19.196 µs 20.508 µs]
simple_end_to_end/100000            time: [62.953 µs 64.149 µs 66.144 µs]

double_server_preprocessing/1000    time: [48.006 ms 49.812 ms 51.950 ms]
double_server_preprocessing/10000   time: [296.64 ms 303.03 ms 310.62 ms]
double_server_preprocessing/100000  time: [1.0074 s 1.0172 s 1.0282 s]

double_end_to_end/1000              time: [296.86 µs 297.90 µs 299.07 µs]
double_end_to_end/10000             time: [321.81 µs 323.37 µs 325.41 µs]
double_end_to_end/100000            time: [495.04 µs 502.32 µs 511.69 µs]
```


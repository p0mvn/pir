# NTT Acceleration Benchmark Results

This document summarizes the performance of NTT (Number Theoretic Transform) acceleration for polynomial multiplication in the ring `Z_q[x]/(x^d + 1)`.

## Overview

NTT transforms polynomial multiplication from **O(n²)** to **O(n log n)**, providing significant speedups for larger ring dimensions commonly used in lattice-based cryptography.

## Benchmark Scenarios

| Scenario | Description | Complexity |
|----------|-------------|------------|
| `schoolbook` | Naive polynomial multiplication | O(n²) |
| `ntt_full` | NTT multiplication including transforms | O(n log n) |
| `ntt_domain_mul` | Point-wise multiply (pre-transformed) | O(n) |

## Results

### Polynomial Multiplication Comparison

| Dimension (d) | Schoolbook | NTT Full | NTT Domain | Speedup (Full) | Speedup (Domain) |
|---------------|------------|----------|------------|----------------|------------------|
| 64            | ~0.5 µs    | ~3 µs    | ~0.16 µs   | 0.2x           | **3x**           |
| 128           | ~2 µs      | ~6 µs    | ~0.3 µs    | 0.3x           | **7x**           |
| 256           | ~8 µs      | ~22 µs   | ~0.65 µs   | 0.4x           | **12x**          |
| 512           | ~30 µs     | ~40 µs   | ~1.2 µs    | 0.8x           | **25x**          |
| 1024          | ~113 µs    | ~86 µs   | ~2.4 µs    | **1.3x**       | **47x**          |
| 2048          | ~438 µs    | ~181 µs  | ~5.1 µs    | **2.4x**       | **86x**          |

### Key Observations

1. **Crossover Point**: NTT becomes faster than schoolbook around d=512-1024
2. **Domain Operations**: Keeping polynomials in NTT domain provides **47-86x speedup** for d≥1024
3. **Transform Overhead**: For small d, the NTT transform overhead dominates

### NTT Transform Overhead

| Dimension (d) | Forward Transform | Inverse Transform |
|---------------|-------------------|-------------------|
| 64            | ~1.5 µs           | ~1.5 µs           |
| 256           | ~7 µs             | ~7 µs             |
| 1024          | ~28 µs            | ~28 µs            |
| 2048          | ~60 µs            | ~60 µs            |
| 4096          | ~130 µs           | ~130 µs           |

### NTT Domain Operations (d=1024)

| Operation    | Time    |
|--------------|---------|
| Addition     | ~1.5 µs |
| Subtraction  | ~1.5 µs |
| Multiplication | ~2.4 µs |
| Scalar Mul   | ~1.5 µs |

## Usage Recommendations

### When to Use NTT

✅ **Use NTT when:**
- Ring dimension d ≥ 512
- Performing many multiplications with the same operand (e.g., secret key)
- Operations can remain in NTT domain (avoiding repeated transforms)

❌ **Avoid NTT when:**
- Ring dimension d < 256
- Only performing a single multiplication
- Transform overhead exceeds multiplication time

### Optimal Pattern

```rust
use std::sync::Arc;
use pir::ntt::NttParams;
use pir::ring::RingElement;

// Precompute NTT parameters once
let params = Arc::new(NttParams::new(1024));

// Convert frequently-used polynomial to NTT domain once
let secret_ntt = secret.to_ntt(params.clone());

// Fast O(n) multiplications in NTT domain
for message in messages {
    let msg_ntt = message.to_ntt(params.clone());
    let result_ntt = secret_ntt.mul(&msg_ntt);  // O(n) instead of O(n²)!
    let result = result_ntt.to_ring_element();
}
```

## Implementation Details

- **Prime**: q = 2013265921 = 15 × 2²⁷ + 1 (NTT-friendly)
- **Max Dimension**: d ≤ 2²⁶ (67 million)
- **Algorithm**: Cooley-Tukey (forward), Gentleman-Sande (inverse)
- **Negacyclic**: Uses ψ twist for mod (x^d + 1) reduction

## Running Benchmarks

```bash
# Run all NTT benchmarks
cargo bench --bench ntt_benchmark

# Run specific benchmark group
cargo bench --bench ntt_benchmark -- polynomial_multiplication
cargo bench --bench ntt_benchmark -- ntt_transform
cargo bench --bench ntt_benchmark -- ntt_domain_ops
```

## Hardware

Results obtained on Apple Silicon (M-series). Actual performance will vary by CPU architecture, cache sizes, and memory bandwidth.

//! NTT (Number Theoretic Transform) Benchmarks
//!
//! Compares schoolbook O(n²) polynomial multiplication vs NTT O(n log n).
//!
//! Run with: `cargo bench --bench ntt_benchmark`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pir::ntt::NttParams;
use pir::ring::RingElement;
use std::sync::Arc;

// ============================================================================
// Polynomial Multiplication: Schoolbook vs NTT
// ============================================================================

/// Benchmark schoolbook O(n²) vs NTT O(n log n) polynomial multiplication.
///
/// Three scenarios are tested:
/// 1. `schoolbook` - Naive O(n²) multiplication
/// 2. `ntt_full` - NTT with transforms included (O(n log n))
/// 3. `ntt_domain_mul` - Just the O(n) point-wise multiply (pre-transformed)
fn bench_polynomial_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("polynomial_multiplication");

    // Test various ring dimensions (typical for lattice crypto)
    for d in [64, 128, 256, 512, 1024, 2048] {
        let mut rng = rand::rng();

        // Create random polynomials
        let a = RingElement::random(d, &mut rng);
        let b = RingElement::random(d, &mut rng);

        // Precompute NTT parameters (done once, reused)
        let ntt_params = NttParams::new(d);
        let ntt_params_arc = Arc::new(NttParams::new(d));

        // Benchmark schoolbook multiplication O(n²)
        group.bench_with_input(
            BenchmarkId::new("schoolbook", d),
            &(&a, &b),
            |bench, (a, b)| {
                bench.iter(|| a.mul(b));
            },
        );

        // Benchmark NTT multiplication (including NTT transforms) O(n log n)
        group.bench_with_input(
            BenchmarkId::new("ntt_full", d),
            &(&a, &b, &ntt_params),
            |bench, (a, b, params)| {
                bench.iter(|| a.mul_ntt(b, params));
            },
        );

        // Benchmark NTT multiplication with pre-transformed operands O(n)
        // This shows the benefit when one operand is reused (e.g., secret key)
        let a_ntt = a.to_ntt(ntt_params_arc.clone());
        let b_ntt = b.to_ntt(ntt_params_arc.clone());

        group.bench_with_input(
            BenchmarkId::new("ntt_domain_mul", d),
            &(&a_ntt, &b_ntt),
            |bench, (a_ntt, b_ntt)| {
                bench.iter(|| a_ntt.mul(b_ntt));
            },
        );
    }

    group.finish();
}

// ============================================================================
// NTT Transform Overhead
// ============================================================================

/// Benchmark NTT forward/inverse transform overhead.
///
/// Shows the cost of converting between coefficient and NTT domains.
fn bench_ntt_transform(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_transform");

    for d in [64, 256, 1024, 2048, 4096] {
        let mut rng = rand::rng();
        let a = RingElement::random(d, &mut rng);
        let ntt_params = Arc::new(NttParams::new(d));

        // Forward transform: coefficient → NTT domain
        group.bench_with_input(
            BenchmarkId::new("forward", d),
            &(&a, &ntt_params),
            |bench, (a, params)| {
                bench.iter(|| a.to_ntt((*params).clone()));
            },
        );

        // Inverse transform: NTT domain → coefficient
        let a_ntt = a.to_ntt(ntt_params.clone());
        group.bench_with_input(BenchmarkId::new("inverse", d), &a_ntt, |bench, a_ntt| {
            bench.iter(|| a_ntt.to_ring_element());
        });
    }

    group.finish();
}

// ============================================================================
// NTT Operations in Domain
// ============================================================================

/// Benchmark various operations when polynomials are kept in NTT domain.
fn bench_ntt_domain_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_domain_ops");

    for d in [256, 1024, 2048] {
        let mut rng = rand::rng();
        let ntt_params = Arc::new(NttParams::new(d));

        let a = RingElement::random(d, &mut rng);
        let b = RingElement::random(d, &mut rng);
        let a_ntt = a.to_ntt(ntt_params.clone());
        let b_ntt = b.to_ntt(ntt_params.clone());

        // Addition in NTT domain
        group.bench_with_input(
            BenchmarkId::new("add", d),
            &(&a_ntt, &b_ntt),
            |bench, (a, b)| {
                bench.iter(|| a.add(b));
            },
        );

        // Subtraction in NTT domain
        group.bench_with_input(
            BenchmarkId::new("sub", d),
            &(&a_ntt, &b_ntt),
            |bench, (a, b)| {
                bench.iter(|| a.sub(b));
            },
        );

        // Multiplication in NTT domain
        group.bench_with_input(
            BenchmarkId::new("mul", d),
            &(&a_ntt, &b_ntt),
            |bench, (a, b)| {
                bench.iter(|| a.mul(b));
            },
        );

        // Scalar multiplication in NTT domain
        group.bench_with_input(
            BenchmarkId::new("scalar_mul", d),
            &(&a_ntt,),
            |bench, (a,)| {
                bench.iter(|| a.scalar_mul(12345));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_polynomial_multiplication,
    bench_ntt_transform,
    bench_ntt_domain_operations,
);
criterion_main!(benches);

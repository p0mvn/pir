use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pir::matrix_database::DoublePirDatabase;
use pir::params::LweParams;
use pir::ypir::{PackingParams, YpirClient, YpirParams, YpirServer};

const RECORD_SIZE: usize = 3;

/// Standard parameters for preprocessing benchmarks (128-bit security).
fn standard_params() -> YpirParams {
    let lwe = LweParams {
        n: 1024,
        p: 256,
        noise_stddev: 6.4,
    };
    let packing = PackingParams {
        ring_dimension: 1024,
        plaintext_modulus: 256,
        noise_stddev: 6.4,
    };
    YpirParams { lwe, packing }
}

/// Smaller parameters for end-to-end benchmarks.
///
/// Packing key generation is O(d² × NUM_DIGITS) RLWE encryptions,
/// so smaller dimensions are needed for reasonable benchmark times.
fn fast_params() -> YpirParams {
    let lwe = LweParams {
        n: 256,
        p: 256,
        noise_stddev: 3.2,
    };
    let packing = PackingParams {
        ring_dimension: 256,
        plaintext_modulus: 256,
        noise_stddev: 3.2,
    };
    YpirParams { lwe, packing }
}

fn create_database(num_records: usize) -> DoublePirDatabase {
    let records: Vec<Vec<u8>> = (0..num_records)
        .map(|i| vec![(i % 256) as u8; RECORD_SIZE])
        .collect();
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    DoublePirDatabase::new(&record_refs, RECORD_SIZE)
}

fn bench_server_preprocessing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ypir_server_preprocessing");

    // YPIR preprocessing is similar to DoublePIR (creates hints)
    for num_records in [1_000, 10_000, 100_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_records),
            &num_records,
            |b, &num_records| {
                let db = create_database(num_records);
                let params = standard_params();
                b.iter(|| {
                    let mut rng = rand::rng();
                    let server = YpirServer::new(db.clone(), &params, &mut rng);
                    server.setup()
                });
            },
        );
    }

    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("ypir_end_to_end");

    // Use smaller parameters for end-to-end because packing key generation
    // is expensive: O(d² × NUM_DIGITS) RLWE encryptions
    for num_records in [100, 1_000, 10_000] {
        let db = create_database(num_records);
        let params = fast_params();
        let mut rng = rand::rng();

        let server = YpirServer::new(db, &params, &mut rng);
        let setup = server.setup();
        let client = YpirClient::new(setup, params);

        group.bench_with_input(
            BenchmarkId::from_parameter(num_records),
            &(server, client),
            |b, (server, client)| {
                b.iter(|| {
                    let mut rng = rand::rng();

                    // Client query (includes packing key generation)
                    let (state, query) = client.query(0, &mut rng);

                    // Server answer (includes LWE-to-RLWE packing)
                    let answer = server.answer(&query);

                    // Client recover (RLWE decryption + row selection)
                    client.recover(&state, &answer)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_server_preprocessing, bench_end_to_end,);
criterion_main!(benches);

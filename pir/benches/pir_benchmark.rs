use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use pir::client::PirClient;
use pir::matrix_database::MatrixDatabase;
use pir::params::LweParams;
use pir::server::PirServer;

const RECORD_SIZE: usize = 3;

fn params() -> LweParams {
    LweParams {
        n: 1024,
        p: 256,
        noise_stddev: 6.4,
    }
}

fn create_database(num_records: usize) -> MatrixDatabase {
    let records: Vec<Vec<u8>> = (0..num_records)
        .map(|i| vec![(i % 256) as u8; RECORD_SIZE])
        .collect();
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    MatrixDatabase::new(&record_refs, RECORD_SIZE)
}

fn bench_server_preprocessing(c: &mut Criterion) {
    let mut group = c.benchmark_group("server_preprocessing");

    for num_records in [1_000, 10_000, 100_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_records),
            &num_records,
            |b, &num_records| {
                let db = create_database(num_records);
                let params = params();
                b.iter(|| {
                    let mut rng = rand::rng();
                    let server = PirServer::new(db.clone(), &params, &mut rng);
                    server.setup_message()
                });
            },
        );
    }

    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");

    for num_records in [1_000, 10_000, 100_000] {
        let db = create_database(num_records);
        let params = params();
        let mut rng = rand::rng();

        let server = PirServer::new(db, &params, &mut rng);
        let setup_msg = server.setup_message();
        let client = PirClient::new(setup_msg, params);

        group.bench_with_input(
            BenchmarkId::from_parameter(num_records),
            &(server, client),
            |b, (server, client)| {
                b.iter(|| {
                    let mut rng = rand::rng();

                    // Client query
                    let (state, query) = client.query(0, &mut rng);

                    // Server answer
                    let answer = server.answer(&query);

                    // Client recover
                    client.recover(&state, &answer)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_server_preprocessing, bench_end_to_end);
criterion_main!(benches);

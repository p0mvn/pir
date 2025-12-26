use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use pir::matrix_database::MatrixDatabase;
use pir::params::LweParams;
use pir::server::PirServer;
use rand::Rng;

/// Paper-like benchmark target:
/// - "1 GB database of 1-bit entries" == 2^33 bits == 2^30 bytes when bit-packed.
/// - We store one *byte* per record (each record encodes 8 one-bit entries).
/// - Total records = 2^30, record_size = 1 → total DB payload = 1 GiB.
///
/// IMPORTANT: This benchmark measures **server online** time only (`answer_into`),
/// not setup/offline preprocessing or any client work.
fn bench_paper_server_online(c: &mut Criterion) {
    let mut group = c.benchmark_group("paper_server_online");
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    // N_bits = 2^33 (paper). We pack 8 bits per byte → N_bytes = 2^30.
    let num_records: usize = 1 << 30;
    let record_size: usize = 1;

    // Paper frequently instantiates q=2^32 for "native" u32 ops; our implementation
    // is naturally mod 2^32 via wrapping arithmetic.
    let params = LweParams {
        n: 1024,
        p: 256,
        noise_stddev: 6.4,
    };

    // Build a 1GiB database without allocating Vec<Vec<u8>>.
    // NOTE: This allocates ~1GiB for DB, plus ~128MiB for A (cols*n*u32),
    // plus output buffer (~128KiB).
    let db = MatrixDatabase::new_generated(num_records, record_size, 0xC0FFEE);
    let db_rows = db.rows;
    let db_cols = db.cols;
    let db_bytes = db.data.len() as u64;

    // Compute communication sizes (paper-style accounting).
    // Offline download: matrix seed (32B) + hint_c (db_rows * n * 4 bytes).
    // Online comm: query (db_cols * 4) + answer (db_rows * 4).
    let offline_bytes = 32u64 + (db_rows as u64) * (params.n as u64) * 4u64;
    let online_query_bytes = (db_cols as u64) * 4u64;
    let online_answer_bytes = (db_rows as u64) * 4u64;
    let online_total_bytes = online_query_bytes + online_answer_bytes;

    eprintln!(
        "[paper_simplepir] db: rows={db_rows}, cols={db_cols}, payload={:.2} GiB",
        (db_bytes as f64) / (1024.0 * 1024.0 * 1024.0)
    );
    eprintln!(
        "[paper_simplepir] comm: offline_download={:.2} MiB, online_query={:.2} KiB, online_answer={:.2} KiB, online_total={:.2} KiB",
        (offline_bytes as f64) / (1024.0 * 1024.0),
        (online_query_bytes as f64) / 1024.0,
        (online_answer_bytes as f64) / 1024.0,
        (online_total_bytes as f64) / 1024.0,
    );

    let mut rng = rand::rng();
    let server = PirServer::new(db, &params, &mut rng);

    // Use a synthetic "ciphertext-like" query: random u32s. Size is √N = 2^15.
    // This avoids including *client* query generation cost in the server-online benchmark.
    let mut query_vec: Vec<u32> = Vec::with_capacity(db_cols);
    for _ in 0..db_cols {
        query_vec.push(rng.random());
    }
    let query = pir::pir::Query(query_vec);

    let mut out = vec![0u32; db_rows];

    group.throughput(Throughput::Bytes(db_bytes));
    group.bench_with_input(
        BenchmarkId::new("1GiB_packed_bits", db_bytes),
        &server,
        |b, server| {
            b.iter(|| {
                server.answer_into(black_box(&query), &mut out);
                black_box(out[0]);
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_paper_server_online);
criterion_main!(benches);



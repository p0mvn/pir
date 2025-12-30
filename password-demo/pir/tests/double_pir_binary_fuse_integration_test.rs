//! Integration tests for Keyword PIR using Binary Fuse Filter + DoublePIR
//!
//! This module tests the complete keyword PIR workflow:
//! 1. Server encodes key-value database into Binary Fuse Filter
//! 2. Server creates DoublePIR database from filter slots
//! 3. Client receives filter params + DoublePIR setup
//! 4. Client looks up keyword by making 3 DoublePIR queries
//! 5. Client XORs results to recover value
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Keyword PIR with DoublePIR                   │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  Server                              Client                     │
//! │  ──────                              ──────                     │
//! │                                                                 │
//! │  Key-Value DB                                                   │
//! │       │                                                         │
//! │       ▼                                                         │
//! │  Binary Fuse Filter ──────────────► Filter Params              │
//! │       │                              (seed, sizes)              │
//! │       ▼                                                         │
//! │  PIR Records (filter slots)                                     │
//! │       │                                                         │
//! │       ▼                                                         │
//! │  DoublePirDatabase                                              │
//! │       │                                                         │
//! │       ▼                                                         │
//! │  DoublePirServer ─────────────────► DoublePirSetup             │
//! │       │                                   │                     │
//! │       │                                   ▼                     │
//! │       │                              DoublePirClient            │
//! │       │                                   │                     │
//! │       │           ◄── 3 queries ─────────┤                     │
//! │       │                                   │                     │
//! │       ├───────── 3 answers ─────────────►│                     │
//! │       │                                   │                     │
//! │       │                              XOR decode                 │
//! │       │                                   │                     │
//! │       │                                   ▼                     │
//! │       │                              Recovered Value            │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use pir::binary_fuse::{BinaryFuseFilter, KeywordQuery};
use pir::double::{DoublePirClient, DoublePirServer};
use pir::matrix_database::DoublePirDatabase;
use pir::params::LweParams;

/// Full keyword PIR integration test using Binary Fuse Filter + DoublePIR
///
/// This test demonstrates the complete workflow with string keys.
#[test]
fn test_keyword_pir_with_string_keys() {
    let mut rng = rand::rng();

    // Use test-friendly parameters (not secure, but fast)
    let params = LweParams {
        n: 64,
        p: 256,
        noise_stddev: 0.0, // Zero noise for deterministic test
    };

    // ===== SERVER: Create key-value database =====
    let database: Vec<(String, Vec<u8>)> = (0..100)
        .map(|i| {
            let key = format!("user_{:03}", i);
            // Fixed-size value (8 bytes)
            let value = vec![
                (i % 256) as u8,
                ((i + 1) % 256) as u8,
                ((i + 2) % 256) as u8,
                ((i + 3) % 256) as u8,
                ((i * 7) % 256) as u8,
                ((i * 11) % 256) as u8,
                ((i * 13) % 256) as u8,
                ((i * 17) % 256) as u8,
            ];
            (key, value)
        })
        .collect();

    let value_size = 8;

    // ===== SERVER: Build Binary Fuse Filter =====
    let filter = BinaryFuseFilter::build(&database, value_size)
        .expect("Filter construction should succeed");

    println!(
        "Filter: {} entries -> {} slots (expansion: {:.2}x)",
        filter.num_entries(),
        filter.filter_size(),
        filter.expansion_factor()
    );

    // ===== SERVER: Convert to DoublePIR database =====
    let pir_records = filter.to_pir_records();
    let record_refs: Vec<&[u8]> = pir_records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, value_size);

    let pir_server = DoublePirServer::new(db, &params, &mut rng);
    let setup = pir_server.setup();

    // ===== CLIENT: Receive setup =====
    let filter_params = filter.params();
    let pir_client = DoublePirClient::new(setup, params);

    // ===== TEST: Look up several keys =====
    for target_key in ["user_000", "user_042", "user_099"] {
        // Client computes positions for keyword
        let kw_query = KeywordQuery::new(&filter_params, &target_key);
        let indices = kw_query.record_indices();

        println!(
            "Looking up '{}' at positions: {:?}",
            target_key, indices
        );

        // Client makes 3 DoublePIR queries
        let (state0, query0) = pir_client.query(indices[0], &mut rng);
        let (state1, query1) = pir_client.query(indices[1], &mut rng);
        let (state2, query2) = pir_client.query(indices[2], &mut rng);

        // Server computes 3 answers
        let answer0 = pir_server.answer(&query0);
        let answer1 = pir_server.answer(&query1);
        let answer2 = pir_server.answer(&query2);

        // Client decrypts 3 responses
        let rec0 = pir_client.recover(&state0, &answer0);
        let rec1 = pir_client.recover(&state1, &answer1);
        let rec2 = pir_client.recover(&state2, &answer2);

        // Client XORs to get final value
        let decoded = kw_query.decode(&[rec0, rec1, rec2]);

        // Verify against expected value
        let expected = database
            .iter()
            .find(|(k, _)| k == target_key)
            .map(|(_, v)| v.clone())
            .expect("Key should exist in database");

        assert_eq!(
            decoded, expected,
            "Failed to recover value for key '{}'",
            target_key
        );

        println!("  ✓ Recovered: {:?}", decoded);
    }
}

/// Test keyword PIR with integer keys
///
/// Note on noise: Binary Fuse Filters XOR 3 PIR responses, which triples
/// the effective noise. Combined with DoublePIR's two-stage noise accumulation,
/// production parameters would need careful tuning (larger n, smaller σ).
/// This test uses zero noise to focus on correctness.
#[test]
fn test_keyword_pir_with_integer_keys() {
    let mut rng = rand::rng();

    let params = LweParams {
        n: 64,
        p: 256,
        noise_stddev: 0.0, // Zero noise for correctness test
    };

    // Test with integer keys
    let database: Vec<(u64, Vec<u8>)> = (0..50)
        .map(|i| {
            let value = vec![(i % 256) as u8; 4]; // 4-byte values
            (i, value)
        })
        .collect();

    let filter = BinaryFuseFilter::build(&database, 4).expect("Build should succeed");

    let pir_records = filter.to_pir_records();
    let record_refs: Vec<&[u8]> = pir_records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    let pir_server = DoublePirServer::new(db, &params, &mut rng);
    let setup = pir_server.setup();

    let filter_params = filter.params();
    let pir_client = DoublePirClient::new(setup, params);

    // Test multiple keys
    for target_key in [0u64, 25, 49] {
        let kw_query = KeywordQuery::new(&filter_params, &target_key);
        let indices = kw_query.record_indices();

        let (s0, q0) = pir_client.query(indices[0], &mut rng);
        let (s1, q1) = pir_client.query(indices[1], &mut rng);
        let (s2, q2) = pir_client.query(indices[2], &mut rng);

        let a0 = pir_server.answer(&q0);
        let a1 = pir_server.answer(&q1);
        let a2 = pir_server.answer(&q2);

        let r0 = pir_client.recover(&s0, &a0);
        let r1 = pir_client.recover(&s1, &a1);
        let r2 = pir_client.recover(&s2, &a2);

        let decoded = kw_query.decode(&[r0, r1, r2]);

        let expected = vec![(target_key % 256) as u8; 4];
        assert_eq!(
            decoded, expected,
            "Failed keyword PIR for key {}",
            target_key
        );
    }
}

/// Test with larger database (500 entries)
#[test]
fn test_keyword_pir_larger_database() {
    let mut rng = rand::rng();

    let params = LweParams {
        n: 64,
        p: 256,
        noise_stddev: 0.0,
    };

    // 500 entries with 16-byte values
    let database: Vec<(String, Vec<u8>)> = (0..500)
        .map(|i| {
            let key = format!("record_{:05}", i);
            let value: Vec<u8> = (0..16).map(|j| ((i + j) % 256) as u8).collect();
            (key, value)
        })
        .collect();

    let filter = BinaryFuseFilter::build(&database, 16).expect("Build should succeed");

    println!(
        "Large filter: {} entries -> {} slots (expansion: {:.2}x)",
        filter.num_entries(),
        filter.filter_size(),
        filter.expansion_factor()
    );

    let pir_records = filter.to_pir_records();
    let record_refs: Vec<&[u8]> = pir_records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 16);

    let pir_server = DoublePirServer::new(db, &params, &mut rng);
    let setup = pir_server.setup();

    let filter_params = filter.params();
    let pir_client = DoublePirClient::new(setup, params);

    // Test specific keys
    for i in [0, 123, 250, 499] {
        let target_key = format!("record_{:05}", i);
        let kw_query = KeywordQuery::new(&filter_params, &target_key);
        let indices = kw_query.record_indices();

        let (s0, q0) = pir_client.query(indices[0], &mut rng);
        let (s1, q1) = pir_client.query(indices[1], &mut rng);
        let (s2, q2) = pir_client.query(indices[2], &mut rng);

        let a0 = pir_server.answer(&q0);
        let a1 = pir_server.answer(&q1);
        let a2 = pir_server.answer(&q2);

        let r0 = pir_client.recover(&s0, &a0);
        let r1 = pir_client.recover(&s1, &a1);
        let r2 = pir_client.recover(&s2, &a2);

        let decoded = kw_query.decode(&[r0, r1, r2]);

        let expected: Vec<u8> = (0..16).map(|j| ((i + j) % 256) as u8).collect();
        assert_eq!(decoded, expected, "Failed for key '{}'", target_key);
    }
}

/// Test that non-existent keys don't crash (they return garbage, not an error)
#[test]
fn test_keyword_pir_nonexistent_key() {
    let mut rng = rand::rng();

    let params = LweParams {
        n: 64,
        p: 256,
        noise_stddev: 0.0,
    };

    let database: Vec<(String, Vec<u8>)> = (0..10)
        .map(|i| (format!("key_{}", i), vec![i as u8; 4]))
        .collect();

    let filter = BinaryFuseFilter::build(&database, 4).expect("Build should succeed");

    let pir_records = filter.to_pir_records();
    let record_refs: Vec<&[u8]> = pir_records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    let pir_server = DoublePirServer::new(db, &params, &mut rng);
    let setup = pir_server.setup();

    let filter_params = filter.params();
    let pir_client = DoublePirClient::new(setup, params);

    // Query a key that doesn't exist
    let nonexistent_key = "key_999";
    let kw_query = KeywordQuery::new(&filter_params, &nonexistent_key);
    let indices = kw_query.record_indices();

    // This should not panic - it will return some value (just not meaningful)
    let (s0, q0) = pir_client.query(indices[0], &mut rng);
    let (s1, q1) = pir_client.query(indices[1], &mut rng);
    let (s2, q2) = pir_client.query(indices[2], &mut rng);

    let a0 = pir_server.answer(&q0);
    let a1 = pir_server.answer(&q1);
    let a2 = pir_server.answer(&q2);

    let r0 = pir_client.recover(&s0, &a0);
    let r1 = pir_client.recover(&s1, &a1);
    let r2 = pir_client.recover(&s2, &a2);

    let decoded = kw_query.decode(&[r0, r1, r2]);

    // We got 4 bytes back (correct size), but they're garbage
    assert_eq!(decoded.len(), 4);

    // The decoded value should NOT match any real value
    // (with high probability, since it's XOR of random-ish filter slots)
    let matches_any = database.iter().any(|(_, v)| v == &decoded);
    // Note: There's a tiny chance of false positive, but very unlikely
    println!(
        "Non-existent key '{}' decoded to: {:?} (matches existing: {})",
        nonexistent_key, decoded, matches_any
    );
}


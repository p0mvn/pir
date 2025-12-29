//! Integration tests for SimplePIR protocol
//!
//! Tests the complete flow:
//! 1. Server setup (generate A, compute hint_c = DB · A)
//! 2. Client receives setup message
//! 3. Client generates encrypted query for a specific record
//! 4. Server computes answer = DB · query
//! 5. Client recovers the original record

use pir::client::PirClient;
use pir::matrix_database::MatrixDatabase;
use pir::params::LweParams;
use pir::server::PirServer;

/// Full PIR round-trip with zero noise (deterministic)
#[test]
fn test_pir_round_trip() {
    let mut rng = rand::rng();

    // Use small parameters for testing (not secure, but fast)
    let params = LweParams {
        n: 16, // small LWE dimension
        p: 256,
        noise_stddev: 0.0, // zero noise for deterministic test
    };

    // Create database: 9 records of 3 bytes each
    let records: Vec<Vec<u8>> = vec![
        vec![10, 11, 12], // record 0
        vec![20, 21, 22], // record 1
        vec![30, 31, 32], // record 2
        vec![40, 41, 42], // record 3
        vec![50, 51, 52], // record 4
        vec![60, 61, 62], // record 5
        vec![70, 71, 72], // record 6
        vec![80, 81, 82], // record 7
        vec![90, 91, 92], // record 8
    ];
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = MatrixDatabase::new(&record_refs, 3);

    // === SERVER SETUP ===
    let server = PirServer::new(db, &params, &mut rng);
    let setup_msg = server.setup_message();

    // === CLIENT SETUP ===
    let client = PirClient::new(setup_msg, params);

    // Test retrieving each record
    for target_idx in 0..9 {
        // === CLIENT QUERY ===
        let (state, query) = client.query(target_idx, &mut rng);

        // === SERVER ANSWER ===
        let answer = server.answer(&query);

        // === CLIENT RECOVER ===
        let recovered = client.recover(&state, &answer);

        // Verify we got the correct record
        assert_eq!(
            recovered, records[target_idx],
            "Failed to recover record {target_idx}"
        );
    }
}

/// PIR round-trip with realistic noise
///
/// Tests that the protocol works even with non-zero noise
/// (as long as noise is small enough for correct decryption)
#[test]
fn test_pir_round_trip_with_noise() {
    let mut rng = rand::rng();

    // Parameters with small noise
    let params = LweParams {
        n: 32,
        p: 256,
        noise_stddev: 3.0, // small but non-zero noise
    };

    // Create database: 4 records of 2 bytes each
    let records: Vec<Vec<u8>> = vec![
        vec![100, 101],
        vec![110, 111],
        vec![120, 121],
        vec![130, 131],
    ];
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = MatrixDatabase::new(&record_refs, 2);

    // Server setup
    let server = PirServer::new(db, &params, &mut rng);
    let setup_msg = server.setup_message();

    // Client setup
    let client = PirClient::new(setup_msg, params);

    // Query for record 2
    let target_idx = 2;
    let (state, query) = client.query(target_idx, &mut rng);
    let answer = server.answer(&query);
    let recovered = client.recover(&state, &answer);

    assert_eq!(recovered, vec![120, 121], "Failed with noise");
}

/// Test with larger database (16 records)
#[test]
fn test_pir_larger_database() {
    let mut rng = rand::rng();

    let params = LweParams {
        n: 16,
        p: 256,
        noise_stddev: 0.0,
    };

    // Create 16 records of 4 bytes each
    let records: Vec<Vec<u8>> = (0..16)
        .map(|i| vec![i as u8, (i + 100) as u8, (i + 200) as u8, (i * 2) as u8])
        .collect();
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = MatrixDatabase::new(&record_refs, 4);

    let server = PirServer::new(db, &params, &mut rng);
    let setup_msg = server.setup_message();
    let client = PirClient::new(setup_msg, params);

    // Test a few specific records
    for &target_idx in &[0, 5, 10, 15] {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(
            recovered, records[target_idx],
            "Failed to recover record {target_idx}"
        );
    }
}

/// Test multiple queries with the same client
/// (verifies fresh secrets are used each time)
#[test]
fn test_pir_multiple_queries_same_client() {
    let mut rng = rand::rng();

    let params = LweParams {
        n: 16,
        p: 256,
        noise_stddev: 0.0,
    };

    let records: Vec<Vec<u8>> = vec![
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
        vec![10, 11, 12],
    ];
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = MatrixDatabase::new(&record_refs, 3);

    let server = PirServer::new(db, &params, &mut rng);
    let setup_msg = server.setup_message();
    let client = PirClient::new(setup_msg, params);

    // Query the same record multiple times - should work each time
    for _ in 0..5 {
        let (state, query) = client.query(1, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, vec![4, 5, 6]);
    }

    // Query different records in sequence
    for target_idx in 0..4 {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, records[target_idx]);
    }
}

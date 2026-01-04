//! Integration tests for YPIR protocol
//!
//! Tests the complete YPIR flow:
//! 1. Server setup (DoublePIR setup + ring dimension)
//! 2. Client receives setup data
//! 3. Client generates query (DoublePIR query + packing key)
//! 4. Server computes packed RLWE answer
//! 5. Client decrypts and recovers the original record
//!
//! YPIR = DoublePIR + LWE-to-RLWE packing for compressed responses.

use pir::matrix_database::DoublePirDatabase;
use pir::pir_trait::{CommunicationCost, PirClient as PirClientTrait, PirServer as PirServerTrait};
use pir::ypir::{LweParams, PackingParams, YpirClient, YpirParams, YpirServer};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create test records with deterministic content
fn create_test_records(num_records: usize, record_size: usize) -> Vec<Vec<u8>> {
    (0..num_records)
        .map(|i| {
            (0..record_size)
                .map(|j| ((i * record_size + j) % 256) as u8)
                .collect()
        })
        .collect()
}

/// Create test records with random-looking but reproducible content
fn create_varied_records(num_records: usize, record_size: usize) -> Vec<Vec<u8>> {
    (0..num_records)
        .map(|i| {
            (0..record_size)
                .map(|j| {
                    // Simple hash-like function for varied data
                    let val = (i * 37 + j * 17 + i * j * 7) % 256;
                    val as u8
                })
                .collect()
        })
        .collect()
}

/// Small test parameters (deterministic, fast)
fn test_params_small() -> YpirParams {
    YpirParams {
        lwe: LweParams {
            n: 4,
            p: 256,
            noise_stddev: 0.0,
        },
        packing: PackingParams {
            ring_dimension: 4,
            plaintext_modulus: 256,
            noise_stddev: 0.0,
        },
    }
}

/// Medium test parameters
fn test_params_medium() -> YpirParams {
    YpirParams {
        lwe: LweParams {
            n: 8,
            p: 256,
            noise_stddev: 0.0,
        },
        packing: PackingParams {
            ring_dimension: 8,
            plaintext_modulus: 256,
            noise_stddev: 0.0,
        },
    }
}

/// Larger test parameters (still deterministic)
fn test_params_large() -> YpirParams {
    YpirParams {
        lwe: LweParams {
            n: 16,
            p: 256,
            noise_stddev: 0.0,
        },
        packing: PackingParams {
            ring_dimension: 16,
            plaintext_modulus: 256,
            noise_stddev: 0.0,
        },
    }
}

// ============================================================================
// Basic Round-Trip Tests
// ============================================================================

/// Full YPIR round-trip with zero noise (deterministic)
#[test]
fn test_ypir_round_trip() {
    let mut rng = rand::rng();
    let params = test_params_small();

    // Create database: 9 records of 4 bytes each
    let records = create_test_records(9, 4);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    // Server setup
    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();

    // Client setup
    let client = YpirClient::new(setup, params);

    // Test retrieving each record
    for target_idx in 0..9 {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(
            recovered, records[target_idx],
            "Failed to recover record {}: expected {:?}, got {:?}",
            target_idx, records[target_idx], recovered
        );
    }
}

/// YPIR round-trip via trait interface
#[test]
fn test_ypir_round_trip_via_traits() {
    let mut rng = rand::rng();
    let params = test_params_small();

    let records = create_test_records(9, 4);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    // Use trait interface explicitly
    let server = YpirServer::new(db, &params, &mut rng);
    let setup = <YpirServer as PirServerTrait>::setup(&server);
    let client = <YpirClient as PirClientTrait>::from_setup(setup, params.lwe);

    for target_idx in 0..9 {
        let (state, query) = <YpirClient as PirClientTrait>::query(&client, target_idx, &mut rng);
        let answer = <YpirServer as PirServerTrait>::answer(&server, &query);
        let recovered = <YpirClient as PirClientTrait>::recover(&client, &state, &answer);

        assert_eq!(recovered, records[target_idx]);
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test with a single record
#[test]
fn test_ypir_single_record() {
    let mut rng = rand::rng();
    let params = test_params_small();

    let records = vec![vec![42u8, 43, 44, 45]];
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    let (state, query) = client.query(0, &mut rng);
    let answer = server.answer(&query);
    let recovered = client.recover(&state, &answer);

    assert_eq!(recovered, records[0]);
}

/// Test with non-square number of records (padding case)
#[test]
fn test_ypir_non_square_records() {
    let mut rng = rand::rng();
    let params = test_params_small();

    // 7 records (not a perfect square)
    let records = create_test_records(7, 4);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    for target_idx in 0..7 {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(
            recovered, records[target_idx],
            "Failed for non-square DB at index {}",
            target_idx
        );
    }
}

/// Test with single-byte records
#[test]
fn test_ypir_single_byte_records() {
    let mut rng = rand::rng();
    let params = test_params_small();

    let records: Vec<Vec<u8>> = (0..9).map(|i| vec![i as u8 * 10]).collect();
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 1);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    for target_idx in 0..9 {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(recovered, records[target_idx]);
    }
}

/// Test with first and last records (boundary conditions)
#[test]
fn test_ypir_boundary_records() {
    let mut rng = rand::rng();
    let params = test_params_medium();

    let records = create_test_records(16, 8);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 8);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    // First record
    let (state, query) = client.query(0, &mut rng);
    let answer = server.answer(&query);
    let recovered = client.recover(&state, &answer);
    assert_eq!(recovered, records[0], "Failed for first record");

    // Last record
    let (state, query) = client.query(15, &mut rng);
    let answer = server.answer(&query);
    let recovered = client.recover(&state, &answer);
    assert_eq!(recovered, records[15], "Failed for last record");
}

// ============================================================================
// Scale Tests
// ============================================================================

/// Test with larger database (25 records)
#[test]
fn test_ypir_larger_database() {
    let mut rng = rand::rng();
    let params = test_params_medium();

    let records = create_test_records(25, 8);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 8);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    // Test a selection of records
    for &target_idx in &[0, 5, 12, 18, 24] {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(
            recovered, records[target_idx],
            "Failed for larger DB at index {}",
            target_idx
        );
    }
}

/// Test with larger records
#[test]
fn test_ypir_larger_records() {
    let mut rng = rand::rng();
    let params = test_params_large();

    let records = create_test_records(16, 32);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 32);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    for &target_idx in &[0, 7, 15] {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(recovered, records[target_idx]);
    }
}

// ============================================================================
// Multiple Query Tests
// ============================================================================

/// Test multiple queries with the same client
#[test]
fn test_ypir_multiple_queries_same_client() {
    let mut rng = rand::rng();
    let params = test_params_small();

    let records = create_test_records(9, 4);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    // Query the same record multiple times
    for _ in 0..5 {
        let (state, query) = client.query(4, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, records[4]);
    }

    // Query different records in sequence
    for target_idx in 0..9 {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, records[target_idx]);
    }
}

/// Test interleaved queries for different records
#[test]
fn test_ypir_interleaved_queries() {
    let mut rng = rand::rng();
    let params = test_params_small();

    let records = create_test_records(9, 4);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    // Interleaved access pattern
    let access_pattern = [0, 8, 1, 7, 2, 6, 3, 5, 4];
    for &target_idx in &access_pattern {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, records[target_idx]);
    }
}

// ============================================================================
// Data Pattern Tests
// ============================================================================

/// Test with all-zeros records
#[test]
fn test_ypir_zero_records() {
    let mut rng = rand::rng();
    let params = test_params_small();

    let records: Vec<Vec<u8>> = (0..9).map(|_| vec![0u8; 4]).collect();
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    for target_idx in 0..9 {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, vec![0u8; 4]);
    }
}

/// Test with all-255 records
#[test]
fn test_ypir_max_value_records() {
    let mut rng = rand::rng();
    let params = test_params_small();

    let records: Vec<Vec<u8>> = (0..9).map(|_| vec![255u8; 4]).collect();
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 4);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    for target_idx in 0..9 {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);
        assert_eq!(recovered, vec![255u8; 4]);
    }
}

/// Test with varied/pseudo-random data
#[test]
fn test_ypir_varied_data() {
    let mut rng = rand::rng();
    let params = test_params_medium();

    let records = create_varied_records(16, 8);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 8);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    for target_idx in 0..16 {
        let (state, query) = client.query(target_idx, &mut rng);
        let answer = server.answer(&query);
        let recovered = client.recover(&state, &answer);

        assert_eq!(
            recovered, records[target_idx],
            "Failed for varied data at index {}",
            target_idx
        );
    }
}

// ============================================================================
// Communication Cost Tests
// ============================================================================

/// Test that communication costs are computed correctly
#[test]
fn test_ypir_communication_costs() {
    let mut rng = rand::rng();
    let params = test_params_medium();

    let records = create_test_records(16, 8);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 8);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();

    // Get setup size before moving setup into client
    let setup_size = setup.size_bytes();
    assert!(setup_size > 0, "Setup size should be positive");

    let client = YpirClient::new(setup, params);

    let (_, query) = client.query(0, &mut rng);
    let answer = server.answer(&query);

    // Query should have non-zero size
    let query_size = query.size_bytes();
    assert!(query_size > 0, "Query size should be positive");

    // Answer should have non-zero size
    let answer_size = answer.size_bytes();
    assert!(answer_size > 0, "Answer size should be positive");

    println!("Communication costs:");
    println!("  Setup: {} bytes", setup_size);
    println!("  Query: {} bytes", query_size);
    println!("  Answer: {} bytes", answer_size);
}

/// Test YPIR compression: answer should be much smaller than raw data
#[test]
fn test_ypir_compression_benefit() {
    let mut rng = rand::rng();
    let params = test_params_large();

    let record_size = 32;
    let records = create_test_records(16, record_size);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, record_size);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    let (_, query) = client.query(0, &mut rng);
    let answer = server.answer(&query);

    let answer_size = answer.size_bytes();

    // Calculate expected answer size for this configuration
    // With d=16, num_rows=4, record_size=32:
    // total_cts = 4 * 32 = 128
    // num_packed = ceil(128/16) = 8
    // expected_size = 8 * 2 * 16 * 4 = 1024 bytes
    let d = params.packing.ring_dimension;
    let num_rows = 4; // sqrt(16)
    let total_cts = num_rows * record_size;
    let num_packed = total_cts.div_ceil(d);
    let expected_size = num_packed * 2 * d * 4;

    assert_eq!(
        answer_size, expected_size,
        "Answer size mismatch: got {}, expected {}",
        answer_size, expected_size
    );

    println!(
        "Compression test: {} ciphertexts packed into {} RLWE ({} bytes)",
        total_cts, num_packed, answer_size
    );
}

// ============================================================================
// Accessor Tests
// ============================================================================

/// Test client/server accessor methods
#[test]
fn test_ypir_accessors() {
    let mut rng = rand::rng();
    let params = test_params_medium();

    let num_records = 16;
    let record_size = 8;
    let records = create_test_records(num_records, record_size);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, record_size);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    // Server accessors
    assert_eq!(server.num_records(), num_records);
    assert_eq!(server.record_size(), record_size);
    assert_eq!(server.ring_dimension(), params.packing.ring_dimension);
    assert_eq!(server.lwe_dimension(), params.lwe.n);

    // Client accessors
    assert_eq!(client.num_records(), num_records);
    assert_eq!(client.record_size(), record_size);
    assert_eq!(client.ring_dimension(), params.packing.ring_dimension);
    assert_eq!(client.lwe_dimension(), params.lwe.n);

    // Trait-based accessors
    assert_eq!(
        <YpirServer as PirServerTrait>::num_records(&server),
        num_records
    );
    assert_eq!(
        <YpirServer as PirServerTrait>::record_size(&server),
        record_size
    );
    assert_eq!(
        <YpirClient as PirClientTrait>::num_records(&client),
        num_records
    );
    assert_eq!(
        <YpirClient as PirClientTrait>::record_size(&client),
        record_size
    );
}

/// Test setup data accessors
#[test]
fn test_ypir_setup_accessors() {
    let mut rng = rand::rng();
    let params = test_params_medium();

    let num_records = 16;
    let record_size = 8;
    let records = create_test_records(num_records, record_size);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, record_size);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();

    assert_eq!(setup.num_records(), num_records);
    assert_eq!(setup.record_size(), record_size);
    assert_eq!(setup.ring_dim, params.packing.ring_dimension);
    assert_eq!(setup.lwe_dim(), params.lwe.n);
}

/// Test answer accessors
#[test]
fn test_ypir_answer_accessors() {
    let mut rng = rand::rng();
    let params = test_params_medium();

    let records = create_test_records(16, 8);
    let record_refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let db = DoublePirDatabase::new(&record_refs, 8);

    let server = YpirServer::new(db, &params, &mut rng);
    let setup = server.setup();
    let client = YpirClient::new(setup, params);

    let (_, query) = client.query(0, &mut rng);
    let answer = server.answer(&query);

    // Should have at least one ciphertext
    assert!(answer.num_ciphertexts() > 0);
    assert_eq!(answer.num_ciphertexts(), answer.packed_cts.len());
}

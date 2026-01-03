# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Rust implementation of Private Information Retrieval (PIR) protocols built from first principles. PIR allows clients to retrieve records from a database without revealing which record they're accessing.

**Implemented Protocols:**
- **SimplePIR**: High-throughput single-server PIR using Regev encryption (~10 GB/s/core)
- **DoublePIR**: Compressed hints via "PIR over PIR" (~16 MB hint vs ~121 MB)
- **YPIR**: DoublePIR + LWE-to-RLWE packing for 1000× response compression
- **Keyword PIR**: Key-value lookups via Binary Fuse filters

## Build and Test Commands

```bash
# Build all crates
cargo build --release

# Run all tests
cargo test

# Run tests for specific crate
cargo test -p pir
cargo test -p ypir

# Run a single test
cargo test -p pir test_simple_pir_via_trait

# Run benchmarks (Criterion)
cargo bench

# Run specific benchmark
cargo bench --bench pir_benchmark
cargo bench --bench ntt_benchmark

# Check compilation without building
cargo check
```

## Workspace Structure

```
pir/                    # Core PIR protocols (main crate)
├── src/
│   ├── simple/        # SimplePIR client/server
│   ├── double/        # DoublePIR client/server/hint
│   ├── regev.rs       # Regev (LWE) encryption
│   ├── ring_regev.rs  # Ring-LWE encryption
│   ├── ring.rs        # RLWE ring arithmetic
│   ├── ntt.rs         # Number Theoretic Transform (O(n log n) polynomial multiplication)
│   ├── lwe_to_rlwe.rs # LWE-to-RLWE packing for response compression
│   ├── binary_fuse.rs # Binary Fuse filters for keyword PIR
│   ├── matrix_database.rs  # √N × √N database matrix storage
│   ├── params.rs      # LWE security parameters
│   └── pir_trait.rs   # Generic PirProtocol trait
│
ypir/                   # YPIR protocol (DoublePIR + packing)
├── src/
│   ├── client.rs      # Query generation, response decryption
│   ├── params.rs      # Dual parameter sets (scan + packing)
│   └── lib.rs         # Protocol types and trait impl
│
password-demo/          # HIBP password checker application
├── server/            # Actix-web Rust backend
├── ui/                # Next.js frontend (Vercel)
├── pir-wasm/          # WebAssembly bindings
└── hibp/              # HIBP dataset processing
```

## Architecture

### Protocol Hierarchy

All PIR protocols implement `PirProtocol` trait (`pir/src/pir_trait.rs`):

```
PirProtocol trait
├── SimplePIR  - Fast database scan, large responses
├── DoublePIR  - Small hints via nested PIR
└── YPIR       - DoublePIR + RLWE packing for compressed responses
```

### Key Abstractions

- **PirClient/PirServer traits**: Common interface for query generation, answering, and recovery
- **MatrixDatabase**: Stores N records as √N × √N matrix for O(√N) communication
- **LweParams**: Security parameters (n=1024, q=2^32 for 128-bit security)

### Core Cryptographic Flow

1. **Setup**: Server computes hint `H = DB × A` where A is LWE matrix (from seed)
2. **Query**: Client encrypts column selector via Regev: `q = A·s + e + Δ·u_col`
3. **Answer**: Server computes `DB × q` (matrix-vector multiply)
4. **Recover**: Client decrypts using hint to extract `DB[row, col]`

### Performance Design

SimplePIR achieves ~10 GB/s throughput (81% of memory bandwidth) through:
- **u32 arithmetic**: Fits in CPU cache, native word size
- **ChaCha20 PRG**: Regenerate matrix A from 32-byte seed
- **NTT acceleration**: O(n log n) polynomial multiplication in `ntt.rs`
- **Rayon parallelization**: Only for hint computation (overhead exceeds benefit for online ops)

### Response Compression (YPIR)

YPIR reduces DoublePIR responses by ~1000×:
- DoublePIR answer: `record_size × (n+1) × 4` bytes
- YPIR answer: `ceil(record_size/d) × 2d × 4` bytes

Achieved via LWE-to-RLWE packing (`lwe_to_rlwe.rs`): pack d LWE ciphertexts into 1 RLWE ciphertext.

## Key Implementation Details

### Security Parameters (`params.rs`)
- LWE dimension n = 1024
- Modulus q = 2^32 (fits in u32)
- Noise distribution χ = discrete Gaussian

### Database Layout
Records stored as √N × √N matrix. To fetch record (row, col):
1. Query encrypts column selector
2. Server multiplies DB × query → encrypted column
3. Client extracts desired row from decrypted column

### Keyword PIR (`binary_fuse.rs`)
Uses Binary Fuse filters for sparse key-value encoding. Three constructions in `docs/keyword-pir.md`:
- KPIRkvs: Direct key-value storage
- KPIRhash: Hash-based mapping
- KPIRindex: Index-based lookup

## Theory Documentation

- `simple-pir-theory.md` - Kushilevitz-Ostrovsky framework, performance analysis
- `lattice-crypto.md` - LWE/SIS hardness, Regev encryption fundamentals
- `ypir-theory.md` - LWE-to-RLWE packing, compression analysis
- `docs/keyword-pir.md` - Keyword PIR constructions

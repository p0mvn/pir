# Benchmark 005: Paper-like SimplePIR (1GiB, 1-bit entries)

**Date:** 2025-12-25  
**Goal:** Match the SimplePIR paper’s experiment style as closely as possible in this codebase  
**Hardware:** (fill in — should match the machine running `cargo bench`)

## What “1GiB of 1-bit entries” means

The paper’s table describes a database of **\(2^{33}\)** 1-bit entries.

- That is **\(2^{33}\) bits = \(2^{30}\) bytes = 1 GiB** when bit-packed.
- This repo models that by storing **one byte per record**, where each byte packs 8 one-bit entries.

So the benchmark uses:

- `num_records = 2^30`
- `record_size = 1`
- Matrix layout: `cols = sqrt(num_records) = 2^15 = 32768`, `rows = 32768`

## What we measure (paper-comparable)

The paper’s “~10 GB/s/core” is **server online throughput**. To match that:

- We benchmark **only** the server’s online routine (`answer_into`), i.e. the DB scan `DB · query`.
- We **exclude** offline preprocessing (`compute_hint`) and any client work.

This benchmark is implemented in `benches/paper_simplepir.rs`.

## Communication sizes (paper-style accounting)

For this 1GiB setup with `n=1024`:

- **Offline download** (server → client during setup):  
  - matrix seed: 32 B  
  - `hint_c`: `rows * n * 4` bytes  
  - total: `32 + 32768 * 1024 * 4` = **134,217,760 B ≈ 128.0 MiB**

- **Online communication** (per query):  
  - query: `cols * 4` = `32768 * 4` = **131,072 B = 128 KiB**
  - answer: `rows * 4` = `32768 * 4` = **131,072 B = 128 KiB**
  - total: **256 KiB**

This is in the same ballpark as the paper’s reported **121 MB offline** and **242 KB online** (the remaining gap is mostly accounting/serialization details and exact parameterization).

## Comparison to paper (Table 8, experiment E1)

Paper-reported values (E1, 1 GB DB of \(2^{33}\) 1-bit entries):

- Throughput: **~10 GB/s/core**
- Offline download: **121 MB**
- Online communication: **242 KB**

This repo’s run (`cargo bench --bench paper_simplepir`, server-online only) produced:

| Metric | Paper | This repo | Notes |
|--------|-------|-----------|-------|
| Throughput | ~10 **GB/s/core** (~9.31 GiB/s) | **13.78 GiB/s** (~14.79 GB/s) | Different hardware; also GB vs GiB units differ |
| Offline download | **121 MB** | **128 MiB** (134.2 MB) | Partly explained by **1 GiB vs 1 GB** database sizing and exact parameter/serialization choices |
| Online comm | **242 KB** | **256 KiB** (262.1 KB) | Partly explained by **GB vs GiB** and size/accounting conventions |

Why the comm numbers aren’t identical:

- The paper says “**1 GB**” (decimal). This benchmark uses **1 GiB** (binary). That alone is a **~7.4%** DB-size difference, and comm scales with \(\sqrt{N}\), so you expect a **~3.6%** bump in online/offline sizes from that factor alone.
- The remaining gap is typically due to parameterization details (exact `n`, `p`, and packing choices) and whether sizes are counted in decimal (MB/KB) vs binary (MiB/KiB), plus serialization overheads in a full system.

## How to run

Run the dedicated paper-like benchmark:

```bash
cargo bench --bench paper_simplepir
```

Notes:
- This allocates ~**1 GiB** for the database payload, plus ~**128 MiB** for the PRG-generated matrix `A` (`cols * n * 4` bytes).
- For “per-core” comparability, run with CPU pinning / single-thread settings on the host OS.

## What still differs from the paper

- We use `q = 2^32` implicitly (wrapping `u32` arithmetic), matching one of the paper’s supported “native” moduli.
- We do **not** yet implement the paper’s full parameter-selection pipeline (hardness-estimator-driven choice of `(n, χ, p)` for a given `(N, δ, T, ε)`).
- The benchmark uses a synthetic “ciphertext-like” query vector (random `u32`s) to avoid including client query generation cost in server-online timing.



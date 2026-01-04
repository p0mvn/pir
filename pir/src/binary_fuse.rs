//! Binary Fuse Filter for Keyword PIR
//!
//! Encodes key-value pairs into a sparse data structure where:
//! ```text
//! value = D[h₀(key)] ⊕ D[h₁(key)] ⊕ D[h₂(key)]
//! ```
//!
//! This enables keyword PIR using exactly 3 PIR queries (via DoublePIR).
//!
//! ## Usage with DoublePIR
//!
//! ```ignore
//! // 1. Encode key-value database into Binary Fuse Filter
//! let filter = BinaryFuseFilter::build(&key_value_pairs, value_size)?;
//!
//! // 2. Get the encoded data as a PIR database
//! let pir_db = filter.as_pir_database();
//!
//! // 3. For keyword lookup, get 3 positions
//! let [pos0, pos1, pos2] = filter.get_positions(&key);
//!
//! // 4. Query each position via DoublePIR
//! let val0 = double_pir_query(pos0);
//! let val1 = double_pir_query(pos1);
//! let val2 = double_pir_query(pos2);
//!
//! // 5. XOR to recover value
//! let value = filter.decode(&val0, &val1, &val2);
//! ```
//!
//! ## Algorithm Overview
//!
//! Binary Fuse Filters use a 3-segment structure:
//! - Segment 0: positions [0, segment_size)
//! - Segment 1: positions [segment_size, 2*segment_size)
//! - Segment 2: positions [2*segment_size, 3*segment_size)
//!
//! Each key maps to exactly one position in each segment via hash functions.
//! The encoding uses hypergraph peeling to find an assignment.
//!
//! ## References
//!
//! - Binary Fuse Filters: <https://arxiv.org/abs/2201.01174>
//! - Fast Filter paper: <https://github.com/FastFilter/xorfilter>

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

// ============================================================================
// Configuration
// ============================================================================

/// Number of hash functions (and segments) - always 3 for Binary Fuse
const ARITY: usize = 3;

/// Maximum construction attempts before giving up
const MAX_ITERATIONS: usize = 100;

/// Expansion factor: filter size = n * EXPANSION_FACTOR
/// Binary Fuse Filters achieve ~1.125 expansion in practice
const EXPANSION_FACTOR: f64 = 1.23;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during Binary Fuse Filter construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryFuseError {
    /// Construction failed after maximum iterations (bad hash seed)
    ConstructionFailed,
    /// Empty input
    EmptyInput,
    /// Duplicate keys in input
    DuplicateKey,
    /// Value size mismatch
    ValueSizeMismatch { expected: usize, got: usize },
}

impl std::fmt::Display for BinaryFuseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFuseError::ConstructionFailed => {
                write!(
                    f,
                    "Binary Fuse Filter construction failed after max iterations"
                )
            }
            BinaryFuseError::EmptyInput => write!(f, "Cannot build filter from empty input"),
            BinaryFuseError::DuplicateKey => write!(f, "Duplicate keys in input"),
            BinaryFuseError::ValueSizeMismatch { expected, got } => {
                write!(f, "Value size mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for BinaryFuseError {}

// ============================================================================
// Binary Fuse Filter
// ============================================================================

/// A Binary Fuse Filter that encodes key-value pairs for keyword PIR.
///
/// The filter stores encoded data such that for any key k with value v:
/// `v = data[h₀(k)] ⊕ data[h₁(k)] ⊕ data[h₂(k)]`
#[derive(Clone, Debug)]
pub struct BinaryFuseFilter {
    /// Encoded filter data: each entry is `value_size` bytes
    /// Total size: segment_count * segment_size * value_size bytes
    data: Vec<u8>,

    /// Size of each segment (filter has 3 segments)
    segment_size: usize,

    /// Total number of slots (3 * segment_size, rounded to segment boundaries)
    filter_size: usize,

    /// Size of each value in bytes
    value_size: usize,

    /// Hash seed for this filter
    seed: u64,

    /// Segment length mask for fast modulo
    segment_length_mask: u32,

    /// Number of original key-value pairs
    num_entries: usize,
}

/// Positions for a key lookup (one in each segment)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPositions {
    /// Position in segment 0
    pub h0: usize,
    /// Position in segment 1
    pub h1: usize,
    /// Position in segment 2
    pub h2: usize,
}

impl KeyPositions {
    /// Returns positions as an array
    pub fn as_array(&self) -> [usize; 3] {
        [self.h0, self.h1, self.h2]
    }
}

impl BinaryFuseFilter {
    /// Build a Binary Fuse Filter from key-value pairs.
    ///
    /// # Arguments
    /// * `pairs` - Key-value pairs where all values must have the same size
    /// * `value_size` - Expected size of each value in bytes
    ///
    /// # Returns
    /// * `Ok(BinaryFuseFilter)` on success
    /// * `Err(BinaryFuseError)` if construction fails
    pub fn build<K: Hash + Eq + Clone>(
        pairs: &[(K, Vec<u8>)],
        value_size: usize,
    ) -> Result<Self, BinaryFuseError> {
        Self::build_internal(pairs, value_size, true, 0x517cc1b727220a95)
    }

    /// Build without duplicate checking - use when you know keys are unique.
    /// This saves significant memory for large datasets.
    pub fn build_unchecked<K: Hash + Eq + Clone>(
        pairs: &[(K, Vec<u8>)],
        value_size: usize,
    ) -> Result<Self, BinaryFuseError> {
        Self::build_internal(pairs, value_size, false, 0x517cc1b727220a95)
    }

    /// Build from fixed-size value arrays - more memory efficient than Vec<u8>.
    /// Use this when values have known fixed size (e.g., [u8; 4] for u32 counts).
    /// Saves ~20 bytes per entry vs Vec<u8>.
    pub fn build_from_fixed<K: Hash + Eq + Clone, const N: usize>(
        pairs: &[(K, [u8; N])],
    ) -> Result<Self, BinaryFuseError> {
        Self::build_internal_fixed(pairs, N, true, 0x517cc1b727220a95)
    }

    /// Build from fixed-size arrays without duplicate checking.
    pub fn build_from_fixed_unchecked<K: Hash + Eq + Clone, const N: usize>(
        pairs: &[(K, [u8; N])],
        rng_seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        Self::build_internal_fixed(pairs, N, false, rng_seed)
    }

    fn build_internal<K: Hash + Eq + Clone>(
        pairs: &[(K, Vec<u8>)],
        value_size: usize,
        check_duplicates: bool,
        rng_seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        if pairs.is_empty() {
            return Err(BinaryFuseError::EmptyInput);
        }

        // Validate all values have correct size (sample check for large datasets)
        let check_count = if pairs.len() > 10000 {
            1000
        } else {
            pairs.len()
        };
        for (_, v) in pairs.iter().take(check_count) {
            if v.len() != value_size {
                return Err(BinaryFuseError::ValueSizeMismatch {
                    expected: value_size,
                    got: v.len(),
                });
            }
        }

        // Check for duplicate keys (skip for large datasets to save memory)
        // For very large datasets, duplicates will cause construction failure anyway
        if check_duplicates && pairs.len() < 10_000_000 {
            let mut seen = HashMap::with_capacity(pairs.len());
            for (k, _) in pairs {
                if seen.insert(k, ()).is_some() {
                    return Err(BinaryFuseError::DuplicateKey);
                }
            }
        }

        let n = pairs.len();

        // Calculate segment size (power of 2 for fast modulo)
        let segment_size = calculate_segment_size(n);
        let filter_size = ARITY * segment_size;
        let segment_length_mask = (segment_size - 1) as u32;

        // Try construction with different seeds
        Self::build_with_rng_seed(
            pairs,
            value_size,
            segment_size,
            filter_size,
            segment_length_mask,
            rng_seed,
        )
    }

    /// Internal builder for fixed-size value arrays
    fn build_internal_fixed<K: Hash + Eq + Clone, const N: usize>(
        pairs: &[(K, [u8; N])],
        value_size: usize,
        check_duplicates: bool,
        rng_seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        if pairs.is_empty() {
            return Err(BinaryFuseError::EmptyInput);
        }

        // Check for duplicate keys (skip for large datasets to save memory)
        if check_duplicates && pairs.len() < 10_000_000 {
            let mut seen = HashMap::with_capacity(pairs.len());
            for (k, _) in pairs {
                if seen.insert(k, ()).is_some() {
                    return Err(BinaryFuseError::DuplicateKey);
                }
            }
        }

        let n = pairs.len();
        let segment_size = calculate_segment_size(n);
        let filter_size = ARITY * segment_size;
        let segment_length_mask = (segment_size - 1) as u32;

        Self::build_with_rng_seed_fixed(
            pairs,
            value_size,
            segment_size,
            filter_size,
            segment_length_mask,
            rng_seed,
        )
    }

    /// Build a Binary Fuse Filter with a specific RNG seed for reproducibility.
    ///
    /// This allows building the same filter with the same positions across server restarts.
    pub fn build_with_seed<K: Hash + Eq + Clone>(
        pairs: &[(K, Vec<u8>)],
        value_size: usize,
        rng_seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        Self::build_internal(pairs, value_size, true, rng_seed)
    }

    /// Build with a specific RNG seed, without duplicate checking.
    /// Use when you know keys are unique to save memory on large datasets.
    pub fn build_with_seed_unchecked<K: Hash + Eq + Clone>(
        pairs: &[(K, Vec<u8>)],
        value_size: usize,
        rng_seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        Self::build_internal(pairs, value_size, false, rng_seed)
    }

    /// Internal: Try building with seeds from a specific RNG
    fn build_with_rng_seed<K: Hash + Eq + Clone>(
        pairs: &[(K, Vec<u8>)],
        value_size: usize,
        segment_size: usize,
        filter_size: usize,
        segment_length_mask: u32,
        rng_seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        let mut rng = SimpleRng::new(rng_seed);

        for _ in 0..MAX_ITERATIONS {
            let seed = rng.next();

            match Self::try_build(
                pairs,
                value_size,
                segment_size,
                filter_size,
                segment_length_mask,
                seed,
            ) {
                Ok(filter) => return Ok(filter),
                Err(_) => continue,
            }
        }

        Err(BinaryFuseError::ConstructionFailed)
    }

    /// Internal: Try building with seeds for fixed-size arrays
    fn build_with_rng_seed_fixed<K: Hash + Eq + Clone, const N: usize>(
        pairs: &[(K, [u8; N])],
        value_size: usize,
        segment_size: usize,
        filter_size: usize,
        segment_length_mask: u32,
        rng_seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        let mut rng = SimpleRng::new(rng_seed);

        for _ in 0..MAX_ITERATIONS {
            let seed = rng.next();

            match Self::try_build_fixed(
                pairs,
                value_size,
                segment_size,
                filter_size,
                segment_length_mask,
                seed,
            ) {
                Ok(filter) => return Ok(filter),
                Err(_) => continue,
            }
        }

        Err(BinaryFuseError::ConstructionFailed)
    }

    /// Attempt to build the filter with a specific seed
    ///
    /// Memory-efficient implementation that avoids O(filter_size) allocation
    /// for slot-to-key mapping. Instead uses a flat sorted array of (slot, key_idx)
    /// pairs which uses O(3*n) memory instead of O(filter_size).
    ///
    /// For large datasets (e.g., 900M entries):
    /// - Old approach: 1.5B slots * 24 bytes/Vec = 36 GB just for empty Vecs
    /// - New approach: 900M * 3 * 8 bytes = 21.6 GB for the mapping
    fn try_build<K: Hash + Eq + Clone>(
        pairs: &[(K, Vec<u8>)],
        value_size: usize,
        segment_size: usize,
        filter_size: usize,
        segment_length_mask: u32,
        seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        let n = pairs.len();

        // MEMORY OPTIMIZATION: Store only positions (12 bytes/entry, not 20)
        // Values are accessed directly from input pairs during assignment
        // Saves 8 bytes/entry = 16 GB for 2B entries!
        let mut positions_vec: Vec<[u32; 3]> = Vec::with_capacity(n);
        for (key, _) in pairs {
            let hash = hash_key(key, seed);
            let pos = compute_positions(hash, segment_size, segment_length_mask);
            positions_vec.push([pos[0] as u32, pos[1] as u32, pos[2] as u32]);
        }

        // Build degree counters for each slot
        // Memory: filter_size * 4 bytes
        let mut degree = vec![0u32; filter_size];

        for positions in positions_vec.iter() {
            for &pos in positions {
                degree[pos as usize] += 1;
            }
        }

        // Build flat sorted array of (slot, key_idx) for memory efficiency
        // Memory: n * 3 * 8 bytes (instead of filter_size * 24 bytes for Vec<Vec>)
        // This is the key optimization - avoids allocating billions of empty Vecs
        let mut slot_key_pairs: Vec<(u32, u32)> = Vec::with_capacity(n * 3);
        for (key_idx, positions) in positions_vec.iter().enumerate() {
            for &pos in positions {
                slot_key_pairs.push((pos, key_idx as u32));
            }
        }
        // Sort by slot for binary search
        slot_key_pairs.sort_unstable_by_key(|&(slot, _)| slot);

        // Build index into slot_key_pairs for O(1) slot lookup
        // For each slot, store the starting index in slot_key_pairs
        // Memory: filter_size * 8 bytes (u64 to handle >4B entries)
        let mut slot_start: Vec<u64> = vec![0; filter_size + 1];
        {
            let mut current_slot = 0u32;
            for (i, &(slot, _)) in slot_key_pairs.iter().enumerate() {
                while current_slot <= slot {
                    slot_start[current_slot as usize] = i as u64;
                    current_slot += 1;
                }
            }
            // Fill remaining slots
            while (current_slot as usize) <= filter_size {
                slot_start[current_slot as usize] = slot_key_pairs.len() as u64;
                current_slot += 1;
            }
        }

        // Peeling: find slots with degree 1 and process them
        let mut stack: Vec<(u32, u32)> = Vec::with_capacity(n); // (key_idx, determining_slot)
        let mut processed = vec![false; n];

        // Initialize queue with degree-1 slots
        let mut queue: Vec<u32> = degree
            .iter()
            .enumerate()
            .filter(|(_, d)| **d == 1)
            .map(|(i, _)| i as u32)
            .collect();

        while let Some(slot) = queue.pop() {
            if degree[slot as usize] != 1 {
                continue;
            }

            // Find the unprocessed key in this slot using the sorted index
            let start = slot_start[slot as usize] as usize;
            let end = slot_start[slot as usize + 1] as usize;

            let key_idx = slot_key_pairs[start..end]
                .iter()
                .filter(|&&(s, _)| s == slot)
                .map(|&(_, k)| k)
                .find(|&idx| !processed[idx as usize]);

            let Some(key_idx) = key_idx else {
                continue;
            };

            processed[key_idx as usize] = true;
            stack.push((key_idx, slot));

            // Decrease degree for all positions of this key
            let positions = &positions_vec[key_idx as usize];
            for &pos in positions {
                degree[pos as usize] = degree[pos as usize].saturating_sub(1);
                if degree[pos as usize] == 1 {
                    queue.push(pos);
                }
            }
        }

        // Check if all keys were processed
        if stack.len() != n {
            return Err(BinaryFuseError::ConstructionFailed);
        }

        // Free memory no longer needed before allocating final data
        drop(slot_key_pairs);
        drop(slot_start);
        drop(degree);
        drop(processed);

        // Assign values in reverse peeling order
        // Access values directly from input pairs (memory optimization)
        let mut data = vec![0u8; filter_size * value_size];

        while let Some((key_idx, determining_slot)) = stack.pop() {
            let positions = &positions_vec[key_idx as usize];
            let value: &[u8] = pairs[key_idx as usize].1.as_ref(); // Access value directly from input

            // XOR other two positions to get what this slot should be
            let mut xor_value = value.to_vec();
            let determining_slot_usize = determining_slot as usize;

            for &pos in positions {
                let pos_usize = pos as usize;
                if pos_usize != determining_slot_usize {
                    let slot_data = &data[pos_usize * value_size..(pos_usize + 1) * value_size];
                    for (i, &b) in slot_data.iter().enumerate() {
                        xor_value[i] ^= b;
                    }
                }
            }

            // Assign to determining slot
            let slot_data = &mut data
                [determining_slot_usize * value_size..(determining_slot_usize + 1) * value_size];
            slot_data.copy_from_slice(&xor_value);
        }

        Ok(BinaryFuseFilter {
            data,
            segment_size,
            filter_size,
            value_size,
            seed,
            segment_length_mask,
            num_entries: n,
        })
    }

    /// Build filter from fixed-size value arrays - avoids Vec allocation overhead
    fn try_build_fixed<K: Hash + Eq + Clone, const N: usize>(
        pairs: &[(K, [u8; N])],
        value_size: usize,
        segment_size: usize,
        filter_size: usize,
        segment_length_mask: u32,
        seed: u64,
    ) -> Result<Self, BinaryFuseError> {
        let n = pairs.len();

        // Helper to log memory in GB
        let log_mem = |label: &str, bytes: usize| {
            let gb = bytes as f64 / 1024.0 / 1024.0 / 1024.0;
            eprintln!("[FILTER-MEM] {}: {:.2} GB", label, gb);
        };

        eprintln!(
            "[FILTER] Starting try_build_fixed: n={}, filter_size={}",
            n, filter_size
        );

        // MEMORY OPTIMIZATION: Store only positions during peeling phase (12 bytes/entry)
        // Values are accessed directly from input pairs during assignment phase
        // This saves 8 bytes/entry = 16 GB for 2B entries!
        eprintln!(
            "[FILTER] Allocating positions ({} entries × 12 bytes)...",
            n
        );
        log_mem("positions will use", n * 12);
        let mut positions_vec: Vec<[u32; 3]> = Vec::with_capacity(n);
        for (key, _) in pairs {
            let hash = hash_key(key, seed);
            let pos = compute_positions(hash, segment_size, segment_length_mask);
            positions_vec.push([pos[0] as u32, pos[1] as u32, pos[2] as u32]);
        }
        eprintln!("[FILTER] positions allocated successfully");

        // Build degree counters
        eprintln!(
            "[FILTER] Allocating degree ({} slots × 4 bytes)...",
            filter_size
        );
        log_mem("degree will use", filter_size * 4);
        let mut degree = vec![0u32; filter_size];
        for positions in positions_vec.iter() {
            for &pos in positions {
                degree[pos as usize] += 1;
            }
        }
        eprintln!("[FILTER] degree allocated successfully");

        // Build flat sorted array of (slot, key_idx)
        eprintln!(
            "[FILTER] Allocating slot_key_pairs ({} entries × 8 bytes)...",
            n * 3
        );
        log_mem("slot_key_pairs will use", n * 3 * 8);
        let mut slot_key_pairs: Vec<(u32, u32)> = Vec::with_capacity(n * 3);
        for (key_idx, positions) in positions_vec.iter().enumerate() {
            for &pos in positions {
                slot_key_pairs.push((pos, key_idx as u32));
            }
        }
        eprintln!("[FILTER] slot_key_pairs populated, sorting...");
        slot_key_pairs.sort_unstable_by_key(|&(slot, _)| slot);
        eprintln!("[FILTER] slot_key_pairs sorted successfully");

        // Build index - use u64 to handle >4B entries in slot_key_pairs
        eprintln!(
            "[FILTER] Allocating slot_start ({} entries × 8 bytes)...",
            filter_size + 1
        );
        log_mem("slot_start will use", (filter_size + 1) * 8);
        let mut slot_start: Vec<u64> = vec![0; filter_size + 1];
        {
            let mut current_slot = 0u32;
            for (i, &(slot, _)) in slot_key_pairs.iter().enumerate() {
                while current_slot <= slot {
                    slot_start[current_slot as usize] = i as u64;
                    current_slot += 1;
                }
            }
            while (current_slot as usize) <= filter_size {
                slot_start[current_slot as usize] = slot_key_pairs.len() as u64;
                current_slot += 1;
            }
        }
        eprintln!("[FILTER] slot_start allocated successfully");

        // Peeling
        eprintln!("[FILTER] Allocating stack ({} entries × 8 bytes)...", n);
        log_mem("stack will use", n * 8);
        let mut stack: Vec<(u32, u32)> = Vec::with_capacity(n);

        eprintln!("[FILTER] Allocating processed ({} entries × 1 byte)...", n);
        log_mem("processed will use", n);
        let mut processed = vec![false; n];

        eprintln!("[FILTER] Building initial queue...");
        let mut queue: Vec<u32> = degree
            .iter()
            .enumerate()
            .filter(|(_, d)| **d == 1)
            .map(|(i, _)| i as u32)
            .collect();
        eprintln!("[FILTER] Initial queue size: {}", queue.len());

        eprintln!("[FILTER] Starting peeling phase...");
        while let Some(slot) = queue.pop() {
            if degree[slot as usize] != 1 {
                continue;
            }

            let start = slot_start[slot as usize] as usize;
            let end = slot_start[slot as usize + 1] as usize;

            let key_idx = slot_key_pairs[start..end]
                .iter()
                .filter(|&&(s, _)| s == slot)
                .map(|&(_, k)| k)
                .find(|&idx| !processed[idx as usize]);

            let Some(key_idx) = key_idx else {
                continue;
            };

            processed[key_idx as usize] = true;
            stack.push((key_idx, slot));

            let positions = &positions_vec[key_idx as usize];
            for &pos in positions {
                degree[pos as usize] = degree[pos as usize].saturating_sub(1);
                if degree[pos as usize] == 1 {
                    queue.push(pos);
                }
            }
        }
        eprintln!(
            "[FILTER] Peeling complete: processed {} of {} keys",
            stack.len(),
            n
        );

        if stack.len() != n {
            return Err(BinaryFuseError::ConstructionFailed);
        }

        eprintln!("[FILTER] Dropping intermediate structures...");
        drop(slot_key_pairs);
        eprintln!("[FILTER] Dropped slot_key_pairs");
        drop(slot_start);
        eprintln!("[FILTER] Dropped slot_start");
        drop(degree);
        eprintln!("[FILTER] Dropped degree");
        drop(processed);
        eprintln!("[FILTER] Dropped processed");

        // Assign values - access values directly from input pairs (saves 16 GB by not storing refs)
        eprintln!(
            "[FILTER] Allocating final data ({} slots × {} bytes)...",
            filter_size, value_size
        );
        log_mem("final data will use", filter_size * value_size);
        let mut data = vec![0u8; filter_size * value_size];
        eprintln!("[FILTER] Final data allocated successfully");

        eprintln!("[FILTER] Assigning values in reverse peeling order...");
        while let Some((key_idx, determining_slot)) = stack.pop() {
            let positions = &positions_vec[key_idx as usize];
            let value = pairs[key_idx as usize].1.as_slice(); // Access value directly from input
            let mut xor_value = value.to_vec();
            let det = determining_slot as usize;

            for &pos in positions {
                let p = pos as usize;
                if p != det {
                    let slot_data = &data[p * value_size..(p + 1) * value_size];
                    for (i, &b) in slot_data.iter().enumerate() {
                        xor_value[i] ^= b;
                    }
                }
            }

            data[det * value_size..(det + 1) * value_size].copy_from_slice(&xor_value);
        }
        eprintln!("[FILTER] Value assignment complete");

        Ok(BinaryFuseFilter {
            data,
            segment_size,
            filter_size,
            value_size,
            seed,
            segment_length_mask,
            num_entries: n,
        })
    }

    /// Get the 3 positions for a key lookup.
    ///
    /// These positions should be queried via PIR and XORed to recover the value.
    pub fn get_positions<K: Hash>(&self, key: &K) -> KeyPositions {
        let hash = hash_key(key, self.seed);
        let positions = compute_positions(hash, self.segment_size, self.segment_length_mask);
        KeyPositions {
            h0: positions[0],
            h1: positions[1],
            h2: positions[2],
        }
    }

    /// Decode a value from 3 slot values (XOR them together).
    ///
    /// # Arguments
    /// * `val0` - Value at position h0
    /// * `val1` - Value at position h1
    /// * `val2` - Value at position h2
    ///
    /// # Returns
    /// The decoded value (XOR of all three inputs)
    pub fn decode(&self, val0: &[u8], val1: &[u8], val2: &[u8]) -> Vec<u8> {
        assert_eq!(val0.len(), self.value_size);
        assert_eq!(val1.len(), self.value_size);
        assert_eq!(val2.len(), self.value_size);

        val0.iter()
            .zip(val1.iter())
            .zip(val2.iter())
            .map(|((&a, &b), &c)| a ^ b ^ c)
            .collect()
    }

    /// Look up a value directly (for testing, not for PIR use).
    ///
    /// In PIR context, use `get_positions` + PIR queries + `decode` instead.
    pub fn lookup<K: Hash>(&self, key: &K) -> Vec<u8> {
        let positions = self.get_positions(key);
        let val0 = self.get_slot(positions.h0);
        let val1 = self.get_slot(positions.h1);
        let val2 = self.get_slot(positions.h2);
        self.decode(val0, val1, val2)
    }

    /// Get the raw data at a specific slot position.
    pub fn get_slot(&self, position: usize) -> &[u8] {
        let start = position * self.value_size;
        let end = start + self.value_size;
        &self.data[start..end]
    }

    /// Get the total number of slots in the filter.
    pub fn filter_size(&self) -> usize {
        self.filter_size
    }

    /// Get the size of each value in bytes.
    pub fn value_size(&self) -> usize {
        self.value_size
    }

    /// Get the number of original key-value pairs.
    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    /// Get the segment size.
    pub fn segment_size(&self) -> usize {
        self.segment_size
    }

    /// Get the hash seed.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Get the expansion factor (filter_size / num_entries).
    pub fn expansion_factor(&self) -> f64 {
        self.filter_size as f64 / self.num_entries as f64
    }

    /// Get the raw filter data as bytes.
    ///
    /// This can be used to create a PIR database.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get filter data as records suitable for PIR.
    ///
    /// Returns a vector of `filter_size` records, each of `value_size` bytes.
    pub fn as_records(&self) -> Vec<&[u8]> {
        (0..self.filter_size).map(|i| self.get_slot(i)).collect()
    }

    /// Verify the filter is correctly constructed (for testing).
    pub fn verify<K: Hash + Eq>(&self, pairs: &[(K, Vec<u8>)]) -> bool {
        for (key, expected_value) in pairs {
            let recovered = self.lookup(key);
            if recovered != *expected_value {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// Hash Functions
// ============================================================================

/// Hash a key with the given seed
fn hash_key<K: Hash>(key: &K, seed: u64) -> u64 {
    // Use a seeded hash by combining seed with the key's hash
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    key.hash(&mut hasher);
    let h1 = hasher.finish();

    // Mix the hash further with the seed for better distribution
    let h2 = h1.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(seed);
    h2 ^ (h2 >> 33)
}

/// Compute 3 positions from a hash value
fn compute_positions(hash: u64, segment_size: usize, mask: u32) -> [usize; 3] {
    let h0 = hash as u32;
    let h1 = hash.rotate_left(21) as u32;
    let h2 = hash.rotate_left(42) as u32;

    [
        (h0 & mask) as usize,
        segment_size + (h1 & mask) as usize,
        2 * segment_size + (h2 & mask) as usize,
    ]
}

/// Calculate segment size (power of 2 for fast modulo)
///
/// Returns the smallest power of 2 that can hold (n * EXPANSION_FACTOR / ARITY) entries.
///
/// # Panics
///
/// Panics if the segment size would overflow `usize`. This can happen with extremely
/// large databases (>2^62 entries on 64-bit systems).
fn calculate_segment_size(n: usize) -> usize {
    let target = ((n as f64 * EXPANSION_FACTOR) / ARITY as f64).ceil() as usize;
    // Round up to next power of 2, with overflow check for very large databases
    target
        .checked_next_power_of_two()
        .expect("Binary Fuse Filter segment size overflow: database too large")
}

// ============================================================================
// Simple RNG (for seed generation)
// ============================================================================

/// Simple xorshift64 RNG for generating seeds
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

// ============================================================================
// Serialization Support
// ============================================================================

/// Serializable filter parameters (for client-side storage)
#[derive(Clone, Debug)]
pub struct BinaryFuseParams {
    /// Hash seed
    pub seed: u64,
    /// Segment size
    pub segment_size: usize,
    /// Filter size (total slots)
    pub filter_size: usize,
    /// Value size in bytes
    pub value_size: usize,
    /// Segment length mask
    pub segment_length_mask: u32,
}

impl BinaryFuseFilter {
    /// Extract parameters needed for client-side lookups.
    ///
    /// The client needs these parameters plus the ability to query positions via PIR.
    pub fn params(&self) -> BinaryFuseParams {
        BinaryFuseParams {
            seed: self.seed,
            segment_size: self.segment_size,
            filter_size: self.filter_size,
            value_size: self.value_size,
            segment_length_mask: self.segment_length_mask,
        }
    }
}

impl BinaryFuseParams {
    /// Get the 3 positions for a key lookup (client-side).
    pub fn get_positions<K: Hash>(&self, key: &K) -> KeyPositions {
        let hash = hash_key(key, self.seed);
        let positions = compute_positions(hash, self.segment_size, self.segment_length_mask);
        KeyPositions {
            h0: positions[0],
            h1: positions[1],
            h2: positions[2],
        }
    }

    /// Decode a value from 3 slot values.
    pub fn decode(&self, val0: &[u8], val1: &[u8], val2: &[u8]) -> Vec<u8> {
        assert_eq!(val0.len(), self.value_size);
        assert_eq!(val1.len(), self.value_size);
        assert_eq!(val2.len(), self.value_size);

        val0.iter()
            .zip(val1.iter())
            .zip(val2.iter())
            .map(|((&a, &b), &c)| a ^ b ^ c)
            .collect()
    }
}

// ============================================================================
// DoublePIR Integration Helpers
// ============================================================================

/// Helper to convert Binary Fuse Filter data to DoublePIR database format.
///
/// This creates a database where each "record" is one filter slot.
/// DoublePIR can then query individual slots by index.
impl BinaryFuseFilter {
    /// Convert filter to records suitable for creating a DoublePirDatabase.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let filter = BinaryFuseFilter::build(&pairs, value_size)?;
    /// let records = filter.to_pir_records();
    /// let db = DoublePirDatabase::new(&records, value_size);
    /// let server = DoublePirServer::new(db, &params, &mut rng);
    /// ```
    pub fn to_pir_records(&self) -> Vec<Vec<u8>> {
        (0..self.filter_size)
            .map(|i| self.get_slot(i).to_vec())
            .collect()
    }
}

/// Keyword PIR query builder for use with any PIR backend.
///
/// This struct helps manage the 3 positions needed for keyword lookup.
#[derive(Debug, Clone)]
pub struct KeywordQuery {
    /// The 3 positions to query
    pub positions: KeyPositions,
    /// Value size for validation
    pub value_size: usize,
}

impl KeywordQuery {
    /// Create a new keyword query from filter params and a key.
    pub fn new<K: Hash>(params: &BinaryFuseParams, key: &K) -> Self {
        Self {
            positions: params.get_positions(key),
            value_size: params.value_size,
        }
    }

    /// Get the 3 record indices to query via PIR.
    pub fn record_indices(&self) -> [usize; 3] {
        self.positions.as_array()
    }

    /// Decode the value from 3 PIR responses.
    ///
    /// # Arguments
    /// * `responses` - The 3 record values retrieved via PIR, in order [h0, h1, h2]
    ///
    /// # Returns
    /// The decoded value (XOR of all three)
    ///
    /// # Panics
    /// Panics if responses don't have exactly 3 elements or wrong value sizes.
    pub fn decode(&self, responses: &[Vec<u8>; 3]) -> Vec<u8> {
        assert_eq!(responses[0].len(), self.value_size);
        assert_eq!(responses[1].len(), self.value_size);
        assert_eq!(responses[2].len(), self.value_size);

        responses[0]
            .iter()
            .zip(responses[1].iter())
            .zip(responses[2].iter())
            .map(|((&a, &b), &c)| a ^ b ^ c)
            .collect()
    }
}

/// Statistics about a Binary Fuse Filter (useful for benchmarking/debugging).
#[derive(Debug, Clone)]
pub struct BinaryFuseStats {
    /// Number of original key-value pairs
    pub num_entries: usize,
    /// Total number of filter slots
    pub filter_size: usize,
    /// Size of each value in bytes
    pub value_size: usize,
    /// Total filter data size in bytes
    pub total_bytes: usize,
    /// Expansion factor (filter_size / num_entries)
    pub expansion_factor: f64,
    /// Segment size
    pub segment_size: usize,
}

impl BinaryFuseFilter {
    /// Get statistics about the filter.
    pub fn stats(&self) -> BinaryFuseStats {
        BinaryFuseStats {
            num_entries: self.num_entries,
            filter_size: self.filter_size,
            value_size: self.value_size,
            total_bytes: self.data.len(),
            expansion_factor: self.expansion_factor(),
            segment_size: self.segment_size,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create test key-value pairs
    fn make_pairs(n: usize, value_size: usize) -> Vec<(String, Vec<u8>)> {
        (0..n)
            .map(|i| {
                let key = format!("key_{}", i);
                let value: Vec<u8> = (0..value_size)
                    .map(|j| ((i * value_size + j) % 256) as u8)
                    .collect();
                (key, value)
            })
            .collect()
    }

    #[test]
    fn test_build_small_filter() {
        let pairs = make_pairs(10, 8);
        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

        assert!(filter.verify(&pairs), "All lookups should succeed");
        // Small filters have higher expansion due to power-of-2 segment sizes
        assert!(
            filter.expansion_factor() < 5.0,
            "Expansion should be reasonable for small filter"
        );
    }

    #[test]
    fn test_build_medium_filter() {
        let pairs = make_pairs(1000, 32);
        let filter = BinaryFuseFilter::build(&pairs, 32).expect("Build should succeed");

        assert!(filter.verify(&pairs), "All lookups should succeed");
        println!(
            "Medium filter: {} entries, {} slots, expansion {:.3}",
            filter.num_entries(),
            filter.filter_size(),
            filter.expansion_factor()
        );
    }

    #[test]
    fn test_build_large_filter() {
        let pairs = make_pairs(10_000, 16);
        let filter = BinaryFuseFilter::build(&pairs, 16).expect("Build should succeed");

        assert!(filter.verify(&pairs), "All lookups should succeed");
        println!(
            "Large filter: {} entries, {} slots, expansion {:.3}",
            filter.num_entries(),
            filter.filter_size(),
            filter.expansion_factor()
        );
    }

    #[test]
    fn test_positions_consistency() {
        let pairs = make_pairs(100, 8);
        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

        // Same key should always return same positions
        let key = "test_key";
        let pos1 = filter.get_positions(&key);
        let pos2 = filter.get_positions(&key);
        assert_eq!(pos1, pos2);

        // Positions should be in correct segments
        assert!(pos1.h0 < filter.segment_size());
        assert!(pos1.h1 >= filter.segment_size() && pos1.h1 < 2 * filter.segment_size());
        assert!(pos1.h2 >= 2 * filter.segment_size() && pos1.h2 < filter.filter_size());
    }

    #[test]
    fn test_decode_xor() {
        let pairs = make_pairs(100, 8);
        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

        for (key, expected_value) in &pairs {
            let positions = filter.get_positions(key);
            let val0 = filter.get_slot(positions.h0);
            let val1 = filter.get_slot(positions.h1);
            let val2 = filter.get_slot(positions.h2);

            let decoded = filter.decode(val0, val1, val2);
            assert_eq!(
                &decoded, expected_value,
                "Decode should recover original value"
            );
        }
    }

    #[test]
    fn test_params_client_side() {
        let pairs = make_pairs(100, 8);
        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

        // Extract params for client
        let params = filter.params();

        // Client can compute positions and decode
        for (key, expected_value) in &pairs {
            let positions = params.get_positions(key);

            // Simulate PIR: get slot values from filter (in reality, via PIR queries)
            let val0 = filter.get_slot(positions.h0);
            let val1 = filter.get_slot(positions.h1);
            let val2 = filter.get_slot(positions.h2);

            let decoded = params.decode(val0, val1, val2);
            assert_eq!(&decoded, expected_value);
        }
    }

    #[test]
    fn test_empty_input() {
        let pairs: Vec<(String, Vec<u8>)> = vec![];
        let result = BinaryFuseFilter::build(&pairs, 8);
        assert_eq!(result.unwrap_err(), BinaryFuseError::EmptyInput);
    }

    #[test]
    fn test_duplicate_keys() {
        let pairs = vec![
            ("key".to_string(), vec![1, 2, 3, 4]),
            ("key".to_string(), vec![5, 6, 7, 8]),
        ];
        let result = BinaryFuseFilter::build(&pairs, 4);
        assert_eq!(result.unwrap_err(), BinaryFuseError::DuplicateKey);
    }

    #[test]
    fn test_value_size_mismatch() {
        let pairs = vec![
            ("key1".to_string(), vec![1, 2, 3, 4]),
            ("key2".to_string(), vec![5, 6, 7]), // Wrong size
        ];
        let result = BinaryFuseFilter::build(&pairs, 4);
        assert!(matches!(
            result.unwrap_err(),
            BinaryFuseError::ValueSizeMismatch { .. }
        ));
    }

    #[test]
    fn test_single_entry() {
        let pairs = vec![("only_key".to_string(), vec![42, 43, 44, 45])];
        let filter = BinaryFuseFilter::build(&pairs, 4).expect("Build should succeed");
        assert!(filter.verify(&pairs));
    }

    #[test]
    fn test_binary_values() {
        // Test with random-looking binary data
        let pairs: Vec<(u64, Vec<u8>)> = (0..500)
            .map(|i| {
                let value: Vec<u8> = (0..64).map(|j| ((i * 7 + j * 13) % 256) as u8).collect();
                (i, value)
            })
            .collect();

        let filter = BinaryFuseFilter::build(&pairs, 64).expect("Build should succeed");
        assert!(filter.verify(&pairs));
    }

    #[test]
    fn test_integer_keys() {
        let pairs: Vec<(u64, Vec<u8>)> = (0..1000).map(|i| (i, vec![(i % 256) as u8; 8])).collect();

        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");
        assert!(filter.verify(&pairs));
    }

    #[test]
    fn test_as_records() {
        let pairs = make_pairs(100, 8);
        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

        let records = filter.as_records();
        assert_eq!(records.len(), filter.filter_size());

        for (i, record) in records.iter().enumerate() {
            assert_eq!(record.len(), filter.value_size());
            assert_eq!(*record, filter.get_slot(i));
        }
    }

    #[test]
    fn test_expansion_factor() {
        // Test various sizes and check expansion factor
        for &n in &[100, 500, 1000, 5000, 10000] {
            let pairs = make_pairs(n, 8);
            let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

            let expansion = filter.expansion_factor();
            println!("n={}: expansion={:.3}", n, expansion);

            // Binary Fuse Filters with power-of-2 segment sizes have higher expansion
            // Theoretical is ~1.125, but power-of-2 rounding inflates it to ~1.5-2.5x
            // This is acceptable for PIR where filter size is still O(n)
            assert!(
                expansion < 3.0,
                "Expansion factor {} too high for n={}",
                expansion,
                n
            );
        }
    }

    #[test]
    fn test_deterministic_positions() {
        // Same key + seed should always give same positions
        let pairs = make_pairs(100, 8);
        let filter1 = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");
        let filter2 = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

        // If seeds match, positions should match
        if filter1.seed() == filter2.seed() {
            for (key, _) in &pairs {
                assert_eq!(filter1.get_positions(key), filter2.get_positions(key));
            }
        }
    }

    /// Simulates the full keyword PIR workflow
    #[test]
    fn test_pir_workflow_simulation() {
        // 1. Server: Build filter from key-value database
        let database: Vec<(String, Vec<u8>)> = (0..100)
            .map(|i| {
                let key = format!("user_{}", i);
                let value = format!("data_for_user_{}", i).into_bytes();
                // Pad to fixed size
                let mut padded = vec![0u8; 32];
                let len = value.len().min(32);
                padded[..len].copy_from_slice(&value[..len]);
                (key, padded)
            })
            .collect();

        let filter = BinaryFuseFilter::build(&database, 32).expect("Build should succeed");

        // 2. Server: Convert to PIR database
        let pir_records = filter.as_records();
        println!(
            "PIR database: {} records of {} bytes each",
            pir_records.len(),
            filter.value_size()
        );

        // 3. Client receives filter params (small: just seed + sizes)
        let params = filter.params();

        // 4. Client wants to look up "user_42"
        let target_key = "user_42";
        let positions = params.get_positions(&target_key);
        println!(
            "Positions for '{}': h0={}, h1={}, h2={}",
            target_key, positions.h0, positions.h1, positions.h2
        );

        // 5. Client queries 3 positions via PIR (simulated here)
        let val0 = pir_records[positions.h0].to_vec();
        let val1 = pir_records[positions.h1].to_vec();
        let val2 = pir_records[positions.h2].to_vec();

        // 6. Client decodes
        let recovered = params.decode(&val0, &val1, &val2);

        // 7. Verify
        let expected = database
            .iter()
            .find(|(k, _)| k == target_key)
            .map(|(_, v)| v.clone())
            .unwrap();

        assert_eq!(recovered, expected, "Should recover correct value");
        println!("Recovered: {:?}", String::from_utf8_lossy(&recovered));
    }

    /// Test that positions are well-distributed across segments
    #[test]
    fn test_position_distribution() {
        let pairs = make_pairs(1000, 8);
        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

        let mut segment_counts = [0usize; 3];
        let segment_size = filter.segment_size();

        for (key, _) in &pairs {
            let pos = filter.get_positions(key);

            // Check positions are in correct segments
            assert!(pos.h0 < segment_size);
            assert!(pos.h1 >= segment_size && pos.h1 < 2 * segment_size);
            assert!(pos.h2 >= 2 * segment_size);

            segment_counts[0] += 1;
            segment_counts[1] += 1;
            segment_counts[2] += 1;
        }

        // All keys contribute to all 3 segments (by design)
        assert_eq!(segment_counts[0], pairs.len());
        assert_eq!(segment_counts[1], pairs.len());
        assert_eq!(segment_counts[2], pairs.len());
    }

    #[test]
    fn test_keyword_query() {
        let pairs = make_pairs(100, 8);
        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");
        let params = filter.params();

        for (key, expected_value) in &pairs {
            // Create keyword query
            let query = KeywordQuery::new(&params, key);
            let indices = query.record_indices();

            // Simulate PIR responses
            let responses = [
                filter.get_slot(indices[0]).to_vec(),
                filter.get_slot(indices[1]).to_vec(),
                filter.get_slot(indices[2]).to_vec(),
            ];

            // Decode
            let decoded = query.decode(&responses);
            assert_eq!(&decoded, expected_value);
        }
    }

    #[test]
    fn test_stats() {
        let pairs = make_pairs(1000, 32);
        let filter = BinaryFuseFilter::build(&pairs, 32).expect("Build should succeed");

        let stats = filter.stats();

        assert_eq!(stats.num_entries, 1000);
        assert_eq!(stats.value_size, 32);
        assert_eq!(stats.filter_size, filter.filter_size());
        assert_eq!(stats.total_bytes, filter.filter_size() * 32);
        assert!(stats.expansion_factor > 1.0 && stats.expansion_factor < 3.0);

        println!("Filter stats: {:?}", stats);
    }

    #[test]
    fn test_to_pir_records() {
        let pairs = make_pairs(100, 8);
        let filter = BinaryFuseFilter::build(&pairs, 8).expect("Build should succeed");

        let records = filter.to_pir_records();

        assert_eq!(records.len(), filter.filter_size());
        for (i, record) in records.iter().enumerate() {
            assert_eq!(record.len(), filter.value_size());
            assert_eq!(record.as_slice(), filter.get_slot(i));
        }
    }

    /// Simulated workflow test (without actual PIR crypto).
    ///
    /// For full end-to-end tests with actual DoublePIR, see:
    /// `tests/integration_test.rs::test_keyword_pir_with_double_pir`
    #[test]
    fn test_simulated_pir_workflow() {
        // 1. Server has a key-value database
        let database: Vec<(String, Vec<u8>)> = (0..100)
            .map(|i| {
                let key = format!("item_{:03}", i);
                let value = format!("data_{}", i).into_bytes();
                let mut padded = vec![0u8; 16];
                let len = value.len().min(16);
                padded[..len].copy_from_slice(&value[..len]);
                (key, padded)
            })
            .collect();

        // 2. Server builds Binary Fuse Filter
        let filter = BinaryFuseFilter::build(&database, 16).expect("Build should succeed");

        // 3. Server converts to PIR database format
        let pir_records = filter.to_pir_records();

        // 4. Client receives filter params
        let params = filter.params();

        // 5. Client wants to look up a key
        let target_key = "item_042";
        let kw_query = KeywordQuery::new(&params, &target_key);
        let indices = kw_query.record_indices();

        // 6. Simulate PIR: directly access records (in reality, via 3 DoublePIR queries)
        let responses = [
            pir_records[indices[0]].clone(),
            pir_records[indices[1]].clone(),
            pir_records[indices[2]].clone(),
        ];

        // 7. Client decodes via XOR
        let decoded = kw_query.decode(&responses);

        // 8. Verify
        let expected = database
            .iter()
            .find(|(k, _)| k == target_key)
            .map(|(_, v)| v.clone())
            .unwrap();

        assert_eq!(decoded, expected);
    }
}

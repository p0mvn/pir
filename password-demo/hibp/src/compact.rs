//! Compact in-memory storage for HIBP data
//!
//! Uses a single sorted array of (hash, count) pairs for minimal memory usage.
//! Memory: ~24 bytes per entry vs ~63 bytes with HashMap+String approach.

/// SHA-1 hash as raw bytes (20 bytes)
pub type HashBytes = [u8; 20];

/// A single entry: full SHA-1 hash + breach count
///
/// Memory layout: 24 bytes total (20 byte hash + 4 byte count)
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HashEntry {
    pub hash: HashBytes,
    pub count: u32,
}

impl HashEntry {
    #[inline]
    pub fn new(hash: HashBytes, count: u32) -> Self {
        Self { hash, count }
    }
}

/// Compact storage for HIBP password hashes
///
/// Stores all hashes in a single sorted vector for efficient binary search.
/// Memory usage: ~24 bytes per entry (vs ~63 bytes with HashMap+String).
///
/// For the full HIBP database (~2 billion entries):
/// - This approach: ~48 GB
/// - HashMap approach: ~126 GB
pub struct CompactHibpData {
    /// Sorted array of hash entries
    entries: Vec<HashEntry>,
}

impl CompactHibpData {
    /// Create empty compact data
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create with pre-allocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Create from a pre-sorted vector of entries
    /// IMPORTANT: entries must already be sorted by hash!
    pub fn from_sorted(entries: Vec<HashEntry>) -> Self {
        Self { entries }
    }

    /// Build from an iterator of (hash_bytes, count) pairs
    /// The data will be sorted automatically
    pub fn from_iter<I>(iter: I) -> Self
    where
        I: Iterator<Item = (HashBytes, u32)>,
    {
        let mut entries: Vec<HashEntry> = iter
            .map(|(hash, count)| HashEntry::new(hash, count))
            .collect();

        // Sort by hash for binary search
        entries.sort_unstable_by(|a, b| a.hash.cmp(&b.hash));

        Self { entries }
    }

    /// Add entries from a downloaded range (prefix + suffixes)
    /// This is used during incremental building
    pub fn add_range(&mut self, prefix: &str, suffixes: &[(String, u32)]) {
        for (suffix, count) in suffixes {
            if let Some(hash) = Self::combine_and_decode(prefix, suffix) {
                self.entries.push(HashEntry::new(hash, *count));
            }
        }
    }

    /// Finalize the data structure after all ranges are added
    /// Must be called before lookups will work correctly
    pub fn finalize(&mut self) {
        self.entries.sort_unstable_by(|a, b| a.hash.cmp(&b.hash));
        self.entries.shrink_to_fit();
    }

    /// Look up a hash and return the breach count if found
    pub fn lookup(&self, hash: &HashBytes) -> Option<u32> {
        self.entries
            .binary_search_by(|entry| entry.hash.cmp(hash))
            .ok()
            .map(|i| self.entries[i].count)
    }

    /// Look up by hex string hash
    pub fn lookup_hex(&self, hash_hex: &str) -> Option<u32> {
        Self::decode_hex(hash_hex).and_then(|hash| self.lookup(&hash))
    }

    /// Number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Estimated memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        self.entries.capacity() * std::mem::size_of::<HashEntry>()
    }

    /// Get an iterator over all entries
    pub fn iter(&self) -> impl Iterator<Item = &HashEntry> {
        self.entries.iter()
    }

    /// Consume and return the entries vector
    /// Use this to transfer ownership for building PIR database
    pub fn into_entries(self) -> Vec<HashEntry> {
        self.entries
    }

    /// Decode a 40-character hex string to 20 bytes
    fn decode_hex(hex: &str) -> Option<HashBytes> {
        if hex.len() != 40 {
            return None;
        }
        let mut bytes = [0u8; 20];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let high = Self::hex_nibble(chunk[0])?;
            let low = Self::hex_nibble(chunk[1])?;
            bytes[i] = (high << 4) | low;
        }
        Some(bytes)
    }

    /// Combine prefix (5 hex chars) + suffix (35 hex chars) and decode to bytes
    fn combine_and_decode(prefix: &str, suffix: &str) -> Option<HashBytes> {
        if prefix.len() != 5 || suffix.len() != 35 {
            return None;
        }
        let full_hex = format!("{}{}", prefix, suffix);
        Self::decode_hex(&full_hex)
    }

    /// Convert a hex character to its nibble value
    #[inline]
    fn hex_nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
}

impl Default for CompactHibpData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex() {
        let hex = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let bytes = CompactHibpData::decode_hex(hex).unwrap();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], 0x5B);
        assert_eq!(bytes[1], 0xAA);
        assert_eq!(bytes[19], 0xD8);
    }

    #[test]
    fn test_combine_and_decode() {
        let prefix = "5BAA6";
        let suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let bytes = CompactHibpData::combine_and_decode(prefix, suffix).unwrap();

        // Should equal decode of full hash
        let full = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let full_bytes = CompactHibpData::decode_hex(full).unwrap();
        assert_eq!(bytes, full_bytes);
    }

    #[test]
    fn test_lookup() {
        let hash1 =
            CompactHibpData::decode_hex("0000000000000000000000000000000000000001").unwrap();
        let hash2 =
            CompactHibpData::decode_hex("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8").unwrap();
        let hash3 =
            CompactHibpData::decode_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap();

        let data = CompactHibpData::from_iter(
            vec![(hash2, 12345), (hash1, 100), (hash3, 999)].into_iter(),
        );

        assert_eq!(data.lookup(&hash1), Some(100));
        assert_eq!(data.lookup(&hash2), Some(12345));
        assert_eq!(data.lookup(&hash3), Some(999));

        let missing =
            CompactHibpData::decode_hex("1111111111111111111111111111111111111111").unwrap();
        assert_eq!(data.lookup(&missing), None);
    }

    #[test]
    fn test_memory_size() {
        // HashEntry should be 24 bytes (20 + 4)
        assert_eq!(std::mem::size_of::<HashEntry>(), 24);
    }
}

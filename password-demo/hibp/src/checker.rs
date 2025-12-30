//! Password checking against downloaded HIBP data

use crate::{hash_password, split_hash, Error};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use tracing::info;

/// Password checker using downloaded HIBP range files
pub struct PasswordChecker {
    ranges_dir: Option<PathBuf>,
    /// Optional in-memory cache for loaded ranges
    /// Uses sorted Vec for memory efficiency (binary search for lookups)
    cache: Option<HashMap<String, Vec<(String, u32)>>>,
}

impl PasswordChecker {
    /// Create a checker that reads from disk on each query
    pub fn from_directory<P: AsRef<Path>>(ranges_dir: P) -> Result<Self, Error> {
        let path = ranges_dir.as_ref().to_path_buf();
        if !path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Ranges directory not found: {:?}", path),
            )));
        }
        Ok(Self {
            ranges_dir: Some(path),
            cache: None,
        })
    }

    /// Create a checker from a pre-loaded in-memory cache
    /// This is useful when data was downloaded directly to memory
    pub fn from_cache(cache: HashMap<String, Vec<(String, u32)>>) -> Self {
        let total_hashes: usize = cache.values().map(|v| v.len()).sum();
        info!(
            "Created PasswordChecker from in-memory cache: {} ranges, {} hashes",
            cache.len(),
            total_hashes
        );
        Self {
            ranges_dir: None,
            cache: Some(cache),
        }
    }

    /// Load all range files into memory for faster lookups
    /// Warning: This uses ~20-40GB of RAM for the full database
    pub fn load_into_memory(mut self) -> Result<Self, Error> {
        // Already loaded from cache
        if self.cache.is_some() {
            return Ok(self);
        }

        let ranges_dir = self.ranges_dir.as_ref().ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No ranges directory configured",
            ))
        })?;

        info!("Loading HIBP data into memory...");
        let mut cache = HashMap::new();

        let entries: Vec<_> = fs::read_dir(ranges_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .collect();

        let total = entries.len();
        for (i, entry) in entries.into_iter().enumerate() {
            let prefix = entry.file_name().to_string_lossy().to_uppercase();
            if prefix.len() != 5 {
                continue;
            }

            let range_data = Self::parse_range_file(&entry.path())?;
            cache.insert(prefix, range_data);

            if (i + 1) % 10000 == 0 || i + 1 == total {
                info!("Loaded {}/{} files", i + 1, total);
            }
        }

        let loaded_count = cache.len();
        self.cache = Some(cache);
        info!("Loaded {} range files into memory", loaded_count);
        Ok(self)
    }

    /// Parse a range file into a sorted Vec of (suffix, count)
    fn parse_range_file(path: &Path) -> Result<Vec<(String, u32)>, Error> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Format: SUFFIX:COUNT (e.g., "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345")
            if let Some((suffix, count_str)) = line.split_once(':') {
                if let Ok(count) = count_str.parse::<u32>() {
                    entries.push((suffix.to_uppercase(), count));
                }
            }
        }
        // HIBP files are sorted, but ensure for binary search
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(entries)
    }

    /// Check if a password hash is in the database
    /// Returns Some(count) if found, None if not found
    pub fn check_hash(&self, hash: &str) -> Result<Option<u32>, Error> {
        if hash.len() != 40 {
            return Err(Error::InvalidHash(format!(
                "Expected 40 character SHA-1 hash, got {} characters",
                hash.len()
            )));
        }

        let (prefix, suffix) = split_hash(hash);
        let prefix = prefix.to_uppercase();
        let suffix = suffix.to_uppercase();

        // Check cache first (uses binary search on sorted Vec)
        if let Some(cache) = &self.cache {
            if let Some(range) = cache.get(&prefix) {
                return Ok(Self::binary_search_suffix(range, &suffix));
            } else {
                return Ok(None); // Prefix not in cache means not downloaded
            }
        }

        // Read from disk
        let ranges_dir = self.ranges_dir.as_ref().ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No ranges directory - checker was created from in-memory cache only",
            ))
        })?;

        let file_path = ranges_dir.join(&prefix);
        if !file_path.exists() {
            return Err(Error::RangeNotFound(prefix));
        }

        let range_data = Self::parse_range_file(&file_path)?;
        Ok(Self::binary_search_suffix(&range_data, &suffix))
    }

    /// Binary search for a suffix in a sorted Vec
    fn binary_search_suffix(entries: &[(String, u32)], suffix: &str) -> Option<u32> {
        entries
            .binary_search_by(|(s, _)| s.as_str().cmp(suffix))
            .ok()
            .map(|idx| entries[idx].1)
    }

    /// Check if a password (plaintext) is in the database
    /// The password is hashed client-side before checking
    pub fn check(&self, password: &str) -> Result<Option<u32>, Error> {
        let hash = hash_password(password);
        self.check_hash(&hash)
    }

    /// Get statistics about loaded data
    pub fn stats(&self) -> CheckerStats {
        if let Some(cache) = &self.cache {
            let total_hashes: usize = cache.values().map(|v| v.len()).sum();
            CheckerStats {
                ranges_loaded: cache.len(),
                total_hashes,
                in_memory: true,
            }
        } else if let Some(ranges_dir) = &self.ranges_dir {
            // Count files on disk
            let ranges_loaded = fs::read_dir(ranges_dir)
                .map(|entries| entries.filter_map(|e| e.ok()).count())
                .unwrap_or(0);
            CheckerStats {
                ranges_loaded,
                total_hashes: 0, // Unknown without loading
                in_memory: false,
            }
        } else {
            CheckerStats {
                ranges_loaded: 0,
                total_hashes: 0,
                in_memory: false,
            }
        }
    }
    
    /// Get a reference to the in-memory cache (if loaded)
    pub fn get_cache(&self) -> Option<&HashMap<String, Vec<(String, u32)>>> {
        self.cache.as_ref()
    }
}

/// Statistics about the password checker
#[derive(Debug)]
pub struct CheckerStats {
    pub ranges_loaded: usize,
    pub total_hashes: usize,
    pub in_memory: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn create_test_range(dir: &Path, prefix: &str, entries: &[(&str, u32)]) {
        let file_path = dir.join(prefix);
        let mut file = fs::File::create(file_path).unwrap();
        for (suffix, count) in entries {
            writeln!(file, "{}:{}", suffix, count).unwrap();
        }
    }

    #[test]
    fn test_check_hash_found() {
        let dir = tempdir().unwrap();
        create_test_range(
            dir.path(),
            "5BAA6",
            &[("1E4C9B93F3F0682250B6CF8331B7EE68FD8", 12345)],
        );

        let checker = PasswordChecker::from_directory(dir.path()).unwrap();
        let result = checker
            .check_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
            .unwrap();
        assert_eq!(result, Some(12345));
    }

    #[test]
    fn test_check_hash_not_found() {
        let dir = tempdir().unwrap();
        create_test_range(
            dir.path(),
            "5BAA6",
            &[("1E4C9B93F3F0682250B6CF8331B7EE68FD8", 12345)],
        );

        let checker = PasswordChecker::from_directory(dir.path()).unwrap();
        // 40 character hash that doesn't match
        let result = checker
            .check_hash("5BAA6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_check_password() {
        let dir = tempdir().unwrap();
        // SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        create_test_range(
            dir.path(),
            "5BAA6",
            &[("1E4C9B93F3F0682250B6CF8331B7EE68FD8", 9999)],
        );

        let checker = PasswordChecker::from_directory(dir.path()).unwrap();
        let result = checker.check("password").unwrap();
        assert_eq!(result, Some(9999));
    }
}

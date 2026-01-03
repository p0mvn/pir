//! HIBP Pwned Passwords downloader
//!
//! Downloads password hash ranges from the HaveIBeenPwned API.
//! Uses parallel HTTP requests for fast downloads.

use crate::compact::{CompactHibpData, HashEntry};
use crate::Error;
use futures::{stream, StreamExt};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// Progress callback for download operations
pub trait DownloadProgress: Send + Sync {
    fn on_file_complete(&self, prefix: &str, current: usize, total: usize);
    fn on_error(&self, prefix: &str, error: &Error);
}

/// Default progress reporter that logs to tracing
pub struct LogProgress;

impl DownloadProgress for LogProgress {
    fn on_file_complete(&self, _prefix: &str, current: usize, total: usize) {
        if current.is_multiple_of(1000) || current == total {
            info!(
                "Downloaded {}/{} files ({:.1}%)",
                current,
                total,
                (current as f64 / total as f64) * 100.0
            );
        }
    }

    fn on_error(&self, prefix: &str, error: &Error) {
        warn!("Failed to download {}: {}", prefix, error);
    }
}

/// HIBP Pwned Passwords downloader
pub struct Downloader {
    output_dir: PathBuf,
    concurrent_requests: usize,
    client: reqwest::Client,
}

impl Downloader {
    /// Create a new downloader with default settings
    pub fn new<P: AsRef<Path>>(output_dir: P) -> Self {
        Self {
            output_dir: output_dir.as_ref().to_path_buf(),
            concurrent_requests: 150,
            client: reqwest::Client::builder()
                .user_agent("pir-password-checker/0.1")
                .timeout(std::time::Duration::from_secs(60))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Set the number of concurrent requests
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrent_requests = n;
        self
    }

    /// Generate all possible 5-character hex prefixes (00000 to FFFFF)
    fn all_prefixes() -> Vec<String> {
        let chars = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        ];
        let mut prefixes = Vec::with_capacity(1_048_576); // 16^5

        for a in &chars {
            for b in &chars {
                for c in &chars {
                    for d in &chars {
                        for e in &chars {
                            prefixes.push(format!("{}{}{}{}{}", a, b, c, d, e));
                        }
                    }
                }
            }
        }
        prefixes
    }

    /// Generate prefixes for a tiny sample (000XX - 256 files)
    fn tiny_prefixes() -> Vec<String> {
        let chars = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        ];
        let mut prefixes = Vec::with_capacity(256);

        for d in &chars {
            for e in &chars {
                prefixes.push(format!("000{}{}", d, e));
            }
        }
        prefixes
    }

    /// Generate prefixes for a sample (0XXXX - 65,536 files)
    fn sample_prefixes() -> Vec<String> {
        let chars = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        ];
        let mut prefixes = Vec::with_capacity(65_536);

        for b in &chars {
            for c in &chars {
                for d in &chars {
                    for e in &chars {
                        prefixes.push(format!("0{}{}{}{}", b, c, d, e));
                    }
                }
            }
        }
        prefixes
    }

    /// Download a single range file
    async fn download_range(&self, prefix: &str) -> Result<(), Error> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let response = self.client.get(&url).send().await?;
        let body = response.text().await?;

        let file_path = self.output_dir.join(prefix);
        let mut file = fs::File::create(&file_path).await?;
        file.write_all(body.as_bytes()).await?;

        Ok(())
    }

    /// Download ranges with progress reporting
    async fn download_prefixes<P: DownloadProgress>(
        &self,
        prefixes: Vec<String>,
        progress: &P,
    ) -> Result<usize, Error> {
        fs::create_dir_all(&self.output_dir).await?;

        let total = prefixes.len();
        let completed = Arc::new(AtomicUsize::new(0));
        let errors = Arc::new(AtomicUsize::new(0));

        stream::iter(prefixes)
            .map(|prefix| {
                let completed = Arc::clone(&completed);
                let errors = Arc::clone(&errors);
                async move {
                    // Retry logic
                    let mut attempts = 0;
                    loop {
                        match self.download_range(&prefix).await {
                            Ok(()) => {
                                let current = completed.fetch_add(1, Ordering::SeqCst) + 1;
                                progress.on_file_complete(&prefix, current, total);
                                break;
                            }
                            Err(e) => {
                                attempts += 1;
                                if attempts >= 3 {
                                    progress.on_error(&prefix, &e);
                                    errors.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                tokio::time::sleep(tokio::time::Duration::from_millis(
                                    100 * attempts,
                                ))
                                .await;
                            }
                        }
                    }
                }
            })
            .buffer_unordered(self.concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        let error_count = errors.load(Ordering::SeqCst);
        if error_count > 0 {
            warn!("{} files failed to download", error_count);
        }

        Ok(completed.load(Ordering::SeqCst))
    }

    /// Download a tiny sample (256 files, ~20MB)
    /// Good for quick testing
    pub async fn download_tiny(&self) -> Result<usize, Error> {
        info!("Downloading tiny HIBP sample (256 files)...");
        self.download_prefixes(Self::tiny_prefixes(), &LogProgress)
            .await
    }

    /// Download a sample (65,536 files, ~2.5GB)
    /// Good for development
    pub async fn download_sample(&self) -> Result<usize, Error> {
        info!("Downloading HIBP sample (65,536 files)...");
        self.download_prefixes(Self::sample_prefixes(), &LogProgress)
            .await
    }

    /// Download the full database (1,048,576 files, ~38GB)
    /// Takes ~15 minutes with good connection
    pub async fn download_full(&self) -> Result<usize, Error> {
        info!("Downloading full HIBP database (1,048,576 files)...");
        self.download_prefixes(Self::all_prefixes(), &LogProgress)
            .await
    }

    /// Download with custom progress reporting
    pub async fn download_with_progress<P: DownloadProgress>(
        &self,
        size: DownloadSize,
        progress: &P,
    ) -> Result<usize, Error> {
        let prefixes = match size {
            DownloadSize::Tiny => Self::tiny_prefixes(),
            DownloadSize::Sample => Self::sample_prefixes(),
            DownloadSize::Full => Self::all_prefixes(),
        };
        self.download_prefixes(prefixes, progress).await
    }
}

/// Download size options
#[derive(Debug, Clone, Copy)]
pub enum DownloadSize {
    /// 256 files, ~20MB
    Tiny,
    /// 65,536 files, ~2.5GB
    Sample,
    /// 1,048,576 files, ~38GB
    Full,
}

impl DownloadSize {
    /// Parse from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tiny" => Some(DownloadSize::Tiny),
            "sample" => Some(DownloadSize::Sample),
            "full" => Some(DownloadSize::Full),
            _ => None,
        }
    }

    /// Get the number of ranges for this size
    pub fn range_count(&self) -> usize {
        match self {
            DownloadSize::Tiny => 256,
            DownloadSize::Sample => 65_536,
            DownloadSize::Full => 1_048_576,
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            DownloadSize::Tiny => "tiny (256 ranges, ~20MB)",
            DownloadSize::Sample => "sample (65,536 ranges, ~2.5GB)",
            DownloadSize::Full => "full (1,048,576 ranges, ~38GB)",
        }
    }

    fn prefixes(&self) -> Vec<String> {
        match self {
            DownloadSize::Tiny => Downloader::tiny_prefixes(),
            DownloadSize::Sample => Downloader::sample_prefixes(),
            DownloadSize::Full => Downloader::all_prefixes(),
        }
    }
}

/// Downloads HIBP data directly into memory without writing to disk
pub struct InMemoryDownloader {
    concurrent_requests: usize,
    client: reqwest::Client,
}

impl InMemoryDownloader {
    /// Create a new in-memory downloader
    pub fn new() -> Self {
        Self {
            concurrent_requests: 150,
            client: reqwest::Client::builder()
                .user_agent("pir-password-checker/0.1")
                .timeout(std::time::Duration::from_secs(60))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Set the number of concurrent requests
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrent_requests = n;
        self
    }

    /// Download a single range and return the parsed data
    /// Returns a sorted Vec for memory efficiency (uses ~40% less RAM than HashMap)
    async fn download_and_parse(
        &self,
        prefix: &str,
    ) -> Result<(String, Vec<(String, u32)>), Error> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let response = self.client.get(&url).send().await?;
        let body = response.text().await?;

        let mut entries = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: SUFFIX:COUNT
            if let Some((suffix, count_str)) = line.split_once(':') {
                if let Ok(count) = count_str.parse::<u32>() {
                    entries.push((suffix.to_uppercase(), count));
                }
            }
        }
        // HIBP returns sorted data, but ensure it for binary search
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        Ok((prefix.to_string(), entries))
    }

    /// Download HIBP data directly into memory
    /// Returns a HashMap of prefix -> sorted Vec of (suffix, count)
    /// Uses Vec instead of inner HashMap for ~40% memory savings
    pub async fn download_to_memory(
        &self,
        size: DownloadSize,
    ) -> Result<HashMap<String, Vec<(String, u32)>>, Error> {
        let prefixes = size.prefixes();
        let total = prefixes.len();

        info!(
            "Starting in-memory download of {} HIBP dataset ({} ranges)...",
            size.description(),
            total
        );

        let cache: Arc<Mutex<HashMap<String, Vec<(String, u32)>>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(total)));
        let completed = Arc::new(AtomicUsize::new(0));
        let errors = Arc::new(AtomicUsize::new(0));

        stream::iter(prefixes)
            .map(|prefix| {
                let cache = Arc::clone(&cache);
                let completed = Arc::clone(&completed);
                let errors = Arc::clone(&errors);
                async move {
                    // Retry logic
                    let mut attempts = 0;
                    loop {
                        // Wrap with explicit timeout as belt-and-suspenders
                        let result = tokio::time::timeout(
                            tokio::time::Duration::from_secs(60),
                            self.download_and_parse(&prefix)
                        ).await;

                        match result {
                            Ok(Ok((prefix, data))) => {
                                let hash_count = data.len();
                                {
                                    let mut cache = cache.lock().unwrap();
                                    cache.insert(prefix, data);
                                }
                                let current = completed.fetch_add(1, Ordering::SeqCst) + 1;

                                // Log progress at regular intervals
                                if current.is_multiple_of(1000) || current == total {
                                    let pct = (current as f64 / total as f64) * 100.0;
                                    info!(
                                        "Download progress: {}/{} ranges ({:.1}%) - last batch had {} hashes",
                                        current, total, pct, hash_count
                                    );
                                }
                                break;
                            }
                            Ok(Err(e)) => {
                                attempts += 1;
                                if attempts >= 3 {
                                    warn!("Failed to download range {} after 3 attempts: {}", prefix, e);
                                    errors.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                warn!("Retry {}/3 for range {}: {}", attempts, prefix, e);
                                tokio::time::sleep(tokio::time::Duration::from_millis(500 * attempts)).await;
                            }
                            Err(_timeout) => {
                                attempts += 1;
                                if attempts >= 3 {
                                    warn!("Range {} timed out after 3 attempts", prefix);
                                    errors.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                warn!("Timeout retry {}/3 for range {}", attempts, prefix);
                                tokio::time::sleep(tokio::time::Duration::from_millis(500 * attempts)).await;
                            }
                        }
                    }
                }
            })
            .buffer_unordered(self.concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        let error_count = errors.load(Ordering::SeqCst);
        let success_count = completed.load(Ordering::SeqCst);

        if error_count > 0 {
            warn!(
                "Download completed with {} errors ({} successful, {} failed)",
                error_count, success_count, error_count
            );
        } else {
            info!(
                "Download completed successfully: {} ranges loaded",
                success_count
            );
        }

        let result = Arc::try_unwrap(cache)
            .expect("Arc should have single owner")
            .into_inner()
            .unwrap();

        let total_hashes: usize = result.values().map(|m| m.len()).sum();
        info!(
            "In-memory dataset ready: {} ranges, {} total hashes",
            result.len(),
            total_hashes
        );

        Ok(result)
    }
}

impl Default for InMemoryDownloader {
    fn default() -> Self {
        Self::new()
    }
}

/// Downloads HIBP data into compact binary format
/// Uses ~24 bytes per entry vs ~63 bytes with HashMap+String
pub struct CompactDownloader {
    concurrent_requests: usize,
    client: reqwest::Client,
}

impl CompactDownloader {
    /// Create a new compact downloader
    pub fn new() -> Self {
        Self {
            concurrent_requests: 150,
            client: reqwest::Client::builder()
                .user_agent("pir-password-checker/0.1")
                .timeout(std::time::Duration::from_secs(60))
                .connect_timeout(std::time::Duration::from_secs(10))
                .pool_max_idle_per_host(200)
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Set the number of concurrent requests
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrent_requests = n;
        self
    }

    /// Download a single range and return entries as binary hash+count
    async fn download_range_compact(&self, prefix: &str) -> Result<Vec<HashEntry>, Error> {
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        let response = self.client.get(&url).send().await?;
        let body = response.text().await?;

        let mut entries = Vec::with_capacity(2000); // typical range size

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: SUFFIX:COUNT
            if let Some((suffix, count_str)) = line.split_once(':') {
                if let Ok(count) = count_str.parse::<u32>() {
                    // Combine prefix + suffix and decode to bytes
                    if let Some(hash) = Self::decode_hash(prefix, suffix) {
                        entries.push(HashEntry::new(hash, count));
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Decode prefix (5 hex) + suffix (35 hex) to 20 bytes
    fn decode_hash(prefix: &str, suffix: &str) -> Option<[u8; 20]> {
        if prefix.len() != 5 || suffix.len() != 35 {
            return None;
        }

        let mut bytes = [0u8; 20];
        let full = format!("{}{}", prefix, suffix);

        for (i, chunk) in full.as_bytes().chunks(2).enumerate() {
            let high = Self::hex_nibble(chunk[0])?;
            let low = Self::hex_nibble(chunk[1])?;
            bytes[i] = (high << 4) | low;
        }

        Some(bytes)
    }

    #[inline]
    fn hex_nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    /// Download HIBP data into compact binary format
    ///
    /// Memory usage: ~24 bytes per entry
    /// Full database (~2B entries): ~48 GB
    pub async fn download_compact(&self, size: DownloadSize) -> Result<CompactHibpData, Error> {
        let prefixes = size.prefixes();
        let total = prefixes.len();

        // Estimate total entries: ~2000 per prefix
        let estimated_entries = total * 2000;

        info!(
            "Starting compact download of {} HIBP dataset ({} ranges, ~{} entries)...",
            size.description(),
            total,
            estimated_entries
        );
        info!(
            "Estimated memory: {} GB",
            (estimated_entries * 24) as f64 / 1024.0 / 1024.0 / 1024.0
        );

        // Collect all entries into a single Vec
        let all_entries: Arc<Mutex<Vec<HashEntry>>> =
            Arc::new(Mutex::new(Vec::with_capacity(estimated_entries)));
        let completed = Arc::new(AtomicUsize::new(0));
        let errors = Arc::new(AtomicUsize::new(0));
        let total_hashes = Arc::new(AtomicUsize::new(0));

        stream::iter(prefixes)
            .map(|prefix| {
                let all_entries = Arc::clone(&all_entries);
                let completed = Arc::clone(&completed);
                let errors = Arc::clone(&errors);
                let total_hashes = Arc::clone(&total_hashes);
                async move {
                    let mut attempts = 0;
                    loop {
                        let result = tokio::time::timeout(
                            tokio::time::Duration::from_secs(60),
                            self.download_range_compact(&prefix),
                        )
                        .await;

                        match result {
                            Ok(Ok(entries)) => {
                                let hash_count = entries.len();
                                total_hashes.fetch_add(hash_count, Ordering::SeqCst);

                                // Append to main vector
                                {
                                    let mut all = all_entries.lock().unwrap();
                                    all.extend(entries);
                                }

                                let current = completed.fetch_add(1, Ordering::SeqCst) + 1;
                                if current.is_multiple_of(1000) || current == total {
                                    let pct = (current as f64 / total as f64) * 100.0;
                                    let total_h = total_hashes.load(Ordering::SeqCst);
                                    let mem_gb = (total_h * 24) as f64 / 1024.0 / 1024.0 / 1024.0;
                                    info!(
                                        "Progress: {}/{} ranges ({:.1}%) - {} hashes ({:.2} GB)",
                                        current, total, pct, total_h, mem_gb
                                    );
                                }
                                break;
                            }
                            Ok(Err(e)) => {
                                attempts += 1;
                                if attempts >= 3 {
                                    warn!(
                                        "Failed to download range {} after 3 attempts: {}",
                                        prefix, e
                                    );
                                    errors.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                warn!("Retry {}/3 for range {}: {}", attempts, prefix, e);
                                tokio::time::sleep(tokio::time::Duration::from_millis(
                                    500 * attempts,
                                ))
                                .await;
                            }
                            Err(_timeout) => {
                                attempts += 1;
                                if attempts >= 3 {
                                    warn!("Range {} timed out after 3 attempts", prefix);
                                    errors.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                warn!("Timeout retry {}/3 for range {}", attempts, prefix);
                                tokio::time::sleep(tokio::time::Duration::from_millis(
                                    500 * attempts,
                                ))
                                .await;
                            }
                        }
                    }
                }
            })
            .buffer_unordered(self.concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        let error_count = errors.load(Ordering::SeqCst);
        let success_count = completed.load(Ordering::SeqCst);
        let hash_count = total_hashes.load(Ordering::SeqCst);

        if error_count > 0 {
            warn!(
                "Download completed with {} errors ({} successful ranges, {} failed)",
                error_count, success_count, error_count
            );
        }

        info!("Sorting {} entries...", hash_count);

        // Extract entries and sort
        let mut entries = Arc::try_unwrap(all_entries)
            .expect("Arc should have single owner")
            .into_inner()
            .unwrap();

        entries.sort_unstable_by(|a, b| a.hash.cmp(&b.hash));
        entries.shrink_to_fit();

        let mem_bytes = entries.len() * std::mem::size_of::<HashEntry>();
        info!(
            "Compact dataset ready: {} hashes, {:.2} GB",
            entries.len(),
            mem_bytes as f64 / 1024.0 / 1024.0 / 1024.0
        );

        Ok(CompactHibpData::from_sorted(entries))
    }
}

impl Default for CompactDownloader {
    fn default() -> Self {
        Self::new()
    }
}

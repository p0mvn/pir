//! HaveIBeenPwned Pwned Passwords library
//!
//! Download and query the HIBP Pwned Passwords database.
//!
//! # Example
//!
//! ```no_run
//! use hibp::{Downloader, PasswordChecker};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), hibp::Error> {
//!     // Download a sample of the database
//!     let downloader = Downloader::new("./data/ranges");
//!     downloader.download_sample().await?;
//!
//!     // Check if a password is pwned
//!     let checker = PasswordChecker::from_directory("./data/ranges")?;
//!     if let Some(count) = checker.check("password123")? {
//!         println!("Password found in {} breaches!", count);
//!     }
//!     Ok(())
//! }
//! ```

mod checker;
mod compact;
mod downloader;
mod error;

pub use checker::{CheckerStats, CompactChecker, PasswordChecker};
pub use compact::{CompactHibpData, HashEntry};
pub use downloader::{
    CompactDownloader, DownloadProgress, DownloadSize, Downloader, InMemoryDownloader,
};
pub use error::Error;

/// SHA-1 hash a password and return uppercase hex string
pub fn hash_password(password: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode_upper(result)
}

/// Split a SHA-1 hash into prefix (5 chars) and suffix (35 chars)
pub fn split_hash(hash: &str) -> (&str, &str) {
    hash.split_at(5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        // Known SHA-1 hash of "password"
        assert_eq!(
            hash_password("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    #[test]
    fn test_split_hash() {
        let hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let (prefix, suffix) = split_hash(hash);
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }
}

//! Example: Check if passwords are pwned
//!
//! Run: cargo run --example check

use hibp::PasswordChecker;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the test data we downloaded
    let checker = PasswordChecker::from_directory("./test_data")?;

    println!("HIBP Password Checker");
    println!("=====================");
    println!();

    // Test some passwords
    // Note: only passwords whose SHA-1 starts with "000" will be found
    // in our tiny sample (prefixes 00000-000FF)

    let test_passwords = [
        "password", // SHA-1: 5BAA6... (not in tiny sample)
        "123456",   // SHA-1: 7C4A8... (not in tiny sample)
        "letmein",  // SHA-1: 0D107... (not in tiny sample, but close!)
    ];

    for password in &test_passwords {
        let hash = hibp::hash_password(password);
        let (prefix, _suffix) = hibp::split_hash(&hash);

        print!("Checking '{}' (hash prefix: {})... ", password, prefix);

        match checker.check(password) {
            Ok(Some(count)) => println!("PWNED! Found {} times", count),
            Ok(None) => println!("Not found (or not in sample)"),
            Err(e) => println!("Error: {}", e),
        }
    }

    // Let's also check by directly looking at what we have
    println!();
    println!("Sample of hashes in range 00000:");

    let file_path = std::path::Path::new("./test_data/00000");
    if file_path.exists() {
        let content = std::fs::read_to_string(file_path)?;
        for line in content.lines().take(5) {
            println!("  00000{}", line);
        }
    }

    Ok(())
}

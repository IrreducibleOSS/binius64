pub mod sha256;

// #[cfg(test)]
// mod test;

pub use sha256::compress;

/// Get number of SHA256 rounds from environment
/// - "small" or "2": 2 rounds (for fast testing)
/// - "full", "64", or unset: 64 rounds (complete SHA256)
pub fn get_num_rounds() -> usize {
    match std::env::var("SHA256_ROUNDS").as_deref() {
        Ok("small") | Ok("2") => 2,
        _ => 64,  // Default to full SHA256 (64 rounds)
    }
}
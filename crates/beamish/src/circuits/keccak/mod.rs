pub mod keccak;
pub mod test;

use crate::circuits::keccak::keccak::ROUNDS;

/// Get the number of Keccak rounds from environment variable
/// Defaults to 24 (full Keccak-f[1600])
pub fn get_num_rounds() -> usize {
    match std::env::var("KECCAK_ROUNDS").as_deref() {
        Ok("1") => 1,
        Ok("2") => 2,
        Ok("4") => 4,
        Ok("12") => 12,
        _ => ROUNDS,  // Default to 24 rounds
    }
}
//! ECDSA verification circuits

mod bitcoin;
mod ecrecover;
mod scalar_mul;

pub use bitcoin::verify as bitcoin_verify;
pub use ecrecover::ecrecover;

#[cfg(test)]
mod tests;

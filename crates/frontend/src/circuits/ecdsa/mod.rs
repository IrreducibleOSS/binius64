//! ECDSA verification circuits

mod bitcoin;
mod ecrecover;
mod shamirs_trick;

pub use bitcoin::verify as bitcoin_verify;
pub use ecrecover::ecrecover;

#[cfg(test)]
mod tests;

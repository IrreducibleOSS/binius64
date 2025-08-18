//! ECDSA verification circuits

mod bitcoin;
mod shamirs_trick;

pub use bitcoin::verify as bitcoin_verify;

#[cfg(test)]
mod tests;

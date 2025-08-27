//! Tweaked Keccak-256 circuits for hash-based signatures.
mod base;
mod chain;
mod message;

pub use chain::{CHAIN_TWEAK, FIXED_MESSAGE_OVERHEAD, build_chain_hash, circuit_chain_hash};
pub use message::{MESSAGE_TWEAK, build_message_hash, circuit_message_hash};

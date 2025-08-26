//! Tweaked Keccak-256 circuits for hash-based signatures.
mod base;
mod chain;
mod message;

pub use chain::{CHAIN_TWEAK, FIXED_MESSAGE_OVERHEAD, build_chain_tweak, verify_chain_tweak};
pub use message::{MESSAGE_TWEAK, build_message_tweak, verify_message_tweak};

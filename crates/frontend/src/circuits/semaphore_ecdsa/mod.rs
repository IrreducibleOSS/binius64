//! Semaphore with ECDSA key derivation on secp256k1.
//!
//! This variant implements the full Semaphore protocol including:
//! - ECDSA key derivation using existing secp256k1 circuits
//! - Keccak-256 for hashing
//! - Nullifier generation from the secret scalar
//!
//! This reuses existing circuits from:
//! - circuits/ecdsa/ for signature operations
//! - circuits/secp256k1/ for elliptic curve operations
//! - circuits/keccak/ for hashing

pub mod circuit;
pub mod reference;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod scaling_test;

pub use circuit::SemaphoreProofECDSA;
pub use reference::{IdentityECDSA, MerkleTree, MerkleProof};
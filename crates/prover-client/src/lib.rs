//! Simplified open-source interface to the Binius prover using serialization
//! 
//! This crate provides a clean API that uses serialization to communicate with
//! the closed-source prover, greatly simplifying the FFI boundary.

pub mod error;
pub mod ffi;
pub mod prover_client;

// Include the FFI implementation when building as cdylib
#[cfg(feature = "ffi-impl")]
pub mod ffi_impl;

pub use error::{ProverError, Result};
pub use prover_client::ProverClient;

// Re-export types from binius-core that users will need
pub use binius_core::constraint_system::{ConstraintSystem, ValuesData};
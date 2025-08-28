//! Open-source interface to the Binius prover
//! 
//! This crate provides a clean, safe API to interact with the closed-source
//! Binius prover implementation.
//!
//! # Example
//!
//! ```no_run
//! use binius_prover_interface::{Prover, ProverConfig, Witness};
//!
//! // Create a prover with default configuration
//! let prover = Prover::default().expect("Failed to create prover");
//!
//! // Create a witness
//! let witness = Witness::new(vec![1, 0, 1, 1, 0, 1]);
//!
//! // Generate a proof
//! let proof = prover.prove(&witness).expect("Failed to generate proof");
//! println!("Proof size: {} bytes", proof.len());
//! ```

pub use crate::config::{ProverConfig, ProverConfigBuilder};
pub use crate::error::ProverError;
pub use crate::prover::Prover;
pub use crate::types::{Proof, Witness};

mod config;
mod error;
mod ffi;
mod prover;
mod types;

/// Result type for prover operations
pub type Result<T> = std::result::Result<T, ProverError>;
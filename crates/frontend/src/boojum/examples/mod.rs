//! Example circuits implemented in the Boojum paradigm
//!
//! This module contains example implementations showing how to use the Boojum
//! architecture for various types of circuits. Each example demonstrates:
//!
//! 1. Pure witness computation (just Rust code)
//! 2. Tracked witness computation (records operations)
//! 3. Constraint compilation (generates optimal constraints)
//!
//! These examples serve as templates for implementing new circuits.

pub mod subset_sum;
pub mod multiplexer;
pub mod add128;

// Re-export for convenience
pub use subset_sum::{SubsetSumBoojum, SubsetSumInput, SubsetSumOutput};
pub use multiplexer::{MultiplexerBoojum, MultiplexerInput, MultiplexerOutput, Mux2Boojum};
pub use add128::{Add128Boojum, Add128Input, Add128Output, Add256Boojum};
//! Example circuits implemented in the Spark paradigm
//!
//! This module contains example implementations showing how to use the Spark
//! architecture for various types of circuits.
//!
//! ## Naming Convention:
//! - `spark_*`: Uses WitnessContext (witness-first approach)
//! - `reference_*`: Pure witness computation without tracking (reference implementation)
//!
//! ## Each example demonstrates:
//! 1. Pure witness computation (just Rust code, no tracking)
//! 2. Tracked witness computation (records operations for constraint compilation)
//!
//! These examples serve as templates for implementing new circuits.

pub mod subset_sum;
pub mod multiplexer;
pub mod add128;

// Re-export main functions and types for convenience
pub use subset_sum::{
    SubsetSumInput, SubsetSumOutput,
    spark_subset_sum, reference_subset_sum,
};

pub use multiplexer::{
    MultiplexerInput, MultiplexerOutput,
    spark_mux2, reference_mux2,
    spark_multiplexer, reference_multiplexer,
};

pub use add128::{
    Add128Input, Add128Output,
    spark_add128, reference_add128,
    spark_add128_with_overflow,
};
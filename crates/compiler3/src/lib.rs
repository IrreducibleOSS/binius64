//! Beamish: A Predicate-Based Compiler for Zero-Knowledge Constraint Systems
//! 
//! This compiler transforms high-level predicate specifications into optimized
//! constraint systems while preserving auxiliary witness computability.

pub mod types;
pub mod ir;
pub mod decompose;
pub mod pack;
pub mod synthesis;

pub use types::*;
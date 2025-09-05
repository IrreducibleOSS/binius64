//! Predicate-Based Constraint Compiler with Witness Recipe Generation
//!
//! This compiler transforms verification predicates into:
//! 1. Optimized constraint systems
//! 2. Witness computation functions
//!
//! Key innovation: Maintains witness computability while aggressively optimizing constraints
//! through tracking of witness recipes and dependency graphs.

pub mod predicate;
pub mod expression;
pub mod witness;
pub mod dependency;
pub mod packing;
pub mod recipe;
pub mod filler;
pub mod compiler;
pub mod constraint_gen;
pub mod error;
pub mod lang;

pub use predicate::*;
pub use expression::*;
pub use witness::*;
pub use compiler::PredicateCompiler;
pub use filler::WitnessFiller;
pub use error::CompilerError;
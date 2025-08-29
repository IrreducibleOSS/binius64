//! Beamish: Functional expression-based constraint generation for Binius64

pub mod expr;
pub mod types;
pub mod ops;
pub mod constraints;
pub mod optimize;

// Re-export core types and functions
pub use expr::{Expr, val, witness, constant, zero, ones};
pub use types::{Field64, U32, U64, Bool};
pub use ops::*;
pub use constraints::{to_constraints, to_constraints_default, Constraint};
pub use optimize::{optimize, optimize_default, OptimizationConfig};
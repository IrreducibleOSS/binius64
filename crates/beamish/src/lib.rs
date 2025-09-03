//! Beamish: Functional expression-based constraint generation for Binius64

pub mod expr;
pub mod types;
pub mod ops;
pub mod constraints;
pub mod generate;
pub mod compute;
pub mod reference;
// pub mod optimize; // Temporarily disabled until Box->Rc conversion
pub mod circuits;

// Re-export core types and functions
pub use expr::{Expr, val, witness, constant, zero, ones};
pub use types::{Field64, U32, U64, Bool};
pub use ops::*;
pub use constraints::{to_constraints, to_constraints_default, Constraint};
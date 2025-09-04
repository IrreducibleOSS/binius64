//! Binius Compiler - Multi-layered constraint compilation
//!
//! Architecture with separation of concerns within the crate:
//! 
//! - ops/ - High-level operations that create Call nodes
//! - expr/ - Expression trees as constraint recipes  
//! - term/ - Atomic constraint terms (MORE granular than constraints)
//! - types/ - Type system
//!
//! Flow: Operations → Call nodes → Terms (XOR,SHIFT,AND,MUL) → Recipes → Core Constraints
//!
//! Key insight: Terms are MORE granular than constraints! 
//! In formal logic, a term is a basic building block - here they are atomic operations
//! that recipes combine into final constraints, optimizing free operations.

pub mod types;
pub mod expr;
pub mod ops;
pub mod term;

pub use types::*;
pub use expr::*;
pub use ops::*;
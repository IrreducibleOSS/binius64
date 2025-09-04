//! Operation combinators for building expressions

pub mod bitwise;      // Bitwise ops: XOR, AND, OR, NOT, shifts, rotations, equality, U32 decomposed ops
pub mod arithmetic;   // Arithmetic ops: add, sub, mul, div, mod (32-bit and 64-bit)
pub mod conditional;  // Comparison and conditional ops: icmp_ult, icmp_eq, select
pub mod control;      // Control flow ops: dynamic_fold, predicated iteration

// Re-export all operations
pub use bitwise::*;
pub use arithmetic::*;
pub use conditional::*;
pub use control::*;
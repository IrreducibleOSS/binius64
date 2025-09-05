//! Operations - high-level typed operations that create Call nodes
//!
//! This module contains all the operation logic but maintains separation:
//! - Operations create Call nodes using the expr primitives
//! - Compiler (grains module) generates constraints from Call nodes
//! - Clear separation of concerns within the same crate

pub mod arithmetic;
pub mod bitwise;  
pub mod compare;

pub use arithmetic::*;
pub use bitwise::*;
pub use compare::*;
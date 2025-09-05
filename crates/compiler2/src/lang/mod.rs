//! High-level typed language using existing recipe system
//!
//! This module provides typed values that work with the existing PredicateCompiler
//! and its built-in recipe system for witness computation.
//!
//! Example usage:
//! ```
//! use binius_compiler2::{PredicateCompiler};
//! use binius_compiler2::lang::U32Value;
//! 
//! let mut compiler = PredicateCompiler::new();
//! let a = U32Value::new(compiler.allocator().new_private());
//! let b = U32Value::new(compiler.allocator().new_private());
//! let result = compiler.allocator().new_auxiliary();
//! 
//! compiler.builder().add_equals(result, a.xor(&b));
//! let (constraints, filler) = compiler.compile().unwrap();
//! ```

pub mod types;

pub use types::*;
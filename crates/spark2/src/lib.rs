//! Spark2: Expression Rewriting Framework for Binius64
//!
//! This crate provides an expression-first approach to constraint generation,
//! leveraging the rich constraint language of Binius64 to optimize high-level
//! operations into minimal constraint sets.

pub mod core;
pub mod patterns;
pub mod gadgets;

// Re-export key types
pub use core::{
    expression::{Expr, Value, BinOp, UnOp},
    pattern::Pattern,
    rewrite::Rewriter,
};
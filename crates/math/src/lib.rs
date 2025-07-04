// Copyright 2024-2025 Irreducible Inc.

//! Mathematical primitives used in Binius, built atop the `binius-field` crate.
//!
//! This crate provides a variety of mathematical primitives used in Binius, including:
//!
//! * Multilinear polynomials
//! * Univariate polynomials
//! * Matrix operations
//! * Additive number-theoretic transform
//! * Error-correcting codes

pub mod binary_subspace;
mod error;
pub mod field_buffer;
pub mod matrix;
pub mod ntt;
pub mod reed_solomon;

pub use binary_subspace::BinarySubspace;
pub use error::Error;
pub use field_buffer::{FieldBuffer, FieldSlice, FieldSliceMut};
pub use matrix::Matrix;
pub use reed_solomon::ReedSolomonCode;

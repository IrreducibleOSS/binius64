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
pub mod fold;
pub mod inner_product;
pub mod line;
pub mod matrix;
pub mod multilinear;
pub mod ntt;
pub mod reed_solomon;
#[cfg(feature = "test-utils")]
pub mod test_utils;

pub use binary_subspace::BinarySubspace;
pub use error::Error;
pub use field_buffer::{FieldBuffer, FieldSlice, FieldSliceMut};
pub use matrix::Matrix;
pub use reed_solomon::ReedSolomonCode;

pub fn evaluate_univariate<F: binius_field::Field>(coeffs: &[F], x: F) -> F {
	// Evaluate using Horner's method
	coeffs
		.iter()
		.rfold(F::ZERO, |eval, &coeff| eval * x + coeff)
}

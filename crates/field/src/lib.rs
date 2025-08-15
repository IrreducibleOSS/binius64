// Copyright 2023-2025 Irreducible Inc.

//! Binary tower field implementations for use in Binius.
//!
//! This library implements binary tower field arithmetic. The canonical binary field tower
//! construction is specified in [DP23], section 2.3. This is a family of binary fields with
//! extension degree $2^{\iota}$ for any tower height $\iota$. Mathematically, we label these sets
//! $T_{\iota}$.
//!
//! [DP23]: https://eprint.iacr.org/2023/1784

pub mod aes_field;
pub mod arch;
pub mod arithmetic_traits;
pub mod as_packed_field;
pub mod binary_field;
mod binary_field_arithmetic;
pub mod byte_iteration;
pub mod error;
pub mod extension;
pub mod field;
pub mod ghash;
pub mod linear_transformation;
mod macros;
pub mod packed;
pub mod packed_aes_field;
pub mod packed_binary_field;
pub mod packed_extension;
pub mod packed_extension_ops;
mod packed_ghash;
mod packed_polyval;
pub mod polyval;
mod random;
#[cfg(test)]
mod tests;
mod tracing;
pub mod transpose;
mod underlier;
pub mod util;

pub use aes_field::*;
pub use binary_field::*;
pub use error::*;
pub use extension::*;
pub use field::Field;
pub use ghash::*;
pub use packed::PackedField;
pub use packed_aes_field::*;
pub use packed_binary_field::*;
pub use packed_extension::*;
pub use packed_extension_ops::*;
pub use packed_ghash::*;
pub use packed_polyval::*;
pub use polyval::*;
pub use random::Random;
pub use transpose::{Error as TransposeError, square_transpose};
pub use underlier::{UnderlierWithBitOps, WithUnderlier};

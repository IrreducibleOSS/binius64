//! Arbitrary-precision bignum arithmetic for circuits.
//!
//! This module provides operations on big integers represented as vectors of `Wire` elements,
//! where each `Wire` represents a 64-bit limb. The representation uses little-endian ordering,
//! meaning the least significant limb is at index 0.

mod addsub;
mod biguint;
mod mul;
mod reduce;

#[cfg(test)]
mod tests;

pub use addsub::{add, sub};
pub use biguint::{BigUint, assert_eq};
pub use mul::{mul, square};
pub use reduce::{ModReduce, PseudoMersenneModReduce};

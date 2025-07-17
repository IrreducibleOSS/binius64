// Copyright 2023-2025 Irreducible Inc.

//! Portable implementation of packed GHASH field operations.

use std::ops::Mul;

use super::{packed::PackedPrimitiveType, packed_macros::impl_broadcast};
use crate::{
	BinaryField128bGhash,
	arch::{PairwiseStrategy, ReuseMultiplyStrategy},
	arithmetic_traits::{InvertOrZero, impl_square_with, impl_transformation_with_strategy},
};

/// GHASH field multiplication using the standard bit-by-bit algorithm.
/// This implements multiplication in GF(2^128) with the irreducible polynomial
/// x^128 + x^7 + x^2 + x + 1, represented as 0xe1000000000000000000000000000000.
/// This is a straightforward implementation portable version of russian peasant multiplication.
/// We most probably won't use this field for the platforms that don't have caryless
/// multiplication instruction, so no need to optimize this for now.
pub fn ghash_mul(mut x: u128, mut y: u128) -> u128 {
	let mut z: u128 = 0;

	for _ in 0..128 {
		// If the top bit of y is set, XOR current x into accumulator z
		if (y & (1 << 127)) != 0 {
			z ^= x;
		}
		// Save the bit that will be shifted out (rightmost/LSB of x)
		let lsb = x & 1;
		// Shift x right by 1 (polynomial division by x)
		x >>= 1;
		// If the bit we shifted out was 1, reduce modulo the GCM polynomial
		if lsb != 0 {
			x ^= 0xe1000000000000000000000000000000u128;
		}
		// Shift y left by 1, bringing the next bit into the top position
		y <<= 1;
	}
	z
}

pub type PackedBinaryGhash1x128b = PackedPrimitiveType<u128, BinaryField128bGhash>;

// Define broadcast
impl_broadcast!(u128, BinaryField128bGhash);

// Define multiply
impl Mul for PackedBinaryGhash1x128b {
	type Output = Self;

	fn mul(self, rhs: Self) -> Self::Output {
		crate::tracing::trace_multiplication!(PackedBinaryGhash1x128b);

		ghash_mul(self.0, rhs.0).into()
	}
}

impl InvertOrZero for PackedBinaryGhash1x128b {
	fn invert_or_zero(self) -> Self {
		todo!("Implement packed GHASH inversion")
	}
}

// Implement squaring using the default strategy
impl_square_with!(PackedBinaryGhash1x128b @ ReuseMultiplyStrategy);

// Implement pairwise strategy for efficient batch operations
impl_transformation_with_strategy!(PackedBinaryGhash1x128b, PairwiseStrategy);

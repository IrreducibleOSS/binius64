// Copyright 2024-2025 Irreducible Inc.

use std::ops::Mul;

use super::{
	super::portable::{
		packed::PackedPrimitiveType,
		packed_arithmetic::{alphas, impl_tower_constants},
	},
	m128::M128,
	packed_macros::*,
	simd_arithmetic::{
		packed_aes_16x8b_into_tower, packed_tower_16x8b_invert_or_zero,
		packed_tower_16x8b_multiply, packed_tower_16x8b_multiply_alpha, packed_tower_16x8b_square,
	},
};
use crate::{
	BinaryField8b, PackedAESBinaryField16x8b,
	arch::portable::packed_macros::*,
	arithmetic_traits::{
		InvertOrZero, MulAlpha, Square, impl_invert_with, impl_mul_alpha_with, impl_mul_with,
		impl_square_with, impl_transformation_with_strategy,
	},
	underlier::WithUnderlier,
};

define_packed_binary_fields!(
	underlier: M128,
	packed_fields: [
		packed_field {
			name: PackedBinaryField128x1b,
			scalar: BinaryField1b,
			alpha_idx: 0,
			mul: (None),
			square: (None),
			invert: (None),
			mul_alpha: (None),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField64x2b,
			scalar: BinaryField2b,
			alpha_idx: 1,
			mul: (SimdStrategy),
			square: (SimdStrategy),
			invert: (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField32x4b,
			scalar: BinaryField4b,
			alpha_idx: 2,
			mul: (SimdStrategy),
			square: (SimdStrategy),
			invert: (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField8x16b,
			scalar: BinaryField16b,
			alpha_idx: 4,
			mul: (SimdStrategy),
			square: (SimdStrategy),
			invert: (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField4x32b,
			scalar: BinaryField32b,
			alpha_idx: 5,
			mul: (PackedStrategy),
			square: (PairwiseStrategy),
			invert: (PairwiseStrategy),
			mul_alpha: (SimdStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField2x64b,
			scalar: BinaryField64b,
			alpha_idx: 6,
			mul: (PairwiseStrategy),
			square: (PairwiseStrategy),
			invert: (PairwiseStrategy),
			mul_alpha: (PairwiseStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField1x128b,
			scalar: BinaryField128b,
			alpha_idx: _,
			mul: (PairwiseRecursiveStrategy),
			square: (PairwiseRecursiveStrategy),
			invert: (PairwiseRecursiveStrategy),
			mul_alpha: (PairwiseRecursiveStrategy),
			transform: (PairwiseStrategy),
		},
	]
);

// PackedBinaryField16x8b is constructed separately
pub type PackedBinaryField16x8b = PackedPrimitiveType<M128, BinaryField8b>;
impl_serialize_deserialize_for_packed_binary_field!(PackedBinaryField16x8b);
impl_tower_constants!(BinaryField8b, M128, { M128::from_u128(alphas!(u128, 3)) });

impl Mul for PackedBinaryField16x8b {
	type Output = Self;

	fn mul(self, rhs: Self) -> Self::Output {
		crate::tracing::trace_multiplication!(PackedBinaryField16x8b);

		self.mutate_underlier(|underlier| {
			packed_tower_16x8b_multiply(underlier, rhs.to_underlier())
		})
	}
}

impl Square for PackedBinaryField16x8b {
	fn square(self) -> Self {
		self.mutate_underlier(packed_tower_16x8b_square)
	}
}

impl InvertOrZero for PackedBinaryField16x8b {
	fn invert_or_zero(self) -> Self {
		self.mutate_underlier(packed_tower_16x8b_invert_or_zero)
	}
}

impl MulAlpha for PackedBinaryField16x8b {
	#[inline]
	fn mul_alpha(self) -> Self {
		self.mutate_underlier(packed_tower_16x8b_multiply_alpha)
	}
}

impl_transformation_with_strategy!(PackedBinaryField16x8b, crate::arch::PackedStrategy);

impl From<PackedAESBinaryField16x8b> for PackedBinaryField16x8b {
	fn from(value: PackedAESBinaryField16x8b) -> Self {
		Self::from_underlier(packed_aes_16x8b_into_tower(value.to_underlier()))
	}
}

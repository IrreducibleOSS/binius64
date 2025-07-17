// Copyright 2024-2025 Irreducible Inc.

use std::ops::Mul;

use super::{
	m128::M128,
	packed_macros::*,
	simd_arithmetic::{
		packed_aes_16x8b_invert_or_zero, packed_aes_16x8b_mul_alpha, packed_aes_16x8b_multiply,
		packed_tower_16x8b_into_aes,
	},
};
use crate::{
	PackedBinaryField16x8b,
	aes_field::AESTowerField8b,
	arch::portable::{
		packed::PackedPrimitiveType,
		packed_arithmetic::{alphas, impl_tower_constants},
		packed_macros::*,
	},
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
			name: PackedAESBinaryField8x16b,
			scalar: AESTowerField16b,
			alpha_idx: 4,
			mul: (SimdStrategy),
			square: (None),
			invert: (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField4x32b,
			scalar: AESTowerField32b,
			alpha_idx: 5,
			mul: (SimdStrategy),
			square: (None),
			invert: (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField2x64b,
			scalar: AESTowerField64b,
			alpha_idx: 6,
			mul: (PairwiseStrategy),
			square: (PairwiseStrategy),
			invert: (PairwiseStrategy),
			mul_alpha: (PairwiseStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField1x128b,
			scalar: AESTowerField128b,
			alpha_idx: _,
			mul: (PairwiseRecursiveStrategy),
			square: (PairwiseRecursiveStrategy),
			invert: (PairwiseRecursiveStrategy),
			mul_alpha: (PairwiseRecursiveStrategy),
			transform: (PairwiseStrategy),
		},
	]
);

pub type PackedAESBinaryField16x8b = PackedPrimitiveType<M128, AESTowerField8b>;
impl_tower_constants!(AESTowerField8b, M128, {
	M128::from_u128(0x00d300d300d300d300d300d300d300d3)
});
impl Mul for PackedAESBinaryField16x8b {
	type Output = Self;

	fn mul(self, rhs: Self) -> Self {
		crate::tracing::trace_multiplication!(PackedAESBinaryField16x8b);

		self.mutate_underlier(|underlier| packed_aes_16x8b_multiply(underlier, rhs.to_underlier()))
	}
}
impl Square for PackedAESBinaryField16x8b {
	fn square(self) -> Self {
		self * self
	}
}
impl Square for PackedAESBinaryField8x16b {
	fn square(self) -> Self {
		self * self
	}
}
impl Square for PackedAESBinaryField4x32b {
	fn square(self) -> Self {
		self * self
	}
}
impl InvertOrZero for PackedAESBinaryField16x8b {
	fn invert_or_zero(self) -> Self {
		self.mutate_underlier(packed_aes_16x8b_invert_or_zero)
	}
}
impl MulAlpha for PackedAESBinaryField16x8b {
	fn mul_alpha(self) -> Self {
		self.mutate_underlier(packed_aes_16x8b_mul_alpha)
	}
}
impl_transformation_with_strategy!(PackedAESBinaryField16x8b, crate::arch::PackedStrategy);
impl From<PackedBinaryField16x8b> for PackedAESBinaryField16x8b {
	fn from(value: PackedBinaryField16x8b) -> Self {
		Self::from_underlier(packed_tower_16x8b_into_aes(value.to_underlier()))
	}
}

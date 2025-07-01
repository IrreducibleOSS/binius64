// Copyright 2024-2025 Irreducible Inc.

use super::{
	packed::PackedPrimitiveType, packed_arithmetic::TowerConstants,
	reuse_multiply_arithmetic::Alpha,
};
use crate::{
	BinaryField1b, BinaryField2b,
	arch::portable::packed_macros::{portable_macros::*, *},
	arithmetic_traits::{
		impl_invert_with, impl_mul_alpha_with, impl_mul_with, impl_square_with,
		impl_transformation_with_strategy,
	},
	underlier::{U2, UnderlierType},
};

define_packed_binary_fields!(
	underlier: U2,
	packed_fields: [
		packed_field {
			name: PackedBinaryField2x1b,
			scalar: BinaryField1b,
			alpha_idx: _,
			mul: (None),
			square: (None),
			invert: (None),
			mul_alpha: (None),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField1x2b,
			scalar: BinaryField2b,
			alpha_idx: _,
			mul: (PairwiseTableStrategy),
			square: (ReuseMultiplyStrategy),
			invert: (PairwiseTableStrategy),
			mul_alpha: (ReuseMultiplyStrategy),
			transform: (PairwiseStrategy),
		}
	]
);

// Define operations for height 0
impl_ops_for_zero_height!(PackedBinaryField2x1b);

// Define constants
impl TowerConstants<U2> for BinaryField1b {
	const ALPHAS_ODD: U2 = U2::new(<Self as TowerConstants<u8>>::ALPHAS_ODD);
}
impl TowerConstants<U2> for BinaryField2b {
	const ALPHAS_ODD: U2 = U2::new(<Self as TowerConstants<u8>>::ALPHAS_ODD);
}

// Define multiply by alpha
impl Alpha for PackedBinaryField1x2b {
	#[inline]
	fn alpha() -> Self {
		Self::from_underlier(U2::new_unchecked(0x02))
	}
}

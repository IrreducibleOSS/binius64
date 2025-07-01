// Copyright 2024-2025 Irreducible Inc.

use cfg_if::cfg_if;

use super::{m512::M512, packed_macros::*};
use crate::{
	arch::portable::{
		packed::PackedPrimitiveType,
		packed_arithmetic::{alphas, impl_tower_constants},
		packed_macros::*,
	},
	arithmetic_traits::{
		impl_invert_with, impl_mul_alpha_with, impl_mul_with, impl_square_with,
		impl_transformation_with_strategy,
	},
};

define_packed_binary_fields!(
	underlier: M512,
	packed_fields: [
		packed_field {
			name: PackedBinaryField512x1b,
			scalar: BinaryField1b,
			alpha_idx: 0,
			mul:       (None),
			square:    (None),
			invert:    (None),
			mul_alpha: (None),
			transform: (SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField256x2b,
			scalar: BinaryField2b,
			alpha_idx: 1,
			mul:       (PackedStrategy),
			square:    (PackedStrategy),
			invert:    (PackedStrategy),
			mul_alpha: (PackedStrategy),
			transform: (SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField128x4b,
			scalar: BinaryField4b,
			alpha_idx: 2,
			mul:       (PackedStrategy),
			square:    (PackedStrategy),
			invert:    (PackedStrategy),
			mul_alpha: (PackedStrategy),
			transform: (SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField64x8b,
			scalar: BinaryField8b,
			alpha_idx: 3,
			mul:       (if gfni AESIsomorphicStrategy else PairwiseTableStrategy),
			square:    (if gfni ReuseMultiplyStrategy else PairwiseTableStrategy),
			invert:    (if gfni GfniStrategy else PairwiseTableStrategy),
			mul_alpha: (if gfni ReuseMultiplyStrategy else PairwiseTableStrategy),
			transform: (if gfni GfniStrategy else SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField32x16b,
			scalar: BinaryField16b,
			alpha_idx: 4,
			mul:       (if gfni AESIsomorphicStrategy else SimdStrategy),
			square:    (if gfni AESIsomorphicStrategy else SimdStrategy),
			invert:    (if gfni AESIsomorphicStrategy else SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (if gfni 2 else SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField16x32b,
			scalar: BinaryField32b,
			alpha_idx: 5,
			mul:       (if gfni AESIsomorphicStrategy else SimdStrategy),
			square:    (if gfni AESIsomorphicStrategy else SimdStrategy),
			invert:    (if gfni AESIsomorphicStrategy else SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (if gfni 4 else SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField8x64b,
			scalar: BinaryField64b,
			alpha_idx: 6,
			mul:       (if gfni AESIsomorphicStrategy else SimdStrategy),
			square:    (if gfni AESIsomorphicStrategy else SimdStrategy),
			invert:    (if gfni AESIsomorphicStrategy else SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (if gfni 8 else SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField4x128b,
			scalar: BinaryField128b,
			alpha_idx: _,
			mul:       (if gfni AESIsomorphicStrategy else SimdStrategy),
			square:    (if gfni AESIsomorphicStrategy else SimdStrategy),
			invert:    (if gfni AESIsomorphicStrategy else SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (if gfni GfniSpecializedStrategy512b else SimdStrategy),
		},
	]
);

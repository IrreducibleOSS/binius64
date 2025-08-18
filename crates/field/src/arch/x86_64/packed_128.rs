// Copyright 2024-2025 Irreducible Inc.

use cfg_if::cfg_if;

use super::{m128::M128, packed_macros::*};
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
	underlier: M128,
	packed_fields: [
		packed_field {
			name: PackedBinaryField128x1b,
			scalar: BinaryField1b,
			alpha_idx: 0,
			mul:       (None),
			square:    (None),
			invert:    (None),
			mul_alpha: (None),
			transform: (SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField64x2b,
			scalar: BinaryField2b,
			alpha_idx: 1,
			mul:       (PackedStrategy),
			square:    (PackedStrategy),
			invert:    (PackedStrategy),
			mul_alpha: (PackedStrategy),
			transform: (SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField32x4b,
			scalar: BinaryField4b,
			alpha_idx: 2,
			mul:       (PackedStrategy),
			square:    (PackedStrategy),
			invert:    (PackedStrategy),
			mul_alpha: (PackedStrategy),
			transform: (SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField16x8b,
			scalar: BinaryField8b,
			alpha_idx: 3,
			mul:       (PairwiseTableStrategy),
			square:    (PairwiseTableStrategy),
			invert:    (if gfni GfniStrategy else PairwiseTableStrategy),
			mul_alpha: (if gfni ReuseMultiplyStrategy else PairwiseTableStrategy),
			transform: (if gfni GfniStrategy else SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField8x16b,
			scalar: BinaryField16b,
			alpha_idx: 4,
			mul:       (SimdStrategy),
			square:    (SimdStrategy),
			invert:    (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (if gfni 2 else SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField4x32b,
			scalar: BinaryField32b,
			alpha_idx: 5,
			mul:       (SimdStrategy),
			square:    (SimdStrategy),
			invert:    (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (if gfni 4 else SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField2x64b,
			scalar: BinaryField64b,
			alpha_idx: 6,
			mul:       (SimdStrategy),
			square:    (SimdStrategy),
			invert:    (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (if gfni 8 else SimdStrategy),
		},
		packed_field {
			name: PackedBinaryField1x128b,
			scalar: BinaryField128b,
			alpha_idx: _,
			mul:       (SimdStrategy),
			square:    (SimdStrategy),
			invert:    (SimdStrategy),
			mul_alpha: (SimdStrategy),
			transform: (if gfni 16 else SimdStrategy),
		},
	]
);

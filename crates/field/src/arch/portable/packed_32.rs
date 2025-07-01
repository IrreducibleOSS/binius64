// Copyright 2024-2025 Irreducible Inc.

use cfg_if::cfg_if;

use super::{
	packed::PackedPrimitiveType,
	packed_arithmetic::{alphas, impl_tower_constants},
};
use crate::{
	arch::portable::packed_macros::{portable_macros::*, *},
	arithmetic_traits::{
		impl_invert_with, impl_mul_alpha_with, impl_mul_with, impl_square_with,
		impl_transformation_with_strategy,
	},
};

define_packed_binary_fields!(
	underlier: u32,
	packed_fields: [
		packed_field {
			name: PackedBinaryField32x1b,
			scalar: BinaryField1b,
			alpha_idx: 0,
			mul:       (None),
			square:    (None),
			invert:    (None),
			mul_alpha: (None),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField16x2b,
			scalar: BinaryField2b,
			alpha_idx: 1,
			mul:       (PackedStrategy),
			square:    (PackedStrategy),
			invert:    (PairwiseRecursiveStrategy),
			mul_alpha: (PackedStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField8x4b,
			scalar: BinaryField4b,
			alpha_idx: 2,
			mul:       (PackedStrategy),
			square:    (PackedStrategy),
			invert:    (PairwiseRecursiveStrategy),
			mul_alpha: (PackedStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField4x8b,
			scalar: BinaryField8b,
			alpha_idx: 3,
			mul:       (if gfni_x86 PackedBinaryField16x8b else PairwiseTableStrategy),
			square:    (if gfni_x86 PackedBinaryField16x8b else PackedStrategy),
			invert:    (if gfni_x86 PackedBinaryField16x8b else PairwiseStrategy),
			mul_alpha: (PackedStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField2x16b,
			scalar: BinaryField16b,
			alpha_idx: 4,
			mul:       (if gfni_x86 PackedBinaryField8x16b else HybridRecursiveStrategy),
			square:    (if gfni_x86 PackedBinaryField8x16b else PackedStrategy),
			invert:    (if gfni_x86 PackedBinaryField8x16b else PackedStrategy),
			mul_alpha: (PackedStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedBinaryField1x32b,
			scalar: BinaryField32b,
			alpha_idx: _,
			mul:       (if gfni_x86 PackedBinaryField4x32b else HybridRecursiveStrategy),
			square:    (if gfni_x86 PackedBinaryField4x32b else PairwiseRecursiveStrategy),
			invert:    (if gfni_x86 PackedBinaryField4x32b else PackedStrategy),
			mul_alpha: (PairwiseRecursiveStrategy),
			transform: (PairwiseStrategy),
		},
	]
);

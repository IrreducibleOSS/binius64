// Copyright 2024-2025 Irreducible Inc.

use cfg_if::cfg_if;

use super::{
	packed::PackedPrimitiveType,
	packed_arithmetic::{alphas, impl_tower_constants},
	packed_macros::impl_broadcast,
};
use crate::{
	AESTowerField8b,
	arch::portable::packed_macros::{portable_macros::*, *},
	arithmetic_traits::{
		impl_invert_with, impl_mul_alpha_with, impl_mul_with, impl_square_with,
		impl_transformation_with_strategy,
	},
};

define_packed_binary_fields!(
	underlier: u64,
	packed_fields: [
		packed_field {
			name: PackedAESBinaryField8x8b,
			scalar: AESTowerField8b,
			alpha_idx: _,
			mul:       (if gfni_x86 PackedAESBinaryField16x8b else PairwiseTableStrategy),
			square:    (if gfni_x86 PackedAESBinaryField16x8b else PairwiseTableStrategy),
			invert:    (if gfni_x86 PackedAESBinaryField16x8b else PairwiseTableStrategy),
			mul_alpha: (PairwiseTableStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField4x16b,
			scalar: AESTowerField16b,
			alpha_idx: 4,
			mul:       (if gfni_x86 PackedAESBinaryField8x16b else PairwiseRecursiveStrategy),
			square:    (if gfni_x86 PackedAESBinaryField8x16b else PairwiseRecursiveStrategy),
			invert:    (if gfni_x86 PackedAESBinaryField8x16b else PairwiseRecursiveStrategy),
			mul_alpha: (PackedStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField2x32b,
			scalar: AESTowerField32b,
			alpha_idx: 5,
			mul:       (if gfni_x86 PackedAESBinaryField4x32b else PairwiseRecursiveStrategy),
			square:    (if gfni_x86 PackedAESBinaryField4x32b else PairwiseRecursiveStrategy),
			invert:    (if gfni_x86 PackedAESBinaryField4x32b else PairwiseRecursiveStrategy),
			mul_alpha: (PackedStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField1x64b,
			scalar: AESTowerField64b,
			alpha_idx: _,
			mul:       (if gfni_x86 PackedAESBinaryField2x64b else PairwiseRecursiveStrategy),
			square:    (if gfni_x86 PackedAESBinaryField2x64b else PairwiseRecursiveStrategy),
			invert:    (if gfni_x86 PackedAESBinaryField2x64b else PairwiseRecursiveStrategy),
			mul_alpha: (PairwiseRecursiveStrategy),
			transform: (PairwiseStrategy),
		},
	]
);

impl_tower_constants!(AESTowerField8b, u64, 0x00d300d300d300d3);

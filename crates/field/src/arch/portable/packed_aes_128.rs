// Copyright 2024-2025 Irreducible Inc.

use super::{
	packed::PackedPrimitiveType,
	packed_arithmetic::{alphas, impl_tower_constants},
	packed_macros::impl_broadcast,
};
use crate::{
	aes_field::AESTowerField8b,
	arch::portable::packed_macros::{portable_macros::*, *},
	arithmetic_traits::{
		impl_invert_with, impl_mul_alpha_with, impl_mul_with, impl_square_with,
		impl_transformation_with_strategy,
	},
};

define_packed_binary_fields!(
	underlier: u128,
	packed_fields: [
		packed_field {
			name: PackedAESBinaryField16x8b,
			scalar: AESTowerField8b,
			alpha_idx: _,
			mul: (PairwiseTableStrategy),
			square: (PairwiseTableStrategy),
			invert: (PairwiseTableStrategy),
			mul_alpha: (PairwiseTableStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField8x16b,
			scalar: AESTowerField16b,
			alpha_idx: 4,
			mul: (PairwiseRecursiveStrategy),
			square: (PairwiseRecursiveStrategy),
			invert: (PairwiseRecursiveStrategy),
			mul_alpha: (PackedStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField4x32b,
			scalar: AESTowerField32b,
			alpha_idx: 5,
			mul: (PairwiseRecursiveStrategy),
			square: (PackedStrategy),
			invert: (PairwiseRecursiveStrategy),
			mul_alpha: (PackedStrategy),
			transform: (PackedStrategy),
		},
		packed_field {
			name: PackedAESBinaryField2x64b,
			scalar: AESTowerField64b,
			alpha_idx: 6,
			mul: (PairwiseRecursiveStrategy),
			square: (PackedStrategy),
			invert: (PairwiseRecursiveStrategy),
			mul_alpha: (PairwiseRecursiveStrategy),
			transform: (PairwiseStrategy),
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

impl_tower_constants!(AESTowerField8b, u128, 0x00d300d300d300d300d300d300d300d3);

// Copyright 2024-2025 Irreducible Inc.

use cfg_if::cfg_if;

use super::{m128::M128, packed_macros::*};
use crate::{
	arch::portable::{packed::PackedPrimitiveType, packed_macros::*},
	arithmetic_traits::{
		impl_invert_with, impl_mul_alpha_with, impl_mul_with, impl_square_with,
		impl_transformation_with_strategy,
	},
};

define_packed_binary_fields!(
	underlier: M128,
	packed_fields: [
		packed_field {
			name: PackedAESBinaryField16x8b,
			scalar: AESTowerField8b,
			alpha_idx: _,
			mul:       (if gfni GfniStrategy else PairwiseTableStrategy),
			square:    (if gfni ReuseMultiplyStrategy else PairwiseTableStrategy),
			invert:    (if gfni GfniStrategy else PairwiseTableStrategy),
			mul_alpha: (if gfni ReuseMultiplyStrategy else PairwiseTableStrategy),
			transform: (if gfni GfniStrategy else SimdStrategy),
		},
	]
);

// Copyright 2024-2025 Irreducible Inc.

use cfg_if::cfg_if;

use super::m256::M256;
use crate::{
	BinaryField128bPolyval,
	arch::{PairwiseStrategy, ReuseMultiplyStrategy, portable::packed::PackedPrimitiveType},
	arithmetic_traits::{impl_invert_with, impl_square_with},
};

/// Define packed type
pub type PackedBinaryPolyval2x128b = PackedPrimitiveType<M256, BinaryField128bPolyval>;

impl From<PackedBinaryPolyval2x128b> for [u128; 2] {
	fn from(value: PackedBinaryPolyval2x128b) -> Self {
		value.0.into()
	}
}

// Define multiplication
cfg_if! {
	if #[cfg(target_feature = "vpclmulqdq")] {
		impl std::ops::Mul for PackedBinaryPolyval2x128b {
			type Output = Self;

			fn mul(self, rhs: Self) -> Self::Output {
				crate::tracing::trace_multiplication!(PackedBinaryPolyval2x128b);
				unsafe { super::pclmul::montgomery_mul::simd_montgomery_multiply(self.0, rhs.0).into() }
			}
		}
	} else {
		crate::arithmetic_traits::impl_mul_with!(PackedBinaryPolyval2x128b @ PairwiseStrategy);
	}

}

// Define square
impl_square_with!(PackedBinaryPolyval2x128b @ ReuseMultiplyStrategy);

// Define invert
// TODO: possible we can use some better strategy using SIMD for some of the operations
impl_invert_with!(PackedBinaryPolyval2x128b @ PairwiseStrategy);

// Define linear transformations
cfg_if! {
	if #[cfg(target_feature = "gfni")] {
		use crate::arch::x86_64::gfni::gfni_arithmetics::impl_transformation_with_gfni_nxn;

		impl_transformation_with_gfni_nxn!(PackedBinaryPolyval2x128b, 16);
	} else {
		crate::arithmetic_traits::impl_transformation_with_strategy!(PackedBinaryPolyval2x128b, crate::arch::SimdStrategy);
	}
}

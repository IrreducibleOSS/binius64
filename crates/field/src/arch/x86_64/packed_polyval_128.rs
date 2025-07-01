// Copyright 2024-2025 Irreducible Inc.

use std::ops::Mul;

use super::{super::portable::packed::PackedPrimitiveType, m128::M128};
use crate::{
	BinaryField128bPolyval,
	arch::{ReuseMultiplyStrategy, cfg_if},
	arithmetic_traits::{InvertOrZero, impl_square_with},
	packed::PackedField,
};

pub type PackedBinaryPolyval1x128b = PackedPrimitiveType<M128, BinaryField128bPolyval>;

// Define multiply
cfg_if! {
	if #[cfg(target_feature = "pclmulqdq")] {
		impl Mul for PackedBinaryPolyval1x128b {
			type Output = Self;

			fn mul(self, rhs: Self) -> Self::Output {
				crate::tracing::trace_multiplication!(PackedBinaryPolyval1x128b);

				unsafe { super::pclmul::montgomery_mul::simd_montgomery_multiply(self.0, rhs.0) }.into()
			}
		}
	} else {
		impl Mul for PackedBinaryPolyval1x128b {
			type Output = Self;

			fn mul(self, rhs: Self) -> Self::Output {
				use super::super::portable::packed_polyval_128::PackedBinaryPolyval1x128b;

				crate::tracing::trace_multiplication!(PackedBinaryPolyval1x128b);

				let portable_lhs = PackedBinaryPolyval1x128b::from(
					u128::from(self.0),
				);
				let portable_rhs = PackedBinaryPolyval1x128b::from(
					u128::from(rhs.0),
				);

				Self::from_underlier(Mul::mul(portable_lhs, portable_rhs).0.into())
			}
		}
	}
}

// Define square
// TODO: implement a more optimal version for square case
impl_square_with!(PackedBinaryPolyval1x128b @ ReuseMultiplyStrategy);

// Define invert
// TODO: implement vectorized version that uses packed multiplication
impl InvertOrZero for PackedBinaryPolyval1x128b {
	fn invert_or_zero(self) -> Self {
		let portable = super::super::portable::packed_polyval_128::PackedBinaryPolyval1x128b::from(
			u128::from(self.0),
		);

		Self::from_underlier(PackedField::invert_or_zero(portable).0.into())
	}
}

// Define linear transformations
cfg_if! {
	if #[cfg(target_feature = "gfni")] {
		use crate::arch::x86_64::gfni::gfni_arithmetics::impl_transformation_with_gfni_nxn;

		impl_transformation_with_gfni_nxn!(PackedBinaryPolyval1x128b, 16);
	} else {
		crate::arithmetic_traits::impl_transformation_with_strategy!(PackedBinaryPolyval1x128b, crate::arch::SimdStrategy);
	}
}

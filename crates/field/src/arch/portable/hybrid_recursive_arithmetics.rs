// Copyright 2024-2025 Irreducible Inc.

use super::packed_arithmetic::PackedTowerField;
use crate::{
	TowerExtensionField,
	arch::HybridRecursiveStrategy,
	arithmetic_traits::{MulAlpha, TaggedMul, TaggedMulAlpha, TaggedSquare},
	packed::PackedField,
};

impl<P> TaggedMul<HybridRecursiveStrategy> for P
where
	P: PackedTowerField,
	P::Scalar: TowerExtensionField<DirectSubfield = P::DirectSubfield>,
	P::PackedDirectSubfield: MulAlpha,
	P::DirectSubfield: MulAlpha,
{
	#[inline]
	fn mul(self, rhs: Self) -> Self {
		let a0_a1 = self.as_packed_subfield();
		let b0_b1 = rhs.as_packed_subfield();
		let z0_z2 = P::from_packed_subfield(a0_a1 * b0_b1);

		P::from_fn(|i| {
			let (a0, a1) = self.get(i).into();
			let (b0, b1) = rhs.get(i).into();
			let (z0, z2) = z0_z2.get(i).into();
			let z0z2 = z0 + z2;
			let z1 = (a0 + a1) * (b0 + b1) - z0z2;
			let z2a = MulAlpha::mul_alpha(z2);

			(z0z2, z1 + z2a).into()
		})
	}
}

impl<P> TaggedSquare<HybridRecursiveStrategy> for P
where
	P: PackedTowerField,
	P::Scalar: TowerExtensionField<DirectSubfield = P::DirectSubfield>,
	P::DirectSubfield: MulAlpha,
{
	#[inline]
	fn square(self) -> Self {
		let a0_a1 = self.as_packed_subfield();
		let z0_z1 = P::from_packed_subfield(PackedField::square(a0_a1));

		P::from_fn(|i| {
			let (z0, z2) = z0_z1.get(i).into();
			let z2a = MulAlpha::mul_alpha(z2);
			(z0 + z2, z2a).into()
		})
	}
}

impl<P> TaggedMulAlpha<HybridRecursiveStrategy> for P
where
	P: PackedTowerField,
	P::Scalar: TowerExtensionField<DirectSubfield = P::DirectSubfield>,
	P::PackedDirectSubfield: MulAlpha,
{
	#[inline]
	fn mul_alpha(self) -> Self {
		let a0_a1 = self.as_packed_subfield();
		let z1 = MulAlpha::mul_alpha(a0_a1);

		P::from_fn(|i| {
			let (a0, a1) = self.get(i).into();
			let z1 = z1.get(2 * i + 1);

			(a1, a0 + z1).into()
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		arithmetic_traits::TaggedInvertOrZero,
		test_utils::{
			define_invert_tests, define_mul_alpha_tests, define_multiply_tests, define_square_tests,
		},
	};

	define_multiply_tests!(
		TaggedMul<HybridRecursiveStrategy>::mul,
		TaggedMul<HybridRecursiveStrategy>
	);

	define_square_tests!(
		TaggedSquare<HybridRecursiveStrategy>::square,
		TaggedSquare<HybridRecursiveStrategy>
	);

	define_invert_tests!(
		TaggedInvertOrZero<HybridRecursiveStrategy>::invert_or_zero,
		TaggedInvertOrZero<HybridRecursiveStrategy>
	);

	define_mul_alpha_tests!(
		TaggedMulAlpha<HybridRecursiveStrategy>::mul_alpha,
		TaggedMulAlpha<HybridRecursiveStrategy>
	);
}

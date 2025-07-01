// Copyright 2024-2025 Irreducible Inc.

use super::gfni_arithmetics::{AES_TO_TOWER_MAP, GfniType, TOWER_TO_AES_MAP, linear_transform};
use crate::{
	AESTowerField8b, AESTowerField16b, AESTowerField32b, AESTowerField64b, AESTowerField128b,
	BinaryField8b, BinaryField16b, BinaryField32b, BinaryField64b, BinaryField128b, PackedField,
	TowerField,
	arch::{AESIsomorphicStrategy, portable::packed::PackedPrimitiveType},
	arithmetic_traits::{TaggedInvertOrZero, TaggedMul, TaggedSquare},
	underlier::UnderlierType,
};

/// Canonical field that is isomorphic to the corresponding AES field.
trait IsomorphicToAESCanonical: TowerField {
	type AESField: TowerField;
}

impl IsomorphicToAESCanonical for BinaryField8b {
	type AESField = AESTowerField8b;
}

impl IsomorphicToAESCanonical for BinaryField16b {
	type AESField = AESTowerField16b;
}

impl IsomorphicToAESCanonical for BinaryField32b {
	type AESField = AESTowerField32b;
}

impl IsomorphicToAESCanonical for BinaryField64b {
	type AESField = AESTowerField64b;
}

impl IsomorphicToAESCanonical for BinaryField128b {
	type AESField = AESTowerField128b;
}

impl<U, Scalar> TaggedMul<AESIsomorphicStrategy> for PackedPrimitiveType<U, Scalar>
where
	U: UnderlierType + GfniType,
	Scalar: IsomorphicToAESCanonical,
	PackedPrimitiveType<U, Scalar::AESField>: PackedField,
{
	#[inline]
	fn mul(self, rhs: Self) -> Self {
		let canonical_lhs = linear_transform(self.0, TOWER_TO_AES_MAP);
		let canonical_rhs = linear_transform(rhs.0, TOWER_TO_AES_MAP);

		let canonical_result =
			PackedPrimitiveType::<U, Scalar::AESField>::from_underlier(canonical_lhs)
				* PackedPrimitiveType::<U, Scalar::AESField>::from_underlier(canonical_rhs);

		let result = linear_transform(canonical_result.0, AES_TO_TOWER_MAP);

		Self::from_underlier(result)
	}
}

impl<U, Scalar> TaggedSquare<AESIsomorphicStrategy> for PackedPrimitiveType<U, Scalar>
where
	U: UnderlierType + GfniType,
	Scalar: IsomorphicToAESCanonical,
	PackedPrimitiveType<U, Scalar::AESField>: PackedField,
{
	#[inline]
	fn square(self) -> Self {
		let canonical_self = linear_transform(self.0, TOWER_TO_AES_MAP);

		let canonical_result = PackedField::square(
			PackedPrimitiveType::<U, Scalar::AESField>::from_underlier(canonical_self),
		);

		let result = linear_transform(canonical_result.0, AES_TO_TOWER_MAP);

		Self::from_underlier(result)
	}
}

impl<U, Scalar> TaggedInvertOrZero<AESIsomorphicStrategy> for PackedPrimitiveType<U, Scalar>
where
	U: UnderlierType + GfniType,
	Scalar: IsomorphicToAESCanonical,
	PackedPrimitiveType<U, Scalar::AESField>: PackedField,
{
	#[inline]
	fn invert_or_zero(self) -> Self {
		let canonical_self = linear_transform(self.0, TOWER_TO_AES_MAP);

		let canonical_result = PackedField::invert_or_zero(PackedPrimitiveType::<
			U,
			Scalar::AESField,
		>::from_underlier(canonical_self));

		let result = linear_transform(canonical_result.0, AES_TO_TOWER_MAP);

		Self::from_underlier(result)
	}
}

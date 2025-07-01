// Copyright 2024-2025 Irreducible Inc.

use crate::{
	ExtensionField, Field, PackedField,
	aes_field::*,
	arch::{
		packed_1::*, packed_2::*, packed_4::*, packed_8::*, packed_16::*, packed_32::*,
		packed_64::*, packed_128::*, packed_aes_8::*, packed_aes_16::*, packed_aes_32::*,
		packed_aes_64::*, packed_aes_128::*, packed_polyval_128::PackedBinaryPolyval1x128b,
	},
	binary_field::*,
	polyval::BinaryField128bPolyval,
	underlier::{UnderlierType, WithUnderlier},
};

/// Trait that establishes correspondence between the scalar field and a packed field of the same
/// bit size with a single element.
///
/// E.g. `BinaryField64b` -> `PackedBinaryField1x64b`.
/// Note that the underlier of the packed field may be different.
/// E.g. `BinaryField128b` has u128 as underlier, while for x64 `PackedBinaryField1x128b`'s
/// underlier may be `M128`.
pub trait AsSinglePacked: Field {
	type Packed: PackedField<Scalar = Self>
		+ WithUnderlier<Underlier: From<Self::Underlier> + Into<Self::Underlier>>;

	fn to_single_packed(self) -> Self::Packed {
		assert_eq!(Self::Packed::WIDTH, 1);

		Self::Packed::set_single(self)
	}

	fn from_single_packed(value: Self::Packed) -> Self {
		assert_eq!(Self::Packed::WIDTH, 1);

		value.get(0)
	}
}

macro_rules! impl_as_single_packed_field {
	($field:ty, $packed_field:ty) => {
		impl AsSinglePacked for $field {
			type Packed = $packed_field;
		}
	};
}

impl_as_single_packed_field!(BinaryField1b, PackedBinaryField1x1b);
impl_as_single_packed_field!(BinaryField2b, PackedBinaryField1x2b);
impl_as_single_packed_field!(BinaryField4b, PackedBinaryField1x4b);
impl_as_single_packed_field!(BinaryField8b, PackedBinaryField1x8b);
impl_as_single_packed_field!(BinaryField16b, PackedBinaryField1x16b);
impl_as_single_packed_field!(BinaryField32b, PackedBinaryField1x32b);
impl_as_single_packed_field!(BinaryField64b, PackedBinaryField1x64b);
impl_as_single_packed_field!(BinaryField128b, PackedBinaryField1x128b);

impl_as_single_packed_field!(AESTowerField8b, PackedAESBinaryField1x8b);
impl_as_single_packed_field!(AESTowerField16b, PackedAESBinaryField1x16b);
impl_as_single_packed_field!(AESTowerField32b, PackedAESBinaryField1x32b);
impl_as_single_packed_field!(AESTowerField64b, PackedAESBinaryField1x64b);
impl_as_single_packed_field!(AESTowerField128b, PackedAESBinaryField1x128b);

impl_as_single_packed_field!(BinaryField128bPolyval, PackedBinaryPolyval1x128b);

/// This trait represents correspondence (UnderlierType, Field) -> PackedField.
/// For example (u64, BinaryField16b) -> PackedBinaryField4x16b.
pub trait PackScalar<F: Field>: UnderlierType {
	type Packed: PackedField<Scalar = F> + WithUnderlier<Underlier = Self>;
}

/// Returns the packed field type for the scalar field `F` and underlier `U`.
pub type PackedType<U, F> = <U as PackScalar<F>>::Packed;

/// A trait to convert field to a same bit size packed field with some smaller scalar.
pub(crate) trait AsPackedField<Scalar: Field>: Field
where
	Self: ExtensionField<Scalar>,
{
	type Packed: PackedField<Scalar = Scalar>
		+ WithUnderlier<Underlier: From<Self::Underlier> + Into<Self::Underlier>>;

	fn to_packed(self) -> Self::Packed {
		Self::Packed::from_underlier(self.to_underlier().into())
	}

	fn from_packed(value: Self::Packed) -> Self {
		Self::from_underlier(value.to_underlier().into())
	}
}

impl<Scalar, F> AsPackedField<Scalar> for F
where
	F: Field
		+ WithUnderlier<Underlier: PackScalar<Scalar>>
		+ AsSinglePacked
		+ ExtensionField<Scalar>,
	Scalar: Field,
{
	type Packed = <Self::Underlier as PackScalar<Scalar>>::Packed;
}

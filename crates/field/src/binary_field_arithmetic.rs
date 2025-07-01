// Copyright 2023-2025 Irreducible Inc.

use super::{arithmetic_traits::InvertOrZero, binary_field::*};
use crate::{PackedField, arithmetic_traits::MulAlpha};

pub(crate) trait TowerFieldArithmetic: TowerField {
	fn multiply(self, rhs: Self) -> Self;

	fn multiply_alpha(self) -> Self;

	fn square(self) -> Self;
}

macro_rules! impl_arithmetic_using_packed {
	($name:ident) => {
		impl InvertOrZero for $name {
			#[inline]
			fn invert_or_zero(self) -> Self {
				use $crate::as_packed_field::AsPackedField;

				$crate::binary_field_arithmetic::invert_or_zero_using_packed::<
					<Self as AsPackedField<$name>>::Packed,
				>(self)
			}
		}

		impl TowerFieldArithmetic for $name {
			#[inline]
			fn multiply(self, rhs: Self) -> Self {
				use $crate::as_packed_field::AsPackedField;

				$crate::binary_field_arithmetic::multiple_using_packed::<
					<Self as AsPackedField<$name>>::Packed,
				>(self, rhs)
			}

			#[inline]
			fn multiply_alpha(self) -> Self {
				use $crate::as_packed_field::AsPackedField;

				$crate::binary_field_arithmetic::mul_alpha_using_packed::<
					<Self as AsPackedField<$name>>::Packed,
				>(self)
			}

			#[inline]
			fn square(self) -> Self {
				use $crate::as_packed_field::AsPackedField;

				$crate::binary_field_arithmetic::square_using_packed::<
					<Self as AsPackedField<$name>>::Packed,
				>(self)
			}
		}
	};
}

pub(crate) use impl_arithmetic_using_packed;

// TODO: try to get rid of `TowerFieldArithmetic` and use `impl_arithmetic_using_packed` here
impl TowerField for BinaryField1b {
	type Canonical = Self;

	fn min_tower_level(self) -> usize {
		0
	}

	#[inline]
	fn mul_primitive(self, _: usize) -> Result<Self, crate::Error> {
		Err(crate::Error::ExtensionDegreeMismatch)
	}
}

impl InvertOrZero for BinaryField1b {
	#[inline]
	fn invert_or_zero(self) -> Self {
		self
	}
}

impl TowerFieldArithmetic for BinaryField1b {
	#[inline]
	fn multiply(self, rhs: Self) -> Self {
		Self(self.0 & rhs.0)
	}

	#[inline]
	fn multiply_alpha(self) -> Self {
		self
	}

	#[inline]
	fn square(self) -> Self {
		self
	}
}

impl_arithmetic_using_packed!(BinaryField2b);
impl_arithmetic_using_packed!(BinaryField4b);
impl_arithmetic_using_packed!(BinaryField8b);
impl_arithmetic_using_packed!(BinaryField16b);
impl_arithmetic_using_packed!(BinaryField32b);
impl_arithmetic_using_packed!(BinaryField64b);
impl_arithmetic_using_packed!(BinaryField128b);

/// For some architectures it may be faster to used SIM versions for packed fields than to use
/// portable single-element arithmetics. That's why we need these functions
#[inline]
pub(super) fn multiple_using_packed<P: PackedField>(lhs: P::Scalar, rhs: P::Scalar) -> P::Scalar {
	(P::set_single(lhs) * P::set_single(rhs)).get(0)
}

#[inline]
pub(super) fn square_using_packed<P: PackedField>(value: P::Scalar) -> P::Scalar {
	P::set_single(value).square().get(0)
}

#[inline]
pub(super) fn invert_or_zero_using_packed<P: PackedField>(value: P::Scalar) -> P::Scalar {
	P::set_single(value).invert_or_zero().get(0)
}

#[inline]
pub(super) fn mul_alpha_using_packed<P: PackedField + MulAlpha>(value: P::Scalar) -> P::Scalar {
	P::set_single(value).mul_alpha().get(0)
}

// `MulPrimitive` implementation for binary tower

/// Multiply `val` by alpha as a packed field with `smaller_type` scalar
macro_rules! mul_alpha_as_repacked {
	($val:ident, $source_type:ty, $smaller_type:ty) => {{
		use $crate::as_packed_field::AsPackedField;

		let repacked_value = <$source_type as AsPackedField<$smaller_type>>::to_packed($val);
		<$source_type as AsPackedField<$smaller_type>>::from_packed(
			$crate::arithmetic_traits::MulAlpha::mul_alpha(repacked_value),
		)
	}};
}

pub(super) use mul_alpha_as_repacked;

macro_rules! impl_mul_primitive {
	($name:ty, $(mul_by $height_0:literal => $expr:expr,)* $(repack $height_1:literal => $subtype:ty,)*) => {
		impl $crate::binary_field::MulPrimitive for $name {
			#[inline]
			fn mul_primitive(self, iota: usize) -> Result<Self, $crate::Error> {
				match iota {
					$($height_0 => Ok(self * $expr),)*
					$($height_1 => {
						let result = $crate::binary_field_arithmetic::mul_alpha_as_repacked!(self, $name, $subtype);
						Ok(result)
					},)*
					_ => Err($crate::Error::ExtensionDegreeMismatch),
				}
			}
		}
	};
}

pub(super) use impl_mul_primitive;

impl_mul_primitive!(BinaryField2b,
	repack 0 => BinaryField2b,
);
impl_mul_primitive!(BinaryField4b,
	repack 0 => BinaryField2b,
	repack 1 => BinaryField4b,
);
impl_mul_primitive!(BinaryField8b,
	repack 0 => BinaryField2b,
	repack 1 => BinaryField4b,
	repack 2 => BinaryField8b,
);
impl_mul_primitive!(BinaryField16b,
	repack 0 => BinaryField2b,
	repack 1 => BinaryField4b,
	repack 2 => BinaryField8b,
	repack 3 => BinaryField16b,
);
impl_mul_primitive!(BinaryField32b,
	repack 0 => BinaryField2b,
	repack 1 => BinaryField4b,
	repack 2 => BinaryField8b,
	repack 3 => BinaryField16b,
	repack 4 => BinaryField32b,
);
impl_mul_primitive!(BinaryField64b,
	repack 0 => BinaryField2b,
	repack 1 => BinaryField4b,
	repack 2 => BinaryField8b,
	repack 3 => BinaryField16b,
	repack 4 => BinaryField32b,
	repack 5 => BinaryField64b,
);
impl_mul_primitive!(BinaryField128b,
	repack 0 => BinaryField2b,
	repack 1 => BinaryField4b,
	repack 2 => BinaryField8b,
	repack 3 => BinaryField16b,
	repack 4 => BinaryField32b,
	repack 5 => BinaryField64b,
	repack 6 => BinaryField128b,
);

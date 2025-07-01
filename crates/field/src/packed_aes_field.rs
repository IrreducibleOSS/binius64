// Copyright 2024-2025 Irreducible Inc.

pub use crate::arch::{
	packed_aes_8::*, packed_aes_16::*, packed_aes_32::*, packed_aes_64::*, packed_aes_128::*,
	packed_aes_256::*, packed_aes_512::*,
};

#[cfg(test)]
mod test_utils {
	/// Test if `mult_func` operation is a valid multiply operation on the given values for
	/// all possible packed fields defined on 8-512 bits.
	macro_rules! define_multiply_tests {
		($mult_func:path, $constraint:ty) => {
			$crate::packed_binary_field::test_utils::define_check_packed_mul!(
				$mult_func,
				$constraint
			);

			proptest! {
				#[test]
				fn test_mul_packed_8(a_val in any::<u8>(), b_val in any::<u8>()) {
					use $crate::arch::packed_aes_8::*;

					TestMult::<PackedAESBinaryField1x8b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}

				#[test]
				fn test_mul_packed_16(a_val in any::<u16>(), b_val in any::<u16>()) {
					use $crate::arch::packed_aes_16::*;

					TestMult::<PackedAESBinaryField2x8b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField1x16b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}

				#[test]
				fn test_mul_packed_32(a_val in any::<u32>(), b_val in any::<u32>()) {
					use $crate::arch::packed_aes_32::*;

					TestMult::<PackedAESBinaryField4x8b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField2x16b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField1x32b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}

				#[test]
				fn test_mul_packed_64(a_val in any::<u64>(), b_val in any::<u64>()) {
					use $crate::arch::packed_aes_64::*;

					TestMult::<PackedAESBinaryField8x8b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField4x16b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField2x32b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField1x64b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}

				#[test]
				fn test_mul_packed_128(a_val in any::<u128>(), b_val in any::<u128>()) {
					use $crate::arch::packed_aes_128::*;

					TestMult::<PackedAESBinaryField16x8b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField8x16b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField4x32b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField2x64b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField1x128b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}

				#[test]
				fn test_mul_packed_256(a_val in any::<[u128; 2]>(), b_val in any::<[u128; 2]>()) {
					use $crate::arch::packed_aes_256::*;

					TestMult::<PackedAESBinaryField32x8b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField16x16b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField8x32b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField4x64b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField2x128b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}

				#[test]
				fn test_mul_packed_512(a_val in any::<[u128; 4]>(), b_val in any::<[u128; 4]>()) {
					use $crate::arch::packed_aes_512::*;

					TestMult::<PackedAESBinaryField64x8b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField32x16b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField16x32b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField8x64b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
					TestMult::<PackedAESBinaryField4x128b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}
			}
		};
	}

	/// Test if `square_func` operation is a valid square operation on the given value for
	/// all possible packed fields.
	macro_rules! define_square_tests {
		($square_func:path, $constraint:ident) => {
			$crate::packed_binary_field::test_utils::define_check_packed_square!(
				$square_func,
				$constraint
			);

			proptest! {
				#[test]
				fn test_square_packed_8(a_val in any::<u8>()) {
					use $crate::arch::packed_aes_8::*;

					TestSquare::<PackedAESBinaryField1x8b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_16(a_val in any::<u16>()) {
					use $crate::arch::packed_aes_16::*;

					TestSquare::<PackedAESBinaryField2x8b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField1x16b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_32(a_val in any::<u32>()) {
					use $crate::arch::packed_aes_32::*;

					TestSquare::<PackedAESBinaryField4x8b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField2x16b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField1x32b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_64(a_val in any::<u64>()) {
					use $crate::arch::packed_aes_64::*;

					TestSquare::<PackedAESBinaryField8x8b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField4x16b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField2x32b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField1x64b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_128(a_val in any::<u128>()) {
					use $crate::arch::packed_aes_128::*;

					TestSquare::<PackedAESBinaryField16x8b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField8x16b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField4x32b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField2x64b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField1x128b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_256(a_val in any::<[u128; 2]>()) {
					use $crate::arch::packed_aes_256::*;

					TestSquare::<PackedAESBinaryField32x8b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField16x16b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField8x32b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField4x64b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField2x128b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_512(a_val in any::<[u128; 4]>()) {
					use $crate::arch::packed_aes_512::*;

					TestSquare::<PackedAESBinaryField64x8b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField32x16b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField16x32b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField8x64b>::test_square(a_val.into());
					TestSquare::<PackedAESBinaryField4x128b>::test_square(a_val.into());
				}
			}
		};
	}

	/// Test if `invert_func` operation is a valid invert operation on the given value for
	/// all possible packed fields.
	macro_rules! define_invert_tests {
		($invert_func:path, $constraint:ident) => {
			$crate::packed_binary_field::test_utils::define_check_packed_inverse!(
				$invert_func,
				$constraint
			);

			proptest! {
				#[test]
				fn test_invert_packed_8(a_val in any::<u8>()) {
					use $crate::arch::packed_aes_8::*;

					TestSquare::<PackedAESBinaryField1x8b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_16(a_val in any::<u16>()) {
					use $crate::arch::packed_aes_16::*;

					TestSquare::<PackedAESBinaryField2x8b>::test_invert(a_val.into());
					TestSquare::<PackedAESBinaryField1x16b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_32(a_val in any::<u32>()) {
					use $crate::arch::packed_aes_32::*;

					TestSquare::<PackedAESBinaryField4x8b>::test_invert(a_val.into());
					TestSquare::<PackedAESBinaryField2x16b>::test_invert(a_val.into());
					TestSquare::<PackedAESBinaryField1x32b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_64(a_val in any::<u64>()) {
					use $crate::arch::packed_aes_64::*;

					TestSquare::<PackedAESBinaryField8x8b>::test_invert(a_val.into());
					TestSquare::<PackedAESBinaryField4x16b>::test_invert(a_val.into());
					TestSquare::<PackedAESBinaryField2x32b>::test_invert(a_val.into());
					TestSquare::<PackedAESBinaryField1x64b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_128(a_val in any::<u128>()) {
					use $crate::arch::packed_aes_128::*;

					TestInvert::<PackedAESBinaryField16x8b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField8x16b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField4x32b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField2x64b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField1x128b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_256(a_val in any::<[u128; 2]>()) {
					use $crate::arch::packed_aes_256::*;

					TestInvert::<PackedAESBinaryField32x8b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField16x16b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField8x32b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField4x64b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField2x128b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_512(a_val in any::<[u128; 4]>()) {
					use $crate::arch::packed_aes_512::*;

					TestInvert::<PackedAESBinaryField64x8b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField32x16b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField16x32b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField8x64b>::test_invert(a_val.into());
					TestInvert::<PackedAESBinaryField4x128b>::test_invert(a_val.into());
				}
			}
		};
	}

	macro_rules! define_transformation_tests {
		($constraint:path) => {
			$crate::packed_binary_field::test_utils::define_check_packed_transformation!(
				$constraint
			);

			proptest::proptest! {
				#[test]
				fn test_transformation_packed_aes_8(a_val in proptest::prelude::any::<u8>()) {
					use crate::arch::packed_aes_8::*;

					TestTransformation::<PackedAESBinaryField1x8b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_aes_16(a_val in proptest::prelude::any::<u16>()) {
					use crate::arch::packed_aes_16::*;

					TestTransformation::<PackedAESBinaryField1x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField2x8b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_aes_32(a_val in proptest::prelude::any::<u32>()) {
					use crate::arch::packed_aes_32::*;

					TestTransformation::<PackedAESBinaryField1x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField2x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField4x8b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_aes_64(a_val in proptest::prelude::any::<u64>()) {
					use crate::arch::packed_aes_64::*;

					TestTransformation::<PackedAESBinaryField1x64b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField2x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField4x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField8x8b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_aes_128(a_val in proptest::prelude::any::<u128>()) {
					use crate::arch::packed_aes_128::*;

					TestTransformation::<PackedAESBinaryField1x128b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField2x64b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField4x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField8x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField16x8b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_aes_256(a_val in proptest::prelude::any::<[u128; 2]>()) {
					use crate::arch::packed_aes_256::*;

					TestTransformation::<PackedAESBinaryField2x128b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField4x64b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField8x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField16x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField32x8b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_aes_512(a_val in proptest::prelude::any::<[u128; 4]>()) {
					use crate::arch::packed_aes_512::*;

					TestTransformation::<PackedAESBinaryField4x128b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField8x64b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField16x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField32x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedAESBinaryField64x8b>::test_transformation(a_val.into());
				}
			}
		};
	}

	pub(crate) use define_invert_tests;
	pub(crate) use define_multiply_tests;
	pub(crate) use define_square_tests;
	pub(crate) use define_transformation_tests;
}

#[cfg(test)]
mod tests {
	use std::ops::Mul;

	use proptest::prelude::*;

	use super::{
		test_utils::{
			define_invert_tests, define_multiply_tests, define_square_tests,
			define_transformation_tests,
		},
		*,
	};
	use crate::{
		PackedField,
		arch::{
			packed_8::*, packed_16::*, packed_32::*, packed_64::*, packed_128::*, packed_256::*,
			packed_512::*,
		},
		linear_transformation::PackedTransformationFactory,
		test_utils::implements_transformation_factory,
	};

	define_multiply_tests!(Mul::mul, PackedField);

	define_square_tests!(PackedField::square, PackedField);

	define_invert_tests!(PackedField::invert_or_zero, PackedField);

	#[allow(unused)]
	trait SelfTransformationFactory: PackedTransformationFactory<Self> {}

	impl<T: PackedTransformationFactory<T>> SelfTransformationFactory for T {}

	define_transformation_tests!(SelfTransformationFactory);

	/// Compile-time test to ensure packed fields implement `PackedTransformationFactory`.
	#[allow(unused)]
	const fn test_implement_transformation_factory() {
		// 8 bit packed aes tower
		implements_transformation_factory::<PackedAESBinaryField1x8b, PackedAESBinaryField1x8b>();
		implements_transformation_factory::<PackedBinaryField1x8b, PackedAESBinaryField1x8b>();

		// 16 bit packed aes tower
		implements_transformation_factory::<PackedAESBinaryField2x8b, PackedAESBinaryField2x8b>();
		implements_transformation_factory::<PackedBinaryField2x8b, PackedAESBinaryField2x8b>();
		implements_transformation_factory::<PackedAESBinaryField1x16b, PackedAESBinaryField1x16b>();
		implements_transformation_factory::<PackedBinaryField1x16b, PackedAESBinaryField1x16b>();

		// 32 bit packed aes tower
		implements_transformation_factory::<PackedAESBinaryField4x8b, PackedAESBinaryField4x8b>();
		implements_transformation_factory::<PackedBinaryField4x8b, PackedAESBinaryField4x8b>();
		implements_transformation_factory::<PackedAESBinaryField2x16b, PackedAESBinaryField2x16b>();
		implements_transformation_factory::<PackedBinaryField2x16b, PackedAESBinaryField2x16b>();
		implements_transformation_factory::<PackedAESBinaryField1x32b, PackedAESBinaryField1x32b>();
		implements_transformation_factory::<PackedBinaryField1x32b, PackedAESBinaryField1x32b>();

		// 64 bit packed aes tower
		implements_transformation_factory::<PackedAESBinaryField8x8b, PackedAESBinaryField8x8b>();
		implements_transformation_factory::<PackedBinaryField8x8b, PackedAESBinaryField8x8b>();
		implements_transformation_factory::<PackedAESBinaryField4x16b, PackedAESBinaryField4x16b>();
		implements_transformation_factory::<PackedBinaryField4x16b, PackedAESBinaryField4x16b>();
		implements_transformation_factory::<PackedAESBinaryField2x32b, PackedAESBinaryField2x32b>();
		implements_transformation_factory::<PackedBinaryField2x32b, PackedAESBinaryField2x32b>();
		implements_transformation_factory::<PackedAESBinaryField1x64b, PackedAESBinaryField1x64b>();
		implements_transformation_factory::<PackedBinaryField1x64b, PackedAESBinaryField1x64b>();

		// 128 bit packed aes tower
		implements_transformation_factory::<PackedAESBinaryField16x8b, PackedAESBinaryField16x8b>();
		implements_transformation_factory::<PackedBinaryField16x8b, PackedAESBinaryField16x8b>();
		implements_transformation_factory::<PackedAESBinaryField8x16b, PackedAESBinaryField8x16b>();
		implements_transformation_factory::<PackedBinaryField8x16b, PackedAESBinaryField8x16b>();
		implements_transformation_factory::<PackedAESBinaryField4x32b, PackedAESBinaryField4x32b>();
		implements_transformation_factory::<PackedBinaryField4x32b, PackedAESBinaryField4x32b>();
		implements_transformation_factory::<PackedAESBinaryField2x64b, PackedAESBinaryField2x64b>();
		implements_transformation_factory::<PackedBinaryField2x64b, PackedAESBinaryField2x64b>();
		implements_transformation_factory::<PackedAESBinaryField1x128b, PackedAESBinaryField1x128b>(
		);
		implements_transformation_factory::<PackedBinaryField1x128b, PackedAESBinaryField1x128b>();

		// 256 bit packed aes tower
		implements_transformation_factory::<PackedAESBinaryField32x8b, PackedAESBinaryField32x8b>();
		implements_transformation_factory::<PackedBinaryField32x8b, PackedAESBinaryField32x8b>();
		implements_transformation_factory::<PackedAESBinaryField16x16b, PackedAESBinaryField16x16b>(
		);
		implements_transformation_factory::<PackedBinaryField16x16b, PackedAESBinaryField16x16b>();
		implements_transformation_factory::<PackedAESBinaryField8x32b, PackedAESBinaryField8x32b>();
		implements_transformation_factory::<PackedBinaryField8x32b, PackedAESBinaryField8x32b>();
		implements_transformation_factory::<PackedAESBinaryField4x64b, PackedAESBinaryField4x64b>();
		implements_transformation_factory::<PackedBinaryField4x64b, PackedAESBinaryField4x64b>();
		implements_transformation_factory::<PackedAESBinaryField2x128b, PackedAESBinaryField2x128b>(
		);
		implements_transformation_factory::<PackedBinaryField2x128b, PackedAESBinaryField2x128b>();

		// 512 bit packed aes tower
		implements_transformation_factory::<PackedAESBinaryField64x8b, PackedAESBinaryField64x8b>();
		implements_transformation_factory::<PackedBinaryField64x8b, PackedAESBinaryField64x8b>();
		implements_transformation_factory::<PackedAESBinaryField32x16b, PackedAESBinaryField32x16b>(
		);
		implements_transformation_factory::<PackedBinaryField32x16b, PackedAESBinaryField32x16b>();
		implements_transformation_factory::<PackedAESBinaryField16x32b, PackedAESBinaryField16x32b>(
		);
		implements_transformation_factory::<PackedBinaryField16x32b, PackedAESBinaryField16x32b>();
		implements_transformation_factory::<PackedAESBinaryField8x64b, PackedAESBinaryField8x64b>();
		implements_transformation_factory::<PackedBinaryField8x64b, PackedAESBinaryField8x64b>();
		implements_transformation_factory::<PackedAESBinaryField4x128b, PackedAESBinaryField4x128b>(
		);
		implements_transformation_factory::<PackedBinaryField4x128b, PackedAESBinaryField4x128b>();
	}
}

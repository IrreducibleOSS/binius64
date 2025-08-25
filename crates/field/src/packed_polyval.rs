// Copyright 2024-2025 Irreducible Inc.

pub use crate::arch::{
	packed_polyval_128::PackedBinaryPolyval1x128b, packed_polyval_256::PackedBinaryPolyval2x128b,
	packed_polyval_512::PackedBinaryPolyval4x128b,
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
				fn test_mul_packed_128(a_val in any::<u128>(), b_val in any::<u128>()) {
					TestMult::<$crate::arch::packed_polyval_128::PackedBinaryPolyval1x128b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}

				#[test]
				fn test_mul_packed_256(a_val in any::<[u128; 2]>(), b_val in any::<[u128; 2]>()) {
					TestMult::<$crate::arch::packed_polyval_256::PackedBinaryPolyval2x128b>::test_mul(
						a_val.into(),
						b_val.into(),
					);
				}

				#[test]
				fn test_mul_packed_512(a_val in any::<[u128; 4]>(), b_val in any::<[u128; 4]>()) {
					TestMult::<$crate::arch::packed_polyval_512::PackedBinaryPolyval4x128b>::test_mul(
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
				fn test_square_packed_128(a_val in any::<u128>()) {
					TestSquare::<$crate::arch::packed_polyval_128::PackedBinaryPolyval1x128b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_256(a_val in any::<[u128; 2]>()) {
					TestSquare::<$crate::arch::packed_polyval_256::PackedBinaryPolyval2x128b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_512(a_val in any::<[u128; 4]>()) {
					TestSquare::<$crate::arch::packed_polyval_512::PackedBinaryPolyval4x128b>::test_square(a_val.into());
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
				fn test_invert_packed_128(a_val in any::<u128>()) {
					TestInvert::<$crate::arch::packed_polyval_128::PackedBinaryPolyval1x128b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_256(a_val in any::<[u128; 2]>()) {
					TestInvert::<$crate::arch::packed_polyval_256::PackedBinaryPolyval2x128b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_512(a_val in any::<[u128; 4]>()) {
					TestInvert::<$crate::arch::packed_polyval_512::PackedBinaryPolyval4x128b>::test_invert(a_val.into());
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
				fn test_transformation_packed_128(a_val in proptest::prelude::any::<u128>()) {
					TestTransformation::<$crate::arch::packed_polyval_128::PackedBinaryPolyval1x128b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_256(a_val in proptest::prelude::any::<[u128; 2]>()) {
					TestTransformation::<$crate::arch::packed_polyval_256::PackedBinaryPolyval2x128b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_512(a_val in proptest::prelude::any::<[u128; 4]>()) {
					TestTransformation::<$crate::arch::packed_polyval_512::PackedBinaryPolyval4x128b>::test_transformation(a_val.into());
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

	use proptest::{arbitrary::any, proptest};

	use super::test_utils::{
		define_invert_tests, define_multiply_tests, define_square_tests,
		define_transformation_tests,
	};
	use crate::{PackedField, linear_transformation::PackedTransformationFactory};

	define_multiply_tests!(Mul::mul, PackedField);

	define_square_tests!(PackedField::square, PackedField);

	define_invert_tests!(PackedField::invert_or_zero, PackedField);

	#[allow(unused)]
	trait SelfTransformationFactory: PackedTransformationFactory<Self> {}

	impl<T: PackedTransformationFactory<T>> SelfTransformationFactory for T {}

	define_transformation_tests!(SelfTransformationFactory);
}

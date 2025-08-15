// Copyright 2023-2025 Irreducible Inc.

pub use crate::arch::{
	packed_1::*, packed_2::*, packed_4::*, packed_8::*, packed_16::*, packed_32::*, packed_64::*,
	packed_128::*, packed_256::*, packed_512::*,
};

/// Common code to test different multiply, square and invert implementations
#[cfg(test)]
pub mod test_utils {
	use crate::{
		BinaryField, PackedField,
		linear_transformation::PackedTransformationFactory,
		underlier::{U1, U2, U4, WithUnderlier},
	};

	pub struct Unit;

	impl From<U1> for Unit {
		fn from(_: U1) -> Self {
			Self
		}
	}

	impl From<U2> for Unit {
		fn from(_: U2) -> Self {
			Self
		}
	}

	impl From<U4> for Unit {
		fn from(_: U4) -> Self {
			Self
		}
	}

	impl From<u8> for Unit {
		fn from(_: u8) -> Self {
			Self
		}
	}

	impl From<u16> for Unit {
		fn from(_: u16) -> Self {
			Self
		}
	}

	impl From<u32> for Unit {
		fn from(_: u32) -> Self {
			Self
		}
	}

	impl From<u64> for Unit {
		fn from(_: u64) -> Self {
			Self
		}
	}

	impl From<u128> for Unit {
		fn from(_: u128) -> Self {
			Self
		}
	}

	impl From<[u128; 2]> for Unit {
		fn from(_: [u128; 2]) -> Self {
			Self
		}
	}

	impl From<[u128; 4]> for Unit {
		fn from(_: [u128; 4]) -> Self {
			Self
		}
	}

	/// We use such helper macros to run tests only for the
	/// types that implement the `constraint` trait.
	/// The idea is inspired by `impls` trait.
	macro_rules! define_check_packed_mul {
		($mult_func:path, $constraint:path) => {
			#[allow(unused)]
			trait TestMulTrait<T> {
				fn test_mul(_a: T, _b: T) {}
			}

			impl<T> TestMulTrait<$crate::packed_binary_field::test_utils::Unit> for T {}

			struct TestMult<T>(std::marker::PhantomData<T>);

			impl<T: $constraint + PackedField + $crate::underlier::WithUnderlier> TestMult<T> {
				fn test_mul(
					a: <T as $crate::underlier::WithUnderlier>::Underlier,
					b: <T as $crate::underlier::WithUnderlier>::Underlier,
				) {
					let a = T::from_underlier(a);
					let b = T::from_underlier(b);

					let c = $mult_func(a, b);
					for i in 0..T::WIDTH {
						assert_eq!(c.get(i), a.get(i) * b.get(i));
					}
				}
			}
		};
	}

	pub(crate) use define_check_packed_mul;

	macro_rules! define_check_packed_square {
		($square_func:path, $constraint:path) => {
			#[allow(unused)]
			trait TestSquareTrait<T> {
				fn test_square(_a: T) {}
			}

			impl<T> TestSquareTrait<$crate::packed_binary_field::test_utils::Unit> for T {}

			struct TestSquare<T>(std::marker::PhantomData<T>);

			impl<T: $constraint + PackedField + $crate::underlier::WithUnderlier> TestSquare<T> {
				fn test_square(a: <T as $crate::underlier::WithUnderlier>::Underlier) {
					let a = T::from_underlier(a);

					let c = $square_func(a);
					for i in 0..T::WIDTH {
						assert_eq!(c.get(i), a.get(i) * a.get(i));
					}
				}
			}
		};
	}

	pub(crate) use define_check_packed_square;

	macro_rules! define_check_packed_inverse {
		($invert_func:path, $constraint:path) => {
			#[allow(unused)]
			trait TestInvertTrait<T> {
				fn test_invert(_a: T) {}
			}

			impl<T> TestInvertTrait<$crate::packed_binary_field::test_utils::Unit> for T {}

			struct TestInvert<T>(std::marker::PhantomData<T>);

			#[allow(unused)]
			impl<T: $constraint + PackedField + $crate::underlier::WithUnderlier> TestInvert<T> {
				fn test_invert(a: <T as $crate::underlier::WithUnderlier>::Underlier) {
					use crate::Field;

					let a = T::from_underlier(a);

					let c = $invert_func(a);
					for i in 0..T::WIDTH {
						assert!(
							(c.get(i).is_zero().into()
								&& a.get(i).is_zero().into()
								&& c.get(i).is_zero().into())
								|| T::Scalar::ONE == a.get(i) * c.get(i)
						);
					}
				}
			}
		};
	}

	pub(crate) use define_check_packed_inverse;

	macro_rules! define_check_packed_mul_alpha {
		($mul_alpha_func:path, $constraint:path) => {
			#[allow(unused)]
			trait TestMulAlphaTrait<T> {
				fn test_mul_alpha(_a: T) {}
			}

			impl<T> TestMulAlphaTrait<$crate::packed_binary_field::test_utils::Unit> for T {}

			struct TestMulAlpha<T>(std::marker::PhantomData<T>);

			impl<T: $constraint + PackedField + $crate::underlier::WithUnderlier> TestMulAlpha<T>
			where
				T::Scalar: $crate::arithmetic_traits::MulAlpha,
			{
				fn test_mul_alpha(a: <T as $crate::underlier::WithUnderlier>::Underlier) {
					use $crate::arithmetic_traits::MulAlpha;

					let a = T::from_underlier(a);

					let c = $mul_alpha_func(a);
					for i in 0..T::WIDTH {
						assert_eq!(c.get(i), MulAlpha::mul_alpha(a.get(i)));
					}
				}
			}
		};
	}

	pub(crate) use define_check_packed_mul_alpha;

	macro_rules! define_check_packed_transformation {
		($constraint:path) => {
			#[allow(unused)]
			trait TestTransformationTrait<T> {
				fn test_transformation(_a: T) {}
			}

			impl<T> TestTransformationTrait<$crate::packed_binary_field::test_utils::Unit> for T {}

			struct TestTransformation<T>(std::marker::PhantomData<T>);

			impl<T: $constraint + PackedField + $crate::underlier::WithUnderlier>
				TestTransformation<T>
			{
				fn test_transformation(a: <T as $crate::underlier::WithUnderlier>::Underlier) {
					use ::rand::prelude::*;
					use $crate::linear_transformation::{
						FieldLinearTransformation, Transformation,
					};

					let a = T::from_underlier(a);

					// TODO: think how we can use random seed from proptests here
					let rng = StdRng::seed_from_u64(0);
					let field_transformation =
						FieldLinearTransformation::<T::Scalar, _>::random(rng);
					let packed_transformation =
						T::make_packed_transformation(field_transformation.clone());

					let c = packed_transformation.transform(&a);
					for i in 0..T::WIDTH {
						assert_eq!(c.get(i), field_transformation.transform(&a.get(i)));
					}
				}
			}
		};
	}

	pub(crate) use define_check_packed_transformation;

	/// Test if `mult_func` operation is a valid multiply operation on the given values for
	/// all possible packed fields defined on u128.
	macro_rules! define_multiply_tests {
		($mult_func:path, $constraint:path) => {
			$crate::packed_binary_field::test_utils::define_check_packed_mul!(
				$mult_func,
				$constraint
			);

			proptest::proptest! {
				#[test]
				fn test_mul_packed_8(a_val in proptest::prelude::any::<u8>(), b_val in proptest::prelude::any::<u8>()) {
					use $crate::arch::packed_8::*;

					TestMult::<PackedBinaryField8x1b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField4x2b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField2x4b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField1x8b>::test_mul(a_val.into(), b_val.into());
				}

				#[test]
				fn test_mul_packed_16(a_val in proptest::prelude::any::<u16>(), b_val in proptest::prelude::any::<u16>()) {
					use $crate::arch::packed_16::*;

					TestMult::<PackedBinaryField16x1b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField8x2b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField4x4b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField2x8b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField1x16b>::test_mul(a_val.into(), b_val.into());
				}

				#[test]
				fn test_mul_packed_32(a_val in proptest::prelude::any::<u32>(), b_val in proptest::prelude::any::<u32>()) {
					use $crate::arch::packed_32::*;

					TestMult::<PackedBinaryField32x1b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField16x2b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField8x4b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField4x8b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField2x16b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField1x32b>::test_mul(a_val.into(), b_val.into());
				}

				#[test]
				fn test_mul_packed_64(a_val in proptest::prelude::any::<u64>(), b_val in proptest::prelude::any::<u64>()) {
					use $crate::arch::packed_64::*;

					TestMult::<PackedBinaryField64x1b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField32x2b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField16x4b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField8x8b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField4x16b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField2x32b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField1x64b>::test_mul(a_val.into(), b_val.into());
				}

				#[test]
				fn test_mul_packed_128(a_val in proptest::prelude::any::<u128>(), b_val in proptest::prelude::any::<u128>()) {
					use $crate::arch::packed_128::*;

					TestMult::<PackedBinaryField128x1b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField64x2b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField32x4b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField16x8b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField8x16b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField4x32b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField2x64b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField1x128b>::test_mul(a_val.into(), b_val.into());
				}

				#[test]
				fn test_mul_packed_256(a_val in proptest::prelude::any::<[u128; 2]>(), b_val in proptest::prelude::any::<[u128; 2]>()) {
					use $crate::arch::packed_256::*;

					TestMult::<PackedBinaryField256x1b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField128x2b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField64x4b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField32x8b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField16x16b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField8x32b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField4x64b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField2x128b>::test_mul(a_val.into(), b_val.into());
				}

				#[test]
				fn test_mul_packed_512(a_val in proptest::prelude::any::<[u128; 4]>(), b_val in proptest::prelude::any::<[u128; 4]>()) {
					use $crate::arch::packed_512::*;

					TestMult::<PackedBinaryField512x1b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField256x2b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField128x4b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField64x8b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField32x16b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField16x32b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField8x64b>::test_mul(a_val.into(), b_val.into());
					TestMult::<PackedBinaryField4x128b>::test_mul(a_val.into(), b_val.into());
				}
			}
		};
	}

	/// Test if `square_func` operation is a valid square operation on the given value for
	/// all possible packed fields.
	macro_rules! define_square_tests {
		($square_func:path, $constraint:path) => {
			$crate::packed_binary_field::test_utils::define_check_packed_square!(
				$square_func,
				$constraint
			);

			proptest::proptest! {
				#[test]
				fn test_square_packed_8(a_val in proptest::prelude::any::<u8>()) {
					use $crate::arch::packed_8::*;

					TestSquare::<PackedBinaryField8x1b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField4x2b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField2x4b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField1x8b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_16(a_val in proptest::prelude::any::<u16>()) {
					use $crate::arch::packed_16::*;

					TestSquare::<PackedBinaryField16x1b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField8x2b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField4x4b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField2x8b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField1x16b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_32(a_val in proptest::prelude::any::<u32>()) {
					use $crate::arch::packed_32::*;

					TestSquare::<PackedBinaryField32x1b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField16x2b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField8x4b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField4x8b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField2x16b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField1x32b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_64(a_val in proptest::prelude::any::<u64>()) {
					use $crate::arch::packed_64::*;

					TestSquare::<PackedBinaryField64x1b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField32x2b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField16x4b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField8x8b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField4x16b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField2x32b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField1x64b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_128(a_val in proptest::prelude::any::<u128>()) {
					use $crate::arch::packed_128::*;

					TestSquare::<PackedBinaryField128x1b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField64x2b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField32x4b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField16x8b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField8x16b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField4x32b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField2x64b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField1x128b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_256(a_val in proptest::prelude::any::<[u128; 2]>()) {
					use $crate::arch::packed_256::*;

					TestSquare::<PackedBinaryField256x1b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField128x2b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField64x4b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField32x8b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField16x16b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField8x32b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField4x64b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField2x128b>::test_square(a_val.into());
				}

				#[test]
				fn test_square_packed_512(a_val in proptest::prelude::any::<[u128; 4]>()) {
					use $crate::arch::packed_512::*;

					TestSquare::<PackedBinaryField512x1b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField256x2b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField128x4b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField64x8b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField32x16b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField16x32b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField8x64b>::test_square(a_val.into());
					TestSquare::<PackedBinaryField4x128b>::test_square(a_val.into());
				}
			}
		};
	}

	/// Test if `invert_func` operation is a valid invert operation on the given value for
	/// all possible packed fields.
	macro_rules! define_invert_tests {
		($invert_func:path, $constraint:path) => {
			$crate::packed_binary_field::test_utils::define_check_packed_inverse!(
				$invert_func,
				$constraint
			);

			proptest::proptest! {
				#[test]
				fn test_invert_packed_8(a_val in proptest::prelude::any::<u8>()) {
					use $crate::arch::packed_8::*;

					TestInvert::<PackedBinaryField8x1b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField4x2b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField2x4b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField1x8b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_16(a_val in proptest::prelude::any::<u16>()) {
					use $crate::arch::packed_16::*;

					TestInvert::<PackedBinaryField16x1b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField8x2b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField4x4b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField2x8b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField1x16b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_32(a_val in proptest::prelude::any::<u32>()) {
					use $crate::arch::packed_32::*;

					TestInvert::<PackedBinaryField32x1b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField16x2b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField8x4b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField4x8b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField2x16b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField1x32b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_64(a_val in proptest::prelude::any::<u64>()) {
					use $crate::arch::packed_64::*;

					TestInvert::<PackedBinaryField64x1b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField32x2b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField16x4b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField8x8b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField4x16b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField2x32b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField1x64b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_128(a_val in proptest::prelude::any::<u128>()) {
					use $crate::arch::packed_128::*;

					TestInvert::<PackedBinaryField128x1b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField64x2b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField32x4b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField16x8b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField8x16b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField4x32b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField2x64b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField1x128b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_256(a_val in proptest::prelude::any::<[u128; 2]>()) {
					use $crate::arch::packed_256::*;

					TestInvert::<PackedBinaryField256x1b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField128x2b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField64x4b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField32x8b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField16x16b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField8x32b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField4x64b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField2x128b>::test_invert(a_val.into());
				}

				#[test]
				fn test_invert_packed_512(a_val in proptest::prelude::any::<[u128; 4]>()) {
					use $crate::arch::packed_512::*;

					TestInvert::<PackedBinaryField512x1b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField256x2b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField128x4b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField64x8b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField32x16b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField16x32b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField8x64b>::test_invert(a_val.into());
					TestInvert::<PackedBinaryField4x128b>::test_invert(a_val.into());
				}
			}
		};
	}

	/// Test if `mul_alpha_func` operation is a valid multiply by alpha operation on the given value
	/// for all possible packed fields.
	macro_rules! define_mul_alpha_tests {
		($mul_alpha_func:path, $constraint:path) => {
			$crate::packed_binary_field::test_utils::define_check_packed_mul_alpha!(
				$mul_alpha_func,
				$constraint
			);

			proptest::proptest! {
				#[test]
				fn test_mul_alpha_packed_8(a_val in proptest::prelude::any::<u8>()) {
					use $crate::arch::packed_8::*;

					TestMulAlpha::<PackedBinaryField8x1b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField4x2b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField2x4b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField1x8b>::test_mul_alpha(a_val.into());
				}

				#[test]
				fn test_mul_alpha_packed_16(a_val in proptest::prelude::any::<u16>()) {
					use $crate::arch::packed_16::*;

					TestMulAlpha::<PackedBinaryField16x1b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField8x2b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField4x4b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField2x8b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField1x16b>::test_mul_alpha(a_val.into());
				}

				#[test]
				fn test_mul_alpha_packed_32(a_val in proptest::prelude::any::<u32>()) {
					use $crate::arch::packed_32::*;

					TestMulAlpha::<PackedBinaryField32x1b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField16x2b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField8x4b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField4x8b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField2x16b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField1x32b>::test_mul_alpha(a_val.into());
				}

				#[test]
				fn test_mul_alpha_packed_64(a_val in proptest::prelude::any::<u64>()) {
					use $crate::arch::packed_64::*;

					TestMulAlpha::<PackedBinaryField64x1b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField32x2b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField16x4b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField8x8b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField4x16b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField2x32b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField1x64b>::test_mul_alpha(a_val.into());
				}

				#[test]
				fn test_mul_alpha_packed_128(a_val in proptest::prelude::any::<u128>()) {
					use $crate::arch::packed_128::*;

					TestMulAlpha::<PackedBinaryField128x1b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField64x2b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField32x4b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField16x8b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField8x16b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField4x32b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField2x64b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField1x128b>::test_mul_alpha(a_val.into());
				}

				#[test]
				fn test_mul_alpha_packed_256(a_val in proptest::prelude::any::<[u128; 2]>()) {
					use $crate::arch::packed_256::*;

					TestMulAlpha::<PackedBinaryField256x1b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField128x2b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField64x4b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField32x8b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField16x16b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField8x32b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField4x64b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField2x128b>::test_mul_alpha(a_val.into());
				}

				#[test]
				fn test_mul_alpha_packed_512(a_val in proptest::prelude::any::<[u128; 4]>()) {
					use $crate::arch::packed_512::*;

					TestMulAlpha::<PackedBinaryField512x1b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField256x2b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField128x4b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField64x8b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField32x16b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField16x32b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField8x64b>::test_mul_alpha(a_val.into());
					TestMulAlpha::<PackedBinaryField4x128b>::test_mul_alpha(a_val.into());
				}
			}
		};
	}

	/// Test if `$constraint::make_packed_transformation` operation creates a valid transformation
	/// operation on the given value for all possible packed fields.
	macro_rules! define_transformation_tests {
		($constraint:path) => {
			$crate::packed_binary_field::test_utils::define_check_packed_transformation!(
				$constraint
			);

			proptest::proptest! {
				#[test]
				fn test_transformation_packed_1(a_val in 0..2u8) {
					use crate::arch::packed_1::*;

					TestTransformation::<PackedBinaryField1x1b>::test_transformation($crate::underlier::U1::new_unchecked(a_val).into());
				}

				#[test]
				fn test_transformation_packed_2(a_val in 0..4u8) {
					use crate::arch::packed_2::*;

					TestTransformation::<PackedBinaryField2x1b>::test_transformation($crate::underlier::U2::new_unchecked(a_val).into());
					TestTransformation::<PackedBinaryField1x2b>::test_transformation($crate::underlier::U2::new_unchecked(a_val).into());
				}

				#[test]
				fn test_transformation_packed_4(a_val in 0..16u8) {
					use crate::arch::packed_4::*;

					TestTransformation::<PackedBinaryField4x1b>::test_transformation($crate::underlier::U4::new_unchecked(a_val).into());
					TestTransformation::<PackedBinaryField2x2b>::test_transformation($crate::underlier::U4::new_unchecked(a_val).into());
					TestTransformation::<PackedBinaryField1x4b>::test_transformation($crate::underlier::U4::new_unchecked(a_val).into());
				}

				#[test]
				fn test_transformation_packed_8(a_val in proptest::prelude::any::<u8>()) {
					use crate::arch::packed_8::*;

					TestTransformation::<PackedBinaryField8x1b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField4x2b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField2x4b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField1x8b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_16(a_val in proptest::prelude::any::<u16>()) {
					use crate::arch::packed_16::*;

					TestTransformation::<PackedBinaryField16x1b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField8x2b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField4x4b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField2x8b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField1x16b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_32(a_val in proptest::prelude::any::<u32>()) {
					use crate::arch::packed_32::*;

					TestTransformation::<PackedBinaryField32x1b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField16x2b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField8x4b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField4x8b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField2x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField1x32b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_64(a_val in proptest::prelude::any::<u64>()) {
					use $crate::arch::packed_64::*;

					TestTransformation::<PackedBinaryField64x1b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField32x2b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField16x4b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField8x8b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField4x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField2x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField1x64b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_128(a_val in proptest::prelude::any::<u128>()) {
					use $crate::arch::packed_128::*;

					TestTransformation::<PackedBinaryField128x1b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField64x2b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField32x4b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField16x8b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField8x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField4x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField2x64b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField1x128b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_256(a_val in proptest::prelude::any::<[u128; 2]>()) {
					use $crate::arch::packed_256::*;

					TestTransformation::<PackedBinaryField256x1b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField128x2b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField64x4b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField32x8b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField16x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField8x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField4x64b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField2x128b>::test_transformation(a_val.into());
				}

				#[test]
				fn test_transformation_packed_512(a_val in proptest::prelude::any::<[u128; 4]>()) {
					use $crate::arch::packed_512::*;

					TestTransformation::<PackedBinaryField512x1b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField256x2b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField128x4b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField64x8b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField32x16b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField16x32b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField8x64b>::test_transformation(a_val.into());
					TestTransformation::<PackedBinaryField4x128b>::test_transformation(a_val.into());
				}
			}
		};
	}

	pub(crate) use define_invert_tests;
	pub(crate) use define_mul_alpha_tests;
	pub(crate) use define_multiply_tests;
	pub(crate) use define_square_tests;
	pub(crate) use define_transformation_tests;

	/// Helper function for compile-time checks
	#[allow(unused)]
	pub const fn implements_transformation_factory<
		P1: PackedField<Scalar: BinaryField>,
		P2: PackedTransformationFactory<P1>,
	>() {
	}

	pub fn check_interleave<P: PackedField + WithUnderlier>(
		lhs: P::Underlier,
		rhs: P::Underlier,
		log_block_len: usize,
	) {
		let lhs = P::from_underlier(lhs);
		let rhs = P::from_underlier(rhs);
		let (a, b) = lhs.interleave(rhs, log_block_len);
		let block_len = 1 << log_block_len;
		for i in (0..P::WIDTH).step_by(block_len * 2) {
			for j in 0..block_len {
				assert_eq!(a.get(i + j), lhs.get(i + j));
				assert_eq!(a.get(i + j + block_len), rhs.get(i + j));

				assert_eq!(b.get(i + j), lhs.get(i + j + block_len));
				assert_eq!(b.get(i + j + block_len), rhs.get(i + j + block_len));
			}
		}
	}

	pub fn check_interleave_all_heights<P: PackedField + WithUnderlier>(
		lhs: P::Underlier,
		rhs: P::Underlier,
	) {
		for log_block_len in 0..P::LOG_WIDTH {
			check_interleave::<P>(lhs, rhs, log_block_len);
		}
	}

	pub fn check_unzip<P: PackedField + WithUnderlier>(
		lhs: P::Underlier,
		rhs: P::Underlier,
		log_block_len: usize,
	) {
		let lhs = P::from_underlier(lhs);
		let rhs = P::from_underlier(rhs);
		let block_len = 1 << log_block_len;
		let (a, b) = lhs.unzip(rhs, log_block_len);
		for i in (0..P::WIDTH / 2).step_by(block_len) {
			for j in 0..block_len {
				assert_eq!(
					a.get(i + j),
					lhs.get(2 * i + j),
					"i: {}, j: {}, log_block_len: {}, P: {:?}",
					i,
					j,
					log_block_len,
					P::zero()
				);
				assert_eq!(
					b.get(i + j),
					lhs.get(2 * i + j + block_len),
					"i: {}, j: {}, log_block_len: {}, P: {:?}",
					i,
					j,
					log_block_len,
					P::zero()
				);
			}
		}

		for i in (0..P::WIDTH / 2).step_by(block_len) {
			for j in 0..block_len {
				assert_eq!(
					a.get(i + j + P::WIDTH / 2),
					rhs.get(2 * i + j),
					"i: {}, j: {}, log_block_len: {}, P: {:?}",
					i,
					j,
					log_block_len,
					P::zero()
				);
				assert_eq!(b.get(i + j + P::WIDTH / 2), rhs.get(2 * i + j + block_len));
			}
		}
	}

	pub fn check_transpose_all_heights<P: PackedField + WithUnderlier>(
		lhs: P::Underlier,
		rhs: P::Underlier,
	) {
		for log_block_len in 0..P::LOG_WIDTH {
			check_unzip::<P>(lhs, rhs, log_block_len);
		}
	}
}

#[cfg(test)]
mod tests {
	use std::{iter::repeat_with, ops::Mul};

	use binius_utils::{DeserializeBytes, SerializeBytes, bytes::BytesMut};
	use proptest::prelude::*;
	use rand::prelude::*;
	use test_utils::{check_interleave_all_heights, implements_transformation_factory};

	use super::{
		test_utils::{
			define_invert_tests, define_mul_alpha_tests, define_multiply_tests,
			define_square_tests, define_transformation_tests,
		},
		*,
	};
	use crate::{
		PackedField, Random,
		arch::{
			packed_aes_16::*, packed_aes_32::*, packed_aes_64::*, packed_aes_128::*,
			packed_aes_256::*, packed_aes_512::*,
		},
		arithmetic_traits::MulAlpha,
		linear_transformation::PackedTransformationFactory,
		test_utils::check_transpose_all_heights,
		underlier::{U2, U4},
	};

	fn test_add_packed<P: PackedField + From<u128>>(a_val: u128, b_val: u128) {
		let a = P::from(a_val);
		let b = P::from(b_val);
		let c = a + b;
		for i in 0..P::WIDTH {
			assert_eq!(c.get(i), a.get(i) + b.get(i));
		}
	}

	fn test_mul_packed<P: PackedField>(a: P, b: P) {
		let c = a * b;
		for i in 0..P::WIDTH {
			assert_eq!(c.get(i), a.get(i) * b.get(i));
		}
	}

	fn test_mul_packed_random<P: PackedField>() {
		let mut rng = StdRng::seed_from_u64(0);
		test_mul_packed(P::random(&mut rng), P::random(&mut rng))
	}

	fn test_set_then_get<P: PackedField>() {
		let mut rng = StdRng::seed_from_u64(0);
		let mut elem = P::random(&mut rng);

		let scalars = repeat_with(|| P::Scalar::random(&mut rng))
			.take(P::WIDTH)
			.collect::<Vec<_>>();

		for (i, val) in scalars.iter().enumerate() {
			elem.set(i, *val);
		}
		for (i, val) in scalars.iter().enumerate() {
			assert_eq!(elem.get(i), *val);
		}
	}

	fn test_serialize_then_deserialize<P: PackedField + DeserializeBytes + SerializeBytes>() {
		let mut buffer = BytesMut::new();
		let mut rng = StdRng::seed_from_u64(0);
		let packed = P::random(&mut rng);
		packed.serialize(&mut buffer).unwrap();

		let mut read_buffer = buffer.freeze();

		assert_eq!(P::deserialize(&mut read_buffer).unwrap(), packed);
	}

	#[test]
	fn test_set_then_get_4b() {
		test_set_then_get::<PackedBinaryField32x4b>();
		test_set_then_get::<PackedBinaryField64x4b>();
		test_set_then_get::<PackedBinaryField128x4b>();
	}

	#[test]
	fn test_serialize_then_deserialize_4b() {
		test_serialize_then_deserialize::<PackedBinaryField32x4b>();
		test_serialize_then_deserialize::<PackedBinaryField64x4b>();
		test_serialize_then_deserialize::<PackedBinaryField128x4b>();
		test_serialize_then_deserialize::<PackedBinaryField8x4b>();
	}

	#[test]
	fn test_set_then_get_32b() {
		test_set_then_get::<PackedBinaryField4x32b>();
		test_set_then_get::<PackedBinaryField8x32b>();
		test_set_then_get::<PackedBinaryField16x32b>();
	}

	#[test]
	fn test_serialize_then_deserialize_32b() {
		test_serialize_then_deserialize::<PackedBinaryField4x32b>();
		test_serialize_then_deserialize::<PackedBinaryField8x32b>();
		test_serialize_then_deserialize::<PackedBinaryField16x32b>();
	}

	#[test]
	fn test_set_then_get_64b() {
		test_set_then_get::<PackedBinaryField2x64b>();
		test_set_then_get::<PackedBinaryField4x64b>();
		test_set_then_get::<PackedBinaryField8x64b>();
	}

	#[test]
	fn test_serialize_then_deserialize_64b() {
		test_serialize_then_deserialize::<PackedBinaryField2x64b>();
		test_serialize_then_deserialize::<PackedBinaryField4x64b>();
		test_serialize_then_deserialize::<PackedBinaryField8x64b>();
	}

	#[test]
	fn test_set_then_get_128b() {
		test_set_then_get::<PackedBinaryField1x128b>();
		test_set_then_get::<PackedBinaryField2x128b>();
		test_set_then_get::<PackedBinaryField4x128b>();
	}

	#[test]
	fn test_serialize_then_deserialize_128b() {
		test_serialize_then_deserialize::<PackedBinaryField1x128b>();
		test_serialize_then_deserialize::<PackedBinaryField2x128b>();
		test_serialize_then_deserialize::<PackedBinaryField4x128b>();
	}

	#[test]
	fn test_serialize_deserialize_different_packing_width() {
		let mut rng = StdRng::seed_from_u64(0);

		let packed0 = PackedBinaryField1x128b::random(&mut rng);
		let packed1 = PackedBinaryField1x128b::random(&mut rng);

		let mut buffer = BytesMut::new();
		packed0.serialize(&mut buffer).unwrap();
		packed1.serialize(&mut buffer).unwrap();

		let mut read_buffer = buffer.freeze();
		let packed01 = PackedBinaryField2x128b::deserialize(&mut read_buffer).unwrap();

		assert!(
			packed01
				.iter()
				.zip([packed0, packed1])
				.all(|(x, y)| x == y.get(0))
		);
	}

	// TODO: Generate lots more proptests using macros
	proptest! {
		#[test]
		fn test_add_packed_128x1b(a_val in any::<u128>(), b_val in any::<u128>()) {
			test_add_packed::<PackedBinaryField128x1b>(a_val, b_val)
		}

		#[test]
		fn test_add_packed_16x8b(a_val in any::<u128>(), b_val in any::<u128>()) {
			test_add_packed::<PackedBinaryField16x8b>(a_val, b_val)
		}

		#[test]
		fn test_add_packed_8x16b(a_val in any::<u128>(), b_val in any::<u128>()) {
			test_add_packed::<PackedBinaryField8x16b>(a_val, b_val)
		}

		#[test]
		fn test_add_packed_4x32b(a_val in any::<u128>(), b_val in any::<u128>()) {
			test_add_packed::<PackedBinaryField4x32b>(a_val, b_val)
		}

		#[test]
		fn test_add_packed_2x64b(a_val in any::<u128>(), b_val in any::<u128>()) {
			test_add_packed::<PackedBinaryField2x64b>(a_val, b_val)
		}

		#[test]
		fn test_add_packed_1x128b(a_val in any::<u128>(), b_val in any::<u128>()) {
			test_add_packed::<PackedBinaryField1x128b>(a_val, b_val)
		}
	}

	#[test]
	fn test_mul_packed_256x1b() {
		test_mul_packed_random::<PackedBinaryField256x1b>()
	}

	#[test]
	fn test_mul_packed_32x8b() {
		test_mul_packed_random::<PackedBinaryField32x8b>()
	}

	#[test]
	fn test_mul_packed_16x16b() {
		test_mul_packed_random::<PackedBinaryField16x16b>()
	}

	#[test]
	fn test_mul_packed_8x32b() {
		test_mul_packed_random::<PackedBinaryField8x32b>()
	}

	#[test]
	fn test_mul_packed_4x64b() {
		test_mul_packed_random::<PackedBinaryField4x64b>()
	}

	#[test]
	fn test_mul_packed_2x128b() {
		test_mul_packed_random::<PackedBinaryField2x128b>()
	}

	#[test]
	fn test_iter_size_hint() {
		assert_valid_iterator_with_exact_size_hint::<crate::BinaryField128b>();
		assert_valid_iterator_with_exact_size_hint::<crate::BinaryField32b>();
		assert_valid_iterator_with_exact_size_hint::<crate::BinaryField1b>();
		assert_valid_iterator_with_exact_size_hint::<PackedBinaryField128x1b>();
		assert_valid_iterator_with_exact_size_hint::<PackedBinaryField64x2b>();
		assert_valid_iterator_with_exact_size_hint::<PackedBinaryField32x4b>();
		assert_valid_iterator_with_exact_size_hint::<PackedBinaryField16x16b>();
		assert_valid_iterator_with_exact_size_hint::<PackedBinaryField8x32b>();
		assert_valid_iterator_with_exact_size_hint::<PackedBinaryField4x64b>();
	}

	fn assert_valid_iterator_with_exact_size_hint<P: PackedField>() {
		assert_eq!(P::default().iter().size_hint(), (P::WIDTH, Some(P::WIDTH)));
		assert_eq!(P::default().into_iter().size_hint(), (P::WIDTH, Some(P::WIDTH)));
		assert_eq!(P::default().iter().count(), P::WIDTH);
		assert_eq!(P::default().into_iter().count(), P::WIDTH);
	}

	define_multiply_tests!(Mul::mul, PackedField);

	define_square_tests!(PackedField::square, PackedField);

	define_invert_tests!(PackedField::invert_or_zero, PackedField);

	define_mul_alpha_tests!(MulAlpha::mul_alpha, MulAlpha);

	#[allow(unused)]
	trait SelfTransformationFactory: PackedTransformationFactory<Self> {}

	impl<T: PackedTransformationFactory<T>> SelfTransformationFactory for T {}

	define_transformation_tests!(SelfTransformationFactory);

	/// Compile-time test to ensure packed fields implement `PackedTransformationFactory`.
	#[allow(unused)]
	const fn test_implement_transformation_factory() {
		// 1 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField1x1b, PackedBinaryField1x1b>();

		// 2 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField2x1b, PackedBinaryField2x1b>();
		implements_transformation_factory::<PackedBinaryField1x2b, PackedBinaryField1x2b>();

		// 4 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField4x1b, PackedBinaryField4x1b>();
		implements_transformation_factory::<PackedBinaryField2x2b, PackedBinaryField2x2b>();
		implements_transformation_factory::<PackedBinaryField1x4b, PackedBinaryField1x4b>();

		// 8 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField8x1b, PackedBinaryField8x1b>();
		implements_transformation_factory::<PackedBinaryField4x2b, PackedBinaryField4x2b>();
		implements_transformation_factory::<PackedBinaryField2x4b, PackedBinaryField2x4b>();
		implements_transformation_factory::<PackedBinaryField1x8b, PackedBinaryField1x8b>();

		// 16 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField16x1b, PackedBinaryField16x1b>();
		implements_transformation_factory::<PackedBinaryField8x2b, PackedBinaryField8x2b>();
		implements_transformation_factory::<PackedBinaryField4x4b, PackedBinaryField4x4b>();
		implements_transformation_factory::<PackedBinaryField2x8b, PackedBinaryField2x8b>();
		implements_transformation_factory::<PackedAESBinaryField2x8b, PackedBinaryField2x8b>();
		implements_transformation_factory::<PackedBinaryField1x16b, PackedBinaryField1x16b>();

		// 32 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField32x1b, PackedBinaryField32x1b>();
		implements_transformation_factory::<PackedBinaryField16x2b, PackedBinaryField16x2b>();
		implements_transformation_factory::<PackedBinaryField8x4b, PackedBinaryField8x4b>();
		implements_transformation_factory::<PackedBinaryField4x8b, PackedBinaryField4x8b>();
		implements_transformation_factory::<PackedAESBinaryField4x8b, PackedBinaryField4x8b>();
		implements_transformation_factory::<PackedBinaryField2x16b, PackedBinaryField2x16b>();
		implements_transformation_factory::<PackedBinaryField1x32b, PackedBinaryField1x32b>();

		// 64 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField64x1b, PackedBinaryField64x1b>();
		implements_transformation_factory::<PackedBinaryField32x2b, PackedBinaryField32x2b>();
		implements_transformation_factory::<PackedBinaryField16x4b, PackedBinaryField16x4b>();
		implements_transformation_factory::<PackedBinaryField8x8b, PackedBinaryField8x8b>();
		implements_transformation_factory::<PackedAESBinaryField8x8b, PackedBinaryField8x8b>();
		implements_transformation_factory::<PackedBinaryField4x16b, PackedBinaryField4x16b>();
		implements_transformation_factory::<PackedBinaryField2x32b, PackedBinaryField2x32b>();
		implements_transformation_factory::<PackedBinaryField1x64b, PackedBinaryField1x64b>();

		// 128 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField128x1b, PackedBinaryField128x1b>();
		implements_transformation_factory::<PackedBinaryField64x2b, PackedBinaryField64x2b>();
		implements_transformation_factory::<PackedBinaryField32x4b, PackedBinaryField32x4b>();
		implements_transformation_factory::<PackedBinaryField16x8b, PackedBinaryField16x8b>();
		implements_transformation_factory::<PackedAESBinaryField16x8b, PackedBinaryField16x8b>();
		implements_transformation_factory::<PackedBinaryField8x16b, PackedBinaryField8x16b>();
		implements_transformation_factory::<PackedBinaryField4x32b, PackedBinaryField4x32b>();
		implements_transformation_factory::<PackedBinaryField2x64b, PackedBinaryField2x64b>();
		implements_transformation_factory::<PackedBinaryField1x128b, PackedBinaryField1x128b>();

		// 256 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField256x1b, PackedBinaryField256x1b>();
		implements_transformation_factory::<PackedBinaryField128x2b, PackedBinaryField128x2b>();
		implements_transformation_factory::<PackedBinaryField64x4b, PackedBinaryField64x4b>();
		implements_transformation_factory::<PackedBinaryField32x8b, PackedBinaryField32x8b>();
		implements_transformation_factory::<PackedAESBinaryField32x8b, PackedBinaryField32x8b>();
		implements_transformation_factory::<PackedBinaryField16x16b, PackedBinaryField16x16b>();
		implements_transformation_factory::<PackedBinaryField8x32b, PackedBinaryField8x32b>();
		implements_transformation_factory::<PackedBinaryField4x64b, PackedBinaryField4x64b>();
		implements_transformation_factory::<PackedBinaryField2x128b, PackedBinaryField2x128b>();

		// 512 bit packed binary tower
		implements_transformation_factory::<PackedBinaryField512x1b, PackedBinaryField512x1b>();
		implements_transformation_factory::<PackedBinaryField256x2b, PackedBinaryField256x2b>();
		implements_transformation_factory::<PackedBinaryField128x4b, PackedBinaryField128x4b>();
		implements_transformation_factory::<PackedBinaryField64x8b, PackedBinaryField64x8b>();
		implements_transformation_factory::<PackedAESBinaryField64x8b, PackedBinaryField64x8b>();
		implements_transformation_factory::<PackedBinaryField32x16b, PackedBinaryField32x16b>();
		implements_transformation_factory::<PackedBinaryField16x32b, PackedBinaryField16x32b>();
		implements_transformation_factory::<PackedBinaryField8x64b, PackedBinaryField8x64b>();
		implements_transformation_factory::<PackedBinaryField4x128b, PackedBinaryField4x128b>();
	}

	proptest! {
		#[test]
		fn test_interleave_2b(a_val in 0u8..3, b_val in 0u8..3) {
			check_interleave_all_heights::<PackedBinaryField2x1b>(U2::new(a_val), U2::new(b_val));
			check_interleave_all_heights::<PackedBinaryField1x2b>(U2::new(a_val), U2::new(b_val));
		}

		#[test]
		fn test_interleave_4b(a_val in 0u8..16, b_val in 0u8..16) {
			check_interleave_all_heights::<PackedBinaryField4x1b>(U4::new(a_val), U4::new(b_val));
			check_interleave_all_heights::<PackedBinaryField2x2b>(U4::new(a_val), U4::new(b_val));
			check_interleave_all_heights::<PackedBinaryField1x4b>(U4::new(a_val), U4::new(b_val));
		}

		#[test]
		fn test_interleave_8b(a_val in 0u8.., b_val in 0u8..) {
			check_interleave_all_heights::<PackedBinaryField8x1b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField4x2b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField2x4b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField1x8b>(a_val, b_val);
		}

		#[test]
		fn test_interleave_16b(a_val in 0u16.., b_val in 0u16..) {
			check_interleave_all_heights::<PackedBinaryField16x1b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField8x2b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField4x4b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField2x8b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField1x16b>(a_val, b_val);
		}

		#[test]
		fn test_interleave_32b(a_val in 0u32.., b_val in 0u32..) {
			check_interleave_all_heights::<PackedBinaryField32x1b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField16x2b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField8x4b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField4x8b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField2x16b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField1x32b>(a_val, b_val);
		}

		#[test]
		fn test_interleave_64b(a_val in 0u64.., b_val in 0u64..) {
			check_interleave_all_heights::<PackedBinaryField64x1b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField32x2b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField16x4b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField8x8b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField4x16b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField2x32b>(a_val, b_val);
			check_interleave_all_heights::<PackedBinaryField1x64b>(a_val, b_val);
		}

		#[test]
		#[allow(clippy::useless_conversion)] // this warning depends on the target platform
		fn test_interleave_128b(a_val in 0u128.., b_val in 0u128..) {
			check_interleave_all_heights::<PackedBinaryField128x1b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField64x2b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField32x4b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField16x8b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField8x16b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField4x32b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField2x64b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField1x128b>(a_val.into(), b_val.into());
		}

		#[test]
		fn test_interleave_256b(a_val in any::<[u128; 2]>(), b_val in any::<[u128; 2]>()) {
			check_interleave_all_heights::<PackedBinaryField256x1b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField128x2b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField64x4b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField32x8b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField16x16b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField8x32b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField4x64b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField2x128b>(a_val.into(), b_val.into());
		}

		#[test]
		fn test_interleave_512b(a_val in any::<[u128; 4]>(), b_val in any::<[u128; 4]>()) {
			check_interleave_all_heights::<PackedBinaryField512x1b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField256x2b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField128x4b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField64x8b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField32x16b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField16x32b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField8x64b>(a_val.into(), b_val.into());
			check_interleave_all_heights::<PackedBinaryField4x128b>(a_val.into(), b_val.into());
		}

		#[test]
		fn check_transpose_2b(a_val in 0u8..3, b_val in 0u8..3) {
			check_transpose_all_heights::<PackedBinaryField2x1b>(U2::new(a_val), U2::new(b_val));
			check_transpose_all_heights::<PackedBinaryField1x2b>(U2::new(a_val), U2::new(b_val));
		}

		#[test]
		fn check_transpose_4b(a_val in 0u8..16, b_val in 0u8..16) {
			check_transpose_all_heights::<PackedBinaryField4x1b>(U4::new(a_val), U4::new(b_val));
			check_transpose_all_heights::<PackedBinaryField2x2b>(U4::new(a_val), U4::new(b_val));
			check_transpose_all_heights::<PackedBinaryField1x4b>(U4::new(a_val), U4::new(b_val));
		}

		#[test]
		fn check_transpose_8b(a_val in 0u8.., b_val in 0u8..) {
			check_transpose_all_heights::<PackedBinaryField8x1b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField4x2b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField2x4b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField1x8b>(a_val, b_val);
		}

		#[test]
		fn check_transpose_16b(a_val in 0u16.., b_val in 0u16..) {
			check_transpose_all_heights::<PackedBinaryField16x1b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField8x2b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField4x4b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField2x8b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField1x16b>(a_val, b_val);
		}

		#[test]
		fn check_transpose_32b(a_val in 0u32.., b_val in 0u32..) {
			check_transpose_all_heights::<PackedBinaryField32x1b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField16x2b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField8x4b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField4x8b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField2x16b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField1x32b>(a_val, b_val);
		}

		#[test]
		fn check_transpose_64b(a_val in 0u64.., b_val in 0u64..) {
			check_transpose_all_heights::<PackedBinaryField64x1b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField32x2b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField16x4b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField8x8b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField4x16b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField2x32b>(a_val, b_val);
			check_transpose_all_heights::<PackedBinaryField1x64b>(a_val, b_val);
		}

		#[test]
		#[allow(clippy::useless_conversion)] // this warning depends on the target platform
		fn check_transpose_128b(a_val in 0u128.., b_val in 0u128..) {
			check_transpose_all_heights::<PackedBinaryField128x1b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField64x2b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField32x4b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField16x8b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField8x16b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField4x32b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField2x64b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField1x128b>(a_val.into(), b_val.into());
		}

		#[test]
		fn check_transpose_256b(a_val in any::<[u128; 2]>(), b_val in any::<[u128; 2]>()) {
			check_transpose_all_heights::<PackedBinaryField256x1b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField128x2b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField64x4b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField32x8b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField16x16b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField8x32b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField4x64b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField2x128b>(a_val.into(), b_val.into());
		}

		#[test]
		fn check_transpose_512b(a_val in any::<[u128; 4]>(), b_val in any::<[u128; 4]>()) {
			check_transpose_all_heights::<PackedBinaryField512x1b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField256x2b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField128x4b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField64x8b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField32x16b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField16x32b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField8x64b>(a_val.into(), b_val.into());
			check_transpose_all_heights::<PackedBinaryField4x128b>(a_val.into(), b_val.into());
		}
	}
}

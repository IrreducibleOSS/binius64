// Copyright 2025 Irreducible Inc.

// These tests were moved to the integration tests to reduce the compilation time of the field
// crate.

use binius_field::{
	PackedAESBinaryField1x128b, PackedAESBinaryField2x64b, PackedAESBinaryField2x128b,
	PackedAESBinaryField4x32b, PackedAESBinaryField4x64b, PackedAESBinaryField4x128b,
	PackedAESBinaryField8x16b, PackedAESBinaryField8x32b, PackedAESBinaryField8x64b,
	PackedAESBinaryField16x8b, PackedAESBinaryField16x16b, PackedAESBinaryField16x32b,
	PackedAESBinaryField32x8b, PackedAESBinaryField32x16b, PackedAESBinaryField64x8b,
	PackedBinaryField128x1b, PackedBinaryField256x1b, PackedBinaryField512x1b, PackedField, Random,
	packed::{get_packed_slice, set_packed_slice},
};
use rand::{Rng, SeedableRng, distr::Uniform, rngs::StdRng};

fn random_scalars<P: PackedField>(mut rng: impl Rng) -> Vec<P::Scalar> {
	(0..P::WIDTH).map(|_| P::Scalar::random(&mut rng)).collect()
}

macro_rules! define_byte_sliced_test {
	($module_name:ident, $name:ident, $scalar_type:ty, $associated_packed:ty) => {
		mod $module_name {
			use binius_field::$name;

			use super::*;

			#[test]
			fn check_from_fn() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems = random_scalars::<$name>(&mut rng);

				let bytesliced = <$name>::from_fn(|i| scalar_elems[i]);
				for i in 0..<$name>::WIDTH {
					assert_eq!(scalar_elems[i], bytesliced.get(i));
				}
			}

			#[test]
			fn check_add() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems_a = random_scalars::<$name>(&mut rng);
				let scalar_elems_b = random_scalars::<$name>(&mut rng);

				let bytesliced_a = <$name>::from_scalars(scalar_elems_a.iter().copied());
				let bytesliced_b = <$name>::from_scalars(scalar_elems_b.iter().copied());

				let bytesliced_result = bytesliced_a + bytesliced_b;

				for i in 0..<$name>::WIDTH {
					assert_eq!(scalar_elems_a[i] + scalar_elems_b[i], bytesliced_result.get(i));
				}
			}

			#[test]
			fn check_add_assign() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems_a = random_scalars::<$name>(&mut rng);
				let scalar_elems_b = random_scalars::<$name>(&mut rng);

				let mut bytesliced_a = <$name>::from_scalars(scalar_elems_a.iter().copied());
				let bytesliced_b = <$name>::from_scalars(scalar_elems_b.iter().copied());

				bytesliced_a += bytesliced_b;

				for i in 0..<$name>::WIDTH {
					assert_eq!(scalar_elems_a[i] + scalar_elems_b[i], bytesliced_a.get(i));
				}
			}

			#[test]
			fn check_sub() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems_a = random_scalars::<$name>(&mut rng);
				let scalar_elems_b = random_scalars::<$name>(&mut rng);

				let bytesliced_a = <$name>::from_scalars(scalar_elems_a.iter().copied());
				let bytesliced_b = <$name>::from_scalars(scalar_elems_b.iter().copied());

				let bytesliced_result = bytesliced_a - bytesliced_b;

				for i in 0..<$name>::WIDTH {
					assert_eq!(scalar_elems_a[i] - scalar_elems_b[i], bytesliced_result.get(i));
				}
			}

			#[test]
			fn check_sub_assign() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems_a = random_scalars::<$name>(&mut rng);
				let scalar_elems_b = random_scalars::<$name>(&mut rng);

				let mut bytesliced_a = <$name>::from_scalars(scalar_elems_a.iter().copied());
				let bytesliced_b = <$name>::from_scalars(scalar_elems_b.iter().copied());

				bytesliced_a -= bytesliced_b;

				for i in 0..<$name>::WIDTH {
					assert_eq!(scalar_elems_a[i] - scalar_elems_b[i], bytesliced_a.get(i));
				}
			}

			#[test]
			fn check_mul() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems_a = random_scalars::<$name>(&mut rng);
				let scalar_elems_b = random_scalars::<$name>(&mut rng);

				let bytesliced_a = <$name>::from_scalars(scalar_elems_a.iter().copied());
				let bytesliced_b = <$name>::from_scalars(scalar_elems_b.iter().copied());

				let bytesliced_result = bytesliced_a * bytesliced_b;

				for i in 0..<$name>::WIDTH {
					assert_eq!(scalar_elems_a[i] * scalar_elems_b[i], bytesliced_result.get(i));
				}
			}

			#[test]
			fn check_mul_assign() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems_a = random_scalars::<$name>(&mut rng);
				let scalar_elems_b = random_scalars::<$name>(&mut rng);

				let mut bytesliced_a = <$name>::from_scalars(scalar_elems_a.iter().copied());
				let bytesliced_b = <$name>::from_scalars(scalar_elems_b.iter().copied());

				bytesliced_a *= bytesliced_b;

				for i in 0..<$name>::WIDTH {
					assert_eq!(scalar_elems_a[i] * scalar_elems_b[i], bytesliced_a.get(i));
				}
			}

			#[test]
			fn check_inv() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems = random_scalars::<$name>(&mut rng);

				let bytesliced = <$name>::from_scalars(scalar_elems.iter().copied());

				let bytesliced_result = bytesliced.invert_or_zero();

				for (i, scalar_elem) in scalar_elems.iter().enumerate() {
					assert_eq!(scalar_elem.invert_or_zero(), bytesliced_result.get(i));
				}
			}

			#[test]
			fn check_square() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems = random_scalars::<$name>(&mut rng);

				let bytesliced = <$name>::from_scalars(scalar_elems.iter().copied());

				let bytesliced_result = bytesliced.square();

				for (i, scalar_elem) in scalar_elems.iter().enumerate() {
					assert_eq!(scalar_elem.square(), bytesliced_result.get(i));
				}
			}

			#[test]
			fn check_linear_transformation() {
				use binius_field::linear_transformation::{
					FieldLinearTransformation, PackedTransformationFactory, Transformation,
				};
				use rand::{SeedableRng, rngs::StdRng};

				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems = random_scalars::<$name>(&mut rng);

				let bytesliced = <$name>::from_scalars(scalar_elems.iter().copied());

				let linear_transformation =
					FieldLinearTransformation::random(StdRng::seed_from_u64(0));
				let packed_transformation =
					<$name>::make_packed_transformation(linear_transformation.clone());

				let bytesliced_result = packed_transformation.transform(&bytesliced);

				for i in 0..<$name>::WIDTH {
					assert_eq!(
						linear_transformation.transform(&scalar_elems[i]),
						bytesliced_result.get(i)
					);
				}
			}

			#[test]
			fn check_interleave() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems_a = random_scalars::<$name>(&mut rng);
				let scalar_elems_b = random_scalars::<$name>(&mut rng);

				let bytesliced_a = <$name>::from_scalars(scalar_elems_a.iter().copied());
				let bytesliced_b = <$name>::from_scalars(scalar_elems_b.iter().copied());

				for log_block_len in 0..<$name>::LOG_WIDTH {
					let (bytesliced_c, bytesliced_d) =
						bytesliced_a.interleave(bytesliced_b, log_block_len);

					let block_len = 1 << log_block_len;
					for offset in (0..<$name>::WIDTH).step_by(2 * block_len) {
						for i in 0..block_len {
							assert_eq!(bytesliced_c.get(offset + i), scalar_elems_a[offset + i]);
							assert_eq!(
								bytesliced_c.get(offset + block_len + i),
								scalar_elems_b[offset + i]
							);

							assert_eq!(
								bytesliced_d.get(offset + i),
								scalar_elems_a[offset + block_len + i]
							);
							assert_eq!(
								bytesliced_d.get(offset + block_len + i),
								scalar_elems_b[offset + block_len + i]
							);
						}
					}
				}
			}

			#[test]
			fn check_spread() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems = random_scalars::<$name>(&mut rng);

				let bytesliced = <$name>::from_scalars(scalar_elems.iter().copied());

				let mut rng = StdRng::seed_from_u64(0);
				for log_block_len in 0..<$name>::LOG_WIDTH {
					// iterating over all possible block lengths is too slow
					let distribution = Uniform::new(0, (1 << (<$name>::LOG_WIDTH - log_block_len)))
						.expect("Failed to create uniform distribution");
					let block_index = rng.sample(distribution);

					let bytesliced_result = bytesliced.spread(log_block_len, block_index);
					let offset = block_index << log_block_len;
					let repeat_count = 1 << (<$name>::LOG_WIDTH - log_block_len);

					for i in 0..<$name>::WIDTH {
						assert_eq!(
							bytesliced_result.get(i),
							scalar_elems[offset + i / repeat_count]
						);
					}
				}
			}

			#[test]
			fn check_transpose_to() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems = random_scalars::<$name>(&mut rng);

				let bytesliced = <$name>::from_scalars(scalar_elems.iter().copied());
				let mut destination = [<$associated_packed>::zero(); <$name>::HEIGHT_BYTES];
				bytesliced.transpose_to(&mut destination);

				for i in 0..<$name>::WIDTH {
					assert_eq!(scalar_elems[i], get_packed_slice(&destination, i));
				}
			}

			#[test]
			fn check_transpose_from() {
				let mut rng = StdRng::seed_from_u64(0);
				let scalar_elems = random_scalars::<$name>(&mut rng);

				let mut destination = [<$associated_packed>::zero(); <$name>::HEIGHT_BYTES];
				for i in 0..<$name>::WIDTH {
					set_packed_slice(&mut destination, i, scalar_elems[i]);
				}

				let bytesliced = <$name>::transpose_from(&destination);

				for i in 0..<$name>::WIDTH {
					assert_eq!(get_packed_slice(&destination, i), bytesliced.get(i));
				}
			}
		}
	};
}

// 128-bit byte-sliced
define_byte_sliced_test!(
	tests_3d_16x128,
	ByteSlicedAES16x128b,
	AESTowerField128b,
	PackedAESBinaryField1x128b
);
define_byte_sliced_test!(
	tests_3d_16x64,
	ByteSlicedAES16x64b,
	AESTowerField64b,
	PackedAESBinaryField2x64b
);
define_byte_sliced_test!(
	tests_3d_2x16x64,
	ByteSlicedAES2x16x64b,
	AESTowerField64b,
	PackedAESBinaryField2x64b
);
define_byte_sliced_test!(
	tests_3d_16x32,
	ByteSlicedAES16x32b,
	AESTowerField32b,
	PackedAESBinaryField4x32b
);
define_byte_sliced_test!(
	tests_3d_4x16x32,
	ByteSlicedAES4x16x32b,
	AESTowerField32b,
	PackedAESBinaryField4x32b
);
define_byte_sliced_test!(
	tests_3d_16x16,
	ByteSlicedAES16x16b,
	AESTowerField16b,
	PackedAESBinaryField8x16b
);
define_byte_sliced_test!(
	tests_3d_8x16x16,
	ByteSlicedAES8x16x16b,
	AESTowerField16b,
	PackedAESBinaryField8x16b
);
define_byte_sliced_test!(
	tests_3d_16x8,
	ByteSlicedAES16x8b,
	AESTowerField8b,
	PackedAESBinaryField16x8b
);
define_byte_sliced_test!(
	tests_3d_16x16x8,
	ByteSlicedAES16x16x8b,
	AESTowerField8b,
	PackedAESBinaryField16x8b
);

define_byte_sliced_test!(
	tests_3d_16x128x1,
	ByteSliced16x128x1b,
	BinaryField1b,
	PackedBinaryField128x1b
);
define_byte_sliced_test!(
	tests_3d_8x128x1,
	ByteSliced8x128x1b,
	BinaryField1b,
	PackedBinaryField128x1b
);
define_byte_sliced_test!(
	tests_3d_4x128x1,
	ByteSliced4x128x1b,
	BinaryField1b,
	PackedBinaryField128x1b
);
define_byte_sliced_test!(
	tests_3d_2x128x1,
	ByteSliced2x128x1b,
	BinaryField1b,
	PackedBinaryField128x1b
);
define_byte_sliced_test!(
	tests_3d_1x128x1,
	ByteSliced1x128x1b,
	BinaryField1b,
	PackedBinaryField128x1b
);

// 256-bit byte-sliced
define_byte_sliced_test!(
	tests_3d_32x128,
	ByteSlicedAES32x128b,
	AESTowerField128b,
	PackedAESBinaryField2x128b
);
define_byte_sliced_test!(
	tests_3d_32x64,
	ByteSlicedAES32x64b,
	AESTowerField64b,
	PackedAESBinaryField4x64b
);
define_byte_sliced_test!(
	tests_3d_2x32x64,
	ByteSlicedAES2x32x64b,
	AESTowerField64b,
	PackedAESBinaryField4x64b
);
define_byte_sliced_test!(
	tests_3d_32x32,
	ByteSlicedAES32x32b,
	AESTowerField32b,
	PackedAESBinaryField8x32b
);
define_byte_sliced_test!(
	tests_3d_4x32x32,
	ByteSlicedAES4x32x32b,
	AESTowerField32b,
	PackedAESBinaryField8x32b
);
define_byte_sliced_test!(
	tests_3d_32x16,
	ByteSlicedAES32x16b,
	AESTowerField16b,
	PackedAESBinaryField16x16b
);
define_byte_sliced_test!(
	tests_3d_8x32x16,
	ByteSlicedAES8x32x16b,
	AESTowerField16b,
	PackedAESBinaryField16x16b
);
define_byte_sliced_test!(
	tests_3d_32x8,
	ByteSlicedAES32x8b,
	AESTowerField8b,
	PackedAESBinaryField32x8b
);
define_byte_sliced_test!(
	tests_3d_16x32x8,
	ByteSlicedAES16x32x8b,
	AESTowerField8b,
	PackedAESBinaryField32x8b
);

define_byte_sliced_test!(
	tests_3d_16x256x1,
	ByteSliced16x256x1b,
	BinaryField1b,
	PackedBinaryField256x1b
);
define_byte_sliced_test!(
	tests_3d_8x256x1,
	ByteSliced8x256x1b,
	BinaryField1b,
	PackedBinaryField256x1b
);
define_byte_sliced_test!(
	tests_3d_4x256x1,
	ByteSliced4x256x1b,
	BinaryField1b,
	PackedBinaryField256x1b
);
define_byte_sliced_test!(
	tests_3d_2x256x1,
	ByteSliced2x256x1b,
	BinaryField1b,
	PackedBinaryField256x1b
);
define_byte_sliced_test!(
	tests_3d_1x256x1,
	ByteSliced1x256x1b,
	BinaryField1b,
	PackedBinaryField256x1b
);

// 512-bit byte-sliced
define_byte_sliced_test!(
	tests_3d_64x128,
	ByteSlicedAES64x128b,
	AESTowerField128b,
	PackedAESBinaryField4x128b
);
define_byte_sliced_test!(
	tests_3d_64x64,
	ByteSlicedAES64x64b,
	AESTowerField64b,
	PackedAESBinaryField8x64b
);
define_byte_sliced_test!(
	tests_3d_2x64x64,
	ByteSlicedAES2x64x64b,
	AESTowerField64b,
	PackedAESBinaryField8x64b
);
define_byte_sliced_test!(
	tests_3d_64x32,
	ByteSlicedAES64x32b,
	AESTowerField32b,
	PackedAESBinaryField16x32b
);
define_byte_sliced_test!(
	tests_3d_4x64x32,
	ByteSlicedAES4x64x32b,
	AESTowerField32b,
	PackedAESBinaryField16x32b
);
define_byte_sliced_test!(
	tests_3d_64x16,
	ByteSlicedAES64x16b,
	AESTowerField16b,
	PackedAESBinaryField32x16b
);
define_byte_sliced_test!(
	tests_3d_8x64x16,
	ByteSlicedAES8x64x16b,
	AESTowerField16b,
	PackedAESBinaryField32x16b
);
define_byte_sliced_test!(
	tests_3d_64x8,
	ByteSlicedAES64x8b,
	AESTowerField8b,
	PackedAESBinaryField64x8b
);
define_byte_sliced_test!(
	tests_3d_16x64x8,
	ByteSlicedAES16x64x8b,
	AESTowerField8b,
	PackedAESBinaryField64x8b
);

define_byte_sliced_test!(
	tests_3d_16x512x1,
	ByteSliced16x512x1b,
	BinaryField1b,
	PackedBinaryField512x1b
);
define_byte_sliced_test!(
	tests_3d_8x512x1,
	ByteSliced8x512x1b,
	BinaryField1b,
	PackedBinaryField512x1b
);
define_byte_sliced_test!(
	tests_3d_4x512x1,
	ByteSliced4x512x1b,
	BinaryField1b,
	PackedBinaryField512x1b
);
define_byte_sliced_test!(
	tests_3d_2x512x1,
	ByteSliced2x512x1b,
	BinaryField1b,
	PackedBinaryField512x1b
);
define_byte_sliced_test!(
	tests_3d_1x512x1,
	ByteSliced1x512x1b,
	BinaryField1b,
	PackedBinaryField512x1b
);

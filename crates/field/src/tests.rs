// Copyright 2024-2025 Irreducible Inc.

use std::iter;

use proptest::prelude::*;

use crate::{
	AESTowerField8b, BinaryField1b, BinaryField2b, BinaryField4b, BinaryField8b, BinaryField16b,
	BinaryField32b, BinaryField64b, BinaryField128b, BinaryField128bPolyval, Field,
	PackedBinaryField1x64b, PackedBinaryField1x128b, PackedBinaryField2x32b,
	PackedBinaryField2x64b, PackedBinaryField2x128b, PackedBinaryField4x16b,
	PackedBinaryField4x32b, PackedBinaryField4x64b, PackedBinaryField4x128b, PackedBinaryField8x8b,
	PackedBinaryField8x16b, PackedBinaryField8x32b, PackedBinaryField8x64b, PackedBinaryField16x4b,
	PackedBinaryField16x8b, PackedBinaryField16x16b, PackedBinaryField16x32b,
	PackedBinaryField32x2b, PackedBinaryField32x4b, PackedBinaryField32x8b,
	PackedBinaryField32x16b, PackedBinaryField64x1b, PackedBinaryField64x2b,
	PackedBinaryField64x4b, PackedBinaryField64x8b, PackedBinaryField128x1b,
	PackedBinaryField128x2b, PackedBinaryField128x4b, PackedBinaryField256x1b,
	PackedBinaryField256x2b, PackedBinaryField512x1b, PackedField,
	underlier::{SmallU, WithUnderlier},
};

#[test]
fn test_field_text_debug() {
	assert_eq!(format!("{:?}", BinaryField1b::ONE), "BinaryField1b(0x1)");
	assert_eq!(format!("{:?}", AESTowerField8b::from_underlier(127)), "AESTowerField8b(0x7f)");
	assert_eq!(
		format!("{:?}", BinaryField128bPolyval::from_underlier(162259276829213363391578010288127)),
		"BinaryField128bPolyval(0xcffc05f0000000000000000000000000)"
	);
	assert_eq!(
		format!(
			"{:?}",
			PackedBinaryField1x128b::broadcast(BinaryField128b::from_underlier(
				162259276829213363391578010288127
			))
		),
		"Packed1x128([0x000007ffffffffffffffffffffffffff])"
	);
	assert_eq!(
		format!("{:?}", PackedBinaryField4x32b::broadcast(BinaryField32b::from_underlier(123))),
		"Packed4x32([0x0000007b,0x0000007b,0x0000007b,0x0000007b])"
	)
}

fn basic_spread<P>(packed: P, log_block_len: usize, block_idx: usize) -> P
where
	P: PackedField,
{
	assert!(log_block_len <= P::LOG_WIDTH);

	let block_len = 1 << log_block_len;
	let repeat = 1 << (P::LOG_WIDTH - log_block_len);
	assert!(block_idx < repeat);

	P::from_scalars(
		packed
			.iter()
			.skip(block_idx * block_len)
			.take(block_len)
			.flat_map(|elem| iter::repeat_n(elem, repeat)),
	)
}

macro_rules! generate_spread_tests_small {
    ($($name:ident, $type:ty, $scalar:ty, $underlier:ty, $width: expr);* $(;)?) => {
        proptest! {
            $(
                #[test]
                #[allow(clippy::modulo_one)]
                fn $name(z in any::<[u8; $width]>()) {
                    let indexed_packed_field = <$type>::from_fn(|i| <$scalar>::from_underlier(<$underlier>::new(z[i])));
                    for log_block_len in 0..=<$type>::LOG_WIDTH {
						for block_idx in 0..(1 <<(<$type>::LOG_WIDTH - log_block_len)) {
							assert_eq!(
								basic_spread(indexed_packed_field, log_block_len, block_idx),
								indexed_packed_field.spread(log_block_len, block_idx)
							);
						}
					}
                }
            )*
        }
    };
}

macro_rules! generate_spread_tests {
    ($($name:ident, $type:ty, $scalar:ty, $underlier:ty, $width: expr);* $(;)?) => {
        proptest! {
            $(
                #[test]
                #[allow(clippy::modulo_one)]
                fn $name(z in any::<[$underlier; $width]>()) {
                    let indexed_packed_field = <$type>::from_fn(|i| <$scalar>::from_underlier(z[i].into()));
                    for log_block_len in 0..=<$type>::LOG_WIDTH {
						for block_idx in 0..(1 <<(<$type>::LOG_WIDTH - log_block_len)) {
							assert_eq!(
								basic_spread(indexed_packed_field, log_block_len, block_idx),
								indexed_packed_field.spread(log_block_len, block_idx)
							);
						}
					}
				}
            )*
        }
    };
}

generate_spread_tests! {
	// 128-bit configurations
	spread_equals_basic_spread_4x128, PackedBinaryField4x128b, BinaryField128b, u128, 4;
	spread_equals_basic_spread_2x128, PackedBinaryField2x128b, BinaryField128b, u128, 2;
	spread_equals_basic_spread_1x128, PackedBinaryField1x128b, BinaryField128b, u128, 1;

	// 64-bit configurations
	spread_equals_basic_spread_8x64, PackedBinaryField8x64b, BinaryField64b, u64, 8;
	spread_equals_basic_spread_4x64, PackedBinaryField4x64b, BinaryField64b, u64, 4;
	spread_equals_basic_spread_2x64, PackedBinaryField2x64b, BinaryField64b, u64, 2;
	spread_equals_basic_spread_1x64, PackedBinaryField1x64b, BinaryField64b, u8, 1;

	// 32-bit configurations
	spread_equals_basic_spread_16x32, PackedBinaryField16x32b, BinaryField32b, u32, 16;
	spread_equals_basic_spread_8x32, PackedBinaryField8x32b, BinaryField32b, u32, 8;
	spread_equals_basic_spread_4x32, PackedBinaryField4x32b, BinaryField32b, u32, 4;
	spread_equals_basic_spread_2x32, PackedBinaryField2x32b, BinaryField32b, u32, 2;

	// 16-bit configurations
	spread_equals_basic_spread_32x16, PackedBinaryField32x16b, BinaryField16b, u16, 32;
	spread_equals_basic_spread_16x16, PackedBinaryField16x16b, BinaryField16b, u16, 16;
	spread_equals_basic_spread_8x16, PackedBinaryField8x16b, BinaryField16b, u16, 8;
	spread_equals_basic_spread_4x16, PackedBinaryField4x16b, BinaryField16b, u16, 4;

	// 8-bit configurations
	spread_equals_basic_spread_64x8, PackedBinaryField64x8b, BinaryField8b, u8, 64;
	spread_equals_basic_spread_32x8, PackedBinaryField32x8b, BinaryField8b, u8, 32;
	spread_equals_basic_spread_16x8, PackedBinaryField16x8b, BinaryField8b, u8, 16;
	spread_equals_basic_spread_8x8, PackedBinaryField8x8b, BinaryField8b, u8, 8;
}

generate_spread_tests_small! {
	// 4-bit configurations
	spread_equals_basic_spread_128x4, PackedBinaryField128x4b, BinaryField4b, SmallU<4>, 128;
	spread_equals_basic_spread_64x4, PackedBinaryField64x4b, BinaryField4b, SmallU<4>, 64;
	spread_equals_basic_spread_32x4, PackedBinaryField32x4b, BinaryField4b, SmallU<4>, 32;
	spread_equals_basic_spread_16x4, PackedBinaryField16x4b, BinaryField4b, SmallU<4>, 16;

	// 2-bit configurations
	spread_equals_basic_spread_256x2, PackedBinaryField256x2b, BinaryField2b, SmallU<2>, 256;
	spread_equals_basic_spread_128x2, PackedBinaryField128x2b, BinaryField2b, SmallU<2>, 128;
	spread_equals_basic_spread_64x2, PackedBinaryField64x2b, BinaryField2b, SmallU<2>, 64;
	spread_equals_basic_spread_32x2, PackedBinaryField32x2b, BinaryField2b, SmallU<2>, 32;

	// 1-bit configurations
	spread_equals_basic_spread_512x1, PackedBinaryField512x1b, BinaryField1b, SmallU<1>, 512;
	spread_equals_basic_spread_256x1, PackedBinaryField256x1b, BinaryField1b, SmallU<1>, 256;
	spread_equals_basic_spread_128x1, PackedBinaryField128x1b, BinaryField1b, SmallU<1>, 128;
	spread_equals_basic_spread_64x1, PackedBinaryField64x1b, BinaryField1b, SmallU<1>, 64;
}

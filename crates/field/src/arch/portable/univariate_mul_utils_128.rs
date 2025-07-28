// Copyright (c) 2019-2025 The RustCrypto Project Developers
// Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

//! Constant-time software implementation of carryless multiplication for 64-bit architectures.
//!
//! This implementation is adapted from the RustCrypto/universal-hashes repository:
//! <https://github.com/RustCrypto/universal-hashes>
//!
//! Which in turn was adapted from BearSSL's `ghash_ctmul64.c`:
//! <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul64.c;hb=4b6046412>

use std::num::Wrapping;

pub fn split_u128(x: u128) -> (u64, u64) {
	((x >> 64) as u64, x as u64)
}

pub fn join_u64s(high: u64, low: u64) -> u128 {
	((high as u128) << 64) | (low as u128)
}

/// Multiplication in GF(2)\[X\], truncated to the low 64-bits, with "holes"
/// (sequences of zeroes) to avoid carry spilling.
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked
/// out of the result.
pub fn bmul64(x: u64, y: u64) -> u64 {
	let x0 = Wrapping(x & 0x1111_1111_1111_1111);
	let x1 = Wrapping(x & 0x2222_2222_2222_2222);
	let x2 = Wrapping(x & 0x4444_4444_4444_4444);
	let x3 = Wrapping(x & 0x8888_8888_8888_8888);
	let y0 = Wrapping(y & 0x1111_1111_1111_1111);
	let y1 = Wrapping(y & 0x2222_2222_2222_2222);
	let y2 = Wrapping(y & 0x4444_4444_4444_4444);
	let y3 = Wrapping(y & 0x8888_8888_8888_8888);

	let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
	let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
	let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
	let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;

	z0 &= 0x1111_1111_1111_1111;
	z1 &= 0x2222_2222_2222_2222;
	z2 &= 0x4444_4444_4444_4444;
	z3 &= 0x8888_8888_8888_8888;

	z0 | z1 | z2 | z3
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_u64x2_conversion() {
		// Test round-trip conversion
		let test_values = [
			0u128,
			1u128,
			u128::MAX,
			0x0123456789abcdef_fedcba9876543210u128,
		];

		for &val in &test_values {
			let u64x2 = split_u128(val);
			let back: u128 = join_u64s(u64x2.0, u64x2.1);
			assert_eq!(val, back, "Round-trip conversion failed for 0x{val:032x}");
		}
	}

	#[test]
	fn test_bmul64_basic() {
		// Test basic cases
		assert_eq!(bmul64(0, 0), 0);
		assert_eq!(bmul64(1, 1), 1);
		assert_eq!(bmul64(2, 2), 4);
		assert_eq!(bmul64(3, 3), 5); // 11b * 11b = 101b in GF(2)[X]

		// Test that bmul64 is commutative
		let test_pairs = [
			(0x1234567890abcdef, 0xfedcba0987654321),
			(0x1111111111111111, 0x2222222222222222),
			(0xaaaaaaaaaaaaaaaa, 0x5555555555555555),
		];

		for (a, b) in test_pairs {
			assert_eq!(
				bmul64(a, b),
				bmul64(b, a),
				"bmul64 not commutative for 0x{a:016x} and 0x{b:016x}",
			);
		}
	}
}

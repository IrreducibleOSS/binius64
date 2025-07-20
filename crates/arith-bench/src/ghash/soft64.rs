// Copyright (c) 2019-2025 The RustCrypto Project Developers
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

//! Constant-time software implementation of GHASH for 64-bit architectures.
//!
//! This implementation is adapted from the RustCrypto/universal-hashes repository:
//! <https://github.com/RustCrypto/universal-hashes>
//!
//! Which in turn was adapted from BearSSL's `ghash_ctmul64.c`:
//! <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul64.c;hb=4b6046412>
//!
//! Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

use core::num::Wrapping;

/// Multiply two GHASH field elements using software implementation.
pub fn mul(x: u128, y: u128) -> u128 {
	// Convert to U64x2 representation
	let x_u64x2 = U64x2::from(x);
	let y_u64x2 = U64x2::from(y);

	// Perform multiplication
	let result = x_u64x2 * y_u64x2;

	// Convert back to u128
	result.into()
}

/// 2 x `u64` values
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct U64x2(u64, u64);

impl From<u128> for U64x2 {
	fn from(x: u128) -> Self {
		// Little-endian: low 64 bits first, then high 64 bits
		U64x2(x as u64, (x >> 64) as u64)
	}
}

impl From<U64x2> for u128 {
	fn from(x: U64x2) -> Self {
		// Little-endian: x.0 is low 64 bits, x.1 is high 64 bits
		(x.0 as u128) | ((x.1 as u128) << 64)
	}
}

impl core::ops::Add for U64x2 {
	type Output = Self;

	/// Adds two GHASH field elements.
	fn add(self, rhs: Self) -> Self::Output {
		U64x2(self.0 ^ rhs.0, self.1 ^ rhs.1)
	}
}

impl core::ops::Mul for U64x2 {
	type Output = Self;

	/// Computes carryless GHASH multiplication over GF(2^128) in constant time.
	///
	/// Method described at:
	/// <https://www.bearssl.org/constanttime.html#ghash-for-gcm>
	///
	/// POLYVAL multiplication is effectively the little endian equivalent of
	/// GHASH multiplication, aside from one small detail described here:
	///
	/// <https://crypto.stackexchange.com/questions/66448/how-does-bearssls-gcm-modular-reduction-work/66462#66462>
	///
	/// > The product of two bit-reversed 128-bit polynomials yields the
	/// > bit-reversed result over 255 bits, not 256. The BearSSL code ends up
	/// > with a 256-bit result in zw[], and that value is shifted by one bit,
	/// > because of that reversed convention issue. Thus, the code must
	/// > include a shifting step to put it back where it should
	///
	/// This shift is unnecessary for POLYVAL and has been removed.
	fn mul(self, rhs: Self) -> Self {
		let h0 = self.0;
		let h1 = self.1;
		let h0r = rev64(h0);
		let h1r = rev64(h1);
		let h2 = h0 ^ h1;
		let h2r = h0r ^ h1r;

		let y0 = rhs.0;
		let y1 = rhs.1;
		let y0r = rev64(y0);
		let y1r = rev64(y1);
		let y2 = y0 ^ y1;
		let y2r = y0r ^ y1r;

		let z0 = bmul64(y0, h0);
		let z1 = bmul64(y1, h1);
		let mut z2 = bmul64(y2, h2);

		let mut z0h = bmul64(y0r, h0r);
		let mut z1h = bmul64(y1r, h1r);
		let mut z2h = bmul64(y2r, h2r);

		z2 ^= z0 ^ z1;
		z2h ^= z0h ^ z1h;
		z0h = rev64(z0h) >> 1;
		z1h = rev64(z1h) >> 1;
		z2h = rev64(z2h) >> 1;

		let mut v0 = z0;
		let mut v1 = z0h ^ z2;
		let mut v2 = z1 ^ z2h;
		let v3 = z1h;

		v1 ^= v3 ^ (v3 << 1) ^ (v3 << 2) ^ (v3 << 7);
		v2 ^= (v3 >> 63) ^ (v3 >> 62) ^ (v3 >> 57);
		v0 ^= v2 ^ (v2 << 1) ^ (v2 << 2) ^ (v2 << 7);
		v1 ^= (v2 >> 63) ^ (v2 >> 62) ^ (v2 >> 57);

		U64x2(v0, v1)
	}
}

/// Multiplication in GF(2)\[X\], truncated to the low 64-bits.
///
/// Performs carryless multiplication using integer multiplication instructions with "holes"
/// (sequences of zeroes) to avoid carry spilling. When carries do occur, they wind up in a "hole"
/// and are subsequently masked out of the result.
///
/// Resources:
/// * <https://www.bearssl.org/constanttime.html#ghash-for-gcm>
/// * <https://crypto.stackexchange.com/questions/66448/how-does-bearssls-gcm-modular-reduction-work/66462#66462>
fn bmul64(x: u64, y: u64) -> u64 {
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

/// Bit-reverse a `u64` in constant time
fn rev64(mut x: u64) -> u64 {
	x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
	x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
	x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
	x = ((x & 0x00ff_00ff_00ff_00ff) << 8) | ((x >> 8) & 0x00ff_00ff_00ff_00ff);
	x = ((x & 0xffff_0000_ffff) << 16) | ((x >> 16) & 0xffff_0000_ffff);
	x.rotate_right(32)
}

#[cfg(test)]
mod tests {
	use proptest::prelude::*;

	use super::*;
	use crate::ghash::ONE;

	proptest! {
		#[test]
		fn test_ghash_soft64_mul_commutative(
			a in any::<u128>(),
			b in any::<u128>()
		) {
			// Test that a * b = b * a
			let ab = mul(a, b);
			let ba = mul(b, a); // // spellchecker:disable-line
			prop_assert_eq!(ab, ba, "GHASH soft64 multiplication is not commutative"); // spellchecker:disable-line
		}

		#[test]
		fn test_ghash_soft64_mul_associative(
			a in any::<u128>(),
			b in any::<u128>(),
			c in any::<u128>()
		) {
			// Test that (a * b) * c = a * (b * c)
			let ab_c = mul(mul(a, b), c);
			let a_bc = mul(a, mul(b, c));
			prop_assert_eq!(ab_c, a_bc, "GHASH soft64 multiplication is not associative");
		}

		#[test]
		fn test_ghash_soft64_mul_distributive(
			a in any::<u128>(),
			b in any::<u128>(),
			c in any::<u128>()
		) {
			// Test that a * (b + c) = (a * b) + (a * c) where + is XOR
			let b_plus_c = b ^ c;
			let a_times_b_plus_c = mul(a, b_plus_c);

			let ab = mul(a, b);
			let ac = mul(a, c);
			let ab_plus_ac = ab ^ ac;

			prop_assert_eq!(a_times_b_plus_c, ab_plus_ac,
				"GHASH soft64 multiplication does not satisfy the distributive law");
		}

		#[test]
		fn test_ghash_soft64_mul_identity(
			a in any::<u128>()
		) {
			// Test that a * ONE = a
			let result = mul(a, ONE);
			prop_assert_eq!(result, a, "The provided identity is not the multiplicative identity in GHASH soft64");
		}
	}

	#[test]
	fn test_u64x2_conversion() {
		// Test round-trip conversion
		let test_values = [
			0u128,
			1u128,
			u128::MAX,
			0x0123456789abcdef_fedcba9876543210u128,
			ONE,
		];

		for &val in &test_values {
			let u64x2 = U64x2::from(val);
			let back: u128 = u64x2.into();
			assert_eq!(val, back, "Round-trip conversion failed for 0x{val:032x}");
		}
	}

	#[test]
	fn test_rev64() {
		// Test bit reversal
		assert_eq!(rev64(0x0000000000000000), 0x0000000000000000);
		assert_eq!(rev64(0xffffffffffffffff), 0xffffffffffffffff);
		assert_eq!(rev64(0x0123456789abcdef), 0xf7b3d591e6a2c480);
		assert_eq!(rev64(0x8000000000000000), 0x0000000000000001);
		assert_eq!(rev64(0x0000000000000001), 0x8000000000000000);
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

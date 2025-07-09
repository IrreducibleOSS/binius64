//! Arithmetic for the GHASH field, GF(2)[X] / (X^128 + X^7 + X^2 + X + 1).

use crate::{PackedUnderlier, Underlier, underlier::OpsClmul};

/// The multiplicative identity in GHASH
///
/// In GHASH, the standard representation of 1 is simply 0x01
pub const GHASH_ONE: u128 = 0x01;

#[inline]
#[allow(dead_code)]
pub fn mul_clmul<U: Underlier + OpsClmul + PackedUnderlier<u128>>(x: U, y: U) -> U {
	// Based on the C++ reference implementation
	// The algorithm performs polynomial multiplication followed by reduction

	// t1a = x.lo * y.hi
	let t1a = U::clmulepi64::<0x01>(x, y);
	// t1b = x.hi * y.lo
	let t1b = U::clmulepi64::<0x10>(x, y);
	// t1 = t1a + t1b (XOR in binary field)
	let mut t1 = U::xor(t1a, t1b);
	// t2 = x.hi * y.hi
	let t2 = U::clmulepi64::<0x11>(x, y);
	// Reduce t1 and t2
	t1 = gf2_128_reduce(t1, t2);
	// t0 = x.lo * y.lo
	let mut t0 = U::clmulepi64::<0x00>(x, y);
	// Final reduction
	t0 = gf2_128_reduce(t0, t1);

	t0
}

/// Performs reduction step: returns t0 + x^64 * t1
#[inline]
fn gf2_128_reduce<U: Underlier + OpsClmul + PackedUnderlier<u128>>(mut t0: U, t1: U) -> U {
	// The reduction polynomial x^128 + x^7 + x^2 + x + 1 is represented as 0x87
	const POLY: u128 = 0x87;
	let poly = <U as PackedUnderlier<u128>>::broadcast(POLY);

	// t0 = t0 XOR (t1 << 64)
	// In SIMD, left shift by 64 bits is shifting by 8 bytes
	t0 = U::xor(t0, U::slli_si128::<8>(t1));

	// t0 = t0 XOR clmul(t1, poly, 0x01)
	// This multiplies the high 64 bits of t1 with the low 64 bits of poly
	t0 = U::xor(t0, U::clmulepi64::<0x01>(t1, poly));

	t0
}

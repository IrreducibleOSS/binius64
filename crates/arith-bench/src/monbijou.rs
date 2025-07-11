//! Arithmetic for the Monbijou field, GF(2)\[X\] / (X^64 + X^4 + X^3 + X + 1).
//!
//! This module implements arithmetic in the GF(2^64) binary field defined by the
//! reduction polynomial X^64 + X^4 + X^3 + X + 1, which is used in the ISO 3309
//! standard for CRC-64 error detection.
//!
//! The implementation uses carry-less multiplication (CLMUL) CPU instructions for
//! efficient field multiplication on modern x86_64 processors. The algorithm is
//! optimized for SIMD parallelism, processing multiple field elements simultaneously
//! when using vector types like __m128i or __m256i.

use crate::{PackedUnderlier, Underlier, underlier::OpsClmul};

/// The multiplicative identity in the Monbijou field
///
/// In this field, the standard representation of 1 is simply 0x01
pub const MONBIJOU_ONE: u64 = 0x01;

/// The multiplicative identity in the Monbijou 128-bit extension field
///
/// In the degree-2 extension GF(2^128), the standard representation of 1 is simply 0x01
pub const MONBIJOU_128B_ONE: u128 = 0x01;

/// Multiplies two elements in GF(2^64) using SIMD carry-less multiplication.
///
/// This function performs multiplication in the Monbijou field GF(2^64) defined by
/// the reduction polynomial X^64 + X^4 + X^3 + X + 1. The algorithm uses a two-stage
/// reduction process to efficiently handle the polynomial reduction after multiplication.
#[inline]
#[allow(dead_code)]
pub fn mul_clmul<U: Underlier + OpsClmul + PackedUnderlier<u64>>(a: U, b: U) -> U {
	// Step 1: Carry-less multiplication of 64-bit operands produces 128-bit results
	// For SIMD types, this processes multiple pairs in parallel
	let prod_0 = U::clmulepi64::<0x00>(a, b); // 128-bit pre-reduction product elements 0
	let prod_1 = U::clmulepi64::<0x11>(a, b); // 128-bit pre-reduction product elements 1
	reduce_pair(prod_0, prod_1)
}

pub fn mul_128b_clmul_uint64x2_t(a_vec: uint64x2_t, b_vec: uint64x2_t) -> uint64x2_t {
	mul_128b_clmul::<uint64x2_t>(a_vec, b_vec)
}

/// Multiplies two elements in GF(2^128), represented as a degree-2 extension of GF(2^64).
///
/// This field is defined as GF(2)[X, Y] / (X^64 + X^4 + X^3 + X + 1) / (Y^2 + XY + 1).
#[inline]
pub fn mul_128b_clmul<U: Underlier + OpsClmul + PackedUnderlier<u64>>(x: U, y: U) -> U {
	// This is the bit representation of the lower-degree terms (X^4 + X^3 + X + 1)
	const POLY: u64 = 0x1B;
	let poly = <U as PackedUnderlier<u64>>::broadcast(POLY);

	// t0 = x.lo * y.lo
	let t0 = U::clmulepi64::<0x00>(x, y);
	// t2 = x.hi * y.hi
	let t2 = U::clmulepi64::<0x11>(x, y);

	// t1a = x.lo * y.hi
	let t1a = U::clmulepi64::<0x01>(x, y);
	// t1b = x.hi * y.lo
	let t1b = U::clmulepi64::<0x10>(x, y);
	// t1 = t1a + t1b (XOR in binary field)
	let t1 = U::xor(t1a, t1b);

	// println!("t2 low:  0x{:?}", t2);

	let mut t2_times_x = t2;
	// U::slli_epi64::<1>(t2);
	// let t2_overflow_mask = U::movepi64_mask(t2);
	// let t2_overflow_redc = U::and(poly, t2_overflow_mask);
	// t2_times_x = U::xor(t2_overflow_redc, t2_times_x);

	let term0 = U::xor(t0, t2);
	let term1 = U::xor(t1, t2_times_x);

	reduce_pair(term0, term1)
}

#[inline]
fn reduce_pair<U: Underlier + OpsClmul + PackedUnderlier<u64>>(prod_0: U, prod_1: U) -> U {
	// The reduction polynomial X^64 + X^4 + X^3 + X + 1 is represented as 0x1B
	// This is the bit representation of the lower-degree terms (X^4 + X^3 + X + 1)
	const POLY: u64 = 0x1B;
	let poly = <U as PackedUnderlier<u64>>::broadcast(POLY);

	// Step 2: First reduction - multiply high 64 bits by reduction polynomial
	// This effectively computes: high_bits * (X^4 + X^3 + X + 1) mod X^128
	let first_reduction_0 = U::clmulepi64::<0x01>(prod_0, poly);
	let first_reduction_1 = U::clmulepi64::<0x01>(prod_1, poly);

	// Extract the low 64 bits from the original products and first reductions
	let prod_lo = U::unpacklo_epi64(prod_0, prod_1);
	let first_reduction_lo = U::unpacklo_epi64(first_reduction_0, first_reduction_1);
	let result = U::xor(prod_lo, first_reduction_lo);

	// Step 3: Second reduction - handle overflow from the first reduction
	// The first reduction can produce results up to 67 bits, so we need another reduction
	let second_reduction_0 = U::clmulepi64::<0x01>(first_reduction_0, poly);
	let second_reduction_1 = U::clmulepi64::<0x01>(first_reduction_1, poly);

	// Extract low 64 bits of the second reduction
	let second_reduction_lo = U::unpacklo_epi64(second_reduction_0, second_reduction_1);

	// Final result: XOR all three components together
	U::xor(result, second_reduction_lo)
}

// MY STUFF

use core::arch::aarch64::uint64x2_t;
use std::{arch::aarch64::*, mem::transmute};

pub fn mul_128b_mine(a_vec: uint64x2_t, b_vec: uint64x2_t) -> uint64x2_t {
	unsafe {
		let low_a = vgetq_lane_u64(a_vec, 0);
		let low_b = vgetq_lane_u64(b_vec, 0);
		let high_a = vgetq_lane_u64(a_vec, 1);
		let high_b = vgetq_lane_u64(b_vec, 1);

		let low_mult = transmute(vmull_p64(low_a, low_b));
		let high_mult = transmute(vmull_p64(high_a, high_b));

		// duplicate high_a
		let high_a_vec = vdupq_n_u64(high_a);
		// add to x.0 to get sum of low_a, high_a
		let sum_a_vec = veorq_u64(a_vec, high_a_vec);
		let low_high_sum_a = vgetq_lane_u64(sum_a_vec, 0);
		let high_b_vec = vdupq_n_u64(high_b);
		let sum_b_vec = veorq_u64(b_vec, high_b_vec);
		let low_high_sum_b = vgetq_lane_u64(sum_b_vec, 0);
		let low_high_sum_mult = transmute(vmull_p64(low_high_sum_a, low_high_sum_b));

		let mid_mult = veor3q_u64(low_high_sum_mult, low_mult, high_mult);

		// we can try not transmuting these things, and instead passing the vmull outputs as u128s
		// to regular registers only reason i did it here is in order to use eor3
		// we should also try doing the reduction inside simd, well i guess the intermediate shifts
		// need to happen in regular registers
		let result_unreduced_low: u128 = transmute(veorq_u64(low_mult, high_mult));
		let mid_mult: u128 = transmute(mid_mult);
		let high_mult: u128 = transmute(high_mult);
		let result_unreduced_high: u128 = mid_mult ^ (high_mult << 1);

		let result_high = reduce_full(result_unreduced_high);
		let result_low = reduce_part(result_unreduced_low);

		let x = (result_high as u128) << 64 | result_low as u128;
		transmute(x)
	}
}

use core::arch::asm;
pub fn swap_lanes_with_ext(a: uint64x2_t) -> uint64x2_t {
	unsafe {
		let result: uint64x2_t;
		asm!(
			"ext {result:v}.16b, {a:v}.16b, {a:v}.16b, #8",
			a = in(vreg) a,
			result = out(vreg) result,
			options(pure, nomem, nostack)
		);
		result
	}
}

pub fn mul_128b_wo_karatsuba(a_vec: uint64x2_t, b_vec: uint64x2_t) -> uint64x2_t {
	unsafe {
		let low_a = vgetq_lane_u64(a_vec, 0);
		let low_b = vgetq_lane_u64(b_vec, 0);
		let high_a = vgetq_lane_u64(a_vec, 1);
		let high_b = vgetq_lane_u64(b_vec, 1);

		let low_mult = transmute(vmull_p64(low_a, low_b));
		let high_mult = transmute(vmull_p64(high_a, high_b));

		// let swapped_a = swap_lanes_with_ext(a_vec);
		// let swapped_lo_a = vgetq_lane_u64(swapped_a, 0);
		// let swapped_hi_a = vgetq_lane_u64(swapped_a, 1);
		let swapped_a_vec = vextq_u64(a_vec, a_vec, 1);
		let swapped_lo_a = vgetq_lane_u64(swapped_a_vec, 0);
		let swapped_hi_a = vgetq_lane_u64(swapped_a_vec, 1);
		let a_lo_b_hi = transmute(vmull_p64(swapped_lo_a, low_b));
		let a_hi_b_lo = transmute(vmull_p64(swapped_hi_a, high_b));
		let mid_mult = veorq_u64(a_lo_b_hi, a_hi_b_lo);

		// first i think we calculate the carryless result. then we reduce.
		// they have t0,t1,t2.
		// first we can try just flipping one of them with an ext, then doing two more muls.
		// add the middles.
		// then we have the whole thing.
		// what next?
		// (a+xb)(c+xd)
		// ac + y(ad+bc) + bd*(x*y+1)
		// (ac+bd) + y(ad+bc + bd*x)
		// so first thing we can get rid of karatsuba.
		//

		// but the whole thing needs to be shifted.

		// // duplicate high_a
		// let high_a_vec = vdupq_n_u64(high_a);
		// // add to x.0 to get sum of low_a, high_a
		// let sum_a_vec = veorq_u64(a_vec, high_a_vec);
		// let low_high_sum_a = vgetq_lane_u64(sum_a_vec, 0);
		// let high_b_vec = vdupq_n_u64(high_b);
		// let sum_b_vec = veorq_u64(b_vec, high_b_vec);
		// let low_high_sum_b = vgetq_lane_u64(sum_b_vec, 0);
		// let low_high_sum_mult = transmute(vmull_p64(low_high_sum_a, low_high_sum_b));

		// let mid_mult = veor3q_u64(low_high_sum_mult, low_mult, high_mult);

		// we can try not transmuting these things, and instead passing the vmull outputs as u128s
		// to regular registers only reason i did it here is in order to use eor3
		// we should also try doing the reduction inside simd, well i guess the intermediate shifts
		// need to happen in regular registers
		// lets try here
		let result_unreduced_low: u128 = transmute(veorq_u64(low_mult, high_mult));
		let mid_mult: u128 = transmute(mid_mult);
		let high_mult: u128 = transmute(high_mult);
		let result_unreduced_high: u128 = mid_mult ^ (high_mult << 1);

		// let result_unreduced_low_hi = vgetq_lane_u64(a_vec, 1);
		// let result_unreduced_high_hi = vgetq_lane_u64(b_vec, 1);

		reduce_full_simd(transmute(result_unreduced_high), transmute(result_unreduced_low))

		// transmute(x)
	}
}

#[inline]
fn reduce_full_simd(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
	unsafe {
		const POLY: u64 = 0x1B;
		// let a_lo = transmute(vgetq_lane_u64(a, 0));
		let a_hi = vgetq_lane_u64(a, 1);
		// let b_lo = transmute(vgetq_lane_u64(b, 0));
		let b_hi = vgetq_lane_u64(b, 1);

		// we can zip the overflows, and do the shifting on those.
		// we can also zhip the botoms.
		// and middles
		//

		let bottom = vzip1q_u64(a, b);

		let a_hi_poly = transmute(vmull_p64(a_hi, POLY));
		let b_hi_poly = transmute(vmull_p64(b_hi, POLY));

		let center = vzip1q_u64(a_hi_poly, b_hi_poly);

		let a_overflow = vgetq_lane_u64(a_hi_poly, 1);
		let b_overlow = vgetq_lane_u64(b_hi_poly, 1);

		let a_next = transmute(vmull_p64(a_overflow, POLY));
		let b_next = transmute(vmull_p64(b_overlow, POLY));

		let top = vzip1q_u64(a_next, b_next);

		let result = veor3q_u64(top, center, bottom);
		result
		// let x = (final_a as u128) << 64 | final_b as u128;
		// transmute(x)
	}
}

#[inline]
fn reduce_full(x: u128) -> u64 {
	let low = x as u64;

	let mut high = x >> 64;
	high ^= high << 1;
	high ^= high << 3;

	let mut overflow = (high >> 64) as u64;
	overflow ^= overflow << 1;
	overflow ^= overflow << 3;

	low ^ (high as u64) ^ overflow
}

#[inline]
fn reduce_part(x: u128) -> u64 {
	let low = x as u64;

	let mut high = (x >> 64) as u64;
	high ^= high << 1;
	let mut high = high as u128;
	high ^= high << 3;

	let mut overflow = (high >> 64) as u64;
	overflow ^= overflow << 1;
	overflow ^= overflow << 3;

	low ^ (high as u64) ^ overflow
}

#[test]
fn test_overflow_case() {
	unsafe {
		// Create inputs that will produce t2 with MSB set (>= 2^63)
		// Using high values in both high parts
		let c = 0xDEADBEEFCAFEBADE0123456789ABCDEFu128; // High part: 0xFFFFFFFFFFFFFFFF
		let d = 0xD123456789ABCD0F0123456789ABCDEFu128; // High part: 0x8000000000000000  
		let c_vec: uint64x2_t = transmute(c);
		let d_vec: uint64x2_t = transmute(d);

		println!("\n=== OVERFLOW TEST CASE ===");
		let result = mul_128b_clmul_uint64x2_t(c_vec, d_vec);
		let result: u128 = transmute(result);
		println!("Result: {}", result);

		// 0xuint64x2_t(9223372036854775808, 9223372036854775807)
		let val1 = 15287300306673673450u64;
		let val2 = 6184362564043165092u64;
		println!("val1: 0x{:016X} (bit 63: {})", val1, (val1 >> 63) & 1);
		println!("val2: 0x{:016X} (bit 63: {})", val2, (val2 >> 63) & 1);
	}
}

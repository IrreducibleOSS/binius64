// Copyright 2023-2025 Irreducible Inc.
// Copyright (c) 2019-2023 RustCrypto Developers

//! ARMv8 `PMULL`-accelerated implementation of POLYVAL.
//!
//! Based on this C intrinsics implementation:
//! <https://github.com/noloader/AES-Intrinsics/blob/master/clmul-arm.c>
//!
//! Original C written and placed in public domain by Jeffrey Walton.
//! Based on code from ARM, and by Johannes Schneiders, Skip Hovsmith and
//! Barry O'Rourke for the mbedTLS project.
//!
//! For more information about PMULL, see:
//! - <https://developer.arm.com/documentation/100069/0608/A64-SIMD-Vector-Instructions/PMULL--PMULL2--vector->
//! - <https://eprint.iacr.org/2015/688.pdf>

use core::{arch::aarch64::*, mem};
use std::ops::Mul;

use super::{super::portable::packed::PackedPrimitiveType, m128::M128};
use crate::{
	BinaryField128bPolyval, PackedField,
	arch::{PairwiseStrategy, ReuseMultiplyStrategy},
	arithmetic_traits::{InvertOrZero, impl_square_with, impl_transformation_with_strategy},
};

pub type PackedBinaryPolyval1x128b = PackedPrimitiveType<M128, BinaryField128bPolyval>;

// Define multiply
impl Mul for PackedBinaryPolyval1x128b {
	type Output = Self;

	#[inline]
	fn mul(self, rhs: Self) -> Self::Output {
		crate::tracing::trace_multiplication!(PackedBinaryPolyval1x128b);

		montgomery_multiply(self.0.into(), rhs.0.into()).into()
	}
}

// Define square
// TODO: implement a more optimal version for square case
impl_square_with!(PackedBinaryPolyval1x128b @ ReuseMultiplyStrategy);

// Define invert
impl InvertOrZero for PackedBinaryPolyval1x128b {
	fn invert_or_zero(self) -> Self {
		let portable = super::super::portable::packed_polyval_128::PackedBinaryPolyval1x128b::from(
			u128::from(self.0),
		);

		Self::from_underlier(PackedField::invert_or_zero(portable).0.into())
	}
}

// Define linear transformations
impl_transformation_with_strategy!(PackedBinaryPolyval1x128b, PairwiseStrategy);

#[inline]
fn montgomery_multiply(a: u128, b: u128) -> u128 {
	unsafe {
		let h = vreinterpretq_u8_p128(a);
		let y = vreinterpretq_u8_p128(b);
		let (h, m, l) = karatsuba1(h, y);
		let (h, l) = karatsuba2(h, m, l);
		vreinterpretq_p128_u8(mont_reduce(h, l))
	}
}

/// Karatsuba decomposition for `x*y`.
#[inline]
unsafe fn karatsuba1(x: uint8x16_t, y: uint8x16_t) -> (uint8x16_t, uint8x16_t, uint8x16_t) {
	// First Karatsuba step: decompose x and y.
	//
	// (x1*y0 + x0*y1) = (x1+x0) * (y1+x0) + (x1*y1) + (x0*y0)
	//        M                                 H         L
	//
	// m = x.hi^x.lo * y.hi^y.lo
	unsafe {
		let m = pmull(
			veorq_u8(x, vextq_u8(x, x, 8)), // x.hi^x.lo
			veorq_u8(y, vextq_u8(y, y, 8)), // y.hi^y.lo
		);
		let h = pmull2(x, y); // h = x.hi * y.hi
		let l = pmull(x, y); // l = x.lo * y.lo
		(h, m, l)
	}
}

/// Karatsuba combine.
#[inline]
unsafe fn karatsuba2(h: uint8x16_t, m: uint8x16_t, l: uint8x16_t) -> (uint8x16_t, uint8x16_t) {
	// Second Karatsuba step: combine into a 2n-bit product.
	//
	// m0 ^= l0 ^ h0 // = m0^(l0^h0)
	// m1 ^= l1 ^ h1 // = m1^(l1^h1)
	// l1 ^= m0      // = l1^(m0^l0^h0)
	// h0 ^= l0 ^ m1 // = h0^(l0^m1^l1^h1)
	// h1 ^= l1      // = h1^(l1^m0^l0^h0)
	unsafe {
		let t = {
			//   {m0, m1} ^ {l1, h0}
			// = {m0^l1, m1^h0}
			let t0 = veorq_u8(m, vextq_u8(l, h, 8));

			//   {h0, h1} ^ {l0, l1}
			// = {h0^l0, h1^l1}
			let t1 = veorq_u8(h, l);

			//   {m0^l1, m1^h0} ^ {h0^l0, h1^l1}
			// = {m0^l1^h0^l0, m1^h0^h1^l1}
			veorq_u8(t0, t1)
		};

		// {m0^l1^h0^l0, l0}
		let x01 = vextq_u8(
			vextq_u8(l, l, 8), // {l1, l0}
			t,
			8,
		);

		// {h1, m1^h0^h1^l1}
		let x23 = vextq_u8(
			t,
			vextq_u8(h, h, 8), // {h1, h0}
			8,
		);

		(x23, x01)
	}
}

#[inline]
unsafe fn mont_reduce(x23: uint8x16_t, x01: uint8x16_t) -> uint8x16_t {
	// Perform the Montgomery reduction over the 256-bit X.
	//    [A1:A0] = X0 • poly
	//    [B1:B0] = [X0 ⊕ A1 : X1 ⊕ A0]
	//    [C1:C0] = B0 • poly
	//    [D1:D0] = [B0 ⊕ C1 : B1 ⊕ C0]
	// Output: [D1 ⊕ X3 : D0 ⊕ X2]
	unsafe {
		let poly =
			vreinterpretq_u8_p128(1 << 127 | 1 << 126 | 1 << 121 | 1 << 63 | 1 << 62 | 1 << 57);
		let a = pmull(x01, poly);
		let b = veorq_u8(x01, vextq_u8(a, a, 8));
		let c = pmull2(b, poly);
		veorq_u8(x23, veorq_u8(c, b))
	}
}

/// Multiplies the low bits in `a` and `b`.
#[inline]
unsafe fn pmull(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
	unsafe {
		mem::transmute(vmull_p64(
			vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
			vgetq_lane_u64(vreinterpretq_u64_u8(b), 0),
		))
	}
}

/// Multiplies the high bits in `a` and `b`.
#[inline]
unsafe fn pmull2(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
	unsafe {
		mem::transmute(vmull_p64(
			vgetq_lane_u64(vreinterpretq_u64_u8(a), 1),
			vgetq_lane_u64(vreinterpretq_u64_u8(b), 1),
		))
	}
}

// Copyright 2023-2025 Irreducible Inc.
// Copyright (c) 2019-2023 RustCrypto Developers

//! ARMv8 `PMULL`-accelerated implementation of GHASH.
//!
//! Based on the optimized GHASH implementation using carryless multiplication
//! instructions available on ARMv8 processors with NEON support.

use core::arch::aarch64::*;
use std::ops::Mul;

use super::{super::portable::packed::PackedPrimitiveType, m128::M128};
use crate::{
	BinaryField128bGhash,
	arch::{PairwiseStrategy, ReuseMultiplyStrategy, shared::ghash::ClMulUnderlier},
	arithmetic_traits::{InvertOrZero, impl_square_with, impl_transformation_with_strategy},
	packed::PackedField,
};

impl ClMulUnderlier for M128 {
	#[inline]
	fn clmulepi64<const IMM8: i32>(a: Self, b: Self) -> Self {
		let a_u64x2: uint64x2_t = a.into();
		let b_u64x2: uint64x2_t = b.into();

		let result = match IMM8 {
			0x00 => unsafe { vmull_p64(vgetq_lane_u64(a_u64x2, 0), vgetq_lane_u64(b_u64x2, 0)) },
			0x11 => unsafe { vmull_p64(vgetq_lane_u64(a_u64x2, 1), vgetq_lane_u64(b_u64x2, 1)) },
			0x10 => unsafe { vmull_p64(vgetq_lane_u64(a_u64x2, 0), vgetq_lane_u64(b_u64x2, 1)) },
			0x01 => unsafe { vmull_p64(vgetq_lane_u64(a_u64x2, 1), vgetq_lane_u64(b_u64x2, 0)) },
			_ => panic!("Unsupported IMM8 value for clmulepi64"),
		};

		unsafe { std::mem::transmute::<u128, uint64x2_t>(result) }.into()
	}

	#[inline]
	fn move_64_to_hi(a: Self) -> Self {
		let a_u64x2: uint64x2_t = a.into();
		// Shift left by 8 bytes
		unsafe {
			let a_bytes: uint8x16_t = std::mem::transmute(a_u64x2);
			let zero: uint8x16_t = vdupq_n_u8(0);
			let shifted: uint8x16_t = vextq_u8::<8>(zero, a_bytes);
			std::mem::transmute::<uint8x16_t, uint64x2_t>(shifted).into()
		}
	}
}

pub type PackedBinaryGhash1x128b = PackedPrimitiveType<M128, BinaryField128bGhash>;

// Define multiply
impl Mul for PackedBinaryGhash1x128b {
	type Output = Self;

	fn mul(self, rhs: Self) -> Self::Output {
		crate::tracing::trace_multiplication!(PackedBinaryGhash1x128b);

		Self::from_underlier(crate::arch::shared::ghash::mul_clmul(
			self.to_underlier(),
			rhs.to_underlier(),
		))
	}
}

// Define square
impl_square_with!(PackedBinaryGhash1x128b @ ReuseMultiplyStrategy);

// Define invert
impl InvertOrZero for PackedBinaryGhash1x128b {
	fn invert_or_zero(self) -> Self {
		let portable = super::super::portable::packed_ghash_128::PackedBinaryGhash1x128b::from(
			u128::from(self.to_underlier()),
		);

		Self::from_underlier(PackedField::invert_or_zero(portable).to_underlier().into())
	}
}

// Define linear transformations
impl_transformation_with_strategy!(PackedBinaryGhash1x128b, PairwiseStrategy);

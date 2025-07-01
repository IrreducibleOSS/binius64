// Copyright 2024-2025 Irreducible Inc.

use std::arch::x86_64::*;

use seq_macro::seq;

use super::montgomery_mul::PolyvalSimdType;
use crate::arch::x86_64::m512::M512;

impl PolyvalSimdType for M512 {
	#[inline(always)]
	unsafe fn shuffle_epi32<const IMM8: i32>(a: Self) -> Self {
		unsafe { _mm512_shuffle_epi32::<IMM8>(a.0).into() }
	}

	#[inline(always)]
	unsafe fn xor(a: Self, b: Self) -> Self {
		unsafe { _mm512_xor_si512(a.0, b.0).into() }
	}

	#[inline(always)]
	unsafe fn clmul_epi64<const IMM8: i32>(a: Self, b: Self) -> Self {
		unsafe { _mm512_clmulepi64_epi128::<IMM8>(a.0, b.0).into() }
	}

	#[inline(always)]
	unsafe fn slli_epi64<const IMM8: i32>(a: Self) -> Self {
		// This is a workaround for the problem that `_mm512_slli_epi64` and
		// `_mm256_slli_epi64` have different generic constant type and stable Rust
		// doesn't allow cast for const parameter.
		// All these `if`s will be eliminated by compiler because `IMM8` is known at compile time.
		unsafe {
			seq!(N in 0..64 {
				if IMM8 == N {
					return _mm512_slli_epi64::<N>(a.0).into()
				}
			});
		}

		unreachable!("bit shift count shouldn't exceed 63")
	}

	#[inline(always)]
	unsafe fn srli_epi64<const IMM8: i32>(a: Self) -> Self {
		unsafe {
			seq!(N in 0..64 {
				if IMM8 == N {
					return _mm512_srli_epi64::<N>(a.0).into()
				}
			});
		}

		unreachable!("bit shift count shouldn't exceed 63")
	}

	#[inline(always)]
	unsafe fn unpacklo_epi64(a: Self, b: Self) -> Self {
		unsafe { _mm512_unpacklo_epi64(a.0, b.0).into() }
	}
}

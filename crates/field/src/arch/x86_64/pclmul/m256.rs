// Copyright 2024-2025 Irreducible Inc.

use std::arch::x86_64::*;

use super::montgomery_mul::PolyvalSimdType;
use crate::arch::x86_64::m256::M256;

impl PolyvalSimdType for M256 {
	#[inline(always)]
	unsafe fn shuffle_epi32<const IMM8: i32>(a: Self) -> Self {
		unsafe { _mm256_shuffle_epi32::<IMM8>(a.0).into() }
	}

	#[inline(always)]
	unsafe fn xor(a: Self, b: Self) -> Self {
		unsafe { _mm256_xor_si256(a.0, b.0).into() }
	}

	#[inline(always)]
	unsafe fn clmul_epi64<const IMM8: i32>(a: Self, b: Self) -> Self {
		unsafe { _mm256_clmulepi64_epi128::<IMM8>(a.0, b.0).into() }
	}

	#[inline(always)]
	unsafe fn slli_epi64<const IMM8: i32>(a: Self) -> Self {
		unsafe { _mm256_slli_epi64::<IMM8>(a.0).into() }
	}

	#[inline(always)]
	unsafe fn srli_epi64<const IMM8: i32>(a: Self) -> Self {
		unsafe { _mm256_srli_epi64::<IMM8>(a.0).into() }
	}

	#[inline(always)]
	unsafe fn unpacklo_epi64(a: Self, b: Self) -> Self {
		unsafe { _mm256_unpacklo_epi64(a.0, b.0).into() }
	}
}

// Copyright 2024-2025 Irreducible Inc.

mod packed_field_utils;

use std::ops::Mul;

use binius_field::arch::{
	byte_sliced::*, packed_8::*, packed_16::*, packed_32::*, packed_64::*, packed_128::*,
	packed_256::*, packed_512::*, packed_aes_8::*, packed_aes_16::*, packed_aes_32::*,
	packed_aes_64::*, packed_aes_128::*, packed_aes_256::*, packed_aes_512::*,
	packed_polyval_128::*, packed_polyval_256::*, packed_polyval_512::*,
};
use cfg_if::cfg_if;
use criterion::criterion_main;
use packed_field_utils::benchmark_packed_operation;

/// This trait is needed to specify `Mul` constraint only
trait SelfMul: Mul<Self, Output = Self> + Sized {}

impl<T: Mul<Self, Output = Self> + Sized> SelfMul for T {}

fn mul_main<T: SelfMul>(lhs: T, rhs: T) -> T {
	lhs * rhs
}

cfg_if! {
	if #[cfg(feature = "benchmark_alternative_strategies")] {
		use binius_field::{
			arch::{HybridRecursiveStrategy, PackedStrategy, PairwiseRecursiveStrategy, PairwiseStrategy,
				PairwiseTableStrategy, SimdStrategy,},
			arithmetic_traits::TaggedMul
		};

		fn mul_pairwise<T: TaggedMul<PairwiseStrategy>>(lhs: T, rhs: T) -> T {
			TaggedMul::<PairwiseStrategy>::mul(lhs, rhs)
		}

		fn mul_pairwise_table<T: TaggedMul<PairwiseTableStrategy>>(lhs: T, rhs: T) -> T {
			TaggedMul::<PairwiseTableStrategy>::mul(lhs, rhs)
		}

		fn mul_pairwise_recursive<T: TaggedMul<PairwiseRecursiveStrategy>>(lhs: T, rhs: T) -> T {
			TaggedMul::<PairwiseRecursiveStrategy>::mul(lhs, rhs)
		}

		fn mul_packed<T: TaggedMul<PackedStrategy>>(lhs: T, rhs: T) -> T {
			TaggedMul::<PackedStrategy>::mul(lhs, rhs)
		}

		fn mul_hybrid_recursive<T: TaggedMul<HybridRecursiveStrategy>>(lhs: T, rhs: T) -> T {
			TaggedMul::<HybridRecursiveStrategy>::mul(lhs, rhs)
		}

		fn mul_simd<T: TaggedMul<SimdStrategy>>(lhs: T, rhs: T) -> T {
			TaggedMul::<SimdStrategy>::mul(lhs, rhs)
		}

		benchmark_packed_operation!(
			op_name @ multiply,
			bench_type @ binary_op,
			strategies @ (
				(main, SelfMul, mul_main),
				(pairwise, TaggedMul::<PairwiseStrategy>, mul_pairwise),
				(pairwise_recursive, TaggedMul::<PairwiseRecursiveStrategy>, mul_pairwise_recursive),
				(pairwise_table, TaggedMul::<PairwiseTableStrategy>, mul_pairwise_table),
				(hybrid_recursive, TaggedMul::<HybridRecursiveStrategy>, mul_hybrid_recursive),
				(packed, TaggedMul::<PackedStrategy>, mul_packed),
				(simd, TaggedMul::<SimdStrategy>, mul_simd),
			)
		);
	} else {
		benchmark_packed_operation!(
			op_name @ multiply,
			bench_type @ binary_op,
			strategies @ (
				(main, SelfMul, mul_main),
			)
		);
	}
}

criterion_main!(multiply);

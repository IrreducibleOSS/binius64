// Copyright 2025 Irreducible Inc.

//! Parallel Vision-6 hash permutation using flattened state arrays.
//!
//! Processes N Vision-6 states simultaneously by flattening them into a single N×6 array.
//! The key optimization is **batch inversion** - replacing N expensive field inversions
//! with a single inversion across all states using Montgomery's algorithm.
//!
//! # Layout
//! States: `[s0[0], s0[1], ..., s0[5], s1[0], s1[1], ...]` where `N` = number of states, `M = 6`.
//!
//! # Round Structure  
//! Each round: inversion → transform → MDS → constants → inversion → transform → MDS → constants

use binius_field::{BinaryField128bGhash as Ghash, arithmetic_traits::Square};
use binius_math::batch_invert::batch_invert;
use binius_verifier::hash::vision_6::{
	constants::{B_FWD_COEFFS, M, NUM_ROUNDS, ROUND_CONSTANTS},
	permutation::{linearized_b_inv_transform_scalar, mds_mul},
};

/// Applies forward B-polynomial transformation: B(x) = c₀ + c₁x + c₂x² + c₃x⁴.
#[inline]
fn parallel_forward_transform<const N: usize, const MN: usize>(states: &mut [Ghash; MN]) {
	for i in 0..MN {
		let scalar = states[i];
		let square = scalar.square();
		let quartic = square.square();

		states[i] = B_FWD_COEFFS[0]
			+ B_FWD_COEFFS[1] * scalar
			+ B_FWD_COEFFS[2] * square
			+ B_FWD_COEFFS[3] * quartic;
	}
}

/// Applies inverse B-polynomial transformation using lookups.
#[inline]
fn parallel_inverse_transform<const N: usize, const MN: usize>(states: &mut [Ghash; MN]) {
	for i in 0..MN {
		linearized_b_inv_transform_scalar(&mut states[i]);
	}
}

/// Applies MDS matrix multiplication to each of the N parallel states.
#[inline]
fn parallel_mds_mul<const N: usize, const MN: usize>(states: &mut [Ghash; MN]) {
	for i in 0..N {
		let state = &mut states[i * M..];
		mds_mul(state);
	}
}

/// Adds round constants to each of the N parallel states.
#[inline]
fn parallel_constants_add<const N: usize, const MN: usize>(
	states: &mut [Ghash; MN],
	constants: &[Ghash; M],
) {
	for i in 0..N {
		let state_start = i * M;
		for j in 0..M {
			states[state_start + j] += constants[j];
		}
	}
}

/// Applies batch inversion to all parallel states, splitting each 6-element state into 3 pairs.
#[inline]
fn parallel_batch_invert<const N: usize, const MN: usize, const MN_DIV_3: usize>(
	states: &mut [Ghash; MN],
	scratchpad: &mut [Ghash],
) {
	batch_invert::<MN_DIV_3>(&mut states[0..MN_DIV_3], &mut scratchpad[0..2 * MN_DIV_3]);
	batch_invert::<MN_DIV_3>(
		&mut states[MN_DIV_3..MN_DIV_3 * 2],
		&mut scratchpad[2 * MN_DIV_3..4 * MN_DIV_3],
	);
	batch_invert::<MN_DIV_3>(
		&mut states[MN_DIV_3 * 2..MN_DIV_3 * 3],
		&mut scratchpad[4 * MN_DIV_3..6 * MN_DIV_3],
	);
}

/// Executes a complete Vision-6 round on all parallel states.
#[inline]
fn parallel_round<const N: usize, const MN: usize, const MN_DIV_3: usize>(
	states: &mut [Ghash; MN],
	scratchpad: &mut [Ghash],
	round_constants_idx: usize,
) {
	// First half-round: inversion → inverse transform → MDS → constants
	parallel_batch_invert::<N, MN, MN_DIV_3>(states, scratchpad);
	parallel_inverse_transform::<N, MN>(states);
	parallel_mds_mul::<N, MN>(states);
	parallel_constants_add::<N, MN>(states, &ROUND_CONSTANTS[round_constants_idx]);

	// Second half-round: inversion → forward transform → MDS → constants
	parallel_batch_invert::<N, MN, MN_DIV_3>(states, scratchpad);
	parallel_forward_transform::<N, MN>(states);
	parallel_mds_mul::<N, MN>(states);
	parallel_constants_add::<N, MN>(states, &ROUND_CONSTANTS[round_constants_idx + 1]);
}

/// Executes the complete Vision-6 permutation on N parallel states.
///
/// Main entry point for parallel Vision-6 hashing. Requires scratchpad ≥ 2×MN-1 elements.
#[inline]
pub fn parallel_permutation<const N: usize, const MN: usize, const MN_DIV_3: usize>(
	states: &mut [Ghash; MN],
	scratchpad: &mut [Ghash],
) {
	// Initial round constant addition
	parallel_constants_add::<N, MN>(states, &ROUND_CONSTANTS[0]);

	// Execute all rounds of the permutation
	for round_num in 0..NUM_ROUNDS {
		parallel_round::<N, MN, MN_DIV_3>(states, scratchpad, 1 + 2 * round_num);
	}
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_field::{Field, Random};
	use binius_verifier::hash::vision_6::permutation::permutation;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	macro_rules! test_parallel_permutation {
		($name:ident, $n:expr) => {
			#[test]
			fn $name() {
				const N: usize = $n;
				const MN: usize = M * N;
				const MN_DIV_3: usize = MN / 3;
				let mut rng = StdRng::seed_from_u64(0);

				for _ in 0..4 {
					let mut parallel_states: [Ghash; MN] =
						array::from_fn(|_| Ghash::random(&mut rng));

					let mut single_states: [[Ghash; M]; N] =
						array::from_fn(|i| array::from_fn(|j| parallel_states[i * M + j]));

					let scratchpad = &mut [Ghash::ZERO; { 2 * MN }];
					parallel_permutation::<N, MN, MN_DIV_3>(&mut parallel_states, scratchpad);

					for state in single_states.iter_mut() {
						permutation(state);
					}

					let expected_parallel: [Ghash; MN] =
						array::from_fn(|i| single_states[i / M][i % M]);

					assert_eq!(parallel_states, expected_parallel);
				}
			}
		};
	}

	test_parallel_permutation!(test_parallel_permutation_1, 1);
	test_parallel_permutation!(test_parallel_permutation_2, 2);
	test_parallel_permutation!(test_parallel_permutation_4, 4);
	test_parallel_permutation!(test_parallel_permutation_8, 8);
	test_parallel_permutation!(test_parallel_permutation_16, 16);
	test_parallel_permutation!(test_parallel_permutation_32, 32);
	test_parallel_permutation!(test_parallel_permutation_64, 64);
}

// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField128bGhash as Ghash, arithmetic_traits::Square};
use binius_verifier::hash::vision::{
	constants::{B_FWD_COEFFS, M, NUM_ROUNDS, ROUND_CONSTANTS},
	permutation::linearized_b_inv_transform_scalar,
};

use super::batch_invert::batch_invert_scratchpad_generic;

fn flattened_forward_transform<const N: usize, const MN: usize>(states: &mut [Ghash; MN]) {
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

fn flattened_inverse_transform<const N: usize, const MN: usize>(states: &mut [Ghash; MN]) {
	for i in 0..MN {
		linearized_b_inv_transform_scalar(&mut states[i]);
	}
}

fn flattened_round<const N: usize, const MN: usize>(
	states: &mut [Ghash; MN],
	scratchpad: &mut [Ghash],
	round_constants_idx: usize,
) {
	// First half
	batch_invert_scratchpad_generic(states, scratchpad);
	flattened_inverse_transform::<N, MN>(states);
	flattened_parallel_mds_mul::<N, MN>(states);
	flattened_constants_add::<N, MN>(states, &ROUND_CONSTANTS[round_constants_idx]);
	// Second half
	batch_invert_scratchpad_generic(states, scratchpad);
	flattened_forward_transform::<N, MN>(states);
	flattened_parallel_mds_mul::<N, MN>(states);
	flattened_constants_add::<N, MN>(states, &ROUND_CONSTANTS[round_constants_idx + 1]);
}

fn flattened_constants_add<const N: usize, const MN: usize>(
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

pub fn flattened_mds_mul(a: &mut [Ghash]) {
	// a = [a0, a1, a2, a3]
	let sum = a[0] + a[1] + a[2] + a[3];
	let a0 = a[0];

	// 2*a0 + 3*a1 + a2 + a3
	a[0] += sum + (a[0] + a[1]).mul_x();

	// a0 + 2*a1 + 3*a2 + a3
	a[1] += sum + (a[1] + a[2]).mul_x();

	// a0 + a1 + 2*a2 + 3*a3
	a[2] += sum + (a[2] + a[3]).mul_x();

	// 3*a0 + a1 + a2 + 2*a3
	a[3] += sum + (a[3] + a0).mul_x();
}

fn flattened_parallel_mds_mul<const N: usize, const MN: usize>(states: &mut [Ghash; MN]) {
	for i in 0..N {
		let state = &mut states[i * M..];
		flattened_mds_mul(state);
	}
}

pub fn flattened_parallel_permutation<const N: usize, const MN: usize>(
	states: &mut [Ghash; MN],
	scratchpad: &mut [Ghash],
) {
	flattened_constants_add::<N, MN>(states, &ROUND_CONSTANTS[0]);
	for round_num in 0..NUM_ROUNDS {
		flattened_round::<N, MN>(states, scratchpad, 1 + 2 * round_num);
	}
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_field::{Field, Random};
	use binius_verifier::hash::vision::permutation::permutation;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	macro_rules! test_parallel_permutation {
		($name:ident, $n:expr) => {
			#[test]
			fn $name() {
				const N: usize = $n;
				const MN: usize = M * N;
				let mut rng = StdRng::seed_from_u64(0);

				// Test multiple trials with random states
				for _ in 0..10 {
					// Create flat array for parallel processing
					let mut parallel_states: [Ghash; MN] =
						array::from_fn(|_| Ghash::random(&mut rng));

					// Create individual states for single processing
					let mut single_states: [[Ghash; M]; N] =
						array::from_fn(|i| array::from_fn(|j| parallel_states[i * M + j]));

					// Apply parallel permutation
					let scratchpad = &mut [Ghash::ZERO; { 2 * MN }];
					flattened_parallel_permutation::<N, MN>(&mut parallel_states, scratchpad);
					// nested_parallel_permutation::<N>(&mut parallel_states);

					// Apply single permutation to each state
					for state in single_states.iter_mut() {
						permutation(state);
					}

					// Convert single states back to flat array for comparison
					let expected_flat: [Ghash; MN] =
						array::from_fn(|i| single_states[i / M][i % M]);

					assert_eq!(parallel_states, expected_flat);
				}

				// Test edge cases
				// All zeros
				let mut parallel_states: [Ghash; MN] = [Ghash::ZERO; MN];
				let mut single_states: [[Ghash; M]; N] = [[Ghash::ZERO; M]; N];

				let scratchpad = &mut [Ghash::ZERO; { 2 * MN }];
				flattened_parallel_permutation::<N, MN>(&mut parallel_states, scratchpad);
				// nested_parallel_permutation::<N>(&mut parallel_states);

				for state in single_states.iter_mut() {
					permutation(state);
				}

				let expected_flat: [Ghash; MN] = array::from_fn(|i| single_states[i / M][i % M]);
				assert_eq!(parallel_states, expected_flat);

				// All ones
				let mut parallel_states: [Ghash; MN] = [Ghash::ONE; MN];
				let mut single_states: [[Ghash; M]; N] = [[Ghash::ONE; M]; N];

				let scratchpad = &mut [Ghash::ZERO; { 2 * MN }];
				flattened_parallel_permutation::<N, MN>(&mut parallel_states, scratchpad);
				// nested_parallel_permutation::<N>(&mut parallel_states);

				for state in single_states.iter_mut() {
					permutation(state);
				}

				let expected_flat: [Ghash; MN] = array::from_fn(|i| single_states[i / M][i % M]);
				assert_eq!(parallel_states, expected_flat);
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

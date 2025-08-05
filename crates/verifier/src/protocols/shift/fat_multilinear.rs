// Copyright 2025 Irreducible Inc.

use binius_field::Field;

use super::SHIFT_VARIANT_COUNT;
use crate::config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS};

/// Evaluates the three h multilinear polynomials (corresponding to SLL, SRL, SRA) at challenge
/// points.
///
/// This is the verifier's version of the h-triplet evaluation - instead of building
/// full multilinear polynomials, it directly computes their evaluations.
pub fn evaluate_h_op<F: Field>(l_tilde: &[F], r_j: &[F], r_s: &[F]) -> [F; SHIFT_VARIANT_COUNT] {
	assert_eq!(l_tilde.len(), WORD_SIZE_BITS);
	assert_eq!(r_j.len(), LOG_WORD_SIZE_BITS);
	assert_eq!(r_s.len(), LOG_WORD_SIZE_BITS);

	// Initialize arrays
	let mut s = [F::ONE; WORD_SIZE_BITS];
	let mut s_prime = [F::ZERO; WORD_SIZE_BITS];
	let mut s_transpose = [F::ONE; WORD_SIZE_BITS];
	let mut s_transpose_prime = [F::ZERO; WORD_SIZE_BITS];
	let mut a = [F::ZERO; WORD_SIZE_BITS];
	let mut j_product = F::ONE;

	// Process each bit position (6 iterations for 6-bit shift amounts)
	for k in 0..LOG_WORD_SIZE_BITS {
		// Precompute boolean combinations for this bit
		let both = r_j[k] * r_s[k]; // jₖ ⋅ sₖ
		let r_j_one_rs = r_j[k] - both; // jₖ ⋅ (1 - sₖ)
		let one_r_j_rs = r_s[k] - both; // (1 - jₖ) ⋅ sₖ
		let xor = r_j[k] + r_s[k]; // jₖ + sₖ
		let eq = F::ONE + xor; // 1 + jₖ + sₖ
		let zero = eq + both; // 1 + jₖ + sₖ + jₖ ⋅ sₖ

		// Update arrays for this bit position
		for i in 0..(1 << k) {
			// Update s arrays
			s[(1 << k) | i] = r_j_one_rs * s[i]; // write upper halves first
			s_prime[(1 << k) | i] = one_r_j_rs * s[i] + eq * s_prime[i]; // Iₖ = 1
			s[i] = eq * s[i] + r_j_one_rs * s_prime[i];
			s_prime[i] *= one_r_j_rs;

			// Update s_transpose arrays
			s_transpose[(1 << k) | i] = xor * s_transpose[i] + zero * s_transpose_prime[i];
			s_transpose_prime[(1 << k) | i] = both * s_transpose_prime[i];
			s_transpose_prime[i] = both * s_transpose[i] + xor * s_transpose_prime[i];
			s_transpose[i] *= zero;

			// Update a array
			a[(1 << k) | i] = r_s[k] + (F::ONE + r_s[k]) * a[i];
			let temp = a[(1 << k) | i] - r_s[k];
			a[i] += temp;
		}
		j_product *= r_j[k];
	}

	// Compute final results
	let sll: F = (0..WORD_SIZE_BITS)
		.map(|i| l_tilde[i] * s_transpose[i])
		.sum();
	let srl: F = (0..WORD_SIZE_BITS).map(|i| l_tilde[i] * s[i]).sum();
	// sra == ∑ᵢ L̃(i) ⋅ (srlᵢ + ∏ₖ rⱼ[k] ⋅ aᵢ)
	//     == ∑ᵢ L̃(i) ⋅ srlᵢ + ∏ₖ rⱼ[k] ⋅ [ ∑ᵢ L̃(i) ⋅ aᵢ ]
	//     == srl + ∏ₖ rⱼ[k] ⋅ [ ∑ᵢ L̃(i) ⋅ aᵢ ]
	let sra: F = srl + j_product * (0..WORD_SIZE_BITS).map(|i| l_tilde[i] * a[i]).sum::<F>();

	[sll, srl, sra]
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash, Random};
	use binius_math::{
		BinarySubspace,
		test_utils::{index_to_hypercube_point, random_scalars},
		univariate::lagrange_evals,
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	#[test]
	fn test_evaluate_h_op_hypercube_vertices() {
		// Test on specific hypercube vertices with known expected outputs
		let mut rng = StdRng::seed_from_u64(42);
		let challenge = BinaryField128bGhash::random(&mut rng);
		let subspace =
			BinarySubspace::<BinaryField128bGhash>::with_dim(LOG_WORD_SIZE_BITS).unwrap();
		let l_tilde = lagrange_evals(&subspace, challenge);

		let test_cases = [
			(
				0,
				0,
				[
					0xb6a8a5afaa62274a4dc9e5bd23dd333au128,
					0xb6a8a5afaa62274a4dc9e5bd23dd333au128,
					0xb6a8a5afaa62274a4dc9e5bd23dd333au128,
				],
			),
			(
				1,
				0,
				[
					0x45b19b700dca6d8208c4c09c9c202f0eu128,
					0x45b19b700dca6d8208c4c09c9c202f0eu128,
					0x45b19b700dca6d8208c4c09c9c202f0eu128,
				],
			),
			(
				0,
				1,
				[
					0x45b19b700dca6d8208c4c09c9c202f0eu128,
					0x00000000000000000000000000000000u128,
					0x00000000000000000000000000000000u128,
				],
			),
			(
				7,
				3,
				[
					(0x78c7u128 << 112) + 0xba7cadff072b58bcee0b2239f699u128, // to pass CI
					0xe126df34a49ea159d737d3677a2c2912u128,
					0xe126df34a49ea159d737d3677a2c2912u128,
				],
			),
			(
				63,
				31,
				[
					0x00000000000000000000000000000000u128,
					0xf9db4a10532e149a975b01ecfa2d13f4u128,
					0x8439596ecb34ada768e264392afa1592u128,
				],
			),
		];

		for (r_j_index, r_s_index, expected) in test_cases {
			let r_j =
				index_to_hypercube_point::<BinaryField128bGhash>(LOG_WORD_SIZE_BITS, r_j_index);
			let r_s =
				index_to_hypercube_point::<BinaryField128bGhash>(LOG_WORD_SIZE_BITS, r_s_index);
			let result = evaluate_h_op(&l_tilde, &r_j, &r_s);

			let expected_result = [
				BinaryField128bGhash::new(expected[0]),
				BinaryField128bGhash::new(expected[1]),
				BinaryField128bGhash::new(expected[2]),
			];

			assert_eq!(
				result, expected_result,
				"Mismatch for r_j_index={r_j_index}, r_s_index={r_s_index}"
			);
		}
	}

	#[test]
	fn test_evaluate_h_op_multilinearity() {
		// Test that the function is multilinear in each variable
		let mut rng = StdRng::seed_from_u64(0);

		// Generate random evaluation points
		let challenge = BinaryField128bGhash::random(&mut rng);
		let subspace =
			BinarySubspace::<BinaryField128bGhash>::with_dim(LOG_WORD_SIZE_BITS).unwrap();
		let l_tilde = lagrange_evals(&subspace, challenge);
		let r_j = random_scalars::<BinaryField128bGhash>(&mut rng, LOG_WORD_SIZE_BITS);
		let r_s = random_scalars::<BinaryField128bGhash>(&mut rng, LOG_WORD_SIZE_BITS);

		// Check linearity in each variable
		for i in 0..LOG_WORD_SIZE_BITS {
			// Check r_j[i]
			let mut r_j_at_0 = r_j.clone();
			r_j_at_0[i] = BinaryField128bGhash::ZERO;
			let mut r_j_at_1 = r_j.clone();
			r_j_at_1[i] = BinaryField128bGhash::ONE;
			let [result_0, result_1, result_y] = [&r_j_at_0, &r_j_at_1, &r_j]
				.map(|r_j_variant| evaluate_h_op(&l_tilde, r_j_variant, &r_s));
			for variant in 0..SHIFT_VARIANT_COUNT {
				let expected = result_0[variant] * (BinaryField128bGhash::ONE - r_j[i])
					+ result_1[variant] * r_j[i];
				assert_eq!(result_y[variant], expected, "Not linear in r_j[{i}]");
			}

			// Check r_s[i]
			let mut r_s_at_0 = r_s.clone();
			r_s_at_0[i] = BinaryField128bGhash::ZERO;
			let mut r_s_at_1 = r_s.clone();
			r_s_at_1[i] = BinaryField128bGhash::ONE;
			let [result_0, result_1, result_y] = [&r_s_at_0, &r_s_at_1, &r_s]
				.map(|r_s_variant| evaluate_h_op(&l_tilde, &r_j, r_s_variant));
			for variant in 0..SHIFT_VARIANT_COUNT {
				let expected = result_0[variant] * (BinaryField128bGhash::ONE - r_s[i])
					+ result_1[variant] * r_s[i];
				assert_eq!(result_y[variant], expected, "Not linear in r_s[{i}]");
			}
		}
	}
}

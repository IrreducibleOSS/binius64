// Copyright 2025 Irreducible Inc.

use std::iter;

use binius_core::{
	ShiftVariant,
	constraint_system::{Operand, ShiftedValueIndex},
};
use binius_field::{AESTowerField8b, BinaryField, Field, util::powers};
use binius_math::{
	BinarySubspace, FieldBuffer,
	inner_product::inner_product,
	multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate_inplace},
	univariate::lagrange_evals,
};
use binius_utils::rayon::prelude::*;

use super::{SHIFT_VARIANT_COUNT, error::Error, verify::OperatorData};
use crate::config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS};

/// Evaluates the three h multilinear polynomials (corresponding to SLL, SRL, SRA) at challenge
/// points.
///
/// This is the verifier's version of the h-parts evaluation - instead of building
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
			// note: in last iteration k = 5, computation of `s_transpose_prime` COULD be skipped.
			// never gets read from. keep it here just to minimize special case logic, but note it
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
	let rotr = (0..WORD_SIZE_BITS)
		.map(|i| l_tilde[i] * (s[i] + s_prime[i]))
		.sum();

	[sll, srl, sra, rotr]
}

/// Evaluates the monster multilinear polynomial for a constraint operation.
///
/// The monster multilinear encodes all constraints of a given type (AND or MUL) into
/// a single polynomial. For an operation with multiple operands, it computes:
///
/// $$
/// \sum_{\text{m_idx} \in \text{enumerate(operands)}}
///     \lambda^{\text{m_idx}+1}
///     \sum_{\text{op}} h_{\text{op}}(r_j, r_s) \cdot M_{\text{m}, \text{op}}(r_x', r_y, r_s)
/// $$
///
/// where:
/// - `m_idx` indexes the operand position (0 to ARITY-1)
/// - `op` ranges over the shift variants (logical/arithmetic shifts)
/// - `h_op` is the shift selector polynomial
/// - `M_m,op` is the multilinear extension of the operand values
///
/// # Arguments
///
/// * `operand_vecs` - Vector of operand vectors, one per operand position in the constraint
/// * `operator_data` - Contains the multilinear challenge `r_x'`, univariate challenge `r_zhat'`,
///   and evaluation claims for each operand
/// * `lambda` - Random coefficient for batching operand evaluations
/// * `r_j` - Challenge point for bit index variables (length `LOG_WORD_SIZE_BITS`)
/// * `r_s` - Challenge point for shift variables (length `LOG_WORD_SIZE_BITS`)
/// * `r_y` - Challenge point for word index variables
///
/// # Returns
///
/// The evaluation of the monster multilinear at the given challenge points, or an error
/// if the computation fails.
///
/// # Errors
///
/// Returns an error if the binary subspace construction fails.
pub fn evaluate_monster_multilinear_for_operation<F, const ARITY: usize>(
	operand_vecs: &[Vec<&Operand>],
	operator_data: &OperatorData<F, ARITY>,
	lambda: F,
	r_j: &[F],
	r_s: &[F],
	r_y: &[F],
) -> Result<F, Error>
where
	F: BinaryField + From<AESTowerField8b>,
{
	let r_x_prime_tensor = eq_ind_partial_eval::<F>(&operator_data.r_x_prime);
	let r_y_tensor = eq_ind_partial_eval::<F>(r_y);

	// TODO: Pass this in instead of constructing subspace here.
	let subspace = BinarySubspace::<AESTowerField8b>::with_dim(LOG_WORD_SIZE_BITS)?.isomorphic();
	let l_tilde = lagrange_evals(&subspace, operator_data.r_zhat_prime);
	let h_op_evals = evaluate_h_op(&l_tilde, r_j, r_s);

	let lambda_powers = powers(lambda).skip(1).take(ARITY).collect::<Vec<_>>();
	let evals = evaluate_matrices(operand_vecs, &lambda_powers, &r_x_prime_tensor, &r_y_tensor);

	let eval = inner_product(
		evals.map(|mut evals_op| {
			let evals_op = FieldBuffer::new(LOG_WORD_SIZE_BITS, &mut evals_op[..])
				.expect("evals_op is an array with length 2^LOG_WORD_SIZE_BITS");
			evaluate_inplace(evals_op, r_s).expect("precondition: r_s length is LOG_WORD_SIZE_BITS")
		}),
		h_op_evals,
	);

	Ok(eval)
}

/// Calculate a batched sum of the M_{\text{op}}(r'_x, r_y, s) matrices.
///
/// Computes one evaluation per shift op, shift amount pair. The matrix evaluations are scaled by
/// the operand coefficients (λ powers) and accumulated.
///
/// # Arguments
///
/// * `operands` - Three-dimensional array of operands where:
///   - dim 1: operation arity
///   - dim 2: constraints
///   - dim 3: shifted indices per term
/// * `operand_coeffs` - Coefficients (λ powers) for batching operand evaluations
/// * `r_x_prime_tensor` - Multilinear challenge tensor for constraint variables
/// * `r_y_tensor` - Challenge tensor for word index variables
///
/// Note: This function uses multithreading (par_iter), which is an exception to the general
/// rule that the verifier should be single-threaded. The sparse matrix evaluation takes time
/// linear in the size of the constraint system, so we use parallelization here to make the
/// verifier performant on large constraint systems.
fn evaluate_matrices<F: BinaryField>(
	operands: &[Vec<&Operand>],
	operand_coeffs: &[F],
	r_x_prime_tensor: &FieldBuffer<F>,
	r_y_tensor: &FieldBuffer<F>,
) -> [[F; WORD_SIZE_BITS]; SHIFT_VARIANT_COUNT] {
	assert_eq!(operands.len(), operand_coeffs.len());

	// Use parallelization for performance (see docstring for rationale).
	(operand_coeffs, operands)
		.into_par_iter()
		.map(|(&coeff, constraint_operands)| {
			let mut evals = [[F::ZERO; WORD_SIZE_BITS]; SHIFT_VARIANT_COUNT];
			for (&operand_terms, &constraint_eval) in
				iter::zip(constraint_operands, r_x_prime_tensor.as_ref())
			{
				for ShiftedValueIndex {
					value_index,
					shift_variant,
					amount,
				} in operand_terms
				{
					let shift_id = match shift_variant {
						ShiftVariant::Sll => 0,
						ShiftVariant::Slr => 1,
						ShiftVariant::Sar => 2,
						ShiftVariant::Rotr => 3,
						ShiftVariant::Sll32 => 4,
						ShiftVariant::Srl32 => 5,
						ShiftVariant::Sra32 => 6,
						ShiftVariant::Rotr32 => 7,
					};
					evals[shift_id][*amount] += constraint_eval
						* r_y_tensor
							.get_checked(value_index.0 as usize)
							.expect("constraint system value indices are in range");
				}
			}

			// Scale all evaluations by the batching coefficient.
			for evals_op in &mut evals {
				for evals_op_s in &mut *evals_op {
					*evals_op_s *= coeff;
				}
			}

			evals
		})
		.reduce(
			|| [[F::ZERO; WORD_SIZE_BITS]; SHIFT_VARIANT_COUNT],
			|mut a, b| {
				for (a_op, b_op) in iter::zip(&mut a, b) {
					for (a_op_s, b_op_s) in iter::zip(&mut *a_op, b_op) {
						*a_op_s += b_op_s;
					}
				}
				a
			},
		)
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash, Random};
	use binius_math::{
		BinarySubspace,
		test_utils::{index_to_hypercube_point, random_scalars},
		univariate::lagrange_evals,
	};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;

	#[test]
	fn test_evaluate_h_op_hypercube_vertices() {
		// Property-based test: for random i, j, s in {0..63}, with challenge being
		// the i-th element of the subspace, the outputs must match indicator relations
		// over integers:
		// - sll == 1 iff j + s == i
		// - srl == 1 iff i + s == j
		// - sra == 1 iff i + s == j || i + s >= 64 && j == 63
		// - rotr == 1 iff (i + s) % 64 == j
		let mut rng = StdRng::seed_from_u64(0);
		let subspace =
			BinarySubspace::<BinaryField128bGhash>::with_dim(LOG_WORD_SIZE_BITS).unwrap();

		// Run a reasonable number of random trials
		for _trial in 0..1024 {
			let i: usize = (rng.random::<u8>() as usize) & 63;
			let j: usize = (rng.random::<u8>() as usize) & 63;
			let s: usize = (rng.random::<u8>() as usize) & 63;

			let challenge = subspace.get(i);
			let l_tilde = lagrange_evals(&subspace, challenge);

			let r_j = index_to_hypercube_point::<BinaryField128bGhash>(LOG_WORD_SIZE_BITS, j);
			let r_s = index_to_hypercube_point::<BinaryField128bGhash>(LOG_WORD_SIZE_BITS, s);

			let [sll, srl, sra, rotr] = evaluate_h_op(&l_tilde, &r_j, &r_s);

			let expected_sll = j + s == i;
			let expected_srl = i + s == j;
			let expected_sra = i + s == j || i + s >= 64 && j == 63;
			let expected_rotr = (i + s) & 63 == j;

			let to_field = |b: bool| {
				if b {
					BinaryField128bGhash::ONE
				} else {
					BinaryField128bGhash::ZERO
				}
			};

			assert_eq!(sll, to_field(expected_sll), "sll failed for i={i}, j={j}, s={s}");
			assert_eq!(srl, to_field(expected_srl), "srl failed for i={i}, j={j}, s={s}");
			assert_eq!(sra, to_field(expected_sra), "sra failed for i={i}, j={j}, s={s}");
			assert_eq!(rotr, to_field(expected_rotr), "rotr failed for i={i}, j={j}, s={s}");
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

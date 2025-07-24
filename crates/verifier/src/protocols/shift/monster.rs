// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, Field};
use binius_frontend::constraint_system::{Operand, ShiftedValueIndex};
use binius_math::{BinarySubspace, univariate::lagrange_evals};
use itertools::izip;

use super::{
	LOG_WORD_SIZE_BITS, WORD_SIZE_BITS, error::Error, utils::tensor_expand, verify::OperatorData,
};

/// Given the list of operands for an operator, one
/// can construct a corresponding matrix.
/// This function evaluates that matrix.
/// For $h$ and $M$ corresponding to the operator,
/// and $m$ corresponding to the operand, the matrix is written
/// $$
/// \sum_{op} h_op(r_j, r_s) M_{m, op}(r_x', r_y, r_s)
/// $$
/// where $op$ ranges over the shift variants.
/// TODO: document further
fn evaluate_matrix_for_operand<F: Field>(
	operands: Vec<Operand>,
	// the values $h_op(r_j, r_s)$ for the three `op`s
	h_op_evals: [F; 3],
	r_x_prime_tensor: &[F],
	r_y_tensor: &[F],
	r_s_tensor: &[F],
) -> F {
	izip!(operands, r_x_prime_tensor)
		.into_iter()
		.map(|(operand, &constraint_eval)| {
			operand
				.iter()
				.map(
					|ShiftedValueIndex {
					     value_index,
					     shift_variant,
					     amount,
					 }| {
						constraint_eval
							// nicer ways to access these than
							// casting an enum to a usize
							* h_op_evals[*shift_variant as usize]
							// and reaching into the tuple?
							* r_y_tensor[value_index.0 as usize]
							* r_s_tensor[*amount]
					},
				)
				.sum::<F>()
		})
		.sum()
}

/// Evaluates the three h-operations (SLL, SRL, SRA) at challenge points.
///
/// This is the verifier's version of the h-triplet evaluation - instead of building
/// full multilinear polynomials, it directly computes their evaluations.
/// (Code nearly copied from Python model.)
pub fn evaluate_h_op<F: Field>(l_tilde: &[F], r_j: &[F], r_s: &[F]) -> [F; 3] {
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
		let both = r_j[k] * r_s[k]; // jₖ ∧ sₖ
		let r_j_one_rs = r_j[k] - both; // jₖ ∧ ¬sₖ 
		let one_r_j_rs = r_s[k] - both; // ¬jₖ ∧ sₖ
		let xor = r_j[k] + r_s[k]; // jₖ ⊕ sₖ
		let eq = F::ONE + xor; // ¬(jₖ ⊕ sₖ)
		let zero = eq + both; // ¬jₖ ∧ ¬sₖ

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

/// The monster multilinear for an operator is written
/// $$
/// \sum_{m_idx, m in enumerate(operands)}
/// 	\lambda^{m_idx+1}
/// 	\sum_{op} h_op(r_j, r_s) M_{m, op}(r_x', r_y, r_s)
/// $$
/// where $op$ ranges over the shift variants.
/// TODO: document further
pub fn evaluate_monster_multilinear_for_operator<F: BinaryField, const ARITY: usize>(
	operand_vecs: Vec<Vec<Operand>>,
	operator_data: OperatorData<F, ARITY>,
	r_j: &[F],
	r_s: &[F],
	r_y: &[F],
) -> Result<F, Error> {
	let r_x_prime_tensor = tensor_expand(&operator_data.r_x_prime, operator_data.r_x_prime.len());
	let r_y_tensor = tensor_expand(r_y, r_y.len());
	let r_s_tensor = tensor_expand(r_s, LOG_WORD_SIZE_BITS);

	let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS)?;
	let univariate_domain = subspace.iter().collect::<Vec<_>>();
	let l_tilde = lagrange_evals(&univariate_domain, operator_data.r_zhat_prime)
		.expect("domain points distinct");
	let h_op_evals = evaluate_h_op(&l_tilde, r_j, r_s);

	let eval = operand_vecs
		.into_iter()
		.enumerate()
		.map(|(i, operand_vec)| {
			operator_data.lambda.pow([i as u64 + 1])
				* evaluate_matrix_for_operand(
					operand_vec,
					h_op_evals,
					&r_x_prime_tensor,
					&r_y_tensor,
					&r_s_tensor,
				)
		})
		.sum();

	Ok(eval)
}

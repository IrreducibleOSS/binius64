// Copyright 2025 Irreducible Inc.

use std::array;

use binius_field::{BinaryField, PackedField};
use binius_math::{BinarySubspace, FieldBuffer, univariate::lagrange_evals};
use binius_verifier::protocols::shift::{
	LOG_WORD_SIZE_BITS, WORD_SIZE_BITS, evaluate_h_op, tensor_expand as tensor_expand_scalar,
};
use tracing::instrument;

use super::{
	error::Error, phase_1::MultilinearTriplet, prove::OperatorData, record::ShiftedValueKey,
	utils::make_field_buffer,
};

// Applied in phase 1
// TODO: document
#[instrument(skip_all, name = "compute_h_triplet_for_operator")]
pub fn compute_h_triplet_for_operator<F: BinaryField, P: PackedField<Scalar = F>>(
	r_zhat_prime: F,
) -> Result<MultilinearTriplet<P>, Error> {
	let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS)?;
	let univariate_domain = subspace.iter().collect::<Vec<_>>();
	let l_tilde = lagrange_evals(&univariate_domain, r_zhat_prime).expect("domain points distinct");

	let [mut sll_data, mut srl_data, mut sra_data] =
		array::from_fn(|_| Vec::with_capacity(WORD_SIZE_BITS * WORD_SIZE_BITS));

	for s in 0..WORD_SIZE_BITS {
		for j in 0..WORD_SIZE_BITS {
			sll_data.push(if j + s < l_tilde.len() {
				l_tilde[j + s]
			} else {
				F::ZERO
			});

			let val = if j >= s { l_tilde[j - s] } else { F::ZERO };
			srl_data.push(val);
			sra_data.push(val);
		}
	}

	for s in 1..WORD_SIZE_BITS {
		let msb_idx = s * WORD_SIZE_BITS + WORD_SIZE_BITS - 1;
		let prev_val = sra_data[msb_idx - WORD_SIZE_BITS];
		sra_data[msb_idx] += prev_val;
	}

	let [sll, srl, sra] = [sll_data, srl_data, sra_data].map(make_field_buffer);

	Ok(MultilinearTriplet { sll, srl, sra })
}

// Applied in phase 2
// TODO: document
#[instrument(skip_all, name = "compute_monster_multilinear_for_operator")]
pub fn compute_monster_multilinear_for_operator<
	const ARITY: usize,
	F: BinaryField,
	P: PackedField<Scalar = F>,
>(
	n_words: usize,
	operator_data: &OperatorData<ARITY, F>,
	r_j: &[F],
	r_s: &[F],
) -> Result<FieldBuffer<P>, Error> {
	// Compute `l_tilde`
	let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS)?;
	let univariate_domain = subspace.iter().collect::<Vec<_>>();
	let l_tilde = lagrange_evals(&univariate_domain, operator_data.r_zhat_prime)
		.expect("domain points distinct");

	let lambda_powers: [F; ARITY] = array::from_fn(|i| operator_data.lambda.pow(1 + i as u64));
	let h_ops = evaluate_h_op(&l_tilde, r_j, r_s);
	let r_s_tensor = tensor_expand_scalar(r_s, LOG_WORD_SIZE_BITS);

	const SHIFT_VARIANT_COUNT: usize = 3;
	let mut scalars = vec![F::ZERO; ARITY * SHIFT_VARIANT_COUNT * WORD_SIZE_BITS];
	for operand_idx in 0..ARITY {
		for op in 0..SHIFT_VARIANT_COUNT {
			let operand_op_idx = operand_idx * SHIFT_VARIANT_COUNT + op;
			let operand_op_scalar = lambda_powers[operand_idx] * h_ops[op];
			for s in 0..WORD_SIZE_BITS {
				let operand_op_s_idx = operand_op_idx << LOG_WORD_SIZE_BITS | s;
				scalars[operand_op_s_idx] = operand_op_scalar * r_s_tensor[s];
			}
		}
	}

	let accumulate_for_operand_keys = |keys: &[ShiftedValueKey<F>], operand_idx: usize| -> F {
		keys.iter().fold(F::ZERO, |acc, key| {
			let base = key.accumulate(&operator_data.r_x_prime_tensor);
			// Replace above with below to try memoization.
			// let base = key.memo;
			let operand_op_idx = operand_idx * SHIFT_VARIANT_COUNT + key.op as usize;
			let operand_op_s_idx = operand_op_idx << LOG_WORD_SIZE_BITS | key.s;
			acc + base * scalars[operand_op_s_idx]
		})
	};

	let values: Vec<F> = (0..n_words)
		.map(|i| {
			(0..ARITY)
				.map(|operand_idx| {
					accumulate_for_operand_keys(&operator_data.records[operand_idx][i], operand_idx)
				})
				.sum()
		})
		.collect();

	Ok(make_field_buffer(values))
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash, PackedBinaryGhash1x128b, Random};
	use binius_math::{inner_product::inner_product_buffers, multilinear::eq::eq_ind_partial_eval};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	/// Test that verifies consistency between direct multilinear evaluation
	/// and the succinct evaluate_h_op implementation
	#[test]
	fn h_op_consistency() {
		type F = BinaryField128bGhash;
		type P = PackedBinaryGhash1x128b;

		let mut rng = StdRng::seed_from_u64(0);

		let num_random_tests = 10;

		for test_case in 0..num_random_tests {
			let r_zhat_prime = F::random(&mut rng);

			let r_j: Vec<F> = (0..6).map(|_| F::random(&mut rng)).collect();
			let r_s: Vec<F> = (0..6).map(|_| F::random(&mut rng)).collect();

			// Method 1: Succinct evaluation using evaluate_h_op
			let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS).unwrap();
			let univariate_domain = subspace.iter().collect::<Vec<_>>();
			let l_tilde = lagrange_evals(&univariate_domain, r_zhat_prime)
				.expect("domain points are distinct");
			let succinct_evaluations = evaluate_h_op(&l_tilde, &r_j, &r_s);

			// Method 2: Direct evaluation via multilinear triplet
			let h_triplet = compute_h_triplet_for_operator(r_zhat_prime).unwrap();
			let evaluation_point: Vec<F> = [r_j.clone(), r_s.clone()].concat();
			let tensor = eq_ind_partial_eval::<P>(&evaluation_point);

			let direct_evaluations = [h_triplet.sll, h_triplet.srl, h_triplet.sra]
				.map(|buf| inner_product_buffers(&buf, &tensor));

			assert_eq!(
				succinct_evaluations, direct_evaluations,
				"H-op evaluation mismatch (test_case={}): succinct != direct",
				test_case
			);
		}
	}
}

// Copyright 2025 Irreducible Inc.

use std::{array, ops::Range};

use binius_field::{BinaryField, PackedField};
use binius_math::{BinarySubspace, FieldBuffer, univariate::lagrange_evals};
use binius_utils::{checked_arithmetics::strict_log_2, rayon::prelude::*};
use binius_verifier::{
	config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS},
	protocols::shift::{evaluate_h_op, tensor_expand as tensor_expand_scalar},
};
use tracing::instrument;

use super::{
	BITMUL_ARITY, INTMUL_ARITY, SHIFT_VARIANT_COUNT,
	error::Error,
	phase_1::MultilinearTriplet,
	prove::OperatorData,
	record::{Operation, ProverConstraintSystem},
	utils::make_field_buffer,
};

// Applied in phase 1
// TODO: document
#[instrument(skip_all, name = "build_h_triplet")]
pub fn build_h_triplet<F: BinaryField, P: PackedField<Scalar = F>>(
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
#[instrument(skip_all, name = "build_monster_multilinear")]
pub fn build_monster_multilinear<F: BinaryField, P: PackedField<Scalar = F>>(
	cs: &ProverConstraintSystem,
	bitmul_operator_data: &OperatorData<F>,
	intmul_operator_data: &OperatorData<F>,
	r_j: &[F],
	r_s: &[F],
) -> Result<FieldBuffer<P>, Error> {
	// Compute lambda powers
	let bitmul_lambda_powers: [F; BITMUL_ARITY] =
		array::from_fn(|i| bitmul_operator_data.lambda.pow(1 + i as u64));
	let intmul_lambda_powers: [F; INTMUL_ARITY] =
		array::from_fn(|i| intmul_operator_data.lambda.pow(1 + i as u64));

	// Compute h_ops
	let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS)?;
	let univariate_domain = subspace.iter().collect::<Vec<_>>();
	let [bitmul_h_ops, intmul_h_ops] = [
		bitmul_operator_data.r_zhat_prime,
		intmul_operator_data.r_zhat_prime,
	]
	.map(|r_zhat_prime| {
		let l_tilde =
			lagrange_evals(&univariate_domain, r_zhat_prime).expect("domain points distinct");
		evaluate_h_op(&l_tilde, r_j, r_s)
	});

	// Compute `r_s` tensor
	let r_s_tensor = tensor_expand_scalar(r_s, LOG_WORD_SIZE_BITS);

	// Allocate the scalars
	let mut bitmul_scalars = vec![F::ZERO; BITMUL_ARITY * SHIFT_VARIANT_COUNT * WORD_SIZE_BITS];
	let mut intmul_scalars = vec![F::ZERO; INTMUL_ARITY * SHIFT_VARIANT_COUNT * WORD_SIZE_BITS];

	// Populate the scalars
	let populate_scalars = |scalars: &mut [F], arity: usize, lambda_powers: &[F], h_ops: &[F]| {
		for operand_idx in 0..arity {
			for op in 0..SHIFT_VARIANT_COUNT {
				let operand_op_idx = operand_idx * SHIFT_VARIANT_COUNT + op;
				let operand_op_scalar = lambda_powers[operand_idx] * h_ops[op];
				for s in 0..WORD_SIZE_BITS {
					let operand_op_s_idx = operand_op_idx * WORD_SIZE_BITS + s;
					scalars[operand_op_s_idx] = operand_op_scalar * r_s_tensor[s];
				}
			}
		}
	};

	populate_scalars(&mut bitmul_scalars, BITMUL_ARITY, &bitmul_lambda_powers, &bitmul_h_ops);
	populate_scalars(&mut intmul_scalars, INTMUL_ARITY, &intmul_lambda_powers, &intmul_h_ops);

	let monster = cs
		.key_ranges
		.par_iter()
		.map(|Range { start, end }| {
			cs.keys[*start as usize..*end as usize]
				.iter()
				.map(|key| {
					let (tensor, scalars) = match key.operation {
						Operation::BitwiseAnd => {
							(&bitmul_operator_data.r_x_prime_tensor, &bitmul_scalars)
						}
						Operation::IntegerMul => {
							(&intmul_operator_data.r_x_prime_tensor, &intmul_scalars)
						}
					};
					key.accumulate(&cs.constraint_indices, tensor) * scalars[key.id as usize]
				})
				.sum()
		})
		.chunks(P::WIDTH)
		.map(|chunk| P::from_scalars(chunk))
		.collect::<Box<[_]>>();

	let log_len =
		strict_log_2(monster.len()).expect("same length as constraint system's `key_ranges`");
	Ok(FieldBuffer::new(log_len, monster).unwrap())
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
			let h_triplet = build_h_triplet(r_zhat_prime).unwrap();
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

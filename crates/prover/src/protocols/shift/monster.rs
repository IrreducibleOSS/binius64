// Copyright 2025 Irreducible Inc.

use std::{array, ops::Range};

use binius_field::{BinaryField, PackedField};
use binius_math::{
	BinarySubspace, FieldBuffer, multilinear::eq::eq_ind_partial_eval, univariate::lagrange_evals,
};
use binius_utils::{checked_arithmetics::strict_log_2, rayon::prelude::*};
use binius_verifier::{
	config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS},
	protocols::shift::evaluate_h_op,
};
use tracing::instrument;

use super::{
	BITAND_ARITY, INTMUL_ARITY, SHIFT_VARIANT_COUNT,
	error::Error,
	key_collection::{KeyCollection, Operation},
	phase_1::MultilinearTriplet,
	prove::OperatorData,
};

/// Constructs the three "h" multilinear polynomials for shift operations at a
/// univariate challenge point. See the paper for definition of h polynomials.
///
/// There is one h multilinear for each shift variant (SLL, SRL, SRA). For each
/// operation there is one univariate challenge `r_zhat_prime` at which to
/// construct the three h multilinears.
///
/// # Usage in Protocol
///
/// Used in phase 1, thus returning a `MultilinearTriplet` defined in `super::phase_1`.
#[instrument(skip_all, name = "build_h_triplet")]
pub fn build_h_triplet<F: BinaryField, P: PackedField<Scalar = F>>(
	r_zhat_prime: F,
) -> Result<MultilinearTriplet<P>, Error> {
	let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS)?;
	let l_tilde = lagrange_evals(&subspace, r_zhat_prime);

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

	let sll = FieldBuffer::from_values(&sll_data)?;
	let srl = FieldBuffer::from_values(&srl_data)?;
	let sra = FieldBuffer::from_values(&sra_data)?;

	Ok(MultilinearTriplet { sll, srl, sra })
}

/// Constructs the "monster multilinear" that combines all shift operations into a single
/// multilinear.
///
/// This function builds a comprehensive multilinear polynomial that encapsulates both AND and MUL
/// constraints with their associated shift operations. For each witness word, it computes the
/// contribution from all constraints involving that word, weighted by the appropriate h-polynomial
/// evaluations and lambda powers.
///
/// # Construction Process
///
/// 1. **Compute lambda powers**: Powers λ^(i+1) for each operand index in both operations
/// 2. **Evaluate h-polynomials**: Compute h_op evaluations for SLL, SRL, SRA at challenge points
/// 3. **Build scalar matrix**: Create scalars combining lambda powers, h-evaluations, and r_s
///    tensor
/// 4. **Process keys in parallel**: For each word, accumulate contributions from all its
///    constraints
///
/// # Formula
///
/// For each word w, computes:
/// ```text
/// ∑_{key ∈ keys[w]} key.accumulate(constraint_indices, tensor) × scalars[key.id]
/// ```
/// where the scalars encode `λ^(operand_idx+1) × h_op[shift_variant] × r_s_tensor[shift_amount]`
/// for operand index `operand_idx` and `shift_variant` in {SLL, SRL, SRA} and `shift_amount` in
/// [0, WORD_SIZE_BITS).
///
/// # Usage
///
/// Used in phase 2 of the shift protocol where the prover needs a single multilinear combining
/// all shift-related constraints for efficient sumcheck computation.
#[instrument(skip_all, name = "build_monster_multilinear")]
pub fn build_monster_multilinear<F: BinaryField, P: PackedField<Scalar = F>>(
	key_collection: &KeyCollection,
	bitand_operator_data: &OperatorData<F>,
	intmul_operator_data: &OperatorData<F>,
	r_j: &[F],
	r_s: &[F],
) -> Result<FieldBuffer<P>, Error> {
	// Compute lambda powers
	let bitand_lambda_powers: [F; BITAND_ARITY] =
		array::from_fn(|i| bitand_operator_data.lambda.pow(1 + i as u64));
	let intmul_lambda_powers: [F; INTMUL_ARITY] =
		array::from_fn(|i| intmul_operator_data.lambda.pow(1 + i as u64));

	// Compute h evaluations
	let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS)?;
	let [bitand_h_ops, intmul_h_ops] = [
		bitand_operator_data.r_zhat_prime,
		intmul_operator_data.r_zhat_prime,
	]
	.map(|r_zhat_prime| {
		let l_tilde = lagrange_evals(&subspace, r_zhat_prime);
		evaluate_h_op(&l_tilde, r_j, r_s)
	});

	let r_s_tensor = eq_ind_partial_eval::<F>(r_s);

	// Allocate and populate the scalars
	let mut bitand_scalars = vec![F::ZERO; BITAND_ARITY * SHIFT_VARIANT_COUNT * WORD_SIZE_BITS];
	let mut intmul_scalars = vec![F::ZERO; INTMUL_ARITY * SHIFT_VARIANT_COUNT * WORD_SIZE_BITS];

	let populate_scalars = |scalars: &mut [F], arity: usize, lambda_powers: &[F], h_ops: &[F]| {
		for operand_idx in 0..arity {
			for op in 0..SHIFT_VARIANT_COUNT {
				let operand_op_idx = operand_idx * SHIFT_VARIANT_COUNT + op;
				let operand_op_scalar = lambda_powers[operand_idx] * h_ops[op];
				for s in 0..WORD_SIZE_BITS {
					let operand_op_s_idx = operand_op_idx * WORD_SIZE_BITS + s;
					scalars[operand_op_s_idx] = operand_op_scalar * r_s_tensor.as_ref()[s];
				}
			}
		}
	};

	populate_scalars(&mut bitand_scalars, BITAND_ARITY, &bitand_lambda_powers, &bitand_h_ops);
	populate_scalars(&mut intmul_scalars, INTMUL_ARITY, &intmul_lambda_powers, &intmul_h_ops);

	let monster_multilinear = key_collection
		.key_ranges
		.par_iter()
		.map(|Range { start, end }| {
			key_collection.keys[*start as usize..*end as usize]
				.iter()
				.map(|key| {
					let (tensor, scalars) = match key.operation {
						Operation::BitwiseAnd => {
							(&bitand_operator_data.r_x_prime_tensor, &bitand_scalars)
						}
						Operation::IntegerMul => {
							(&intmul_operator_data.r_x_prime_tensor, &intmul_scalars)
						}
					};
					key.accumulate(&key_collection.constraint_indices, tensor)
						* scalars[key.id as usize]
				})
				.sum()
		})
		.chunks(P::WIDTH)
		.map(|chunk| P::from_scalars(chunk))
		.collect::<Box<[_]>>();

	let log_len = strict_log_2(monster_multilinear.len())
		.expect("same length as constraint system's `key_ranges`");
	Ok(FieldBuffer::new(log_len, monster_multilinear).expect("checked log_len"))
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash, PackedBinaryGhash2x128b, Random};
	use binius_math::{inner_product::inner_product_buffers, multilinear::eq::eq_ind_partial_eval};
	use binius_verifier::protocols::shift::evaluate_h_op;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	/// Test consistency between direct multilinear evaluation of h
	/// multilinears and the succinct `evaluate_h_op` implementation
	#[test]
	fn h_op_consistency() {
		type F = BinaryField128bGhash;
		type P = PackedBinaryGhash2x128b;

		let mut rng = StdRng::seed_from_u64(0);

		let num_random_tests = 10;

		for test_case in 0..num_random_tests {
			let r_zhat_prime = F::random(&mut rng);

			let r_j: Vec<F> = (0..6).map(|_| F::random(&mut rng)).collect();
			let r_s: Vec<F> = (0..6).map(|_| F::random(&mut rng)).collect();

			// Method 1: Succinct evaluation using `evaluate_h_op`
			let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS).unwrap();
			let l_tilde = lagrange_evals(&subspace, r_zhat_prime);
			let succinct_evaluations = evaluate_h_op(&l_tilde, &r_j, &r_s);

			// Method 2: Direct evaluation via multilinear triplet
			let h_triplet = build_h_triplet(r_zhat_prime).unwrap();
			let evaluation_point: Vec<F> = [r_j.clone(), r_s.clone()].concat();
			let tensor = eq_ind_partial_eval::<P>(&evaluation_point);

			let direct_evaluations = [h_triplet.sll, h_triplet.srl, h_triplet.sra]
				.map(|buf| inner_product_buffers(&buf, &tensor));

			assert_eq!(
				succinct_evaluations, direct_evaluations,
				"H-op evaluation mismatch (test_case={test_case}): succinct != direct",
			);
		}
	}
}

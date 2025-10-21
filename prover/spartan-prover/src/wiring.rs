// Copyright 2025 Irreducible Inc.

#![allow(dead_code)]

use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};
use binius_spartan_frontend::constraint_system::{MulConstraint, WitnessIndex};
use binius_utils::{checked_arithmetics::checked_log_2, rayon::prelude::*};

/// Transpose of the wiring sparse matrix.
#[derive(Debug)]
pub struct WiringTranspose {
	flat_keys: Vec<Key>,
	keys_start_by_witness_index: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Key {
	pub operand_idx: u8,
	pub constraint_idx: u32,
}

impl WiringTranspose {
	pub fn transpose(witness_size: usize, mul_constraints: &[MulConstraint<WitnessIndex>]) -> Self {
		let mut operands_keys_by_wit_idx = vec![Vec::new(); witness_size];

		let mut n_total_keys = 0;
		for (i, MulConstraint { a, b, c }) in mul_constraints.iter().enumerate() {
			for (operand_idx, operand) in [a, b, c].into_iter().enumerate() {
				for &witness_idx in operand.wires() {
					operands_keys_by_wit_idx[witness_idx.0 as usize].push(Key {
						operand_idx: operand_idx as u8,
						constraint_idx: i as u32,
					});
					n_total_keys += 1;
				}
			}
		}

		// Flatten the sparse matrix representation.
		let mut operand_keys = Vec::with_capacity(n_total_keys);
		let mut operand_key_start_by_word = Vec::with_capacity(witness_size);
		for keys in operands_keys_by_wit_idx {
			let start = operand_keys.len() as u32;
			operand_keys.extend(keys);
			operand_key_start_by_word.push(start);
		}

		Self {
			flat_keys: operand_keys,
			keys_start_by_witness_index: operand_key_start_by_word,
		}
	}

	/// Returns an iterator over keys for a specific witness index.
	pub fn keys_for_witness(&self, witness_idx: usize) -> &[Key] {
		let start = self.keys_start_by_witness_index[witness_idx] as usize;
		let end = self
			.keys_start_by_witness_index
			.get(witness_idx + 1)
			.map(|&x| x as usize)
			.unwrap_or(self.flat_keys.len());
		&self.flat_keys[start..end]
	}
}

/// Folds the wiring matrix along the constraint axis by partially evaluating at r_x.
///
/// Also batches the three operands (a, b, c) using powers of lambda.
/// Returns a multilinear polynomial over witness indices where each coefficient is the
/// weighted sum of constraint contributions.
pub fn fold_constraints<F: Field, P: PackedField<Scalar = F>>(
	transposed: &WiringTranspose,
	witness_size: usize,
	lambda: F,
	r_x: &[F],
) -> FieldBuffer<P> {
	// Compute eq indicator tensor for constraint evaluation points
	let r_x_tensor = eq_ind_partial_eval::<F>(r_x);

	// Batching powers for the three operands
	let lambda_powers = [F::ONE, lambda, lambda.square()];

	// Create packed field buffer for witness indices
	let log_witness_size = checked_log_2(witness_size);
	let len = 1 << log_witness_size.saturating_sub(P::LOG_WIDTH);

	// Process in parallel over chunks of P::WIDTH witness indices
	let result = (0..len)
		.into_par_iter()
		.map(|packed_idx| {
			let base_witness_idx = packed_idx << P::LOG_WIDTH;

			P::from_fn(|scalar_idx| {
				let witness_idx = base_witness_idx + scalar_idx;
				if witness_idx >= witness_size {
					return F::ZERO;
				}

				let mut acc = F::ZERO;
				for key in transposed.keys_for_witness(witness_idx) {
					let r_x_weight = r_x_tensor[key.constraint_idx as usize];
					let lambda_weight = lambda_powers[key.operand_idx as usize];
					acc += r_x_weight * lambda_weight;
				}
				acc
			})
		})
		.collect::<Vec<_>>();

	FieldBuffer::new(log_witness_size, result.into_boxed_slice())
		.expect("FieldBuffer::new should succeed with correct log_witness_size")
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash as B128, Field, Random};
	use binius_math::{
		multilinear::eq::eq_ind_partial_eval,
		test_utils::{Packed128b, random_scalars},
		univariate::evaluate_univariate,
	};
	use binius_spartan_frontend::constraint_system::{MulConstraint, Operand, WitnessIndex};
	use binius_spartan_verifier::wiring::evaluate_wiring_mle;
	use rand::{Rng, SeedableRng, rngs::StdRng};
	use smallvec::SmallVec;

	use super::*;

	/// Generate random MulConstraints for testing.
	/// Each operand has 0-4 random wires.
	fn generate_random_constraints(
		rng: &mut StdRng,
		n_constraints: usize,
		witness_size: usize,
	) -> Vec<MulConstraint<WitnessIndex>> {
		(0..n_constraints)
			.map(|_| {
				let a = generate_random_operand(rng, witness_size);
				let b = generate_random_operand(rng, witness_size);
				let c = generate_random_operand(rng, witness_size);
				MulConstraint { a, b, c }
			})
			.collect()
	}

	fn generate_random_operand(rng: &mut StdRng, witness_size: usize) -> Operand<WitnessIndex> {
		let n_wires = rng.random_range(0..=4);
		let wires: SmallVec<[WitnessIndex; 4]> = (0..n_wires)
			.map(|_| WitnessIndex(rng.random_range(0..witness_size as u32)))
			.collect();
		Operand::new(wires)
	}

	/// Evaluate the wiring MLE using the transposed representation.
	fn evaluate_wiring_mle_transposed<F: Field>(
		transposed: &WiringTranspose,
		witness_size: usize,
		lambda: F,
		r_x_tensor: &[F],
		r_y_tensor: &[F],
	) -> F {
		let mut acc = [F::ZERO; 3];

		for witness_idx in 0..witness_size {
			let r_y_weight = r_y_tensor[witness_idx];
			for key in transposed.keys_for_witness(witness_idx) {
				let r_x_weight = r_x_tensor[key.constraint_idx as usize];
				acc[key.operand_idx as usize] += r_x_weight * r_y_weight;
			}
		}

		evaluate_univariate(&acc, lambda)
	}

	#[test]
	fn test_wiring_transpose_equivalence() {
		let mut rng = StdRng::seed_from_u64(0);

		// Generate random constraints
		let n_constraints = 16;
		let witness_size = 32;
		let constraints = generate_random_constraints(&mut rng, n_constraints, witness_size);

		// Sample random evaluation points
		let log_n_constraints = (n_constraints as f64).log2().ceil() as usize;
		let log_witness_size = (witness_size as f64).log2().ceil() as usize;

		let r_x = random_scalars::<B128>(&mut rng, log_n_constraints);
		let r_y = random_scalars::<B128>(&mut rng, log_witness_size);
		let lambda = B128::random(&mut rng);

		// Compute expected result using the original representation
		let expected = evaluate_wiring_mle(&constraints, lambda, &r_x, &r_y);

		// Compute result using the transposed representation
		let transposed = WiringTranspose::transpose(witness_size, &constraints);
		let r_x_tensor = eq_ind_partial_eval::<B128>(&r_x);
		let r_y_tensor = eq_ind_partial_eval::<B128>(&r_y);
		let actual = evaluate_wiring_mle_transposed(
			&transposed,
			witness_size,
			lambda,
			r_x_tensor.as_ref(),
			r_y_tensor.as_ref(),
		);

		assert_eq!(actual, expected, "Transposed evaluation does not match original evaluation");
	}

	#[test]
	fn test_fold_constraints_equivalence() {
		use binius_math::multilinear::evaluate::evaluate;

		let mut rng = StdRng::seed_from_u64(1);

		// Generate random constraints
		let n_constraints = 16;
		let witness_size = 32;
		let constraints = generate_random_constraints(&mut rng, n_constraints, witness_size);

		// Sample random evaluation points
		let log_n_constraints = (n_constraints as f64).log2().ceil() as usize;
		let log_witness_size = (witness_size as f64).log2().ceil() as usize;

		let r_x = random_scalars::<B128>(&mut rng, log_n_constraints);
		let r_y = random_scalars::<B128>(&mut rng, log_witness_size);
		let lambda = B128::random(&mut rng);

		// Method 1: Compute expected result using evaluate_wiring_mle
		let expected = evaluate_wiring_mle(&constraints, lambda, &r_x, &r_y);

		// Method 2: Use fold_constraints then evaluate at r_y
		let transposed = WiringTranspose::transpose(witness_size, &constraints);
		let folded = fold_constraints::<_, Packed128b>(&transposed, witness_size, lambda, &r_x);
		let actual = evaluate(&folded, &r_y).expect("evaluation should succeed");

		assert_eq!(
			actual, expected,
			"fold_constraints + evaluate does not match evaluate_wiring_mle"
		);
	}
}

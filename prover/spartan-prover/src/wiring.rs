// Copyright 2025 Irreducible Inc.

#![allow(dead_code)]

use binius_field::{Field, PackedField};
use binius_math::{
	FieldBuffer, FieldSlice, multilinear::eq::eq_ind_partial_eval, univariate::evaluate_univariate,
};
use binius_prover::protocols::{
	sumcheck,
	sumcheck::{ProveSingleOutput, bivariate_product::BivariateProductSumcheckProver},
};
use binius_spartan_frontend::constraint_system::{MulConstraint, Operand, WitnessIndex};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{checked_arithmetics::checked_log_2, rayon::prelude::*};

use crate::Error;

/// Transpose of the wiring sparse matrix.
#[derive(Debug)]
pub struct WiringTranspose {
	flat_keys: Vec<Key>,
	keys_start_by_witness_index: Vec<u32>,
	log_witness_size: usize,
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

		let log_witness_size = checked_log_2(witness_size);

		Self {
			flat_keys: operand_keys,
			keys_start_by_witness_index: operand_key_start_by_word,
			log_witness_size,
		}
	}

	/// Returns the log2 of the witness size.
	pub fn log_witness_size(&self) -> usize {
		self.log_witness_size
	}

	/// Returns the witness size.
	pub fn witness_size(&self) -> usize {
		1 << self.log_witness_size
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
	lambda: F,
	r_x: &[F],
) -> FieldBuffer<P> {
	// Compute eq indicator tensor for constraint evaluation points
	let r_x_tensor = eq_ind_partial_eval::<F>(r_x);

	// Batching powers for the three operands
	let lambda_powers = [F::ONE, lambda, lambda.square()];

	// Create packed field buffer for witness indices
	let witness_size = transposed.witness_size();
	let log_witness_size = transposed.log_witness_size();
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

/// Output of the wiring check protocol.
#[derive(Debug)]
pub struct Output<F> {
	pub r_y: Vec<F>,
	pub witness_eval: F,
}

/// Proves the wiring check protocol.
///
/// This function implements the prover side of the wiring check reduction protocol.
/// It batches the mulcheck evaluations, runs a sumcheck over the bivariate product
/// of the witness and folded wiring polynomial, and returns the evaluation point
/// and witness evaluation.
pub fn prove<F: Field, P: PackedField<Scalar = F>, Challenger_: Challenger>(
	wiring_transpose: &WiringTranspose,
	r_x: &[F],
	witness: FieldBuffer<P>,
	mulcheck_evals: &[F],
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<Output<F>, Error> {
	// Sample batching challenge
	let lambda = transcript.sample();

	// Fold constraints with batching
	let l_poly = fold_constraints(wiring_transpose, lambda, r_x);

	// Batch the mulcheck evaluations
	let batched_sum = evaluate_univariate(mulcheck_evals, lambda);

	// Run sumcheck on bivariate product
	let sumcheck_prover = BivariateProductSumcheckProver::new([witness, l_poly], batched_sum)
		.expect("multilinears have equal numbers of variables");

	let ProveSingleOutput {
		multilinear_evals,
		challenges: mut r_y,
	} = sumcheck::prove_single(sumcheck_prover, transcript)
		.expect("prover instance satisfies preconditions");

	// Reverse challenges to match expected order
	r_y.reverse();

	// Extract witness evaluation
	let [witness_eval, _l_poly_eval] = multilinear_evals
		.try_into()
		.expect("prover has two multilinears; it returns two evaluations");

	// Write witness evaluation to transcript
	transcript.message().write(&witness_eval);

	Ok(Output { r_y, witness_eval })
}

/// Witness data for multiplication constraint checking.
///
/// Contains the evaluated operands a, b, and c for all multiplication constraints,
/// packed into field buffers for efficient processing.
pub struct MulCheckWitness<P: PackedField> {
	pub a: FieldBuffer<P>,
	pub b: FieldBuffer<P>,
	pub c: FieldBuffer<P>,
}

/// Evaluates an operand by XORing witness values at the specified indices.
fn eval_operand<P: PackedField>(
	witness: &FieldSlice<P>,
	operand: &Operand<WitnessIndex>,
) -> P::Scalar
where
	P::Scalar: Field,
{
	operand
		.wires()
		.iter()
		.map(|idx| witness.get(idx.0 as usize))
		.sum()
}

/// Builds the witness for multiplication constraint checking.
///
/// Extracts and packs the a, b, and c operand values for each multiplication constraint.
/// This is analogous to `build_bitand_witness` in binius-prover but works with B128
/// field elements instead of word-level operations.
#[tracing::instrument(skip_all, level = "debug")]
pub fn build_mulcheck_witness<F: Field, P: PackedField<Scalar = F>>(
	mul_constraints: &[MulConstraint<WitnessIndex>],
	witness: FieldSlice<P>,
) -> MulCheckWitness<P> {
	fn get_a(c: &MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex> {
		&c.a
	}
	fn get_b(c: &MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex> {
		&c.b
	}
	fn get_c(c: &MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex> {
		&c.c
	}

	let n_constraints = mul_constraints.len();
	assert!(n_constraints > 0, "mul_constraints must not be empty");

	let log_n_constraints = checked_log_2(n_constraints);

	let len = 1 << log_n_constraints.saturating_sub(P::LOG_WIDTH);
	let mut a = Vec::<P>::with_capacity(len);
	let mut b = Vec::<P>::with_capacity(len);
	let mut c = Vec::<P>::with_capacity(len);

	(a.spare_capacity_mut(), b.spare_capacity_mut(), c.spare_capacity_mut())
		.into_par_iter()
		.enumerate()
		.for_each(|(i, (a_i, b_i, c_i))| {
			let offset = i << P::LOG_WIDTH;

			for (dst, get_operand) in [
				(a_i, get_a as fn(&MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex>),
				(b_i, get_b as fn(&MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex>),
				(c_i, get_c as fn(&MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex>),
			] {
				let val = P::from_fn(|j| {
					let constraint_idx = offset + j;
					if constraint_idx < n_constraints {
						eval_operand(&witness, get_operand(&mul_constraints[constraint_idx]))
					} else {
						F::ZERO
					}
				});
				dst.write(val);
			}
		});

	// Safety: all entries in a, b, c are initialized in the parallel loop above.
	unsafe {
		a.set_len(len);
		b.set_len(len);
		c.set_len(len);
	}

	MulCheckWitness {
		a: FieldBuffer::new(log_n_constraints, a.into_boxed_slice())
			.expect("FieldBuffer::new should succeed with correct log_n_constraints"),
		b: FieldBuffer::new(log_n_constraints, b.into_boxed_slice())
			.expect("FieldBuffer::new should succeed with correct log_n_constraints"),
		c: FieldBuffer::new(log_n_constraints, c.into_boxed_slice())
			.expect("FieldBuffer::new should succeed with correct log_n_constraints"),
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash as B128, Field, Random};
	use binius_math::{
		inner_product::inner_product_buffers,
		multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate},
		test_utils::{Packed128b, random_field_buffer, random_scalars},
		univariate::evaluate_univariate,
	};
	use binius_spartan_frontend::constraint_system::{
		ConstraintSystem, MulConstraint, Operand, WitnessIndex,
	};
	use binius_spartan_verifier::{
		config::StdChallenger,
		wiring::{self as verifier_wiring, evaluate_wiring_mle},
	};
	use binius_transcript::ProverTranscript;
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
		lambda: F,
		r_x_tensor: &[F],
		r_y_tensor: &[F],
	) -> F {
		let mut acc = [F::ZERO; 3];

		for witness_idx in 0..transposed.witness_size() {
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
			lambda,
			r_x_tensor.as_ref(),
			r_y_tensor.as_ref(),
		);

		assert_eq!(actual, expected, "Transposed evaluation does not match original evaluation");
	}

	#[test]
	fn test_fold_constraints_equivalence() {
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

		// Method 1: Compute expected result using evaluate_wiring_mle
		let expected = evaluate_wiring_mle(&constraints, lambda, &r_x, &r_y);

		// Method 2: Use fold_constraints then evaluate at r_y
		let transposed = WiringTranspose::transpose(witness_size, &constraints);
		let folded = fold_constraints::<_, Packed128b>(&transposed, lambda, &r_x);
		let actual = evaluate(&folded, &r_y).expect("evaluation should succeed");

		assert_eq!(
			actual, expected,
			"fold_constraints + evaluate does not match evaluate_wiring_mle"
		);
	}

	#[test]
	fn test_wiring_prove_verify() {
		let mut rng = StdRng::seed_from_u64(0);

		// Generate random constraints
		let n_constraints = 16;
		let witness_size = 32;
		let constraints = generate_random_constraints(&mut rng, n_constraints, witness_size);

		// Sample random evaluation points
		let log_n_constraints = (n_constraints as f64).log2().ceil() as usize;
		let log_witness_size = (witness_size as f64).log2().ceil() as usize;

		// Create random witness using random_field_buffer
		let witness_packed = random_field_buffer::<Packed128b>(&mut rng, log_witness_size);

		// Compute mulcheck witness
		let mulcheck_witness = build_mulcheck_witness(&constraints, witness_packed.to_ref());

		// Sample r_x
		let r_x = random_scalars::<B128>(&mut rng, log_n_constraints);

		// Compute mulcheck evaluations
		let r_x_tensor = eq_ind_partial_eval::<Packed128b>(&r_x);
		let mulcheck_evals = [
			inner_product_buffers(&mulcheck_witness.a, &r_x_tensor),
			inner_product_buffers(&mulcheck_witness.b, &r_x_tensor),
			inner_product_buffers(&mulcheck_witness.c, &r_x_tensor),
		];

		// Create transposed wiring
		let wiring_transpose = WiringTranspose::transpose(witness_size, &constraints);

		// Prover side
		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let prover_output =
			prove(&wiring_transpose, &r_x, witness_packed, &mulcheck_evals, &mut prover_transcript)
				.expect("prove should succeed");

		// Verifier side
		let mut verifier_transcript = prover_transcript.into_verifier();
		let verifier_output =
			verifier_wiring::verify(log_witness_size, &mulcheck_evals, &mut verifier_transcript)
				.expect("verify should succeed");

		// Check that outputs match
		assert_eq!(
			prover_output.r_y, verifier_output.r_y,
			"r_y should match between prover and verifier"
		);
		assert_eq!(
			prover_output.witness_eval, verifier_output.witness_eval,
			"witness_eval should match between prover and verifier"
		);

		// Check eval consistency using ConstraintSystem
		let constraint_system = ConstraintSystem::new(
			vec![],                  // constants
			0,                       // n_inout
			0,                       // n_private
			0,                       // log_public
			log_witness_size as u32, // log_size
			constraints,             // mul_constraints
		);
		verifier_wiring::check_eval(&constraint_system, &r_x, &verifier_output)
			.expect("check_eval should succeed");
	}
}

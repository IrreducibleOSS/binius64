// Copyright 2025 Irreducible Inc.

use binius_core::constraint_system::{AndConstraint, ConstraintSystem, MulConstraint};
use binius_field::{BinaryField, Field};
use binius_math::{multilinear::eq::eq_ind, univariate::evaluate_univariate};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::checked_arithmetics::strict_log_2;
use itertools::Itertools;

use super::{BITAND_ARITY, INTMUL_ARITY, error::Error, evaluate_monster_multilinear_for_operation};
use crate::{
	config::LOG_WORD_SIZE_BITS,
	protocols::{
		pubcheck::VerifyOutput,
		sumcheck::{SumcheckOutput, verify as verify_sumcheck},
	},
};

/// Verifier data for an operation with the specified arity.
///
/// Contains the challenge points and evaluation claims needed by the verifier.
/// The verifier receives these values during the protocol and uses them to
/// verify the monster multilinear evaluations.
///
/// # Fields
///
/// - `r_x_prime`: multilinear challenge point from the protocol
/// - `r_zhat_prime`: univariate challenge point
/// - `lambda`: random linear combination coefficient for operand weighting
/// - `evals`: array of evaluation claims, one per operand position
#[derive(Debug, Clone)]
pub struct OperatorData<F, const ARITY: usize> {
	pub r_x_prime: Vec<F>,
	pub r_zhat_prime: F,
	pub lambda: F,
	pub evals: [F; ARITY],
}

impl<F: Field, const ARITY: usize> OperatorData<F, ARITY> {
	// Constructs a new operator data instance encoding
	// evaluation claim with univariate challenge `r_zhat_prime`
	// multilinear challenge `r_x_prime`, and evaluations `evals`
	// with one eval for each operand of the operation.
	pub fn new(r_zhat_prime: F, r_x_prime: Vec<F>, evals: [F; ARITY]) -> Self {
		Self {
			r_x_prime,
			r_zhat_prime,
			lambda: F::ZERO,
			evals,
		}
	}

	// Batching is scaled by random lambda and therefore this batched
	// evaluation claim can be added to other batched evaluation claims
	// without further random scaling.
	fn batched_eval(&self) -> F {
		self.lambda * evaluate_univariate(&self.evals, self.lambda)
	}
}

/// Verifies the shift protocol using a two-phase sumcheck approach.
///
/// # Protocol Overview
/// 1. **Sampling Phase**: Samples random lambda coefficients for batching bitand and intmul
///    evaluation claims across operands.
/// 2. **First Sumcheck**: Verifies the batched evaluation claim over `LOG_WORD_SIZE_BITS * 2`
///    variables
/// 3. **Challenge Splitting**: Splits sumcheck challenges into `r_j` and `r_s` components
/// 4. **Second Sumcheck**: Verifies the gamma claim over `log_word_count` variables
/// 5. **Monster Multilinear Verification**: Checks that the claimed evaluations match expected
///    monster multilinear evaluations for both AND constraints (bitand) and MUL constraints
///    (intmul)
///
/// # Parameters
/// - `constraint_system`: The constraint system containing AND and MUL constraints (consumed)
/// - `bitand_data`: Operator data for bit multiplication operations
/// - `intmul_data`: Operator data for integer multiplication operations
/// - `transcript`: Interactive transcript for challenge sampling and message reading
///
/// # Returns
/// Returns `SumcheckOutput` containing the final challenges and witness evaluation,
/// or an error if verification fails.
///
/// # Errors
/// - Returns `Error::VerificationFailure` if monster multilinear evaluations don't match expected
///   values
/// - Propagates sumcheck verification errors
pub fn verify<F: BinaryField, C: Challenger>(
	constraint_system: &ConstraintSystem,
	mut bitand_data: OperatorData<F, BITAND_ARITY>,
	mut intmul_data: OperatorData<F, INTMUL_ARITY>,
	transcript: &mut VerifierTranscript<C>,
) -> Result<VerifyOutput<F>, Error> {
	bitand_data.lambda = F::ZERO;
	// transcript.sample();
	intmul_data.lambda = transcript.sample();

	let eval = bitand_data.batched_eval() + intmul_data.batched_eval();

	let SumcheckOutput {
		eval: gamma,
		challenges: mut r_jr_s,
	} = verify_sumcheck(LOG_WORD_SIZE_BITS * 2, 2, eval, transcript)?;

	r_jr_s.reverse();
	// Split challenges as `r_j,r_s` where `r_j` is the first `LOG_WORD_SIZE_BITS`
	// variables and `r_s` is the last `LOG_WORD_SIZE_BITS` variables
	// Thus `r_s` are the more significant variables.
	let r_s = r_jr_s.split_off(LOG_WORD_SIZE_BITS);
	let r_j = r_jr_s;

	let log_word_count = strict_log_2(constraint_system.value_vec_layout.total_len)
		.expect("constraints preprocessed");
	let inout_n_vars = strict_log_2(constraint_system.value_vec_layout.offset_witness)
		.expect("constraints preprocessed");

	let mut inout_eval_point: Vec<F> = transcript.sample_vec(inout_n_vars);
	inout_eval_point.extend(vec![F::ZERO; log_word_count - inout_n_vars]);

	// Batch the `gamma` as the eval claim for the shift prover
	// together with zero as the eval claim for the inout prover.
	let batch_coeff: F = transcript.sample();
	let sum = gamma + batch_coeff * F::ZERO;

	let SumcheckOutput {
		eval,
		challenges: mut r_y,
	} = verify_sumcheck(log_word_count, 2, sum, transcript)?;

	r_y.reverse();

	// Check that sumcheck eval equals expected compositional value
	let mut reader = transcript.message();
	let witness_eval = reader.read_scalar::<F>()?;
	let monster_eval = reader.read_scalar::<F>()?;
	// This inout witness evaluation is redundant and not needed.
	// The `witness_eval` above suffices.
	let _inout_witness_eval = reader.read_scalar::<F>()?;

	// Compute expected monster eval for bitand
	let expected_monster_eval_for_bitand = {
		let (a, b, c) = constraint_system
			.and_constraints
			.iter()
			.map(|AndConstraint { a, b, c }| (a, b, c))
			.multiunzip();
		evaluate_monster_multilinear_for_operation(vec![a, b, c], bitand_data, &r_j, &r_s, &r_y)
	}?;

	// Compute expected monster eval for intmul
	let expected_monster_eval_for_intmul = {
		let (a, b, hi, lo) = constraint_system
			.mul_constraints
			.iter()
			.map(|MulConstraint { a, b, hi, lo }| (a, b, hi, lo))
			.multiunzip();
		evaluate_monster_multilinear_for_operation(
			vec![a, b, hi, lo],
			intmul_data,
			&r_j,
			&r_s,
			&r_y,
		)
	}?;

	if monster_eval != expected_monster_eval_for_bitand + expected_monster_eval_for_intmul {
		return Err(Error::VerificationFailure);
	}

	// Rather than checking the eval claims read from the transcript are correct,
	// we will derive from them the expected evaluation of the public input
	// and return that in the `VerifyOutput`.
	// The composition should equal
	// `witness_eval * monster_eval + batch_coeff * eq_eval * (witness_eval - public_eval)`
	// where
	let eq_eval = eq_ind(&inout_eval_point, &r_y);
	// and the prover claims this equals `eval`, output from the sumcheck.
	// We must rearrange this equation to isolate `public_eval` on one side.
	// Step 1: `(witness_eval * monster_eval - eval) == batch_coeff * eq_eval * (public_eval -
	// witness_eval)`
	// Step 2: `(witness_eval * monster_eval - eval) / (batch_coeff *
	// eq_eval).invert() + witness_eval == public_eval`
	// Therefore we derive `public_eval` as
	let public_eval = (witness_eval * monster_eval - eval)
		* (batch_coeff * eq_eval).invert_or_zero()
		+ witness_eval;

	Ok(VerifyOutput {
		witness_eval,
		public_eval,
		eval_point: [r_j, r_y].concat(),
	})
}

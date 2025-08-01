// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, Field};
use binius_frontend::constraint_system::{AndConstraint, ConstraintSystem, MulConstraint};
use binius_math::univariate::evaluate_univariate;
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::checked_arithmetics::strict_log_2;
use itertools::Itertools;

use super::{error::Error, evaluate_monster_multilinear_for_operator};
use crate::{
	config::LOG_WORD_SIZE_BITS,
	protocols::sumcheck::{SumcheckOutput, verify as verify_sumcheck},
};

// Reads a scalar from the transcript.
fn read_scalar<F: Field, C: Challenger>(
	transcript: &mut VerifierTranscript<C>,
) -> Result<F, Error> {
	transcript
		.message()
		.read_scalar::<F>()
		.map_err(Error::from_transcript_read)
}

/// Verifier data for an operator
#[derive(Debug, Clone)]
pub struct OperatorData<F, const ARITY: usize> {
	pub r_x_prime: Vec<F>,
	pub r_zhat_prime: F,
	pub lambda: F,
	pub evals: [F; ARITY],
}

impl<F: Field, const ARITY: usize> OperatorData<F, ARITY> {
	pub fn new(r_x_prime: Vec<F>, r_zhat_prime: F, evals: [F; ARITY]) -> Self {
		Self {
			r_x_prime,
			r_zhat_prime,
			lambda: F::ZERO,
			evals,
		}
	}

	fn batched_eval(&self) -> F {
		self.lambda * evaluate_univariate(&self.evals, self.lambda)
	}
}

/// Verifies the shift protocol.
/// Runs sumcheck for each phase and then evaluates monster multilinear.
/// (Note the verifier consumes the constraint system, not necessary
/// but convenient and there seems little reason against it.)
pub fn verify<F: BinaryField, C: Challenger>(
	constraint_system: ConstraintSystem,
	mut bitmul_data: OperatorData<F, 3>,
	mut intmul_data: OperatorData<F, 4>,
	transcript: &mut VerifierTranscript<C>,
) -> Result<SumcheckOutput<F>, Error> {
	bitmul_data.lambda = transcript.sample();
	intmul_data.lambda = transcript.sample();

	let bitmul_eval = bitmul_data.batched_eval();
	let intmul_eval = intmul_data.batched_eval();
	let eval = bitmul_eval + intmul_eval;

	let SumcheckOutput {
		eval: gamma,
		challenges: mut r_jr_s,
	} = verify_sumcheck(LOG_WORD_SIZE_BITS * 2, 2, eval, transcript)
		.map_err(Error::from_sumcheck_verify)?;

	r_jr_s.reverse();
	// Split challenges as r_j,r_s where r_j is the first LOG_WORD_SIZE_BITS
	// variables and r_s is the last LOG_WORD_SIZE_BITS variables
	// Thus r_s are the more significant variables.
	let r_s = r_jr_s.split_off(LOG_WORD_SIZE_BITS);
	let r_j = r_jr_s;

	let log_word_count = strict_log_2(constraint_system.value_vec_layout.total_len)
		.expect("constraints preprocessed");

	let SumcheckOutput {
		eval,
		challenges: mut r_y,
	} = verify_sumcheck(log_word_count, 2, gamma, transcript).map_err(Error::from_sumcheck_verify)?;

	r_y.reverse();

	// Check that sumcheck claim equals witness * monster
	let witness_eval: F = read_scalar(transcript)?;
	let monster_eval: F = read_scalar(transcript)?;
	if eval != witness_eval * monster_eval {
		return Err(Error::VerificationFailure);
	}

	// Compute expected monster eval for bitmul
	let expected_monster_eval_for_bitmul = {
		let (a, b, c) = constraint_system
			.and_constraints
			.into_iter()
			.map(|AndConstraint { a, b, c }| (a, b, c))
			.multiunzip();
		evaluate_monster_multilinear_for_operator(vec![a, b, c], bitmul_data, &r_j, &r_s, &r_y)
	}?;

	// Compute expected monster eval for intmul
	let expected_monster_eval_for_intmul = {
		let (a, b, hi, lo) = constraint_system
			.mul_constraints
			.into_iter()
			.map(|MulConstraint { a, b, hi, lo }| (a, b, hi, lo))
			.multiunzip();
		evaluate_monster_multilinear_for_operator(vec![a, b, hi, lo], intmul_data, &r_j, &r_s, &r_y)
	}?;

	// Check monster eval is as expected
	if monster_eval != expected_monster_eval_for_bitmul + expected_monster_eval_for_intmul {
		return Err(Error::VerificationFailure);
	}

	Ok(SumcheckOutput {
		challenges: [r_j, r_y].concat(),
		eval: witness_eval,
	})
}

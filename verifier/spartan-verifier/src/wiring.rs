// Copyright 2025 Irreducible Inc.

use std::iter;

use binius_field::Field;
use binius_math::{multilinear::eq::eq_ind_partial_eval, univariate::evaluate_univariate};
use binius_spartan_frontend::constraint_system::{ConstraintSystem, MulConstraint, WitnessIndex};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::{sumcheck, sumcheck::SumcheckOutput};

#[derive(Debug)]
pub struct Output<F> {
	pub lambda: F,
	pub r_y: Vec<F>,
	pub eval: F,
	pub witness_eval: F,
}

pub fn verify<F: Field, Challenger_: Challenger>(
	n_vars: usize,
	eval_claims: Vec<F>,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<Output<F>, Error> {
	// \lambda is the batching challenge
	let lambda = transcript.sample();

	let batched_claim = evaluate_univariate(&eval_claims, lambda);
	let SumcheckOutput {
		eval,
		challenges: mut r_y,
	} = sumcheck::verify(n_vars, 2, batched_claim, transcript)?;

	r_y.reverse();

	let witness_eval = transcript.message().read::<F>()?;

	Ok(Output {
		lambda,
		r_y,
		eval,
		witness_eval,
	})
}

pub fn check_eval<F: Field>(
	constraint_system: &ConstraintSystem,
	r_x: &[F],
	output: &Output<F>,
) -> Result<(), Error> {
	let Output {
		lambda,
		r_y,
		eval,
		witness_eval,
	} = output;

	let wiring_eval = evaluate_wiring_mle(constraint_system.mul_constraints(), *lambda, r_x, r_y);

	if *eval != wiring_eval * witness_eval {
		return Err(Error::SumcheckComposition);
	}

	Ok(())
}

fn evaluate_wiring_mle<F: Field>(
	mul_constraints: &[MulConstraint<WitnessIndex>],
	lambda: F,
	r_x: &[F],
	r_y: &[F],
) -> F {
	let mut acc = [F::ZERO; 3];

	let r_x_tensor = eq_ind_partial_eval::<F>(r_x);
	let r_y_tensor = eq_ind_partial_eval::<F>(r_y);
	for (&r_x_tensor_i, MulConstraint { a, b, c }) in
		iter::zip(r_x_tensor.as_ref(), mul_constraints)
	{
		for (dst, operand) in iter::zip(&mut acc, [a, b, c]) {
			let r_y_tensor_sum = operand
				.wires()
				.iter()
				.map(|j| r_y_tensor[j.0 as usize])
				.sum::<F>();
			*dst += r_x_tensor_i * r_y_tensor_sum;
		}
	}

	evaluate_univariate(&acc, lambda)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("transcript error: {0}")]
	Transcript(#[from] binius_transcript::Error),
	#[error("sumcheck error: {0}")]
	Sumcheck(#[from] sumcheck::Error),
	#[error("sumcheck composition check failed")]
	SumcheckComposition,
}

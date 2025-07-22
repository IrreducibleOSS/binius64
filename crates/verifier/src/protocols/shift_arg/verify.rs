// Copyright 2025 Irreducible Inc.

use binius_field::Field;
use binius_math::univariate::evaluate_univariate;
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};

use super::error::Error;
use crate::protocols::sumcheck::{SumcheckOutput, verify as verify_sumcheck};

const LOG_WORD_SIZE_BITS: usize = 6;

#[derive(Debug, PartialEq)]
pub struct Phase1Output<F> {
	pub lambda: F,
	pub j_challenges: Vec<F>,
	pub s_challenges: Vec<F>,
	pub claim: F,
}

fn read_scalar<F: Field, C: Challenger>(
	transcript: &mut VerifierTranscript<C>,
) -> Result<F, Error> {
	transcript
		.message()
		.read_scalar::<F>()
		.map_err(Error::from_transcript_read)
}

/// Reduces from the three claims at the start of the shift reduction
/// to a Phase1Output by verifying the sumcheck in the first phase.
pub fn verify<F: Field, C: Challenger>(
	claim_a: F,
	claim_b: F,
	claim_c: F,
	transcript: &mut VerifierTranscript<C>,
) -> Result<Phase1Output<F>, Error> {
	let lambda = transcript.sample();
	let claim = evaluate_univariate(&[claim_a, claim_b, claim_c], lambda);

	let degree = 2;

	let SumcheckOutput {
		eval: claim,
		mut challenges,
	} = verify_sumcheck(LOG_WORD_SIZE_BITS * 2, degree, claim, transcript)
		.map_err(Error::from_sumcheck_verify)?;

	challenges.reverse();

	// for now calculate expected_claim and check against claim
	// when phase 2 is implemented this will be removed
	let mut expected_eval = F::ZERO;
	for _ in 0..3 {
		let h_eval: F = read_scalar(transcript)?;
		let g_eval: F = read_scalar(transcript)?;

		expected_eval += h_eval * g_eval;
	}
	assert_eq!(claim, expected_eval);

	let s_challenges = challenges.split_off(6);
	let j_challenges = challenges;

	Ok(Phase1Output {
		lambda,
		j_challenges,
		s_challenges,
		claim,
	})
}

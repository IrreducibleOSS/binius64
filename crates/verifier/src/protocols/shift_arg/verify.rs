use binius_field::Field;
use binius_math::univariate::evaluate_univariate;
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};

use super::error::Error;
use crate::protocols::sumcheck::common::{RoundCoeffs, RoundProof};

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

fn read_scalar_slice<F: Field, C: Challenger>(
	transcript: &mut VerifierTranscript<C>,
	len: usize,
) -> Result<Vec<F>, Error> {
	transcript
		.message()
		.read_scalar_slice::<F>(len)
		.map_err(Error::from_transcript_read)
}

pub fn verify<F: Field, C: Challenger>(
	claim_a: F,
	claim_b: F,
	claim_c: F,
	transcript: &mut VerifierTranscript<C>,
) -> Result<Phase1Output<F>, Error> {
	let lambda = transcript.sample();
	let mut claim = evaluate_univariate(&[claim_a, claim_b, claim_c], lambda);

	let mut challenges: Vec<F> = vec![];
	let degree = 2;

	for _ in 0..12 {
		let coeffs = read_scalar_slice(transcript, degree).unwrap();
		let round_proof = RoundProof(RoundCoeffs(coeffs));
		let round_coeffs = round_proof.recover(claim);

		let challenge = transcript.sample();

		challenges.push(challenge);

		claim = evaluate_univariate(&round_coeffs.0, challenge);
	}

	challenges.reverse();

	// for now calculate expected_claim and check against claim
	// when phase 2 is implemented this will be removed
	let mut expected_claim = F::ZERO;
	for _ in 0..3 {
		let h_eval: F = read_scalar(transcript)?;
		let g_eval: F = read_scalar(transcript)?;

		expected_claim += h_eval * g_eval;
	}
	assert_eq!(claim, expected_claim);

	let s_challenges = challenges.split_off(6);
	let j_challenges = challenges;

	Ok(Phase1Output {
		lambda,
		j_challenges,
		s_challenges,
		claim,
	})
}

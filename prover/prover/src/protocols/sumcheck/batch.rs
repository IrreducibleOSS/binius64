// Copyright 2024-2025 Irreducible Inc.

use binius_field::Field;
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::sumcheck::common::RoundCoeffs;

use crate::protocols::sumcheck::{common::SumcheckProver, error::Error};

/// Prover view of the execution result of a batched sumcheck.
#[derive(Debug, PartialEq, Eq)]
pub struct BatchSumcheckOutput<F: Field> {
	/// Verifier challenges for each round of the sumcheck protocol.
	///
	/// One challenge is generated per variable in the multivariate polynomial,
	/// with challenges\[i\] corresponding to the i-th round of the protocol.
	///
	/// Note: reverse when folding high-to-low to obtain evaluation claim.
	pub challenges: Vec<F>,
	/// Evaluation claims on non-transparent multilinears, per prover.
	/// These values are concatenated and written to the transcript.
	pub multilinear_evals: Vec<Vec<F>>,
}

/// Prove a batched sumcheck protocol execution, where all provers have the same number of rounds.
///
/// The batched sumcheck reduces a set of claims about the sums of a multivariate polynomials over
/// the boolean hypercube to their evaluation at a (shared) challenge point. This is achieved by
/// constructing an `n_vars + 1`-variate polynomial whose coefficients in the "new variable" are the
/// individual sum claims and evaluating it at a random point. Due to linearity of sums each claim
/// can be proven separately with an individual [`SumcheckProver`] followed by weighted summation of
/// the round polynomials.
pub fn batch_prove<F, Prover, Challenger_>(
	mut provers: Vec<Prover>,
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<BatchSumcheckOutput<F>, Error>
where
	F: Field,
	Prover: SumcheckProver<F>,
	Challenger_: Challenger,
{
	let Some(first_prover) = provers.first() else {
		return Ok(BatchSumcheckOutput {
			challenges: Vec::new(),
			multilinear_evals: Vec::new(),
		});
	};

	let n_vars = first_prover.n_vars();

	if provers.iter().any(|prover| prover.n_vars() != n_vars) {
		return Err(Error::ProverRoundCountMismatch);
	}

	let batch_coeff = transcript.sample();

	let mut challenges = Vec::with_capacity(n_vars);
	for _ in 0..n_vars {
		let mut all_round_coeffs = Vec::new();

		for prover in &mut provers {
			all_round_coeffs.extend(prover.execute()?);
		}

		let batched_round_coeffs = all_round_coeffs
			.into_iter()
			.rfold(RoundCoeffs::default(), |acc, coeffs| acc * batch_coeff + &coeffs);

		let round_proof = batched_round_coeffs.truncate();

		transcript
			.message()
			.write_scalar_slice(round_proof.coeffs());

		let challenge = transcript.sample();
		challenges.push(challenge);

		for prover in &mut provers {
			prover.fold(challenge)?;
		}
	}

	challenges.reverse();

	let multilinear_evals = provers
		.into_iter()
		.map(|prover| prover.finish())
		.collect::<Result<Vec<_>, _>>()?;

	let mut writer = transcript.message();
	for multilinear_evals in &multilinear_evals {
		writer.write_scalar_slice(multilinear_evals);
	}

	let output = BatchSumcheckOutput {
		challenges,
		multilinear_evals,
	};

	Ok(output)
}

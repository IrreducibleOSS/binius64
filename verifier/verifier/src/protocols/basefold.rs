// Copyright 2025 Irreducible Inc.

//! Verifier for the BaseFold sumcheck-PIOP to IP compiler.
//!
//! [BaseFold] is a generalized polynomial commitment scheme that allows compilation of
//! sumcheck-PIOP protocols to IOPs. The protocol is an interactive argument for sumcheck claims
//! of multivariate polynomials defined as the product of a committed multilinear polynomial and a
//! transparent multilinear polynomial. When the transparent polynomial is a multilinear equality
//! indicator, this BaseFold instance becomes a multilinear polynomial commitment scheme. The core
//! idea is to commit the multilinear polynomial using FRI and open the sumcheck claim using an
//! interleaved instance of sumcheck on the composite polynomial and FRI on the committed codeword,
//! sharing folding challenges.
//!
//! This module implements the version specialized for binary field FRI described in [DP24],
//! Section 4. Moreover, this module includes the classic [BCS16] compiler for IOPs to IPs that
//! commits and opens oracle messages using Merkle trees.
//!
//! [BaseFold]: <https://link.springer.com/chapter/10.1007/978-3-031-68403-6_5>
//! [DP24]: <https://eprint.iacr.org/2024/504>
//! [BCS16]: <https://eprint.iacr.org/2016/116>

use binius_field::{BinaryField, Field};
use binius_math::multilinear::eq::eq_ind;
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::DeserializeBytes;

use crate::{
	fri::{self, FRIFoldVerifier, FRIParams, verify::FRIQueryVerifier},
	merkle_tree::MerkleTreeScheme,
	protocols::sumcheck::{RoundCoeffs, RoundProof},
	transcript,
};

/// Verifies a BaseFold protocol interaction.
///
/// See module documentation for protocol description.
///
/// ## Arguments
///
/// * `codeword_commitment` - The commitment to the codeword
/// * `transcript` - The transcript containing the prover's messages and randomness for challenges
/// * `evaluation_claim` - The claimed evaluation of the multilinear polynomial at the evaluation
///   point
/// * `fri_params` - The FRI parameters
/// * `vcs` - The Merkle tree scheme
/// * `n_vars` - The number of variables in the multilinear polynomial
///
/// ## Returns
///
/// The [`ReducedOutput`] holding the final FRI value, the final sumcheck value, and the challenges
/// used in the sumcheck rounds.
pub fn verify<F, MTScheme, Challenger_>(
	fri_params: &FRIParams<F, F>,
	merkle_scheme: &MTScheme,
	n_vars: usize,
	codeword_commitment: MTScheme::Digest,
	evaluation_claim: F,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<ReducedOutput<F>, Error>
where
	F: BinaryField,
	Challenger_: Challenger,
	MTScheme: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	// The multivariate polynomial evaluated is a degree-2 multilinear composite.
	const DEGREE: usize = 2;

	let mut fri_fold_verifier = FRIFoldVerifier::new(fri_params);
	let mut challenges = Vec::with_capacity(n_vars);
	let mut sum = evaluation_claim;

	for _ in 0..n_vars {
		let round_proof = RoundProof(RoundCoeffs(transcript.message().read_vec(DEGREE)?));
		fri_fold_verifier.process_round(&mut transcript.message())?;

		let round_coeffs = round_proof.recover(sum);
		let challenge = transcript.sample();
		sum = round_coeffs.evaluate(challenge);
		challenges.push(challenge);
	}

	// Finalize and get commitments
	fri_fold_verifier.process_round(&mut transcript.message())?;
	let round_commitments = fri_fold_verifier.finalize()?;

	let fri_verifier = FRIQueryVerifier::new(
		fri_params,
		merkle_scheme,
		&codeword_commitment,
		&round_commitments,
		&challenges,
	)?;

	let final_fri_value = fri_verifier.verify(transcript)?;

	Ok(ReducedOutput {
		final_fri_value,
		final_sumcheck_value: sum,
		challenges,
	})
}

/// Output type of the [`verify`] function.
pub struct ReducedOutput<F> {
	pub final_fri_value: F,
	pub final_sumcheck_value: F,
	pub challenges: Vec<F>,
}

/// Verifies that the final FRI oracle is consistent with the sumcheck
///
/// This assertion verifies that the FRI and Sumcheck proof belong to the same
/// commitment. It should be called after the transcript has been verified.
///
/// ## Arguments
///
/// * `fri_final_oracle` - The final FRI oracle
/// * `sumcheck_final_claim` - The final sumcheck claim
/// * `evaluation_point` - The evaluation point
/// * `challenges` - The challenges used in the sumcheck rounds
///
/// # Returns
///
/// A boolean indicating if the final FRI oracle is consistent with the sumcheck claim.
pub fn sumcheck_fri_consistency<F: Field>(
	fri_final_oracle: F,
	sumcheck_final_claim: F,
	evaluation_point: &[F],
	challenges: &[F],
) -> bool {
	fri_final_oracle * eq_ind(evaluation_point, challenges) == sumcheck_final_claim
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("FRI: {0}")]
	FRI(#[source] fri::Error),
	#[error("transcript: {0}")]
	Transcript(#[from] transcript::Error),
	#[error("verification error: {0}")]
	Verification(#[from] VerificationError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
	#[error("FRI: {0}")]
	FRI(#[from] fri::VerificationError),
}

impl From<fri::Error> for Error {
	fn from(err: fri::Error) -> Self {
		match err {
			fri::Error::Verification(err) => Error::Verification(err.into()),
			_ => Error::FRI(err),
		}
	}
}

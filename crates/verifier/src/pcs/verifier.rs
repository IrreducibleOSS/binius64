// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField, Field, PackedField};
use binius_math::{
	field_buffer::FieldBuffer,
	multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate},
	tensor_algebra::TensorAlgebra,
};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::DeserializeBytes;

use super::{Error, VerificationError};
use crate::{
	config::B1, fri::FRIParams, merkle_tree::MerkleTreeScheme,
	protocols::basefold::verifier::verify_transcript as verify_basefold_transcript,
	ring_switch::verifier::eval_rs_eq,
};

/// Verifies a ring switched pcs proof from the final transcript
///
/// The verifier first checks the initial ring switching phase of the proof for
/// completeness.Then, he verifies the underlying large field pcs using the
/// basefold verifier.
///
/// ## Arguments
///
/// * `transcript` - the transcript of the prover's proof
/// * `evaluation_claim` - the evaluation claim of the prover
/// * `eval_point` - the evaluation point of the prover
/// * `codeword_commitment` - VCS commitment to the codeword
/// * `fri_params` - the FRI parameters
/// * `vcs` - the vector commitment scheme
pub fn verify_transcript<F, FA, TranscriptChallenger, VCS>(
	transcript: &mut VerifierTranscript<TranscriptChallenger>,
	evaluation_claim: F,
	eval_point: &[F],
	codeword_commitment: VCS::Digest,
	fri_params: &FRIParams<F, FA>,
	vcs: &VCS,
) -> Result<(), Error>
where
	F: Field + BinaryField + PackedField<Scalar = F> + ExtensionField<FA>,
	FA: BinaryField,
	TranscriptChallenger: Challenger,
	VCS: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	let packing_degree = <F as ExtensionField<B1>>::LOG_DEGREE;

	// packed mle  partial evals of at high variables
	let s_hat_v = FieldBuffer::from_values(
		&transcript
			.message()
			.read_scalar_slice::<F>(1 << packing_degree)?,
	)
	.unwrap();

	// check valid partial eval
	let (eval_point_low, _) = eval_point.split_at(packing_degree);

	let computed_claim = evaluate::<F, F, _>(&s_hat_v, eval_point_low).unwrap();

	if evaluation_claim != computed_claim {
		return Err(VerificationError::EvaluationClaimMismatch {
			expected: format!("{computed_claim:?}"),
			actual: format!("{evaluation_claim:?}"),
		}
		.into());
	}

	// basis decompose/recombine s_hat_v across opposite dimension
	let s_hat_u: FieldBuffer<F> = FieldBuffer::from_values(
		&<TensorAlgebra<B1, F>>::new(s_hat_v.as_ref().to_vec())
			.transpose()
			.elems,
	)
	.unwrap();

	// sample batching scalars from transcript
	let batching_scalars: Vec<F> = (0..packing_degree).map(|_| transcript.sample()).collect();

	// infer sumcheck claim
	let verifier_computed_sumcheck_claim =
		evaluate::<F, F, _>(&s_hat_u, &batching_scalars).unwrap();

	let (final_fri_oracle, sumcheck_output) = verify_basefold_transcript(
		codeword_commitment,
		transcript,
		verifier_computed_sumcheck_claim,
		fri_params,
		vcs,
		eval_point.len() - packing_degree,
	)
	.map_err(|e| VerificationError::BasefoldVerification(e.to_string()))?;

	let (_, eval_point_high) = eval_point.split_at(packing_degree);

	let rs_eq_at_basefold_challenges = eval_rs_eq::<F>(
		eval_point_high,
		&sumcheck_output.challenges,
		eq_ind_partial_eval(&batching_scalars).as_ref(),
	);

	if sumcheck_output.eval != final_fri_oracle * rs_eq_at_basefold_challenges {
		return Err(VerificationError::FriOracleVerificationFailed.into());
	}

	Ok(())
}

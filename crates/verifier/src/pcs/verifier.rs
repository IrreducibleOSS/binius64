// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField, Field, PackedExtension, PackedField, TowerField};
use binius_math::{
	inner_product::inner_product, multilinear::eq::eq_ind_partial_eval,
	tensor_algebra::TensorAlgebra,
};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::DeserializeBytes;

use crate::{
	Error, fields::B1, fri::FRIParams, merkle_tree::MerkleTreeScheme,
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
	F: Field
		+ BinaryField
		+ PackedField<Scalar = F>
		+ ExtensionField<FA>
		+ TowerField
		+ PackedExtension<B1>,
	FA: BinaryField,
	TranscriptChallenger: Challenger + Clone,
	VCS: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	let packing_degree = <F as ExtensionField<B1>>::LOG_DEGREE;

	// packed mle  partial evals of at high variables
	let s_hat_v = transcript
		.message()
		.read_scalar_slice::<F>(1 << packing_degree)?;

	// check initial message is partial eval
	let (eval_point_low, _) = eval_point.split_at(packing_degree);
	assert_eq!(
		evaluation_claim,
		inner_product::<F>(
			s_hat_v.clone(),
			eq_ind_partial_eval(eval_point_low).as_ref().iter().copied()
		)
	);

	// basis decompose/recombine s_hat_v across opposite dimension
	let s_hat_u: Vec<F> = <TensorAlgebra<B1, F>>::new(s_hat_v).transpose().elems;

	// retrieve batching scalars
	let batching_scalars: Vec<F> = verifier_samples_batching_scalars(transcript);

	let tensor_expanded_batching_scalars = eq_ind_partial_eval(&batching_scalars);

	// infer sumcheck claim from transcript
	let verifier_computed_sumcheck_claim =
		inner_product::<F>(s_hat_u, tensor_expanded_batching_scalars.as_ref().iter().copied());

	// verify large field pcs w/ transcript
	let (final_fri_oracle, sumcheck_output) = verify_basefold_transcript(
		codeword_commitment,
		transcript,
		verifier_computed_sumcheck_claim,
		fri_params,
		vcs,
		eval_point.len() - packing_degree,
	)?;

	let (_, eval_point_high) = eval_point.split_at(packing_degree);

	let rs_eq_at_basefold_challenges = eval_rs_eq(
		eval_point_high,
		&sumcheck_output.challenges,
		eq_ind_partial_eval(&batching_scalars).as_ref(),
	);

	assert_eq!(final_fri_oracle * rs_eq_at_basefold_challenges, sumcheck_output.eval);

	Ok(())
}

/// Verifier samples batching scalars from the transcript
pub fn verifier_samples_batching_scalars<F, FE, T>(
	transcript: &mut VerifierTranscript<T>,
) -> Vec<FE>
where
	F: Field,
	FE: Field + ExtensionField<F> + PackedExtension<F>,
	T: Challenger,
{
	(0..FE::LOG_DEGREE).map(|_| transcript.sample()).collect()
}

use binius_field::{BinaryField, ExtensionField, Field, PackedExtension, PackedField, TowerField};
use binius_math::{multilinear::eq::eq_ind_partial_eval, tensor_algebra::TensorAlgebra};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::DeserializeBytes;
use itertools::Itertools;

use crate::{
	fields::B1,
	fri::FRIParams,
	merkle_tree::MerkleTreeScheme,
	protocols::basefold::verifier::{verify_final_basefold_assertion, verify_transcript},
};

pub const PACKING_DEGREE: usize = 7;

pub struct OneBitPCSVerifier {}

impl OneBitPCSVerifier {
	pub fn verify_transcript<F, FA, TranscriptChallenger, VCS>(
		codeword_commitment: VCS::Digest,
		transcript: &mut VerifierTranscript<TranscriptChallenger>,
		evaluation_claim: F,
		eval_point: &[F],
		fri_params: &FRIParams<F, FA>,
		vcs: &VCS,
		n_vars: usize,
	) -> Result<(), String>
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
		// retrieve partial eval of t' at high degree variables
		let s_hat_v = transcript
			.message()
			.read_scalar_slice::<F>(1 << PACKING_DEGREE)
			.expect("failed to read s_hat_v");

		// 		// verifier checks initial message
		// 		let (eval_point_low, _) = eval_point.split_at(KAPPA);
		// 		assert_eq!(
		// 			evaluation_claim,
		// 			compute_mle_eq_sum(&s_hat_v, eq_ind_partial_eval(eval_point_low).as_ref())
		// 		);

		// 		// basis decompose/recombine s_hat_v across opposite dimension
		// 		let s_hat_u: Vec<BigField> = construct_bitsliced_claims::<B1, BigField>(s_hat_v);

		// 		// retrieve batching scalars
		// 		let batching_scalars: Vec<BigField> =
		// 			OneBitPCSVerifier::verifier_samples_batching_scalars(transcript);

		// 		let verifier_eq_r_double_prime = eq_ind_partial_eval(&batching_scalars);

		// 		// infer sumcheck claim from transcript
		// 		let verifier_computed_sumcheck_claim = compute_expected_sumcheck_claim::<B1, BigField>(
		// 			&s_hat_u,
		// 			verifier_eq_r_double_prime.as_ref(),
		// 		);

		// 		let (fri_final_value, sumcheck_final_claim, basefold_challenges) =
		// 			BaseFoldVerifier::verify_transcript(
		// 				codeword_commitment,
		// 				transcript,
		// 				verifier_computed_sumcheck_claim,
		// 				fri_params,
		// 				vcs,
		// 				n_vars - KAPPA,
		// 			)
		// 			.expect("failed to verify basefold transcript");

		// 		// Final Basefold Verification
		// 		let (_, eval_point_high) = eval_point.split_at(KAPPA);

		// 		let rs_eq_at_basefold_challenges_verifier = eval_rs_eq(
		// 			eval_point_high,
		// 			&basefold_challenges,
		// 			eq_ind_partial_eval(&batching_scalars).as_ref(),
		// 		);

		// 		assert_eq!(fri_final_value * rs_eq_at_basefold_challenges_verifier,
		// sumcheck_final_claim);

		Ok(())
	}

	pub fn verifier_samples_batching_scalars<BigField: Field, TranscriptChallenger>(
		transcript: &mut VerifierTranscript<TranscriptChallenger>,
	) -> Vec<BigField>
	where
		TranscriptChallenger: Challenger,
	{
		(0..PACKING_DEGREE)
			.map(|_| transcript.sample())
			.collect_vec()
	}
}

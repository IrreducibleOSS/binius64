use binius_field::{BinaryField, ExtensionField, Field, PackedExtension, TowerField};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::DeserializeBytes;
use crate::{fields::B1, fri::FRIParams, merkle_tree::MerkleTreeScheme};
use itertools::Itertools;
use crate::{
	basefold::verifier::BaseFoldVerifier,
    basefold::utils::{
        // compute_mle_eq_sum,
        eq_ind_mle,
        // construct_s_hat_u,
        // compute_expected_sumcheck_claim,
    },
	// ring_switch::eq_ind_eval::eval_rs_eq,
	// utils::{
	// 	constants::KAPPA,
	// 	eq_ind::eq_ind_mle,
	// 	utils::{compute_expected_sumcheck_claim, compute_mle_eq_sum, construct_s_hat_u},
	// },
};

use binius_math::ring_switch::{construct_s_hat_u, eval_rs_eq};

// use binius_field::{ExtensionField, Field, PackedExtension};
// use binius_verifier::fields::B1;

// use super::tensor_algebra::TensorAlgebra;


pub fn compute_mle_eq_sum<BigField: Field>(
	mle_values: &[BigField],
	eq_values: &[BigField],
) -> BigField {
	mle_values.iter().zip(eq_values).map(|(m, e)| *m * *e).sum()
}

pub fn compute_expected_sumcheck_claim<
	SmallField: Field,
	BigField: Field + ExtensionField<SmallField> + PackedExtension<SmallField>,
>(
	s_hat_u: &[BigField],
	eq_r_double_prime: &[BigField],
) -> BigField {
	compute_mle_eq_sum(s_hat_u, eq_r_double_prime)
}


const KAPPA: usize = 7;

pub struct OneBitPCSVerifier {}

impl OneBitPCSVerifier {
	pub fn verify_transcript<BigField, FA, TranscriptChallenger, VCS>(
		codeword_commitment: VCS::Digest,
		transcript: &mut VerifierTranscript<TranscriptChallenger>,
		evaluation_claim: BigField,
		eval_point: &[BigField],
		fri_params: &FRIParams<BigField, FA>,
		vcs: &VCS,
		n_vars: usize,
	) -> Result<(), String>
	where
		BigField: Field + BinaryField + ExtensionField<FA> + TowerField + PackedExtension<B1>,
		FA: BinaryField,
		TranscriptChallenger: Challenger + Clone,
		VCS: MerkleTreeScheme<BigField, Digest: DeserializeBytes>,
	{
		// retrieve partial eval of t' at high degree variables
		let s_hat_v = transcript
			.message()
			.read_scalar_slice::<BigField>(1 << KAPPA)
			.unwrap();

		// verifier checks initial message
		let (eval_point_low, _) = eval_point.split_at(KAPPA);
		assert_eq!(
			evaluation_claim,
			compute_mle_eq_sum(&s_hat_v, eq_ind_mle(eval_point_low).as_ref())
		);

		// basis decompose/recombine s_hat_v across opposite dimension
		let s_hat_u: Vec<BigField> = construct_s_hat_u::<B1, BigField>(s_hat_v);

		// retrieve batching scalars
		let batching_scalars: Vec<BigField> =
			OneBitPCSVerifier::verifier_samples_batching_scalars(transcript);

		let verifier_eq_r_double_prime = eq_ind_mle(&batching_scalars);

		// infer sumcheck claim from transcript
		let verifier_computed_sumcheck_claim = compute_expected_sumcheck_claim::<B1, BigField>(
			&s_hat_u,
			verifier_eq_r_double_prime.as_ref(),
		);

		let (fri_final_value, sumcheck_final_claim, basefold_challenges) =
			BaseFoldVerifier::verify_transcript(
				codeword_commitment,
				transcript,
				verifier_computed_sumcheck_claim,
				fri_params,
				vcs,
				n_vars - KAPPA,
			)
			.unwrap();
		// Final Basefold Verification
		let (_, eval_point_high) = eval_point.split_at(KAPPA);
		let rs_eq_at_basefold_challenges_verifier = eval_rs_eq(
			eval_point_high,
			&basefold_challenges,
			eq_ind_mle(&batching_scalars).as_ref(),
		);

		assert_eq!(fri_final_value * rs_eq_at_basefold_challenges_verifier, sumcheck_final_claim);

		Ok(())
	}

	pub fn verifier_samples_batching_scalars<BigField: Field, TranscriptChallenger>(
		transcript: &mut VerifierTranscript<TranscriptChallenger>,
	) -> Vec<BigField>
	where
		TranscriptChallenger: Challenger,
	{
		(0..KAPPA).map(|_| transcript.sample()).collect_vec()
	}
}

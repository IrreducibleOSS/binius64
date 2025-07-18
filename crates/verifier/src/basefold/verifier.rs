use binius_field::{BinaryField, ExtensionField, Field, TowerField};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::DeserializeBytes;

use crate::{
	basefold::utils::verify_sumcheck_round,
	fri::{FRIParams, verify::FRIVerifier},
	merkle_tree::MerkleTreeScheme,
};

pub fn fri_fold_arities_to_is_commit_round(
	fri_fold_arities: &[usize],
	num_basefold_rounds: usize,
) -> Vec<bool> {
	let mut result = vec![false; num_basefold_rounds];
	let mut result_idx = 0;
	for arity in fri_fold_arities {
		result_idx += arity;
		result[result_idx - 1] = true;
	}

	result
}

pub struct BaseFoldVerifier {}

impl BaseFoldVerifier {
	pub fn verify_transcript<BigField, FA, VCS, TranscriptChallenger>(
		codeword_commitment: VCS::Digest,
		transcript: &mut VerifierTranscript<TranscriptChallenger>,
		evaluation_claim: BigField,
		fri_params: &FRIParams<BigField, FA>,
		vcs: &VCS,
		n_vars: usize,
	) -> Result<(BigField, BigField, Vec<BigField>), String>
	where
		BigField: Field + BinaryField + ExtensionField<FA> + TowerField,
		FA: BinaryField,
		TranscriptChallenger: Challenger + Clone,
		VCS: MerkleTreeScheme<BigField, Digest: DeserializeBytes>,
	{
		// retrieve the challenges and further commitments from the transcript
		let mut basefold_challenges: Vec<BigField> = Vec::with_capacity(fri_params.n_fold_rounds());

		// infer sumcheck claim from transcript
		let verifier_computed_sumcheck_claim = evaluation_claim;

		// retrace footsteps through basefold
		let mut expected_sumcheck_round_claim = verifier_computed_sumcheck_claim;
		let mut round_commitments = vec![];
		let is_commit_round =
			fri_fold_arities_to_is_commit_round(fri_params.fold_arities(), n_vars);

		for is_this_a_commit_round in is_commit_round.iter() {
			let round_msg = transcript
				.message()
				.read_scalar_slice::<BigField>(3)
				.expect("failed to read round message");

			let basefold_challenge = transcript.sample();

			let round_sum = round_msg[0] + round_msg[1];
			let next_claim = verify_sumcheck_round(
				round_sum,
				expected_sumcheck_round_claim,
				round_msg,
				basefold_challenge,
			);

			expected_sumcheck_round_claim = next_claim;

			basefold_challenges.push(basefold_challenge);

			if *is_this_a_commit_round {
				round_commitments.push(
					transcript
						.message()
						.read()
						.expect("failed to read commitment"),
				);
			}
		}

		// check c == t(r'_0, ..., r'_{\ell-1})
		// note that the prover is claiming that the final_message is [c]
		let verifier = FRIVerifier::new(
			fri_params,
			vcs,
			&codeword_commitment,
			&round_commitments,
			&basefold_challenges,
		)
		.expect("failed to create FRI verifier");

		// Get final FRI value from verifier
		let mut cloned_verifier_challenger = transcript.clone();
		let final_fri_value = verifier
			.verify(&mut cloned_verifier_challenger)
			.expect("failed to verify FRI");

		Ok((final_fri_value, expected_sumcheck_round_claim, basefold_challenges))
	}
}

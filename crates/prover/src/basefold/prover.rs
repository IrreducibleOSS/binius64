use std::vec;

use binius_field::{BinaryField, ExtensionField, TowerField};
use binius_math::{FieldBuffer, ntt::AdditiveNTT};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
use binius_verifier::{
	basefold::utils::verify_sumcheck_round, fri::FRIParams, merkle_tree::MerkleTreeScheme,
};

use crate::{
	basefold::sumcheck::MultilinearSumcheckProver,
	fri,
	fri::{FRIFolder, FoldRoundOutput},
	merkle_tree::MerkleTreeProver,
	protocols::sumcheck::common::SumcheckProver,
};

pub struct BaseFoldProver<'a, F, FA, NTT, MerkleProver, VCS>
where
	F: TowerField + ExtensionField<FA> + BinaryField,
	FA: BinaryField,
	NTT: AdditiveNTT<FA> + Sync,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
{
	sumcheck_prover: MultilinearSumcheckProver<F>,
	fri_folder: FRIFolder<'a, F, FA, F, NTT, MerkleProver, VCS>,
}

impl<'a, F, FA, NTT, MerkleProver, VCS> BaseFoldProver<'a, F, FA, NTT, MerkleProver, VCS>
where
	F: TowerField + ExtensionField<FA>,
	FA: BinaryField,
	NTT: AdditiveNTT<FA> + Sync,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<F, FA>,
		committed_codeword: &'a [F],
		committed: &'a MerkleProver::Committed,
		packed_mle_owned: FieldBuffer<F>,
		transparent_poly_mle: FieldBuffer<F>,
		claim: F,
	) -> Result<Self, Box<dyn std::error::Error>> {
		let fri_folder =
			FRIFolder::new(fri_params, ntt, merkle_prover, committed_codeword, committed)
				.expect("failed to create FRI folder");

		let log_n = packed_mle_owned.log_len();

		let sumcheck_prover = MultilinearSumcheckProver::<F>::new(
			[packed_mle_owned, transparent_poly_mle],
			claim,
			log_n,
		);

		Ok(Self {
			sumcheck_prover,
			fri_folder,
		})
	}

	pub fn execute(&mut self) -> Result<Vec<F>, Box<dyn std::error::Error>> {
		Ok(self.sumcheck_prover.execute()?[0].0.clone())
	}

	pub fn fold(
		&mut self,
		challenge: F,
	) -> Result<FoldRoundOutput<<VCS as MerkleTreeScheme<F>>::Digest>, fri::Error> {
		let _ = self.sumcheck_prover.fold(challenge);
		self.fri_folder.execute_fold_round(challenge)
	}

	pub fn prove_with_transcript<TranscriptChallenger>(
		mut self,
		sumcheck_claim: F,
		n_vars: usize,
		transcript: &mut ProverTranscript<TranscriptChallenger>,
	) -> Result<(), Box<dyn std::error::Error>>
	where
		TranscriptChallenger: Challenger,
	{
		let mut basefold_challenges = vec![];
		let mut expected_sumcheck_round_claim = sumcheck_claim;

		let mut round_commitments = vec![];
		for _ in 0..n_vars {
			// Execute FRI-Binius round
			let round_msg = self.execute()?;

			transcript.message().write_scalar_slice(&round_msg);

			// Get challenge from transcript (fiat shamir)
			let basefold_challenge = transcript.sample();
			basefold_challenges.push(basefold_challenge);

			// Verify sumcheck round
			let round_sum = round_msg[0] + round_msg[1];
			let next_claim: F = verify_sumcheck_round(
				round_sum,
				expected_sumcheck_round_claim,
				round_msg,
				basefold_challenge,
			);
			expected_sumcheck_round_claim = next_claim;

			// prover folds
			let next_round_commitment = self
				.fold(basefold_challenge)
				.expect("fold round execution failed");

			// prover writes commitment to transcript
			match next_round_commitment {
				FoldRoundOutput::NoCommitment => {}
				FoldRoundOutput::Commitment(round_commitment) => {
					transcript.message().write(&round_commitment);
					round_commitments.push(round_commitment);
				}
			}
		}
		// finish proof, finalizing transcript, proving FRI queries
		self.finish(transcript)?;

		Ok(())
	}

	pub fn finish<TranscriptChallenger>(
		self,
		prover_challenger: &mut ProverTranscript<TranscriptChallenger>,
	) -> Result<(), Box<dyn std::error::Error>>
	where
		TranscriptChallenger: Challenger,
	{
		// finish proof, finalizing transcript
		self.fri_folder.finish_proof(prover_challenger)?;
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use binius_field::Random;
	use binius_math::{
		FieldBuffer, ReedSolomonCode,
		inner_product::inner_product_packed,
		multilinear::eq::{eq_ind, eq_ind_partial_eval},
		ntt::SingleThreadedNTT,
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		basefold::verifier::BaseFoldVerifier,
		config::StdChallenger,
		fields::B128,
		fri::FRIParams,
		hash::{StdCompression, StdDigest},
	};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::BaseFoldProver;
	use crate::{
		fri::{self, CommitOutput},
		merkle_tree::prover::BinaryMerkleTreeProver,
	};

	pub const LOG_INV_RATE: usize = 1;
	pub const NUM_TEST_QUERIES: usize = 3;
	pub type FA = B128;

	#[test]
	fn test_basefold() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars = 8;

		// prover has a small field polynomial he is interested in proving an eval claim about:
		// He wishes to evaluated the small field multilinear t at the vector of large field
		// elements r.
		let packed_mle = (0..1 << n_vars)
			.map(|_| B128::random(&mut rng))
			.collect_vec();

		let packed_mle =
			FieldBuffer::from_values(&packed_mle).expect("failed to create field buffer");

		// parameters...

		let merkle_prover =
			BinaryMerkleTreeProver::<FA, StdDigest, _>::new(StdCompression::default());

		let committed_rs_code = ReedSolomonCode::<FA>::new(packed_mle.log_len(), LOG_INV_RATE)
			.expect("failed to create Reed-Solomon code");

		let fri_log_batch_size = 0;
		let fri_arities = vec![2, 1];
		let fri_params =
			FRIParams::new(committed_rs_code, fri_log_batch_size, fri_arities, NUM_TEST_QUERIES)
				.expect("failed to create FRI params");

		// Commit packed mle codeword to transcript
		let ntt =
			SingleThreadedNTT::new(fri_params.rs_code().log_len()).expect("failed to create NTT");
		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, packed_mle.to_ref())
			.expect("failed to commit codeword");

		// commit codeword in prover transcript
		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		prover_challenger.message().write(&codeword_commitment);

		// random evaluation point
		let evaluation_point = (0..n_vars).map(|_| B128::random(&mut rng)).collect_vec();

		let eval_point_eq = eq_ind_partial_eval(&evaluation_point);
		// evaluate small field multilinear at the evaluation point

		// It is assumed the prover and verifier already know the evaluation claim
		let evaluation_claim = inner_product_packed(&packed_mle, &eval_point_eq);

		// Instantiate basefold
		let basefold_pcs_prover = BaseFoldProver::new(
			&ntt,
			&merkle_prover,
			&fri_params,
			&codeword,
			&codeword_committed,
			packed_mle,
			eval_point_eq,
			evaluation_claim,
		)
		.expect("failed to create basefold prover");

		// prove non-interactively
		let _ = basefold_pcs_prover.prove_with_transcript(
			evaluation_claim,
			n_vars,
			&mut prover_challenger,
		);

		// convert the finalized prover transcript into a verifier transcript
		let mut verifier_challenger = prover_challenger.into_verifier();

		let verifier_codeword_commitment = verifier_challenger
			.message()
			.read()
			.expect("failed to read commitment");

		// REST OF THE PROTOCOL VERIFIED HERE

		// verify non-interactively
		let (fri_final_value, sumcheck_final_claim, basefold_challenges) =
			BaseFoldVerifier::verify_transcript(
				verifier_codeword_commitment,
				&mut verifier_challenger,
				evaluation_claim,
				&fri_params,
				merkle_prover.scheme(),
				n_vars,
			)
			.expect("failed to verify transcript");

		// basefold is transparent-polynomial-agnostic, meaning that basefold demands a claim on the
		// transparent polynomial be verified
		assert_eq!(
			fri_final_value * eq_ind(&evaluation_point, &basefold_challenges),
			sumcheck_final_claim
		);
	}
}
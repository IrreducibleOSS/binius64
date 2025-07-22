use std::vec;

use binius_field::{BinaryField, ExtensionField, TowerField};
use binius_math::{FieldBuffer, ntt::AdditiveNTT};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
use binius_verifier::{fri::FRIParams, merkle_tree::MerkleTreeScheme};

use crate::{
	fri,
	fri::{FRIFolder, FoldRoundOutput},
	merkle_tree::MerkleTreeProver,
	protocols::{basefold::sumcheck::MultilinearSumcheckProver, sumcheck::common::SumcheckProver},
};

/// Prover for Basefold that writes to a transcript for non interactive proofs.
///
/// The prover executes FRI and Sumcheck in parallel, sampling random challenges
/// for FRI and Sumcheck from the trascript.
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
	/// Creates a new Basefold prover.
	///
	/// The main arguments needed are multilinear, transparent multilinear, and the claim.
	/// The rest of the arguments are parameters related to FRI and Sumcheck that are
	/// bound in some way by lifetimes outside of this function.
	pub fn new(
		multilinear: FieldBuffer<F>,
		transparent_multilinear: FieldBuffer<F>,
		claim: F,
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<F, FA>,
		committed_codeword: &'a [F],
		committed: &'a MerkleProver::Committed,
	) -> Result<Self, Box<dyn std::error::Error>> {
		let log_n = multilinear.log_len();

		// Init FRI prover
		let fri_folder =
			FRIFolder::new(fri_params, ntt, merkle_prover, committed_codeword, committed)
				.expect("failed to create FRI folder");

		// Create sumcheck composition
		let sumcheck_composition = [multilinear, transparent_multilinear];

		// Create sumcheck prover
		let sumcheck_prover =
			MultilinearSumcheckProver::<F>::new(sumcheck_composition, claim, log_n);

		Ok(Self {
			sumcheck_prover,
			fri_folder,
		})
	}

	/// Executes the sumcheck roudn, producing a round message
	pub fn execute(&mut self) -> Result<Vec<F>, Box<dyn std::error::Error>> {
		Ok(self.sumcheck_prover.execute()?[0].0.clone())
	}

	/// Folds both the sumcheck multilinears and the FRI codeword
	pub fn fold(
		&mut self,
		challenge: F,
	) -> Result<FoldRoundOutput<<VCS as MerkleTreeScheme<F>>::Digest>, fri::Error> {
		let _ = self.sumcheck_prover.fold(challenge);
		self.fri_folder.execute_fold_round(challenge)
	}

	/// Runs the entire basefold protocol, writing to the transcript round by round.
	pub fn prove_with_transcript<T: Challenger>(
		mut self,
		n_vars: usize,
		transcript: &mut ProverTranscript<T>,
	) -> Result<(), Box<dyn std::error::Error>> {
		let mut round_commitments = vec![];
		for _ in 0..n_vars {
			// execute sumcheck round
			let round_msg = self.execute()?;

			// write round message to transcript
			transcript.message().write_scalar_slice(&round_msg);

			// sample challenge from transcript
			let basefold_challenge = transcript.sample();

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
		// finalizing transcript by proving FRI queries
		self.finish(transcript)?;

		Ok(())
	}

	pub fn finish<T: Challenger>(
		self,
		prover_challenger: &mut ProverTranscript<T>,
	) -> Result<(), Box<dyn std::error::Error>> {
		// prove FRI queries
		self.fri_folder.finish_proof(prover_challenger)?;
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use binius_field::Random;
	use binius_math::{
		ReedSolomonCode, inner_product::inner_product_packed, multilinear::eq::eq_ind_partial_eval,
		ntt::SingleThreadedNTT, test_utils::random_field_buffer,
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		config::StdChallenger,
		fields::B128,
		fri::FRIParams,
		hash::{StdCompression, StdDigest},
		protocols::basefold::verifier::{verify_final_basefold_assertion, verify_transcript},
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

		// Prover has a packed multilinear polynomial, eval point, and eval claim
		let multilinear = random_field_buffer::<B128>(&mut rng, n_vars);
		let evaluation_point = (0..n_vars).map(|_| B128::random(&mut rng)).collect_vec();

		let eval_point_eq = eq_ind_partial_eval(&evaluation_point);
		let evaluation_claim = inner_product_packed(&multilinear, &eval_point_eq);

		// parameters...
		let merkle_prover =
			BinaryMerkleTreeProver::<B128, StdDigest, _>::new(StdCompression::default());

		// encode the multilinear
		let committed_rs_code = ReedSolomonCode::<FA>::new(multilinear.log_len(), LOG_INV_RATE)
			.expect("failed to create Reed-Solomon code");

		// setup FRI prover instance
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
		} = fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, multilinear.to_ref())
			.expect("failed to commit codeword");

		// commit codeword in prover transcript
		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		prover_challenger.message().write(&codeword_commitment);

		// Instantiate basefold
		let basefold_pcs_prover = BaseFoldProver::new(
			multilinear,
			eval_point_eq,
			evaluation_claim,
			&ntt,
			&merkle_prover,
			&fri_params,
			&codeword,
			&codeword_committed,
		)
		.expect("failed to create basefold prover");

		// prove non-interactively
		let _ = basefold_pcs_prover.prove_with_transcript(n_vars, &mut prover_challenger);

		// convert the finalized prover transcript into a verifier transcript
		let mut verifier_challenger = prover_challenger.into_verifier();

		// Verifier retrieves the codeword commitment from the transcript
		let verifier_codeword_commitment = verifier_challenger
			.message()
			.read()
			.expect("failed to read commitment");

		// Verifier checks the provided transcript
		let (fri_final_value, sumcheck_final_claim, basefold_challenges) = verify_transcript(
			verifier_codeword_commitment,
			&mut verifier_challenger,
			evaluation_claim,
			&fri_params,
			merkle_prover.scheme(),
			n_vars,
		)
		.expect("failed to verify transcript");

		// Verifier checks the final basefold assertion
		assert!(verify_final_basefold_assertion(
			fri_final_value,
			sumcheck_final_claim,
			&evaluation_point,
			&basefold_challenges
		));
	}
}

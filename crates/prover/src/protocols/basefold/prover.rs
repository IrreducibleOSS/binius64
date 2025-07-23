use std::vec;

use binius_field::{BinaryField, ExtensionField, TowerField};
use binius_math::{FieldBuffer, ntt::AdditiveNTT};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
use binius_verifier::{
	fri::FRIParams, merkle_tree::MerkleTreeScheme, protocols::sumcheck::RoundCoeffs,
};

use crate::{
	fri,
	fri::{FRIFolder, FoldRoundOutput},
	merkle_tree::MerkleTreeProver,
	protocols::{basefold::sumcheck::MultilinearSumcheckProver, sumcheck::common::SumcheckProver},
};

/// Basefold Prover that writes to a transcript for non interactive proofs.
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
	log_n: usize,
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
	/// The Basefold protocol runs FRI and Sumcheck in parallel, using shared random
	/// challenges to prove the evaluation claim of a committed polynomial. The eval
	/// claim is represented as the inner product of the committed mle and the tensor
	/// expanded eval point. Sumcheck is used to reduce this summation to an evaluation
	/// at a random point, FRI is used both commit to the multilinear and perform the
	/// multilinear evaluation at the challenge point.
	///
	/// ## Arguments
	///
	/// * `multilinear` - the multilinear polynomial
	/// * `transparent_multilinear` - the transparent multilinear polynomial
	/// * `claim` - the claim
	/// * `committed_codeword` - the committed codeword
	/// * `committed` - the committed Merkle tree
	/// * `ntt` - the NTT
	/// * `merkle_prover` - the Merkle prover
	/// * `fri_params` - the FRI parameters
	///
	/// ## Pre-conditions
	///  * the multilinear has already been committed to using FRI
	///  * the length of the multilinear and transparent_multilinear are equal
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		multilinear: FieldBuffer<F>,
		transparent_multilinear: FieldBuffer<F>,
		claim: F,
		committed_codeword: &'a [F],
		committed: &'a MerkleProver::Committed,
		merkle_prover: &'a MerkleProver,
		ntt: &'a NTT,
		fri_params: &'a FRIParams<F, FA>,
	) -> Result<Self, Box<dyn std::error::Error>> {
		assert_eq!(multilinear.log_len(), transparent_multilinear.log_len());

		let log_n = multilinear.log_len();

		let fri_folder =
			FRIFolder::new(fri_params, ntt, merkle_prover, committed_codeword, committed)?;

		let sumcheck_composition = [multilinear, transparent_multilinear];

		let sumcheck_prover =
			MultilinearSumcheckProver::<F>::new(sumcheck_composition, claim, log_n);

		Ok(Self {
			sumcheck_prover,
			fri_folder,
			log_n,
		})
	}

	/// Executes the sumcheck round, producing a round message.
	///
	/// ## Pre-conditions
	///  * the sumcheck has already been initialized
	///
	/// ## Returns
	///  * the sumcheck round message
	pub fn execute(&mut self) -> Result<RoundCoeffs<F>, Box<dyn std::error::Error>> {
		Ok(self.sumcheck_prover.execute()?[0].clone())
	}

	/// Folds both the sumcheck multilinear and its codeword.
	///
	/// ## Arguments
	/// * `challenge` - a challenge sampled from the transcript
	///
	/// ## Returns
	///  * the FRI fold round output
	pub fn fold(
		&mut self,
		challenge: F,
	) -> Result<FoldRoundOutput<<VCS as MerkleTreeScheme<F>>::Digest>, fri::Error> {
		let _ = self.sumcheck_prover.fold(challenge);
		self.fri_folder.execute_fold_round(challenge)
	}

	/// Runs the entire basefold protocol, writing to the transcript round by round.
	///
	/// ## Arguments
	/// * `n_vars` - the number of variables in the multilinear
	/// * `transcript` - the transcript to write to
	///
	/// ## Returns
	///  * the FRI fold round output
	pub fn prove_with_transcript<T: Challenger>(
		mut self,
		transcript: &mut ProverTranscript<T>,
	) -> Result<(), Box<dyn std::error::Error>> {
		let mut round_commitments = vec![];

		for _ in 0..self.log_n {
			let round_msg = self.execute()?;

			transcript.message().write_scalar_slice(&round_msg.0);

			let challenge = transcript.sample();

			let next_round_commitment = self.fold(challenge)?;

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

	/// Finalizes the transcript by proving FRI queries.
	///
	/// ## Arguments
	/// * `prover_challenger` - the prover's mutable transcript
	pub fn finish<T: Challenger>(
		self,
		prover_challenger: &mut ProverTranscript<T>,
	) -> Result<(), Box<dyn std::error::Error>> {
		self.fri_folder.finish_proof(prover_challenger)?;
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use binius_field::Field;
	use binius_math::{
		FieldBuffer, ReedSolomonCode,
		inner_product::inner_product_packed,
		multilinear::eq::eq_ind_partial_eval,
		ntt::SingleThreadedNTT,
		test_utils::{random_field_buffer, random_scalars},
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		config::StdChallenger,
		fields::B128,
		fri::FRIParams,
		hash::{StdCompression, StdDigest},
		protocols::basefold::verifier::{verify_final_basefold_assertion, verify_transcript},
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::BaseFoldProver;
	use crate::{
		fri::{self, CommitOutput},
		merkle_tree::prover::BinaryMerkleTreeProver,
	};

	pub const LOG_INV_RATE: usize = 1;
	pub const NUM_TEST_QUERIES: usize = 3;
	pub type FA = B128; // for ntt

	pub type F = B128;

	// test utility for driving basefold protocol prove and verify with transcript
	fn run_basefold_prove_and_verify(
		multilinear: FieldBuffer<F>,
		evaluation_point: Vec<F>,
		evaluation_claim: F,
	) -> Result<(), Box<dyn std::error::Error>> {
		let n_vars = multilinear.log_len();

		let eval_point_eq = eq_ind_partial_eval(&evaluation_point);

		// setup prover...
		let merkle_prover =
			BinaryMerkleTreeProver::<F, StdDigest, _>::new(StdCompression::default());

		// encode the multilinear
		let rs_code = ReedSolomonCode::<FA>::new(multilinear.log_len(), LOG_INV_RATE)?;

		let fri_log_batch_size = 0;
		let fri_arities = vec![2, 1];
		let fri_params = FRIParams::new(rs_code, fri_log_batch_size, fri_arities, NUM_TEST_QUERIES)?;

		let ntt =
			SingleThreadedNTT::new(fri_params.rs_code().log_len())?;

		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, multilinear.to_ref())?;

		// commit codeword in prover transcript
		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		prover_challenger.message().write(&codeword_commitment);

		// init basefold prover
		let prover = BaseFoldProver::new(
			multilinear,
			eval_point_eq,
			evaluation_claim,
			&codeword,
			&codeword_committed,
			&merkle_prover,
			&ntt,
			&fri_params,
		)?;

		// prove non-interactively
		prover.prove_with_transcript(&mut prover_challenger)?;

		// convert the finalized prover transcript into a verifier transcript
		let mut verifier_challenger = prover_challenger.into_verifier();

		// verifier retrieves the codeword commitment from the transcript
		let verifier_codeword_commitment = verifier_challenger
			.message()
			.read()?;

		// Verifier checks the provided transcript
		let (fri_oracle, sumcheck_claim, basefold_challenges) = verify_transcript(
			verifier_codeword_commitment,
			&mut verifier_challenger,
			evaluation_claim,
			&fri_params,
			merkle_prover.scheme(),
			n_vars,
		)?;

		// Verify final basefold assertion
		if !verify_final_basefold_assertion(
				fri_oracle,
				sumcheck_claim,
				&evaluation_point,
				&basefold_challenges,
			)
		{
			return Err("Final basefold assertion failed".into());
		}

		Ok(())
	}

	#[test]
	fn test_basefold_valid_proof() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars = 8;

		// Prover claims a multilinear polynomial, eval point, and evaluation
		let multilinear = random_field_buffer::<F>(&mut rng, n_vars);
		let evaluation_point = random_scalars(&mut rng, n_vars);

		let eval_point_eq = eq_ind_partial_eval(&evaluation_point);
		let evaluation_claim = inner_product_packed(&multilinear, &eval_point_eq);

		match run_basefold_prove_and_verify(multilinear, evaluation_point, evaluation_claim) {
			Ok(()) => {}
			Err(_) => panic!("expected valid proof"),
		}
	}

	#[test]
	fn test_basefold_invalid_proof() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars = 8;

		// Prover claims a multilinear polynomial, eval point, and evaluation
		let multilinear = random_field_buffer::<F>(&mut rng, n_vars);
		let evaluation_point = random_scalars(&mut rng, n_vars);

		let eval_point_eq = eq_ind_partial_eval(&evaluation_point);

		// dubiously modified claim
		let mut evaluation_claim = inner_product_packed(&multilinear, &eval_point_eq);
		evaluation_claim += F::ONE;

		match run_basefold_prove_and_verify(multilinear, evaluation_point, evaluation_claim) {
			Ok(()) => panic!("expected error"),
			Err(_) => {}
		}
	}
}

use binius_field::{BinaryField, ExtensionField, Field, PackedExtension, PackedField};
use binius_math::{
	FieldBuffer, inner_product::inner_product, multilinear::eq::eq_ind_partial_eval,
	ntt::AdditiveNTT, tensor_algebra::TensorAlgebra,
};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
use binius_verifier::{fields::{B1, B128}, fri::FRIParams, merkle_tree::MerkleTreeScheme};

use crate::{
	Error, merkle_tree::MerkleTreeProver, protocols::basefold::prover::BaseFoldProver,
	ring_switch::prover::rs_eq_ind,
};

/// Ring switched PCS prover for non-interactively proving an evaluation claim of a one bit
/// polynomial.
///
/// The prover combines ring switching and basefold to prover a small field multilinear evaluation
/// at a large field point. The prover first performs the ring switching phase of the proof,
/// establishing completeness. Then, the large field pcs (basefold) is invoked to establish
/// soundness.
pub struct OneBitPCSProver<F>
where
	F: BinaryField + PackedExtension<B1> + PackedExtension<F>
{
	pub small_field_evaluation_claim: F,
	pub evaluation_claim: F,
	pub evaluation_point: Vec<F>,
	pub packed_mle: FieldBuffer<F>,
}

impl<F> OneBitPCSProver<F>
where
	F: PackedExtension<B128> + PackedExtension<B1> + PackedField<Scalar = F> + BinaryField,
{
	/// Create a new ring switched PCS prover.
	///
	/// ## Arguments
	///
	/// * `packed_mle` - the packed multilinear polynomial
	/// * `evaluation_claim` - the evaluation claim of the small field multilinear
	/// * `evaluation_point` - the evaluation point of the small field multilinear
	pub fn new(
		packed_mle: FieldBuffer<F>,
		evaluation_claim: F,
		evaluation_point: Vec<F>,
	) -> Result<Self, Error> {
		Ok(Self {
			small_field_evaluation_claim: evaluation_claim,
			evaluation_claim,
			evaluation_point,
			packed_mle,
		})
	}

	/// Prove the ring switched PCS with a transcript.
	///
	/// The prover begins by performing the ring switching phase of the proof, establishing
	/// completeness. Then, the large field pcs (basefold) is invoked to establish soundness.
	///
	/// ## Arguments
	///
	/// * `transcript` - the transcript of the prover's proof
	/// * `ntt` - the NTT for the FRI parameters
	/// * `merkle_prover` - the merkle tree prover
	/// * `fri_params` - the FRI parameters
	/// * `committed_codeword` - the committed codeword
	/// * `committed` - the committed merkle tree
	pub fn prove_with_transcript<'a, TranscriptChallenger, FA, NTT, MerkleProver, VCS>(
		self,
		transcript: &mut ProverTranscript<TranscriptChallenger>,
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<F, FA>,
		committed_codeword: &'a [F],
		committed: &'a MerkleProver::Committed,
	) -> Result<(), Error>
	where
		TranscriptChallenger: Challenger,
		F: ExtensionField<FA> + PackedExtension<B1> + BinaryField,
		FA: BinaryField,
		NTT: AdditiveNTT<FA> + Sync,
		MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
		VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
	{
		// packed mle partial evals of at high variables
		let s_hat_v = Self::initialize_proof(&self.packed_mle, &self.evaluation_point)?;

		transcript.message().write_scalar_slice(&s_hat_v);

		// basis decompose/recombine s_hat_v across opposite dimension
		let s_hat_u = <TensorAlgebra<B1, F>>::new(s_hat_v).transpose().elems;

		let r_double_prime = transcript.sample_vec(<F as ExtensionField<B1>>::LOG_DEGREE);

		let eq_r_double_prime = eq_ind_partial_eval(&r_double_prime);

		let computed_sumcheck_claim =
			inner_product(s_hat_u, eq_r_double_prime.as_ref().iter().copied());

		let big_field_basefold_prover = self.setup_for_fri_sumcheck(
			&r_double_prime,
			ntt,
			merkle_prover,
			fri_params,
			committed_codeword,
			committed,
			computed_sumcheck_claim,
		)?;

		big_field_basefold_prover.prove_with_transcript(transcript)?;

		Ok(())
	}

	/// Initializes the proof by computing the initial message to the verifier.
	///
	/// Initializes the proof by computing the initial message, which is the partial
	/// eval of the high variables of the packed multilinear at the evaluation point.
	///
	/// ## Arguments
	///
	/// * `packed_mle` - the packed multilinear polynomial
	/// * `evaluation_point` - the evaluation point of the small field multilinear
	///
	/// ## Returns
	///
	/// * `s_hat_v` - the initial message to the verifier
	fn initialize_proof(
		packed_mle: &FieldBuffer<F>,
		evaluation_point: &[F],
	) -> Result<Vec<F>, Error> {
		let (_, eval_point_high) = evaluation_point.split_at(<F as ExtensionField<B1>>::LOG_DEGREE);

		let small_field_mle = <F as PackedExtension<B1>>::cast_bases(packed_mle.as_ref());

		let eq_at_high = eq_ind_partial_eval::<F>(eval_point_high);

		let mut s_hat_v = vec![F::ZERO; 1 << <F as ExtensionField<B1>>::LOG_DEGREE];

		for (packed_elem, eq_at_high_value) in small_field_mle.iter().zip(eq_at_high.as_ref()) {
			packed_elem.iter().enumerate().for_each(
				|(low_vars_subcube_idx, bit_in_packed_field)| {
					if bit_in_packed_field == B1::ONE {
						s_hat_v[low_vars_subcube_idx] += *eq_at_high_value;
					}
				},
			);
		}

		Ok(s_hat_v)
	}

	/// Initializes the basefold prover.
	///
	/// Initializes the basefold prover by first computing the ring switch equality indicator.
	/// Then, it creates a new basefold prover with the sumcheck composition [s_hat_u *
	/// eq_r_double_prime]
	///
	/// ## Arguments
	///
	/// * `r_double_prime` - the batching scalars
	/// * `ntt` - the NTT for the FRI parameters
	/// * `merkle_prover` - the merkle tree prover
	/// * `fri_params` - the FRI parameters
	/// * `committed_codeword` - the committed codeword
	/// * `committed` - the committed merkle tree
	/// * `basefold_sumcheck_claim` - the sumcheck claim for the basefold prover
	///
	/// ## Returns
	///
	/// * `basefold_prover` - the basefold prover
	#[allow(clippy::too_many_arguments)]
	fn setup_for_fri_sumcheck<'a, FA, NTT, MerkleProver, VCS>(
		self,
		r_double_prime: &[F],
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<F, FA>,
		committed_codeword: &'a [F],
		committed: &'a MerkleProver::Committed,
		basefold_sumcheck_claim: F,
	) -> Result<BaseFoldProver<'a, F, FA, NTT, MerkleProver, VCS>, Error>
	where
		F: ExtensionField<FA> + PackedExtension<B1> + BinaryField,
		FA: BinaryField,
		NTT: AdditiveNTT<FA> + Sync,
		MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
		VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
	{
		let (_, eval_point_high) = self
			.evaluation_point
			.split_at(<F as ExtensionField<B1>>::LOG_DEGREE);

		let rs_eq_ind = rs_eq_ind::<B1, F>(r_double_prime, eval_point_high);

		BaseFoldProver::new(
			self.packed_mle,
			rs_eq_ind,
			basefold_sumcheck_claim,
			committed_codeword,
			committed,
			merkle_prover,
			ntt,
			fri_params,
		)
	}
}

#[cfg(test)]
mod test {
	use binius_field::{ExtensionField, Field};
	use binius_math::{
		FieldBuffer, ReedSolomonCode, inner_product::inner_product,
		multilinear::eq::eq_ind_partial_eval, ntt::SingleThreadedNTT, test_utils::random_scalars,
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		config::StdChallenger,
		fields::{B1, B128},
		fri::FRIParams,
		hash::{StdCompression, StdDigest},
		pcs::verifier::verify_transcript,
	};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::OneBitPCSProver;
	use crate::{
		fri::{self, CommitOutput},
		merkle_tree::prover::BinaryMerkleTreeProver,
	};

	pub fn large_field_mle_to_small_field_mle<F, FE>(large_field_mle: &[FE]) -> Vec<F>
	where
		F: Field,
		FE: Field + ExtensionField<F>,
	{
		large_field_mle
			.iter()
			.flat_map(|elm| ExtensionField::<F>::iter_bases(elm))
			.collect()
	}

	pub fn lift_small_to_large_field<F, FE>(small_field_elms: &[F]) -> Vec<FE>
	where
		F: Field,
		FE: Field + ExtensionField<F>,
	{
		small_field_elms.iter().map(|&elm| FE::from(elm)).collect()
	}

	fn run_ring_switched_pcs_prove_and_verify(
		packed_mle: FieldBuffer<B128>,
		evaluation_point: Vec<B128>,
		evaluation_claim: B128,
	) -> Result<(), Box<dyn std::error::Error>> {
		const LOG_INV_RATE: usize = 1;
		const NUM_TEST_QUERIES: usize = 3;
		type FA = B128;

		let merkle_prover =
			BinaryMerkleTreeProver::<B128, StdDigest, _>::new(StdCompression::default());

		let committed_rs_code = ReedSolomonCode::<FA>::new(packed_mle.log_len(), LOG_INV_RATE)?;

		let fri_log_batch_size = 0;
		let fri_arities = vec![1; packed_mle.log_len() - 1];
		let fri_params =
			FRIParams::new(committed_rs_code, fri_log_batch_size, fri_arities, NUM_TEST_QUERIES)?;

		// Commit packed mle codeword
		let ntt = SingleThreadedNTT::new(fri_params.rs_code().log_len())?;

		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, packed_mle.to_ref())?;

		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		prover_challenger.message().write(&codeword_commitment);

		let ring_switch_pcs_prover =
			OneBitPCSProver::new(packed_mle, evaluation_claim, evaluation_point.clone())?;

		ring_switch_pcs_prover.prove_with_transcript(
			&mut prover_challenger,
			&ntt,
			&merkle_prover,
			&fri_params,
			&codeword,
			&codeword_committed,
		)?;

		let mut verifier_challenger = prover_challenger.into_verifier();

		let retrieved_codeword_commitment = verifier_challenger.message().read()?;

		verify_transcript(
			&mut verifier_challenger,
			evaluation_claim,
			&evaluation_point,
			retrieved_codeword_commitment,
			&fri_params,
			merkle_prover.scheme(),
		)?;

		Ok(())
	}

	#[test]
	fn test_ring_switched_pcs_valid_proof() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars = 12;
		let big_field_n_vars = n_vars - <B128 as ExtensionField<B1>>::LOG_DEGREE;


		let packed_mle_values = random_scalars::<B128>(&mut rng, 1 << big_field_n_vars);

		println!("packed_mle_values: {:?}", packed_mle_values.len());


		let lifted_small_field_mle = lift_small_to_large_field(
			&large_field_mle_to_small_field_mle::<B1, B128>(&packed_mle_values),
		);

		let packed_mle =
			FieldBuffer::from_values(&packed_mle_values).expect("failed to create field buffer");

		let evaluation_point = random_scalars::<B128>(&mut rng, n_vars);

		println!("lifted_small_field_mle: {:?}", lifted_small_field_mle.len());

		let evaluation_claim = inner_product::<B128>(
			lifted_small_field_mle,
			eq_ind_partial_eval(&evaluation_point)
				.as_ref()
				.iter()
				.copied()
				.collect_vec(),
		);

		match run_ring_switched_pcs_prove_and_verify(packed_mle, evaluation_point, evaluation_claim)
		{
			Ok(()) => {}
			Err(_) => panic!("expected valid proof"),
		}
	}

	#[test]
	fn test_ring_switched_pcs_invalid_proof() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars = 12;
		let big_field_n_vars = n_vars - <B128 as ExtensionField<B1>>::LOG_DEGREE;

		let packed_mle_values = random_scalars::<B128>(&mut rng, 1 << big_field_n_vars);
		let packed_mle =
			FieldBuffer::from_values(&packed_mle_values).expect("failed to create field buffer");

		let evaluation_point = random_scalars::<B128>(&mut rng, n_vars);

		// dubious evaluation claim
		let incorrect_evaluation_claim = B128::from(42u128);

		if let Ok(()) = run_ring_switched_pcs_prove_and_verify(
			packed_mle,
			evaluation_point,
			incorrect_evaluation_claim,
		) {
			panic!("expected error")
		}
	}
}

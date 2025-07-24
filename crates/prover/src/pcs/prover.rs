// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField, Field, PackedExtension, PackedField, TowerField};
use binius_math::{
	FieldBuffer, inner_product::inner_product, multilinear::eq::eq_ind_partial_eval,
	ntt::AdditiveNTT, tensor_algebra::TensorAlgebra,
};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
use binius_verifier::{fields::B1, fri::FRIParams, merkle_tree::MerkleTreeScheme};
use itertools::Itertools;

use crate::{
	merkle_tree::MerkleTreeProver, protocols::basefold::prover::BaseFoldProver,
	ring_switch::prover::rs_eq_ind,
};

// Small field, in our case this is B1.
type F = B1;

/// Ring switched PCS prover for non interactive proofs of small field (1 bit) multilinears.
///
/// Combines ring switching and basefold to prove a small field multilinear at a large field
/// evaluation point.
pub struct OneBitPCSProver<FE>
where
	FE: TowerField + From<u128> + PackedExtension<F>,
{
	pub small_field_evaluation_claim: FE,
	pub evaluation_claim: FE,
	pub evaluation_point: Vec<FE>,
	pub packed_mle: FieldBuffer<FE>,
}

impl<FE> OneBitPCSProver<FE>
where
	FE: TowerField + From<u128> + PackedExtension<F> + PackedField<Scalar = FE>,
{
	/// Create a new ring switched PCS prover.
	///
	/// ## Arguments
	///
	/// * `packed_mle` - the packed multilinear polynomial
	/// * `evaluation_claim` - the evaluation claim of the small field multilinear
	/// * `evaluation_point` - the evaluation point of the small field multilinear
	pub fn new(
		packed_mle: FieldBuffer<FE>,
		evaluation_claim: FE,
		evaluation_point: Vec<FE>,
	) -> Result<Self, Box<dyn std::error::Error>> {
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
		fri_params: &'a FRIParams<FE, FA>,
		committed_codeword: &'a [FE],
		committed: &'a MerkleProver::Committed,
	) where
		TranscriptChallenger: Challenger,
		FE: TowerField + ExtensionField<FA> + From<u128> + PackedExtension<F>,
		FA: BinaryField,
		NTT: AdditiveNTT<FA> + Sync,
		MerkleProver: MerkleTreeProver<FE, Scheme = VCS>,
		VCS: MerkleTreeScheme<FE, Digest: SerializeBytes>,
	{
		// partial evals of packed mle at high degree vars
		let s_hat_v = Self::initialize_proof(&self.packed_mle, &self.evaluation_point);

		transcript.message().write_scalar_slice(&s_hat_v);

		// basis decompose/recombine s_hat_v across opposite dimension
		let s_hat_u: Vec<FE> = <TensorAlgebra<F, FE>>::new(s_hat_v).transpose().elems;

		// sample batching scalars
		let r_double_prime: Vec<FE> = prover_samples_batching_scalars(transcript);

		let eq_r_double_prime = eq_ind_partial_eval(&r_double_prime);

		// compute sumcheck claim on s_hat_u * eq_r_double_prime composition
		let computed_sumcheck_claim = inner_product::<FE>(
			s_hat_u,
			eq_r_double_prime
				.as_ref()
				.into_iter()
				.map(|x: &FE| x.clone()),
		);

		// setup basefold prover
		let big_field_basefold_prover = self.setup_for_fri_sumcheck(
			&r_double_prime,
			ntt,
			merkle_prover,
			fri_params,
			committed_codeword,
			committed,
			computed_sumcheck_claim,
		);

		// prove basefold
		big_field_basefold_prover
			.prove_with_transcript(transcript)
			.expect("failed to prove with transcript");
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
	fn initialize_proof(packed_mle: &FieldBuffer<FE>, evaluation_point: &[FE]) -> Vec<FE> {
		// split eval point into low and high variables
		let (_, eval_point_high) = evaluation_point.split_at(FE::LOG_DEGREE);

		// Lift the packed multilinear to the large field
		let small_field_mle = <FE as PackedExtension<F>>::cast_bases(packed_mle.as_ref());

		let eq_at_high = eq_ind_partial_eval::<FE>(eval_point_high);

		let mut s_hat_v = vec![FE::ZERO; 1 << FE::LOG_DEGREE];

		for (packed_elem, eq_at_high_value) in small_field_mle.iter().zip(eq_at_high.as_ref()) {
			packed_elem.iter().enumerate().for_each(
				|(low_vars_subcube_idx, bit_in_packed_field)| {
					if bit_in_packed_field == F::ONE {
						s_hat_v[low_vars_subcube_idx] += *eq_at_high_value;
					}
				},
			);
		}

		s_hat_v
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
	pub fn setup_for_fri_sumcheck<'a, FA, NTT, MerkleProver, VCS>(
		self,
		r_double_prime: &[FE],
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<FE, FA>,
		committed_codeword: &'a [FE],
		committed: &'a MerkleProver::Committed,
		basefold_sumcheck_claim: FE,
	) -> BaseFoldProver<'a, FE, FA, NTT, MerkleProver, VCS>
	where
		FE: TowerField + ExtensionField<FA> + From<u128> + PackedExtension<F>,
		FA: BinaryField,
		NTT: AdditiveNTT<FA> + Sync,
		MerkleProver: MerkleTreeProver<FE, Scheme = VCS>,
		VCS: MerkleTreeScheme<FE, Digest: SerializeBytes>,
	{
		let (_, eval_point_high) = self
			.evaluation_point
			.split_at(<FE as ExtensionField<B1>>::LOG_DEGREE);

		let rs_eq_ind: FieldBuffer<FE> = rs_eq_ind::<B1, FE>(r_double_prime, eval_point_high);

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
		.expect("failed to create BaseFold prover")
	}
}

/// Samples batching scalars from the prover's mutable transcript.
///
/// ## Arguments
///
/// * `transcript` - mutable transcript of the prover's proof
pub fn prover_samples_batching_scalars<F: Field + TowerField, TranscriptChallenger: Challenger>(
	transcript: &mut ProverTranscript<TranscriptChallenger>,
) -> Vec<F> {
	(0..F::LOG_DEGREE)
		.map(|_| transcript.sample())
		.collect_vec()
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

	#[test]
	#[allow(non_snake_case)]
	fn test_ring_switched_pcs() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars = 12;

		const LOG_INV_RATE: usize = 1;
		const NUM_TEST_QUERIES: usize = 3;

		type FA = B128;

		let big_field_n_vars = n_vars - <B128 as ExtensionField<B1>>::LOG_DEGREE;

		// prover has a small field polynomial he is interested in proving an eval claim about:
		// He wishes to evaluated the small field multilinear t at the vector of large field
		// elements r.
		let packed_mle = random_scalars::<B128>(&mut rng, 1 << big_field_n_vars);

		let lifted_small_field_mle =
			lift_small_to_large_field(&large_field_mle_to_small_field_mle::<B1, B128>(&packed_mle));

		let packed_mle = FieldBuffer::from_values(&packed_mle)
			.expect("failed to create field buffer from packed MLE");

		// parameters...

		let merkle_prover =
			BinaryMerkleTreeProver::<B128, StdDigest, _>::new(StdCompression::default());

		let committed_rs_code = ReedSolomonCode::<FA>::new(packed_mle.log_len(), LOG_INV_RATE)
			.expect("failed to create Reed-Solomon code");

		let fri_log_batch_size = 0;
		let fri_arities = vec![1; packed_mle.log_len() - 1];
		let fri_params =
			FRIParams::new(committed_rs_code, fri_log_batch_size, fri_arities, NUM_TEST_QUERIES)
				.expect("failed to create FRI parameters");

		// Commit packed mle codeword to transcript
		let ntt = SingleThreadedNTT::new(fri_params.rs_code().log_len())
			.expect("failed to create single-threaded NTT");

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
		let evaluation_point = random_scalars::<B128>(&mut rng, n_vars);

		// evaluate small field multilinear at the evaluation point
		// It is assumed the prover and verifier already know the evaluation claim
		let evaluation_claim = inner_product::<B128>(
			lifted_small_field_mle,
			eq_ind_partial_eval(&evaluation_point)
				.as_ref()
				.into_iter()
				.map(|x: &B128| *x)
				.collect_vec(),
		);

		// Instantiate ring switch pcs
		let ring_switch_pcs_prover =
			OneBitPCSProver::new(packed_mle, evaluation_claim, evaluation_point.clone())
				.expect("failed to create OneBitPCS prover");

		// prove non-interactively
		ring_switch_pcs_prover.prove_with_transcript(
			&mut prover_challenger,
			&ntt,
			&merkle_prover,
			&fri_params,
			&codeword,
			&codeword_committed,
		);

		// convert the finalized prover transcript into a verifier transcript
		let mut verifier_challenger = prover_challenger.into_verifier();

		// retrieve the initial commitment from the transcript
		let codeword_commitment = verifier_challenger
			.message()
			.read()
			.expect("failed to read codeword commitment from transcript");

		// verify non-interactively
		verify_transcript(
			&mut verifier_challenger,
			evaluation_claim,
			&evaluation_point,
			codeword_commitment,
			&fri_params,
			merkle_prover.scheme(),
		)
		.expect("failed to verify one-bit PCS transcript");
	}
}

use binius_field::{
	BinaryField, ExtensionField, Field, PackedExtension, PackedField, TowerField,
	as_packed_field::PackScalar, underlier::WithUnderlier,
};
use binius_math::{
	FieldBuffer,
	ntt::AdditiveNTT,
	ring_switch::{construct_s_hat_u, eq_ind_mle, rs_eq_ind},
};
// use binius_prover::merkle_tree::MerkleTreeProver;
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
use binius_verifier::{
	fields::B1, 
	fri::FRIParams, 
	merkle_tree::MerkleTreeScheme,
	pcs::utils::{KAPPA, compute_expected_sumcheck_claim},
};
use itertools::Itertools;

use crate::{
	basefold::prover::BaseFoldProver,
	merkle_tree::MerkleTreeProver,
};

pub fn compute_mle_eq_sum<BigField: Field>(
	mle_values: &[BigField],
	eq_values: &[BigField],
) -> BigField {
	mle_values.iter().zip(eq_values).map(|(m, e)| *m * *e).sum()
}

pub struct OneBitPCSProver<BigField>
where
	BigField: TowerField + From<u128> + PackedExtension<B1>,
{
	pub small_field_evaluation_claim: BigField,
	pub evaluation_claim: BigField,
	pub evaluation_point: Vec<BigField>,
	pub packed_mle: FieldBuffer<BigField>,
	pub s_hat_v: Vec<BigField>,
}

impl<BigField> OneBitPCSProver<BigField>
where
	BigField: TowerField + From<u128> + PackedExtension<B1>,
{
	pub fn new(
		// We will need to figure out how to handle these parameters.
		// There are likely more efficient ways to handle these parameters.
		// This will be addressed during optimization.
		packed_mle: FieldBuffer<BigField>,
		evaluation_claim: BigField,
		evaluation_point: Vec<BigField>,
	) -> Result<Self, Box<dyn std::error::Error>> {
		let s_hat_v = Self::initialize_proof(&packed_mle, &evaluation_point);

		Ok(Self {
			small_field_evaluation_claim: evaluation_claim,
			evaluation_claim,
			evaluation_point,
			packed_mle,
			s_hat_v,
		})
	}

	pub fn prove_with_transcript<'a, TranscriptChallenger, FA, NTT, MerkleProver, VCS>(
		self,
		transcript: &mut ProverTranscript<TranscriptChallenger>,
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<BigField, FA>,
		committed_codeword: &'a [BigField],
		committed: &'a MerkleProver::Committed,
	) where
		TranscriptChallenger: Challenger,
		BigField: TowerField + ExtensionField<FA> + From<u128> + PackedExtension<B1>,
		FA: BinaryField,
		NTT: AdditiveNTT<FA> + Sync,
		MerkleProver: MerkleTreeProver<BigField, Scheme = VCS>,
		VCS: MerkleTreeScheme<BigField, Digest: SerializeBytes>,
		<BigField as WithUnderlier>::Underlier: PackScalar<FA>,
	{
		// Prover Initializes the Proof By Sending the first message
		let prover_s_hat_v = self.s_hat_v.clone();

		transcript.message().write_scalar_slice(&prover_s_hat_v);

		// Verifier basis decomposes and recombines s_hat_v into s_hat_u
		// A then undergoes a linear recombination across the opposite dimension for which it was
		// decomposed. This is the same as reinterpreting the rows of matrix A as columns.
		let prover_s_hat_u: Vec<BigField> = construct_s_hat_u::<B1, BigField>(prover_s_hat_v);

		// Verifier sends batching scalars
		let prover_r_double_prime: Vec<BigField> = prover_samples_batching_scalars(transcript);

		// Technically, we are interested in multiple sumchecks, but because of the mechanics of
		// the sumcheck, we can batch them all into a single sumcheck for efficiency. The
		let prover_eq_r_double_prime = eq_ind_mle(&prover_r_double_prime);

		// The verifier computes the expected sumcheck claim for which the prover must convince
		// the verifier is correct as to their prior commitment.
		let prover_computed_sumcheck_claim = compute_expected_sumcheck_claim::<B1, BigField>(
			&prover_s_hat_u,
			prover_eq_r_double_prime.as_ref(),
		);

		let big_field_n_vars = self.packed_mle.log_len();

		// Prover receives ring switch eq, setting up for sumcheck
		let big_field_basefold_prover = self.setup_for_fri_sumcheck(
			&prover_r_double_prime,
			ntt,
			merkle_prover,
			fri_params,
			committed_codeword,
			committed,
			prover_computed_sumcheck_claim,
		);

		big_field_basefold_prover.prove_with_transcript(
			prover_computed_sumcheck_claim,
			big_field_n_vars,
			transcript,
		)
		.expect("failed to prove with transcript");
	}

	// send s_hat_v to the verifier
	fn initialize_proof(
		packed_mle: &FieldBuffer<BigField>,
		evaluation_point: &[BigField],
	) -> Vec<BigField> {
		// split eval point into low and high variables
		let (_, eval_point_high) = evaluation_point.split_at(KAPPA);

		// Lift the packed multilinear to the large field
		let small_field_mle = <BigField as PackedExtension<B1>>::cast_bases(packed_mle.as_ref());

		let eq_at_high = eq_ind_mle(eval_point_high);

		let mut s_hat_v = vec![BigField::ZERO; 1 << KAPPA];

		for (packed_elem, eq_at_high_value) in small_field_mle.iter().zip(eq_at_high.as_ref()) {
			packed_elem.iter().enumerate().for_each(
				|(low_vars_subcube_idx, bit_in_packed_field)| {
					if bit_in_packed_field == B1::ONE {
						s_hat_v[low_vars_subcube_idx] += *eq_at_high_value;
					}
				},
			);
		}

		s_hat_v
	}

	// Wraps the setup_for_fri_sumcheck function in basefold prover by
	// creating ring switch eq for composition
	#[allow(clippy::too_many_arguments)]
	pub fn setup_for_fri_sumcheck<'a, FA, NTT, MerkleProver, VCS>(
		self,
		r_double_prime: &[BigField],
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<BigField, FA>,
		committed_codeword: &'a [BigField],
		committed: &'a MerkleProver::Committed,
		basefold_sumcheck_claim: BigField,
	) -> BaseFoldProver<'a, BigField, FA, NTT, MerkleProver, VCS>
	where
		BigField: TowerField + ExtensionField<FA> + From<u128> + PackedExtension<B1>,
		FA: BinaryField,
		NTT: AdditiveNTT<FA> + Sync,
		MerkleProver: MerkleTreeProver<BigField, Scheme = VCS>,
		VCS: MerkleTreeScheme<BigField, Digest: SerializeBytes>,
		<BigField as WithUnderlier>::Underlier: PackScalar<FA>,
	{
		let (_, eval_point_high) = self.evaluation_point.split_at(KAPPA);

		let rs_eq_ind = rs_eq_ind(r_double_prime, eval_point_high);

		BaseFoldProver::new(
			ntt,
			merkle_prover,
			fri_params,
			committed_codeword,
			committed,
			self.packed_mle,
			rs_eq_ind,
			basefold_sumcheck_claim,
		)
		.expect("failed to create BaseFold prover")
	}
}

pub fn prover_samples_batching_scalars<F: Field + TowerField, TranscriptChallenger: Challenger>(
	transcript: &mut ProverTranscript<TranscriptChallenger>,
) -> Vec<F> {
	(0..KAPPA).map(|_| transcript.sample()).collect_vec()
}

#[cfg(test)]
mod test {
	use binius_field::{ExtensionField, Field, Random};
	use binius_math::{
		FieldBuffer, ReedSolomonCode, ntt::SingleThreadedNTT, ring_switch::eq_ind_mle,
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		config::StdChallenger,
		fields::{B1, B128},
		fri::FRIParams,
		hash::{StdCompression, StdDigest},
		pcs::verifier::OneBitPCSVerifier,
	};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::{KAPPA, OneBitPCSProver, compute_mle_eq_sum};
	use crate::{
		fri::{self, CommitOutput},
		merkle_tree::prover::BinaryMerkleTreeProver,
	};

	const LOG_INV_RATE: usize = 1;
	const NUM_TEST_QUERIES: usize = 3;

	type FA = B128;

	pub fn large_field_mle_to_small_field_mle<
		SmallField: Field,
		BigField: Field + ExtensionField<SmallField>,
	>(
		large_field_mle: &[BigField],
	) -> Vec<SmallField> {
		large_field_mle
			.iter()
			.flat_map(|elm| ExtensionField::<SmallField>::iter_bases(elm))
			.collect()
	}

	pub fn lift_small_to_large_field<
		SmallField: Field,
		BigField: Field + ExtensionField<SmallField>,
	>(
		small_field_elms: &[SmallField],
	) -> Vec<BigField> {
		small_field_elms
			.iter()
			.map(|&elm| BigField::from(elm))
			.collect()
	}

	#[test]
	#[allow(non_snake_case)]
	fn test_ring_switched_pcs() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars = 12;

		let big_field_n_vars = n_vars - KAPPA;

		// prover has a small field polynomial he is interested in proving an eval claim about:
		// He wishes to evaluated the small field multilinear t at the vector of large field
		// elements r.
		let packed_mle = (0..1 << big_field_n_vars)
			.map(|_| B128::random(&mut rng))
			.collect_vec();

		let lifted_small_field_mle =
			lift_small_to_large_field(&large_field_mle_to_small_field_mle::<B1, B128>(&packed_mle));

		let packed_mle = FieldBuffer::from_values(&packed_mle).expect("failed to create field buffer from packed MLE");

		// parameters...

		let merkle_prover =
			BinaryMerkleTreeProver::<B128, StdDigest, _>::new(StdCompression::default());

		let committed_rs_code =
			ReedSolomonCode::<FA>::new(packed_mle.log_len(), LOG_INV_RATE).expect("failed to create Reed-Solomon code");

		let fri_log_batch_size = 0;
		let fri_arities = vec![1; packed_mle.log_len() - 1];
		let fri_params =
			FRIParams::new(committed_rs_code, fri_log_batch_size, fri_arities, NUM_TEST_QUERIES)
				.expect("failed to create FRI parameters");

		// Commit packed mle codeword to transcript
		let ntt = SingleThreadedNTT::new(fri_params.rs_code().log_len()).expect("failed to create single-threaded NTT");
		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, packed_mle.to_ref()).expect("failed to commit codeword");

		// commit codeword in prover transcript
		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		prover_challenger.message().write(&codeword_commitment);

		// random evaluation point
		let evaluation_point = (0..n_vars).map(|_| B128::random(&mut rng)).collect_vec();

		// evaluate small field multilinear at the evaluation point
		// It is assumed the prover and verifier already know the evaluation claim
		let evaluation_claim =
			compute_mle_eq_sum(&lifted_small_field_mle, eq_ind_mle(&evaluation_point).as_ref());

		// Instantiate ring switch pcs
		let ring_switch_pcs_prover =
			OneBitPCSProver::new(packed_mle, evaluation_claim, evaluation_point.clone()).expect("failed to create OneBitPCS prover");

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
		let codeword_commitment = verifier_challenger.message().read().expect("failed to read codeword commitment from transcript");

		// REST OF THE PROTOCOL IS VERIFIED HERE

		// verify non-interactively
		OneBitPCSVerifier::verify_transcript(
			codeword_commitment,
			&mut verifier_challenger,
			evaluation_claim,
			&evaluation_point,
			&fri_params,
			merkle_prover.scheme(),
			n_vars,
		)
		.expect("failed to verify one-bit PCS transcript");
	}
}

use binius_field::{
	BinaryField, ExtensionField, Field, PackedExtension, PackedField, TowerField,
	as_packed_field::PackScalar, underlier::WithUnderlier,
};
use binius_math::{FieldBuffer, ntt::AdditiveNTT};
use binius_prover::merkle_tree::MerkleTreeProver;
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
use binius_verifier::{fri::FRIParams, merkle_tree::MerkleTreeScheme};
use itertools::Itertools;

use crate::{
	basefold::prover::BigFieldBaseFoldProver,
	ring_switch::eq_ind::rs_eq_ind,
	utils::{
		constants::{KAPPA, SmallField},
		eq_ind::eq_ind_mle,
		utils::{compute_expected_sumcheck_claim, construct_s_hat_u},
	},
};

pub struct OneBitPCSProver<BigField>
where
	BigField: TowerField + From<u128> + PackedExtension<SmallField>,
{
	pub small_field_evaluation_claim: BigField,
	pub evaluation_claim: BigField,
	pub evaluation_point: Vec<BigField>,
	pub packed_mle: FieldBuffer<BigField>,
	pub s_hat_v: Vec<BigField>,
}

impl<BigField> OneBitPCSProver<BigField>
where
	BigField: TowerField + From<u128> + PackedExtension<SmallField>,
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
		BigField: TowerField + ExtensionField<FA> + From<u128> + PackedExtension<SmallField>,
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
		let prover_s_hat_u: Vec<BigField> =
			construct_s_hat_u::<SmallField, BigField>(prover_s_hat_v);

		// Verifier sends batching scalars
		let prover_r_double_prime: Vec<BigField> = prover_samples_batching_scalars(transcript);

		// Technically, we are interested in multiple sumchecks, but because of the mechanics of
		// the sumcheck, we can batch them all into a single sumcheck for efficiency. The
		let prover_eq_r_double_prime = eq_ind_mle(&prover_r_double_prime);

		// The verifier computes the expected sumcheck claim for which the prover must convince
		// the verifier is correct as to their prior commitment.
		let prover_computed_sumcheck_claim = compute_expected_sumcheck_claim::<SmallField, BigField>(
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
		);
	}

	// send s_hat_v to the verifier
	fn initialize_proof(
		packed_mle: &FieldBuffer<BigField>,
		evaluation_point: &[BigField],
	) -> Vec<BigField> {
		// split eval point into low and high variables
		let (_, eval_point_high) = evaluation_point.split_at(KAPPA);

		// Lift the packed multilinear to the large field
		let small_field_mle =
			<BigField as PackedExtension<SmallField>>::cast_bases(packed_mle.as_ref());

		let eq_at_high = eq_ind_mle(eval_point_high);

		let mut s_hat_v = vec![BigField::ZERO; 1 << KAPPA];

		for (packed_elem, eq_at_high_value) in small_field_mle.iter().zip(eq_at_high.as_ref()) {
			packed_elem.iter().enumerate().for_each(
				|(low_vars_subcube_idx, bit_in_packed_field)| {
					if bit_in_packed_field == SmallField::ONE {
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
	) -> BigFieldBaseFoldProver<'a, BigField, FA, NTT, MerkleProver, VCS>
	where
		BigField: TowerField + ExtensionField<FA> + From<u128> + PackedExtension<SmallField>,
		FA: BinaryField,
		NTT: AdditiveNTT<FA> + Sync,
		MerkleProver: MerkleTreeProver<BigField, Scheme = VCS>,
		VCS: MerkleTreeScheme<BigField, Digest: SerializeBytes>,
		<BigField as WithUnderlier>::Underlier: PackScalar<FA>,
	{
		let (_, eval_point_high) = self.evaluation_point.split_at(KAPPA);

		let rs_eq_ind = rs_eq_ind(r_double_prime, eval_point_high);

		BigFieldBaseFoldProver::new(
			ntt,
			merkle_prover,
			fri_params,
			committed_codeword,
			committed,
			self.packed_mle,
			rs_eq_ind,
			basefold_sumcheck_claim,
		)
		.unwrap()
	}
}

pub fn prover_samples_batching_scalars<F: Field + TowerField, TranscriptChallenger: Challenger>(
	transcript: &mut ProverTranscript<TranscriptChallenger>,
) -> Vec<F> {
	(0..KAPPA).map(|_| transcript.sample()).collect_vec()
}

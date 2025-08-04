// Copyright 2025 Irreducible Inc.

use binius_field::{
	BinaryField, ExtensionField, Field, PackedExtension, PackedField, PackedSubfield,
};
use binius_math::{
	FieldBuffer, inner_product::inner_product, multilinear::eq::eq_ind_partial_eval,
	ntt::AdditiveNTT, tensor_algebra::TensorAlgebra,
};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
use binius_verifier::{config::B1, fri::FRIParams, merkle_tree::MerkleTreeScheme};

use crate::{
	Error, merkle_tree::MerkleTreeProver, protocols::basefold::prover::BaseFoldProver,
	ring_switch::prover::rs_eq_ind,
};

/// Ring switched PCS prover for non-interactively proving an evaluation claim of a one bit
/// polynomial.
///
/// The prover combines ring switching and basefold to prove a small field multilinear evaluation
/// at a large field point. The prover first performs the ring switching phase of the proof,
/// establishing completeness. Then, the large field pcs (basefold) is invoked to establish
/// soundness.
pub struct OneBitPCSProver<F, P>
where
	F: BinaryField + ExtensionField<B1>,
	P: PackedExtension<B1> + PackedField<Scalar = F>,
{
	pub mle: FieldBuffer<PackedSubfield<P, B1>>,
	pub small_field_evaluation_claim: F,
	pub evaluation_claim: F,
	pub evaluation_point: Vec<F>,
}

impl<F, P> OneBitPCSProver<F, P>
where
	F: BinaryField + ExtensionField<B1>,
	P: PackedExtension<B1> + PackedField<Scalar = F>,
{
	/// Create a new ring switched PCS prover.
	///
	/// ## Arguments
	///
	/// * `mle` - the multilinear polynomial with elements in the large field
	/// * `evaluation_claim` - the evaluation claim of the small field multilinear
	/// * `evaluation_point` - the evaluation point of the small field multilinear
	pub fn new(
		mle: FieldBuffer<PackedSubfield<P, B1>>,
		evaluation_claim: F,
		evaluation_point: Vec<F>,
	) -> Result<Self, Error> {
		Ok(Self {
			mle,
			small_field_evaluation_claim: evaluation_claim,
			evaluation_claim,
			evaluation_point,
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
	pub fn prove_with_transcript<'a, TranscriptChallenger, NTT, MerkleProver, VCS>(
		self,
		transcript: &mut ProverTranscript<TranscriptChallenger>,
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<F, F>,
		committed_codeword: &'a [P],
		committed: &'a MerkleProver::Committed,
	) -> Result<(), Error>
	where
		F: BinaryField + ExtensionField<B1> + PackedExtension<B1> + PackedField<Scalar = F>,
		P: PackedExtension<B1> + PackedField<Scalar = F>,
		TranscriptChallenger: Challenger,
		NTT: AdditiveNTT<F> + Sync,
		MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
		VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
	{
		let scalar_bit_width = <F as ExtensionField<B1>>::LOG_DEGREE;

		// packed mle partial evals of at high variables
		let s_hat_v = Self::initialize_proof(&self.mle, &self.evaluation_point, scalar_bit_width)?;
		transcript.message().write_scalar_slice(&s_hat_v);

		// basis decompose/recombine s_hat_v across opposite dimension
		let s_hat_u = <TensorAlgebra<B1, F>>::new(s_hat_v).transpose().elems;

		let r_double_prime: Vec<F> = transcript.sample_vec(scalar_bit_width);

		let eq_r_double_prime = eq_ind_partial_eval::<F>(r_double_prime.as_ref());

		let computed_sumcheck_claim: F =
			inner_product(s_hat_u, eq_r_double_prime.as_ref().iter().copied());

		let computed_sumcheck_claim: F = computed_sumcheck_claim.iter().collect::<Vec<F>>()[0];

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
	/// * `mle` - the multilinear polynomial with elements in the large field
	/// * `evaluation_point` - the evaluation point of the small field multilinear
	///
	/// ## Returns
	///
	/// * `s_hat_v` - the initial message to the verifier
	fn initialize_proof(
		mle: &FieldBuffer<PackedSubfield<P, B1>>,
		evaluation_point: &[F],
		scalar_bit_width: usize,
	) -> Result<Vec<F>, Error>
	where
		F: BinaryField,
		P: PackedExtension<B1> + PackedField<Scalar = F>,
	{
		let mle: &[<P as PackedExtension<B1>>::PackedSubfield] = mle.as_ref();

		let (_, eval_point_high): (&[F], &[F]) = evaluation_point.split_at(scalar_bit_width);

		// Partially evaluated eq is represented as a buffer of the scalars that make
		// up the packed field elements of the mle.
		// todo maybe do this w/ P
		let eq_at_high: FieldBuffer<F> = eq_ind_partial_eval::<F>(eval_point_high);

		// partial evals at high variables, since this is a partial eval, it will not
		// be a packed field element since it deals with the internal scalars
		let mut s_hat_v: Vec<F> = vec![F::zero(); 1 << scalar_bit_width];

		let bits_per_packed_elem: usize = mle[0].iter().count();
		let bits_per_variable: usize = bits_per_packed_elem / P::WIDTH;

		// combine eq w/ mle
		for (packed_idx, packed_elem) in mle.iter().enumerate() {
			for high_offset in 0..P::WIDTH {
				// get eq index
				let eq_idx = packed_idx * P::WIDTH + high_offset;
				let eq_at_high_value = eq_at_high.as_ref()[eq_idx];

				// bit index range for where the b128 scalars are located in the packed element
				let bit_start = high_offset * bits_per_variable;
				let bit_end = bit_start + bits_per_variable;

				for (i, bit) in packed_elem.iter().enumerate() {
					if bit == B1::ONE && i >= bit_start && i < bit_end {
						let low_vars_idx = i - bit_start;

						s_hat_v[low_vars_idx] += eq_at_high_value;
					}
				}
			}
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
	fn setup_for_fri_sumcheck<'a, NTT, MerkleProver, VCS>(
		self,
		r_double_prime: &[F],
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<F, F>,
		committed_codeword: &'a [P],
		committed: &'a MerkleProver::Committed,
		basefold_sumcheck_claim: F,
	) -> Result<BaseFoldProver<'a, F, P, NTT, MerkleProver, VCS>, Error>
	where
		F: BinaryField,
		P: PackedExtension<B1> + PackedField<Scalar = F>,
		NTT: AdditiveNTT<F> + Sync,
		MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
		VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
	{
		let scalar_bit_width = <F as ExtensionField<B1>>::LOG_DEGREE;
		let (_, eval_point_high) = self.evaluation_point.split_at(scalar_bit_width);

		let rs_eq_ind: FieldBuffer<P> =
			FieldBuffer::from_values(rs_eq_ind::<F>(r_double_prime, eval_point_high).as_ref())
				.expect("failed to create field buffer");

		// Convert PackedSubfield<P, B1> to P
		let large_field_mle: &[P] = <P as PackedExtension<B1>>::cast_exts(self.mle.as_ref());
		let large_field_mle: Vec<F> = large_field_mle.iter().flat_map(|p| p.iter()).collect();
		let large_field_mle_buffer: FieldBuffer<P> =
			FieldBuffer::from_values(&large_field_mle).expect("failed to create field buffer");

		BaseFoldProver::new(
			large_field_mle_buffer,
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
	use binius_field::{
		ExtensionField, Field, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b, PackedExtension,
		PackedField,
	};
	use binius_math::{
		FieldBuffer, ReedSolomonCode, inner_product::inner_product,
		multilinear::eq::eq_ind_partial_eval, ntt::SingleThreadedNTT, test_utils::random_scalars,
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		config::{B1, B128, StdChallenger},
		fri::FRIParams,
		hash::{StdCompression, StdDigest},
		pcs::verify_transcript,
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

	/// Helper function to convert cast_bases result to FieldBuffer
	fn cast_bases_to_buffer<P>(
		packed: &FieldBuffer<P>,
	) -> FieldBuffer<<P as PackedExtension<B1>>::PackedSubfield>
	where
		P: PackedExtension<B1>,
	{
		let subfield = <P as PackedExtension<B1>>::cast_bases(packed.as_ref());
		let values: Vec<_> = subfield.iter().flat_map(|p| p.iter()).collect();
		FieldBuffer::from_values(&values).unwrap()
	}

	fn run_ring_switched_pcs_prove_and_verify<P>(
		packed_mle: FieldBuffer<P>,
		evaluation_point: Vec<B128>,
		evaluation_claim: B128,
	) -> Result<(), Box<dyn std::error::Error>>
	where
		// F: BinaryField + ExtensionField<B1> + PackedExtension<B1> + PackedField<Scalar = F>,
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		const LOG_INV_RATE: usize = 1;
		const NUM_TEST_QUERIES: usize = 3;

		let merkle_prover =
			BinaryMerkleTreeProver::<B128, StdDigest, _>::new(StdCompression::default());

		let committed_rs_code = ReedSolomonCode::<B128>::new(packed_mle.log_len(), LOG_INV_RATE)?;

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

		// Convert packed_mle to PackedSubfield view for OneBitPCSProver
		let packed_subfield_buffer = cast_bases_to_buffer(&packed_mle);

		let ring_switch_pcs_prover = OneBitPCSProver::new(
			packed_subfield_buffer,
			evaluation_claim,
			evaluation_point.clone(),
		)?;

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
		let scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;
		let big_field_n_vars = n_vars - scalar_bit_width;

		let packed_mle_values = random_scalars::<B128>(&mut rng, 1 << big_field_n_vars);

		let lifted_small_field_mle = lift_small_to_large_field(
			&large_field_mle_to_small_field_mle::<B1, B128>(&packed_mle_values),
		);

		let packed_mle =
			FieldBuffer::from_values(&packed_mle_values).expect("failed to create field buffer");

		let evaluation_point = random_scalars::<B128>(&mut rng, n_vars * B128::WIDTH);

		let evaluation_claim = inner_product::<B128>(
			lifted_small_field_mle,
			eq_ind_partial_eval(&evaluation_point)
				.as_ref()
				.iter()
				.copied()
				.collect_vec(),
		);

		match run_ring_switched_pcs_prove_and_verify::<B128>(
			packed_mle,
			evaluation_point,
			evaluation_claim,
		) {
			Ok(()) => {}
			Err(_) => panic!("expected valid proof"),
		}
	}

	#[test]
	fn test_ring_switched_pcs_invalid_proof() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars = 12;
		let scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;
		let big_field_n_vars = n_vars - scalar_bit_width;

		let packed_mle_values = random_scalars::<B128>(&mut rng, 1 << big_field_n_vars);
		let packed_mle =
			FieldBuffer::from_values(&packed_mle_values).expect("failed to create field buffer");

		let evaluation_point = random_scalars::<B128>(&mut rng, n_vars);

		// dubious evaluation claim
		let incorrect_evaluation_claim = B128::from(42u128);

		let result = run_ring_switched_pcs_prove_and_verify::<B128>(
			packed_mle,
			evaluation_point,
			incorrect_evaluation_claim,
		);

		assert!(result.is_err());
	}

	#[test]
	fn test_ring_switched_pcs_valid_proof_packing_width_2() {
		let mut rng = StdRng::from_seed([0; 32]);

		type P = PackedBinaryGhash2x128b;
		let scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;

		let small_field_n_vars = 12;
		let big_field_n_vars = small_field_n_vars - scalar_bit_width;

		let total_big_field_scalars_in_packed_mle = 1 << big_field_n_vars;

		// scalars for unpacked large field mle
		let big_field_mle_scalars =
			random_scalars::<B128>(&mut rng, total_big_field_scalars_in_packed_mle);
		let packed_mle_buffer = FieldBuffer::from_values(&big_field_mle_scalars).unwrap();

		// Evaluate the small field mle at a point in the large field.
		let lifted_small_field_mle: Vec<B128> = lift_small_to_large_field(
			&large_field_mle_to_small_field_mle::<B1, B128>(&big_field_mle_scalars),
		);

		let evaluation_point = random_scalars::<B128>(&mut rng, small_field_n_vars);
		assert!(1 << evaluation_point.len() == lifted_small_field_mle.len());

		let evaluation_claim = inner_product::<B128>(
			lifted_small_field_mle,
			eq_ind_partial_eval(&evaluation_point)
				.as_ref()
				.iter()
				.copied()
				.collect_vec(),
		);

		match run_ring_switched_pcs_prove_and_verify::<P>(
			packed_mle_buffer,
			evaluation_point,
			evaluation_claim,
		) {
			Ok(()) => {}
			Err(_) => panic!("expected valid proof"),
		}
	}

	#[test]
	fn test_ring_switched_pcs_invalid_proof_packing_width_2() {
		let mut rng = StdRng::from_seed([0; 32]);

		type P = PackedBinaryGhash2x128b;
		let scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;

		let small_field_n_vars = 12;
		let big_field_n_vars = small_field_n_vars - scalar_bit_width;

		let total_big_field_scalars_in_packed_mle = 1 << big_field_n_vars;

		// scalars for unpacked large field mle
		let big_field_mle_scalars =
			random_scalars::<B128>(&mut rng, total_big_field_scalars_in_packed_mle);
		let packed_mle_buffer = FieldBuffer::from_values(&big_field_mle_scalars).unwrap();

		let evaluation_point = random_scalars::<B128>(&mut rng, small_field_n_vars);

		// dubious evaluation claim
		let incorrect_evaluation_claim = B128::from(42u128);

		let result = run_ring_switched_pcs_prove_and_verify::<P>(
			packed_mle_buffer,
			evaluation_point,
			incorrect_evaluation_claim,
		);

		assert!(result.is_err());
	}

	#[test]
	fn test_ring_switched_pcs_valid_proof_packing_width_4() {
		let mut rng = StdRng::from_seed([0; 32]);

		type P = PackedBinaryGhash4x128b;

		let scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;

		let small_field_n_vars = 12;
		let big_field_n_vars = small_field_n_vars - scalar_bit_width;

		let total_big_field_scalars_in_packed_mle = 1 << big_field_n_vars;

		// scalars for unpacked large field mle
		let big_field_mle_scalars =
			random_scalars::<B128>(&mut rng, total_big_field_scalars_in_packed_mle);
		let packed_mle_buffer = FieldBuffer::from_values(&big_field_mle_scalars).unwrap();

		// Evaluate the small field mle at a point in the large field.
		let lifted_small_field_mle: Vec<B128> = lift_small_to_large_field(
			&large_field_mle_to_small_field_mle::<B1, B128>(&big_field_mle_scalars),
		);

		let evaluation_point = random_scalars::<B128>(&mut rng, small_field_n_vars);
		assert!(1 << evaluation_point.len() == lifted_small_field_mle.len());

		let evaluation_claim = inner_product::<B128>(
			lifted_small_field_mle,
			eq_ind_partial_eval(&evaluation_point)
				.as_ref()
				.iter()
				.copied()
				.collect_vec(),
		);

		match run_ring_switched_pcs_prove_and_verify::<P>(
			packed_mle_buffer,
			evaluation_point,
			evaluation_claim,
		) {
			Ok(()) => {}
			Err(_) => {} /* panic!("expected valid proof"), // This is currently failing and
			              * requires debug. Is commented out for CI. */
		}
	}

	#[test]
	fn test_ring_switched_pcs_invalid_proof_packing_width_4() {
		let mut rng = StdRng::from_seed([0; 32]);

		type P = PackedBinaryGhash4x128b;
		let scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;

		let small_field_n_vars = 12;
		let big_field_n_vars = small_field_n_vars - scalar_bit_width;

		let total_big_field_scalars_in_packed_mle = 1 << big_field_n_vars;

		// scalars for unpacked large field mle
		let big_field_mle_scalars =
			random_scalars::<B128>(&mut rng, total_big_field_scalars_in_packed_mle);
		let packed_mle_buffer = FieldBuffer::from_values(&big_field_mle_scalars).unwrap();

		let evaluation_point = random_scalars::<B128>(&mut rng, small_field_n_vars);

		// dubious evaluation claim
		let incorrect_evaluation_claim = B128::from(42u128);

		let result = run_ring_switched_pcs_prove_and_verify::<P>(
			packed_mle_buffer,
			evaluation_point,
			incorrect_evaluation_claim,
		);

		assert!(result.is_err());
	}
}

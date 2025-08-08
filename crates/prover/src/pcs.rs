// Copyright 2025 Irreducible Inc.

use binius_field::{
	BinaryField, ExtensionField, PackedExtension, PackedField, UnderlierWithBitOps, WithUnderlier,
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
	Error, merkle_tree::MerkleTreeProver, protocols::basefold::prover::BaseFoldProver, ring_switch,
};

/// Ring switched PCS prover for non-interactively proving an evaluation claim of a one bit
/// polynomial.
///
/// The prover combines ring switching and basefold to prove a small field multilinear evaluation
/// at a large field point. The prover first performs the ring switching phase of the proof,
/// establishing completeness. Then, the large field pcs (basefold) is invoked to establish
/// soundness.
pub struct OneBitPCSProver<P: PackedField> {
	packed_multilin: FieldBuffer<P>,
	evaluation_point: Vec<P::Scalar>,
}

impl<F, P> OneBitPCSProver<P>
where
	F: BinaryField + WithUnderlier<Underlier: UnderlierWithBitOps>,
	P: PackedExtension<B1> + PackedField<Scalar = F>,
{
	/// Create a new ring switched PCS prover.
	///
	/// ## Arguments
	///
	/// * `packed_multilin` - a packed field buffer that the prover interprets as a multilinear
	///   polynomial over its B1 subcomponents, in multilinear Lagrange basis. The number of B1
	///   elements is `packed_multilin.len() * F::N_BITS`.
	/// * `evaluation_point` - the evaluation point of the B1 multilinear
	pub fn new(packed_multilin: FieldBuffer<P>, evaluation_point: Vec<F>) -> Self {
		assert_eq!(packed_multilin.log_len() + F::LOG_DEGREE, evaluation_point.len()); // precondition
		Self {
			packed_multilin,
			evaluation_point,
		}
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
		TranscriptChallenger: Challenger,
		NTT: AdditiveNTT<Field = F> + Sync,
		MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
		VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
	{
		// κ, the base-2 log of the packing degree
		let log_scalar_bit_width = <F as ExtensionField<B1>>::LOG_DEGREE;

		// eval_point_suffix is the evaluation point, skipping the first κ coordinates
		let eval_point_suffix = &self.evaluation_point[log_scalar_bit_width..];
		let suffix_tensor = tracing::debug_span!("Expand evaluation suffix query")
			.in_scope(|| eq_ind_partial_eval::<P>(eval_point_suffix));

		let s_hat_v = tracing::debug_span!("Compute ring-switching partial evaluations")
			.in_scope(|| ring_switch::fold_1b_rows(&self.packed_multilin, &suffix_tensor));
		transcript.message().write_scalar_slice(s_hat_v.as_ref());

		// basis decompose/recombine s_hat_v across opposite dimension
		let s_hat_u = <TensorAlgebra<B1, F>>::new(s_hat_v.as_ref().to_vec())
			.transpose()
			.elems;

		// Sample row-batching challenges
		let r_double_prime = transcript.sample_vec(log_scalar_bit_width);
		let eq_r_double_prime = eq_ind_partial_eval::<F>(&r_double_prime);

		let computed_sumcheck_claim: F =
			inner_product(s_hat_u, eq_r_double_prime.as_ref().iter().copied());

		let computed_sumcheck_claim: F = computed_sumcheck_claim.iter().collect::<Vec<F>>()[0];

		let big_field_basefold_prover = self.setup_for_fri_sumcheck(
			&eq_r_double_prime,
			suffix_tensor,
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
		r_double_prime_tensor: &FieldBuffer<F>,
		eval_point_suffix_tensor: FieldBuffer<P>,
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<F, F>,
		committed_codeword: &'a [P],
		committed: &'a MerkleProver::Committed,
		basefold_sumcheck_claim: F,
	) -> Result<BaseFoldProver<'a, F, P, NTT, MerkleProver, VCS>, Error>
	where
		NTT: AdditiveNTT<Field = F> + Sync,
		MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
		VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
	{
		// Compute the multilinear extension of the ring switching equality indicator.
		//
		// This is functionally equivalent to crate::ring_switch::rs_eq_ind, except that
		// we reuse the already-computed tensor expansions of the challenges.
		let rs_eq_ind =
			tracing::debug_span!("Compute ring-switching equality indicator").in_scope(|| {
				ring_switch::fold_elems_inplace(eval_point_suffix_tensor, r_double_prime_tensor)
			});

		BaseFoldProver::new(
			self.packed_multilin,
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
		BinarySubspace, FieldBuffer, ReedSolomonCode,
		inner_product::inner_product,
		multilinear::eq::eq_ind_partial_eval,
		ntt::{NeighborsLastSingleThread, domain_context::GenericOnTheFly},
		test_utils::random_scalars,
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

	fn run_ring_switched_pcs_prove_and_verify<P>(
		packed_mle: FieldBuffer<P>,
		evaluation_point: Vec<B128>,
		evaluation_claim: B128,
	) -> Result<(), Box<dyn std::error::Error>>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	{
		const LOG_INV_RATE: usize = 1;
		const NUM_TEST_QUERIES: usize = 3;

		let merkle_prover =
			BinaryMerkleTreeProver::<B128, StdDigest, _>::new(StdCompression::default());

		let committed_rs_code = ReedSolomonCode::<B128>::new(packed_mle.log_len(), LOG_INV_RATE)?;

		let fri_log_batch_size = 0;

		// fri arities must support the packing width of the mle
		let fri_arities = if P::LOG_WIDTH == 2 {
			vec![2, 2]
		} else {
			vec![1; packed_mle.log_len() - 1]
		};

		let fri_params =
			FRIParams::new(committed_rs_code, fri_log_batch_size, fri_arities, NUM_TEST_QUERIES)?;

		// Commit packed mle codeword
		let subspace = BinarySubspace::with_dim(fri_params.rs_code().log_len())?;
		let domain_context = GenericOnTheFly::generate_from_subspace(&subspace);
		let ntt: NeighborsLastSingleThread<_> = NeighborsLastSingleThread { domain_context };

		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, packed_mle.to_ref())?;

		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		prover_challenger.message().write(&codeword_commitment);

		let ring_switch_pcs_prover = OneBitPCSProver::new(packed_mle, evaluation_point.clone());
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
		let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;
		let big_field_n_vars = n_vars - log_scalar_bit_width;

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
		let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;
		let big_field_n_vars = n_vars - log_scalar_bit_width;

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
		let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;

		let small_field_n_vars = 12;
		let big_field_n_vars = small_field_n_vars - log_scalar_bit_width;

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
		let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;

		let small_field_n_vars = 12;
		let big_field_n_vars = small_field_n_vars - log_scalar_bit_width;

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

		let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;

		let small_field_n_vars = 12;
		let big_field_n_vars = small_field_n_vars - log_scalar_bit_width;

		let total_big_field_scalars_in_packed_mle = 1 << big_field_n_vars;

		// scalars for unpacked large field mle
		let big_field_mle_scalars =
			random_scalars::<B128>(&mut rng, total_big_field_scalars_in_packed_mle);
		let packed_mle_buffer: FieldBuffer<P> =
			FieldBuffer::from_values(&big_field_mle_scalars).unwrap();

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
	fn test_fri_commit_packing_width_4() {
		let mut rng = StdRng::from_seed([0; 32]);

		type P = PackedBinaryGhash4x128b;

		const LOG_INV_RATE: usize = 1;
		const NUM_TEST_QUERIES: usize = 3;

		let log_dimension = 5;
		let n_scalars = 1 << log_dimension;
		let scalars = random_scalars::<B128>(&mut rng, n_scalars);
		let packed_buffer: FieldBuffer<P> = FieldBuffer::from_values(&scalars).unwrap();

		let merkle_prover =
			BinaryMerkleTreeProver::<B128, StdDigest, _>::new(StdCompression::default());
		let committed_rs_code = ReedSolomonCode::<B128>::new(log_dimension, LOG_INV_RATE).unwrap();

		let fri_log_batch_size = 0;
		let fri_arities = vec![1; log_dimension - 1];
		let fri_params =
			FRIParams::new(committed_rs_code, fri_log_batch_size, fri_arities, NUM_TEST_QUERIES)
				.unwrap();

		let subspace = BinarySubspace::with_dim(fri_params.rs_code().log_len()).unwrap();
		let domain_context = GenericOnTheFly::generate_from_subspace(&subspace);
		let ntt: NeighborsLastSingleThread<_> = NeighborsLastSingleThread { domain_context };

		let commit_result =
			fri::commit_interleaved(&fri_params, &ntt, &merkle_prover, packed_buffer.to_ref());

		commit_result.expect("FRI commit should work with packing width 4");
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

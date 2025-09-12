// Copyright 2025 Irreducible Inc.

use std::ops::Deref;

use binius_field::{ExtensionField, PackedField};
use binius_math::{
	FieldBuffer, inner_product::inner_product, multilinear::eq::eq_ind_partial_eval,
	ntt::AdditiveNTT, tensor_algebra::TensorAlgebra,
};
use binius_transcript::{
	ProverTranscript, TranscriptWriter,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::{
	config::{B1, B128},
	fri::FRIParams,
	hash::PseudoCompressionFunction,
};
use bytes::BufMut;
use digest::{Digest, Output, core_api::BlockSizeUser};

use crate::{Error, fri::FRIProver, protocols::basefold::prover::BaseFoldProver, ring_switch};

/// Prover for the FRI-Binius 1-bit multilinear polynomial commitment scheme.
///
/// The polynomial commitment scheme composes the ring switching reduction with the BaseFold
/// interactive argument.
///
/// See [`binius_verifier::pcs`] module documentation for more details.
pub struct OneBitPCSProver<'a, H, C, NTT>
where
	NTT: AdditiveNTT<Field = B128> + Sync,
{
	ntt: &'a NTT,
	fri_params: &'a FRIParams<B128, H, C>,
}

impl<'a, H, C, NTT> OneBitPCSProver<'a, H, C, NTT>
where
	H: Digest + BlockSizeUser + Sync,
	C: PseudoCompressionFunction<Output<H>, 2> + Sync,
	NTT: AdditiveNTT<Field = B128> + Sync,
{
	/// Creates a new PCS prover.
	///
	/// ## Arguments
	///
	/// * `ntt` - the NTT for the FRI parameters
	/// * `merkle_prover` - the merkle tree prover
	/// * `fri_params` - the FRI parameters
	pub fn new(ntt: &'a NTT, fri_params: &'a FRIParams<B128, H, C>) -> Self {
		let rs_code = fri_params.rs_code();
		assert_eq!(&ntt.subspace(rs_code.log_len()), rs_code.subspace()); // precondition
		Self { ntt, fri_params }
	}

	/// Commit to a multilinear polynomial using FRI.
	///
	/// ## Arguments
	///
	/// * `packed_multilin` - a packed field buffer that the prover interprets as a multilinear
	///   polynomial over its B1 subcomponents, in multilinear Lagrange basis. The number of B1
	///   elements is `packed_multilin.len() * B128::N_BITS`.
	pub fn commit<P, Data>(
		&self,
		packed_multilin: FieldBuffer<P, Data>,
		transcript: &mut TranscriptWriter<impl BufMut>,
	) -> FRIProver<'_, B128, H, C, NTT>
	where
		P: PackedField<Scalar = B128>,
		Data: Deref<Target = [P]>,
	{
		FRIProver::write_initial_commitment(
			self.fri_params,
			packed_multilin.as_ref(),
			self.ntt,
			transcript,
		)
	}

	/// Prove the committed polynomial's evaluation at a given point.
	///
	/// ## Arguments
	///
	/// * `committed_codeword` - the committed codeword
	/// * `committed` - the committed merkle tree
	/// * `packed_multilin` - a packed field buffer that the prover interprets as a multilinear
	///   polynomial over its B1 subcomponents, in multilinear Lagrange basis. The number of B1
	///   elements is `packed_multilin.len() * B128::N_BITS`.
	/// * `evaluation_point` - the evaluation point of the B1 multilinear
	/// * `transcript` - the transcript of the prover's proof
	pub fn prove<P>(
		&self,
		fri_prover: FRIProver<P::Scalar, H, C, NTT>,
		packed_multilin: FieldBuffer<P>,
		evaluation_point: Vec<B128>,
		transcript: &mut ProverTranscript<impl Challenger>,
	) -> Result<(), Error>
	where
		P: PackedField<Scalar = B128>,
	{
		assert_eq!(
			packed_multilin.log_len() + <B128 as ExtensionField<B1>>::LOG_DEGREE,
			evaluation_point.len()
		); // precondition

		// κ, the base-2 log of the packing degree
		let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;

		// eval_point_suffix is the evaluation point, skipping the first κ coordinates
		let eval_point_suffix = &evaluation_point[log_scalar_bit_width..];
		let suffix_tensor = tracing::debug_span!("Expand evaluation suffix query")
			.in_scope(|| eq_ind_partial_eval::<P>(eval_point_suffix));

		let s_hat_v = tracing::debug_span!("Compute ring-switching partial evaluations")
			.in_scope(|| ring_switch::fold_1b_rows_for_b128(&packed_multilin, &suffix_tensor));
		transcript.message().write_scalar_slice(s_hat_v.as_ref());

		// basis decompose/recombine s_hat_v across opposite dimension
		let s_hat_u = <TensorAlgebra<B1, B128>>::new(s_hat_v.as_ref().to_vec())
			.transpose()
			.elems;

		// Sample row-batching challenges
		let r_double_prime = transcript.sample_vec(log_scalar_bit_width);
		let eq_r_double_prime = eq_ind_partial_eval::<B128>(&r_double_prime);

		let computed_sumcheck_claim =
			inner_product(s_hat_u, eq_r_double_prime.as_ref().iter().copied());

		// Compute the multilinear extension of the ring switching equality indicator.
		//
		// This is functionally equivalent to crate::ring_switch::rs_eq_ind, except that
		// we reuse the already-computed tensor expansions of the challenges.
		let rs_eq_ind = tracing::debug_span!("Compute ring-switching equality indicator")
			.in_scope(|| ring_switch::fold_b128_elems_inplace(suffix_tensor, &eq_r_double_prime));

		let basefold_prover =
			BaseFoldProver::new(packed_multilin, rs_eq_ind, computed_sumcheck_claim, fri_prover)?;

		basefold_prover.prove(transcript)?;

		Ok(())
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
		fri::{FRIParams, FRIVerifier},
		hash::{StdCompression, StdDigest},
		pcs::verify,
	};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::OneBitPCSProver;

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
		const COMMIT_LAYER: usize = 0;

		// fri arities must support the packing width of the mle
		let fri_arities = if P::LOG_WIDTH == 2 {
			vec![2, 2]
		} else {
			vec![1; packed_mle.log_len() - 1]
		};

		let committed_rs_code =
			ReedSolomonCode::<B128>::new(packed_mle.log_len() - fri_arities[0], LOG_INV_RATE)?;

		let compression = StdCompression::default();
		type H = StdDigest;
		let fri_params = FRIParams::<_, H, _>::new(
			compression,
			COMMIT_LAYER,
			packed_mle.log_len(),
			committed_rs_code,
			fri_arities,
			NUM_TEST_QUERIES,
		);

		// Commit packed mle codeword
		let subspace = BinarySubspace::with_dim(fri_params.rs_code().log_len())?;
		let domain_context = GenericOnTheFly::generate_from_subspace(&subspace);
		let ntt = NeighborsLastSingleThread::new(&domain_context);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());

		let ring_switch_pcs_prover = OneBitPCSProver::new(&ntt, &fri_params);

		let fri_prover =
			ring_switch_pcs_prover.commit(packed_mle.to_ref(), &mut prover_transcript.message());

		ring_switch_pcs_prover.prove(
			fri_prover,
			packed_mle,
			evaluation_point.clone(),
			&mut prover_transcript,
		)?;

		let mut verifier_transcript = prover_transcript.into_verifier();

		let fri_verifier = FRIVerifier::read_initial_commitment(
			&fri_params,
			&domain_context,
			&mut verifier_transcript.message(),
		);

		verify(&mut verifier_transcript, evaluation_claim, &evaluation_point, fri_verifier)?;

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

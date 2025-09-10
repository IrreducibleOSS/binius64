// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, PackedField};
use binius_math::{FieldBuffer, ntt::AdditiveNTT};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::{hash::PseudoCompressionFunction, protocols::sumcheck::RoundCoeffs};
use digest::{Digest, Output, OutputSizeUser, core_api::BlockSizeUser};

use crate::{
	Error,
	fri::FRIProver,
	protocols::{basefold::sumcheck::MultilinearSumcheckProver, sumcheck::common::SumcheckProver},
};

/// Prover for the BaseFold protocol.
///
/// The [BaseFold] protocol is a sumcheck-PIOP to IP compiler, used in the [DP24] polynomial
/// commitment scheme. The verifier module [`binius_verifier::protocols::basefold`] provides a
/// description of the protocol.
///
/// This struct exposes a round-by-round interface for one instance of the interactive protocol.
///
/// [BaseFold]: <https://link.springer.com/chapter/10.1007/978-3-031-68403-6_5>
/// [DP24]: <https://eprint.iacr.org/2024/504>
pub struct BaseFoldProver<'a, F, P: PackedField<Scalar = F>, H: OutputSizeUser, C, NTT>
where
	F: BinaryField,
	NTT: AdditiveNTT<Field = F> + Sync,
{
	sumcheck_prover: MultilinearSumcheckProver<F, P>,
	fri_prover: FRIProver<'a, F, H, C, NTT>,
	log_n: usize,
}

impl<'a, F, P, H, C, NTT> BaseFoldProver<'a, F, P, H, C, NTT>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	H: Digest + BlockSizeUser + Sync,
	C: PseudoCompressionFunction<Output<H>, 2> + Sync,
	NTT: AdditiveNTT<Field = F> + Sync,
{
	/// Constructs a new prover.
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
		multilinear: FieldBuffer<P>,
		transparent_multilinear: FieldBuffer<P>,
		claim: F,
		fri_prover: FRIProver<'a, F, H, C, NTT>,
	) -> Result<Self, Error> {
		assert_eq!(multilinear.log_len(), transparent_multilinear.log_len());

		let log_n = multilinear.log_len();

		let sumcheck_composition = [multilinear, transparent_multilinear];

		let sumcheck_prover =
			MultilinearSumcheckProver::<F, P>::new(sumcheck_composition, claim, log_n);

		Ok(Self {
			sumcheck_prover,
			fri_prover,
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
	pub fn execute(&mut self) -> Result<RoundCoeffs<F>, Error> {
		Ok(self
			.sumcheck_prover
			.execute()
			.map_err(|e| Error::ArgumentError {
				arg: "sumcheck".to_string(),
				msg: e.to_string(),
			})?[0]
			.clone())
	}

	/// Runs the protocol to completion.
	///
	/// ## Arguments
	/// * `transcript` - the prover's view of the proof transcript
	///
	/// ## Returns
	///  * the FRI fold round output
	pub fn prove<T: Challenger>(
		mut self,
		transcript: &mut ProverTranscript<T>,
	) -> Result<(), Error> {
		let _scope = tracing::debug_span!("Basefold").entered();

		for _ in 0..self.log_n {
			let round_coeffs = self.execute()?;
			transcript
				.message()
				.write_scalar_slice(round_coeffs.truncate().coeffs());

			let challenge = transcript.sample();

			// fold
			self.sumcheck_prover.fold(challenge)?;
			self.fri_prover
				.prove_fold_round(challenge, &mut transcript.message());
		}

		self.fri_prover.prove_queries(transcript);

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use binius_field::{
		BinaryField, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b, PackedExtension,
		PackedField, arch::OptimalPackedB128,
	};
	use binius_math::{
		FieldBuffer, ReedSolomonCode,
		inner_product::inner_product_buffers,
		multilinear::eq::eq_ind_partial_eval,
		ntt::{NeighborsLastSingleThread, domain_context::GenericOnTheFly},
		test_utils::{random_field_buffer, random_scalars},
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		config::StdChallenger,
		fri::{FRIParams, FRIVerifier},
		hash::{StdCompression, StdDigest},
		protocols::basefold,
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::BaseFoldProver;
	use crate::fri::FRIProver;

	pub const LOG_INV_RATE: usize = 1;
	pub const NUM_TEST_QUERIES: usize = 3;
	pub const COMMIT_LAYER: usize = 2;

	fn run_basefold_prove_and_verify<F, P>(
		multilinear: FieldBuffer<P>,
		evaluation_point: Vec<F>,
		evaluation_claim: F,
	) -> Result<(), Box<dyn std::error::Error>>
	where
		F: BinaryField,
		P: PackedField<Scalar = F> + PackedExtension<F>,
	{
		let n_vars = multilinear.log_len();

		let eval_point_eq = eq_ind_partial_eval::<P>(&evaluation_point);

		let fri_arities = vec![2, 1];
		let rs_code =
			ReedSolomonCode::<F>::new(multilinear.log_len() - fri_arities[0], LOG_INV_RATE)?;
		let compression = StdCompression::default();
		type H = StdDigest;
		let fri_params = FRIParams::<F, H, _>::new(
			compression,
			COMMIT_LAYER,
			multilinear.log_len(),
			rs_code,
			fri_arities,
			NUM_TEST_QUERIES,
		);

		let subspace = fri_params.rs_code().subspace();
		let domain_context = GenericOnTheFly::generate_from_subspace(subspace);
		let ntt = NeighborsLastSingleThread::new(&domain_context);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());

		let fri_prover = FRIProver::write_initial_commitment(
			&fri_params,
			multilinear.to_ref().as_ref(),
			&ntt,
			&mut prover_transcript.message(),
		);

		let prover = BaseFoldProver::new(multilinear, eval_point_eq, evaluation_claim, fri_prover)?;

		prover.prove(&mut prover_transcript)?;

		let mut verifier_transcript = prover_transcript.into_verifier();

		let fri_verifier = FRIVerifier::read_initial_commitment(
			&fri_params,
			&domain_context,
			&mut verifier_transcript.message(),
		);

		let basefold::ReducedOutput {
			final_fri_value,
			final_sumcheck_value,
			challenges,
		} = basefold::verify(fri_verifier, n_vars, evaluation_claim, &mut verifier_transcript)?;

		if !basefold::sumcheck_fri_consistency(
			final_fri_value,
			final_sumcheck_value,
			&evaluation_point,
			&challenges,
		) {
			return Err("Sumcheck and FRI are inconsistent".into());
		}

		Ok(())
	}

	fn test_setup<F, P>(n_vars: usize) -> (FieldBuffer<P>, Vec<F>, F)
	where
		F: BinaryField,
		P: PackedField<Scalar = F>,
	{
		let mut rng = StdRng::from_seed([0; 32]);

		let multilinear = random_field_buffer::<P>(&mut rng, n_vars);
		let evaluation_point = random_scalars::<F>(&mut rng, n_vars);

		let eval_point_eq = eq_ind_partial_eval(&evaluation_point);
		let evaluation_claim = inner_product_buffers(&multilinear, &eval_point_eq);

		(multilinear, evaluation_point, evaluation_claim)
	}

	fn dubiously_modify_claim<F, P>(claim: &mut F)
	where
		F: BinaryField,
		P: PackedField<Scalar = F>,
	{
		*claim += P::Scalar::ONE
	}

	#[test]
	fn test_basefold_valid_proof() {
		type P = OptimalPackedB128;

		let n_vars = 8;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<_, P>(n_vars);

		match run_basefold_prove_and_verify::<_, P>(multilinear, evaluation_point, evaluation_claim)
		{
			Ok(()) => {}
			Err(_) => panic!("expected valid proof"),
		}
	}

	#[test]
	fn test_basefold_invalid_proof() {
		type P = OptimalPackedB128;

		let n_vars = 8;
		let (multilinear, evaluation_point, mut evaluation_claim) = test_setup::<_, P>(n_vars);

		dubiously_modify_claim::<_, P>(&mut evaluation_claim);
		let result =
			run_basefold_prove_and_verify::<_, P>(multilinear, evaluation_point, evaluation_claim);
		assert!(result.is_err());
	}

	#[test]
	fn test_basefold_valid_packing_width_2() {
		type P = PackedBinaryGhash2x128b;

		let n_vars = 8;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<_, P>(n_vars);

		match run_basefold_prove_and_verify::<_, P>(multilinear, evaluation_point, evaluation_claim)
		{
			Ok(()) => {}
			Err(_) => panic!("expected valid proof"),
		}
	}

	#[test]
	fn test_basefold_invalid_proof_packing_width_2() {
		type P = PackedBinaryGhash2x128b;

		let n_vars = 8;
		let (multilinear, evaluation_point, mut evaluation_claim) = test_setup::<_, P>(n_vars);

		dubiously_modify_claim::<_, P>(&mut evaluation_claim);
		let result =
			run_basefold_prove_and_verify::<_, P>(multilinear, evaluation_point, evaluation_claim);
		assert!(result.is_err());
	}

	#[test]
	fn test_basefold_valid_packing_width_4() {
		type P = PackedBinaryGhash4x128b;

		let n_vars = 8;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<_, P>(n_vars);

		match run_basefold_prove_and_verify::<_, P>(multilinear, evaluation_point, evaluation_claim)
		{
			Ok(()) => {}
			Err(_) => panic!("expected valid proof"),
		}
	}

	#[test]
	fn test_basefold_invalid_proof_packing_width_4() {
		type P = PackedBinaryGhash4x128b;

		let n_vars = 8;
		let (multilinear, evaluation_point, mut evaluation_claim) = test_setup::<_, P>(n_vars);

		dubiously_modify_claim::<_, P>(&mut evaluation_claim);
		let result =
			run_basefold_prove_and_verify::<_, P>(multilinear, evaluation_point, evaluation_claim);
		assert!(result.is_err());
	}
}

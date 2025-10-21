// Copyright 2025 Irreducible Inc.

pub mod config;
pub mod pcs;
mod wiring;

use binius_math::{
	BinarySubspace,
	ntt::{NeighborsLastSingleThread, domain_context::GenericOnTheFly},
};
use binius_spartan_frontend::constraint_system::ConstraintSystem;
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{DeserializeBytes, checked_arithmetics::checked_log_2};
use binius_verifier::{
	fri::{self, FRIParams, estimate_optimal_arity},
	hash::PseudoCompressionFunction,
	merkle_tree::BinaryMerkleTreeScheme,
};
use digest::{Digest, Output, core_api::BlockSizeUser};

use crate::config::B128;

pub const SECURITY_BITS: usize = 96;

/// Struct for verifying instances of a particular constraint system.
///
/// The [`Self::setup`] constructor determines public parameters for proving instances of the given
/// constraint system. Then [`Self::verify`] is called one or more times with individual instances.
#[derive(Debug, Clone)]
pub struct Verifier<MerkleHash, MerkleCompress> {
	constraint_system: ConstraintSystem,
	fri_params: FRIParams<B128>,
	merkle_scheme: BinaryMerkleTreeScheme<B128, MerkleHash, MerkleCompress>,
}

impl<MerkleHash, MerkleCompress> Verifier<MerkleHash, MerkleCompress>
where
	MerkleHash: Digest + BlockSizeUser,
	MerkleCompress: PseudoCompressionFunction<Output<MerkleHash>, 2>,
	Output<MerkleHash>: DeserializeBytes,
{
	/// Constructs a verifier for a constraint system.
	///
	/// See [`Verifier`] struct documentation for details.
	pub fn setup(
		constraint_system: ConstraintSystem,
		log_inv_rate: usize,
		compression: MerkleCompress,
	) -> Result<Self, Error> {
		let log_witness_len = constraint_system.log_size() as usize;
		let log_code_len = log_witness_len + log_inv_rate;
		let fri_arity = estimate_optimal_arity(
			log_code_len,
			size_of::<Output<MerkleHash>>(),
			size_of::<binius_verifier::config::B128>(),
		);

		let subspace = BinarySubspace::with_dim(log_code_len)?;
		let domain_context = GenericOnTheFly::generate_from_subspace(&subspace);
		let ntt = NeighborsLastSingleThread::new(domain_context);
		let fri_params = FRIParams::choose_with_constant_fold_arity(
			&ntt,
			log_witness_len,
			SECURITY_BITS,
			log_inv_rate,
			fri_arity,
		)?;

		let merkle_scheme = BinaryMerkleTreeScheme::new(compression);

		Ok(Self {
			constraint_system,
			fri_params,
			merkle_scheme,
		})
	}

	pub fn constraint_system(&self) -> &ConstraintSystem {
		&self.constraint_system
	}

	pub fn fri_params(&self) -> &FRIParams<B128> {
		&self.fri_params
	}

	pub fn verify<Challenger_: Challenger>(
		&self,
		public: &[B128],
		transcript: &mut VerifierTranscript<Challenger_>,
	) -> Result<(), Error> {
		let _verify_guard =
			tracing::info_span!("Verify", operation = "verify", perfetto_category = "operation")
				.entered();

		let cs = self.constraint_system();

		// Check that the public input length is correct
		if public.len() != 1 << cs.log_public() {
			return Err(Error::IncorrectPublicInputLength {
				expected: 1 << self.constraint_system.log_public(),
				actual: public.len(),
			});
		}

		let log_mul_constraints = checked_log_2(cs.mul_constraints().len());

		// Receive the trace commitment.
		let trace_commitment = transcript.message().read::<Output<MerkleHash>>()?;

		// Sample random evaluation point
		let _r_x: Vec<B128> = transcript.sample_vec(log_mul_constraints);

		// Read the claimed evaluation
		let _a_eval = transcript.message().read::<B128>()?;
		let _b_eval = transcript.message().read::<B128>()?;
		let _c_eval = transcript.message().read::<B128>()?;

		// // Verify the wiring reduction
		// let wiring_output = wiring::verify(log_mul_constraints, evaluation_claims, transcript)?;
		// wiring::check_eval(&self.constraint_system, &r_x, &wiring_output)?;
		//
		// let wiring::Output {
		// 	r_y, witness_eval, ..
		// } = wiring_output;

		// Sample random evaluation point
		let r_y = transcript.sample_vec(cs.log_size() as usize);

		let witness_eval = transcript.message().read::<B128>()?;

		// Verify the PCS opening
		pcs::verify(
			transcript,
			witness_eval,
			&r_y,
			trace_commitment,
			&self.fri_params,
			&self.merkle_scheme,
		)?;

		Ok(())
	}
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("FRI error: {0}")]
	FRI(#[from] fri::Error),
	#[error("PCS error: {0}")]
	PCS(#[from] pcs::Error),
	#[error("Math error: {0}")]
	Math(#[from] binius_math::Error),
	#[error("wiring error: {0}")]
	Wiring(#[from] wiring::Error),
	#[error("Transcript error: {0}")]
	Transcript(#[from] binius_transcript::Error),
	#[error("incorrect public inputs length: expected {expected}, got {actual}")]
	IncorrectPublicInputLength { expected: usize, actual: usize },
}

// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField};
use binius_frontend::{constraint_system::ConstraintSystem, word::Word};
use binius_math::ntt::SingleThreadedNTT;
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{
	DeserializeBytes,
	checked_arithmetics::{checked_log_2, log2_ceil_usize},
};

use super::error::Error;
use crate::{
	fields::{B1, B128},
	fri::{FRIParams, estimate_optimal_arity},
	merkle_tree::MerkleTreeScheme,
	pcs::verifier::verify_transcript,
};

/// The protocol proves constraint systems over 64-bit words.
pub const WORD_SIZE_BITS: usize = 64;

/// log2 of [`WORD_SIZE_BITS`].
pub const LOG_WORD_SIZE_BITS: usize = checked_log_2(WORD_SIZE_BITS);
pub const LOG_WORDS_PER_ELEM: usize = checked_log_2(B128::N_BITS) - LOG_WORD_SIZE_BITS;

pub const SECURITY_BITS: usize = 96;

/// Public parameters for proving constraint systems of a certain size.
#[derive(Debug, Clone)]
pub struct Params<MTScheme> {
	fri_params: FRIParams<B128, B128>,
	merkle_scheme: MTScheme,
}

impl<MTScheme: MerkleTreeScheme<B128>> Params<MTScheme> {
	pub fn new(
		cs: &ConstraintSystem,
		log_inv_rate: usize,
		merkle_scheme: MTScheme,
	) -> Result<Self, Error> {
		// The number of field elements that constitute the packed witness.
		let log_witness_words = log2_ceil_usize(cs.value_vec_len()).max(LOG_WORDS_PER_ELEM);
		let log_witness_elems = log_witness_words - LOG_WORDS_PER_ELEM;

		let log_code_len = log_witness_words + log_inv_rate;
		let fri_arity =
			estimate_optimal_arity(log_code_len, size_of::<MTScheme::Digest>(), size_of::<B128>());

		let ntt = SingleThreadedNTT::new(log_code_len)?;
		let fri_params = FRIParams::choose_with_constant_fold_arity(
			&ntt,
			log_witness_elems,
			SECURITY_BITS,
			log_inv_rate,
			fri_arity,
		)?;

		Ok(Self {
			fri_params,
			merkle_scheme,
		})
	}

	/// Returns log2 of the number of words in the witness.
	pub fn log_witness_words(&self) -> usize {
		self.log_witness_elems() + LOG_WORDS_PER_ELEM
	}

	/// Returns log2 of the number of field elements in the packed trace.
	pub fn log_witness_elems(&self) -> usize {
		let rs_code = self.fri_params.rs_code();
		rs_code.log_dim() + self.fri_params.log_batch_size()
	}

	/// Returns the chosen FRI parameters.
	pub fn fri_params(&self) -> &FRIParams<B128, B128> {
		&self.fri_params
	}

	/// Returns the [`MerkleTreeScheme`] instance used.
	pub fn merkle_scheme(&self) -> &MTScheme {
		&self.merkle_scheme
	}
}

pub fn verify<Challenger_, MTScheme>(
	params: &Params<MTScheme>,
	_cs: &ConstraintSystem,
	_inout: &[Word],
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(), Error>
where
	Challenger_: Challenger,
	MTScheme: MerkleTreeScheme<B128>,
	MTScheme::Digest: DeserializeBytes,
{
	// Receive the trace commitment.
	let trace_commitment = transcript.message().read::<MTScheme::Digest>()?;

	let small_field_log_n_vars =
		params.log_witness_elems() + <B128 as ExtensionField<B1>>::LOG_DEGREE;

	let evaluation_point: Vec<B128> = transcript.sample_vec(small_field_log_n_vars);
	let evaluation_claim = transcript.message().read::<B128>()?;

	// verify ring switched pcs
	verify_transcript(
		transcript,
		evaluation_claim,
		&evaluation_point,
		trace_commitment,
		params.fri_params(),
		params.merkle_scheme(),
	)
	.unwrap();

	Ok(())
}

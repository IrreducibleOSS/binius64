// Copyright 2025 Irreducible Inc.

use binius_field::BinaryField;
use binius_frontend::{constraint_system::ConstraintSystem, word::Word};
use binius_math::{
	FieldBuffer,
	inner_product::inner_product_subfield,
	multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate_inplace},
	ntt::SingleThreadedNTT,
};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{DeserializeBytes, checked_arithmetics::log2_ceil_usize};

use super::{
	ConstraintSystemError, VerificationError, config::LOG_WORDS_PER_ELEM, error::Error, pcs,
};
use crate::{
	config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS},
	fields::{B1, B128},
	fri::{FRIParams, estimate_optimal_arity},
	merkle_tree::MerkleTreeScheme,
	protocols::pubcheck,
};

pub const SECURITY_BITS: usize = 96;

/// Public parameters for proving constraint systems of a certain size.
#[derive(Debug, Clone)]
pub struct Params<MTScheme> {
	fri_params: FRIParams<B128, B128>,
	merkle_scheme: MTScheme,
	log_public_words: usize,
}

impl<MTScheme: MerkleTreeScheme<B128>> Params<MTScheme> {
	pub fn new(
		cs: &ConstraintSystem,
		log_inv_rate: usize,
		merkle_scheme: MTScheme,
	) -> Result<Self, Error> {
		// Use offset_witness which is guaranteed to be power of two
		let n_public = cs.value_vec_layout.offset_witness;

		// Verify it's a power of two (should always be true by construction)
		if !n_public.is_power_of_two() {
			return Err(ConstraintSystemError::PublicInputPowerOfTwo.into());
		}

		let log_public_words = log2_ceil_usize(n_public);
		if log_public_words < LOG_WORDS_PER_ELEM {
			return Err(ConstraintSystemError::PublicInputTooShort.into());
		}

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
			log_public_words,
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

	/// Returns log2 of the number of public constants and input/output words.
	pub fn log_public_words(&self) -> usize {
		self.log_public_words
	}
}

pub fn verify<Challenger_, MTScheme>(
	params: &Params<MTScheme>,
	_cs: &ConstraintSystem,
	public: &[Word],
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<(), Error>
where
	Challenger_: Challenger,
	MTScheme: MerkleTreeScheme<B128>,
	MTScheme::Digest: DeserializeBytes,
{
	// Check that the public input length is correct
	if public.len() != 1 << params.log_public_words() {
		return Err(Error::IncorrectPublicInputLength {
			expected: 1 << params.log_public_words(),
			actual: public.len(),
		});
	}

	// Receive the trace commitment.
	let trace_commitment = transcript.message().read::<MTScheme::Digest>()?;

	// Sample a challenge point during the shift reduction.
	let z_challenge = transcript.sample_vec(LOG_WORD_SIZE_BITS);
	let public_input_challenge = transcript.sample_vec(params.log_public_words());

	let pubcheck::VerifyOutput {
		witness_eval,
		public_eval,
		eval_point: y_challenge,
	} = pubcheck::verify(params.log_witness_words(), &public_input_challenge, transcript)?;

	let expected_public_eval =
		evaluate_public_mle(public, &z_challenge, &y_challenge[..params.log_public_words()]);
	if public_eval != expected_public_eval {
		return Err(VerificationError::PublicInputCheckFailed.into());
	}

	// PCS opening
	let evaluation_point = [z_challenge, y_challenge].concat();
	pcs::verify_transcript(
		transcript,
		witness_eval,
		&evaluation_point,
		trace_commitment,
		params.fri_params(),
		params.merkle_scheme(),
	)?;

	Ok(())
}

/// Evaluate the multilinear extension of the public inputs at a point.
///
/// ## Arguments
///
/// * `public` - the public input words
/// * `z_coords` - coordinates for the lower variables, corresponding to bits of words
/// * `y_coords` - coordinates for the upper variables, corresponding to words
fn evaluate_public_mle<F: BinaryField>(public: &[Word], z_coords: &[F], y_coords: &[F]) -> F {
	assert_eq!(public.len(), 1 << y_coords.len()); // precondition
	assert_eq!(LOG_WORD_SIZE_BITS, z_coords.len()); // precondition

	// First, fold the bits of the word with the z coordinates
	let z_tensor = eq_ind_partial_eval::<F>(z_coords);
	let z_folded_words = public
		.iter()
		.map(|&word| {
			let word_bits = (0..WORD_SIZE_BITS).map(|i| B1::from((word.as_u64() >> i) & 1 == 1));
			inner_product_subfield(word_bits, z_tensor.as_ref().iter().copied())
		})
		.collect::<Box<[_]>>();
	let z_folded_words = FieldBuffer::new(y_coords.len(), z_folded_words)
		.expect("precondition: public.len() == 1 << y_coords.len()");

	// Then, fold the partial evaluation with the y coordinates
	evaluate_inplace(z_folded_words, y_coords)
		.expect("z_folded_words constructed with log_len = y_coords.len()")
}

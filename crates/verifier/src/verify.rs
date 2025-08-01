// Copyright 2025 Irreducible Inc.

use binius_field::{AESTowerField8b, BinaryField};
use binius_frontend::{constraint_system::ConstraintSystem, word::Word};
use binius_math::{
	BinarySubspace, FieldBuffer,
	inner_product::inner_product_subfield,
	multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate_inplace},
	ntt::SingleThreadedNTT,
};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{DeserializeBytes, checked_arithmetics::log2_ceil_usize};
use digest::{Digest, Output, core_api::BlockSizeUser};
use itertools::Itertools;

use super::{
	ConstraintSystemError, VerificationError, config::LOG_WORDS_PER_ELEM, error::Error, pcs,
};
use crate::{
	and_reduction::verifier::{AndReductionOutput, verify_with_transcript},
	config::{
		B1, B128, LOG_WORD_SIZE_BITS, PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES, WORD_SIZE_BITS,
	},
	fri::{FRIParams, estimate_optimal_arity},
	hash::PseudoCompressionFunction,
	merkle_tree::BinaryMerkleTreeScheme,
	protocols::pubcheck,
};

pub const SECURITY_BITS: usize = 96;

/// Struct for verifying instances of a particular constraint system.
///
/// The [`Self::setup`] constructor determines public parameters for proving instances of the given
/// constraint system. Then [`Self::verify`] is called one or more times with individual instances.
#[derive(Debug, Clone)]
pub struct Verifier<'a, MerkleHash, MerkleCompress> {
	constraint_system: &'a ConstraintSystem,
	fri_params: FRIParams<B128, B128>,
	merkle_scheme: BinaryMerkleTreeScheme<B128, MerkleHash, MerkleCompress>,
	log_public_words: usize,
}

impl<'a, MerkleHash, MerkleCompress> Verifier<'a, MerkleHash, MerkleCompress>
where
	MerkleHash: Digest + BlockSizeUser,
	MerkleCompress: PseudoCompressionFunction<Output<MerkleHash>, 2> + Sync,
	Output<MerkleHash>: DeserializeBytes,
{
	/// Constructs a verifier for a constraint system.
	///
	/// See [`Verifier`] struct documentation for details.
	pub fn setup(
		constraint_system: &'a ConstraintSystem,
		log_inv_rate: usize,
		compression: MerkleCompress,
	) -> Result<Self, Error> {
		// Use offset_witness which is guaranteed to be power of two
		let n_public = constraint_system.value_vec_layout.offset_witness;

		// Verify it's a power of two (should always be true by construction)
		if !n_public.is_power_of_two() {
			return Err(ConstraintSystemError::PublicInputPowerOfTwo.into());
		}

		let log_public_words = log2_ceil_usize(n_public);
		if log_public_words < LOG_WORDS_PER_ELEM {
			return Err(ConstraintSystemError::PublicInputTooShort.into());
		}

		// The number of field elements that constitute the packed witness.
		let log_witness_words =
			log2_ceil_usize(constraint_system.value_vec_len()).max(LOG_WORDS_PER_ELEM);
		let log_witness_elems = log_witness_words - LOG_WORDS_PER_ELEM;

		let log_code_len = log_witness_words + log_inv_rate;
		let fri_arity = estimate_optimal_arity(
			log_code_len,
			size_of::<Output<MerkleHash>>(),
			size_of::<B128>(),
		);

		let ntt = SingleThreadedNTT::new(log_code_len)?;
		let fri_params = FRIParams::choose_with_constant_fold_arity(
			&ntt,
			log_witness_elems,
			SECURITY_BITS,
			log_inv_rate,
			fri_arity,
		)?;

		let merkle_scheme = BinaryMerkleTreeScheme::new(compression);

		Ok(Self {
			constraint_system,
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

	/// Returns the constraint system.
	pub fn constraint_system(&self) -> &ConstraintSystem {
		self.constraint_system
	}

	/// Returns the chosen FRI parameters.
	pub fn fri_params(&self) -> &FRIParams<B128, B128> {
		&self.fri_params
	}

	/// Returns the [`crate::merkle_tree::MerkleTreeScheme`] instance used.
	pub fn merkle_scheme(&self) -> &BinaryMerkleTreeScheme<B128, MerkleHash, MerkleCompress> {
		&self.merkle_scheme
	}

	/// Returns log2 of the number of public constants and input/output words.
	pub fn log_public_words(&self) -> usize {
		self.log_public_words
	}

	pub fn verify<Challenger_: Challenger>(
		&self,
		public: &[Word],
		transcript: &mut VerifierTranscript<Challenger_>,
	) -> Result<(), Error> {
		// Check that the public input length is correct
		if public.len() != 1 << self.log_public_words() {
			return Err(Error::IncorrectPublicInputLength {
				expected: 1 << self.log_public_words(),
				actual: public.len(),
			});
		}

		// Receive the trace commitment.
		let trace_commitment = transcript.message().read::<Output<MerkleHash>>()?;

		// verify the and reduction
		let _output: AndReductionOutput<B128> =
			run_and_check(self.log_witness_words(), transcript)?;

		// Sample a challenge point during the shift reduction.
		let z_challenge = transcript.sample_vec(LOG_WORD_SIZE_BITS);
		let public_input_challenge = transcript.sample_vec(self.log_public_words());

		let pubcheck::VerifyOutput {
			witness_eval,
			public_eval,
			eval_point: y_challenge,
		} = pubcheck::verify(self.log_witness_words(), &public_input_challenge, transcript)?;

		let expected_public_eval =
			evaluate_public_mle(public, &z_challenge, &y_challenge[..self.log_public_words()]);
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
			&self.fri_params,
			&self.merkle_scheme,
		)?;

		Ok(())
	}
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

fn run_and_check<F: BinaryField + From<AESTowerField8b>, Challenger_: Challenger>(
	log_witness_words: usize,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<AndReductionOutput<F>, Error> {
	// The structure of the AND reduction requires that it verifies at least 2^3 word-level
	// constraints, you can zero-pad if necessary to reach this minimum
	assert!(log_witness_words >= 3);

	let big_field_zerocheck_challenges = transcript.sample_vec(log_witness_words - 3);

	let mut all_zerocheck_challenges = vec![];

	let small_field_zerocheck_challenges = PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES
		.into_iter()
		.map(F::from)
		.collect_vec();

	let verifier_message_domain =
		BinarySubspace::<AESTowerField8b>::with_dim(LOG_WORD_SIZE_BITS + 1)
			.expect("dim is positive and less than field dim")
			.isomorphic();

	for small_field_challenge in small_field_zerocheck_challenges {
		all_zerocheck_challenges.push(small_field_challenge);
	}

	for big_field_challenge in &big_field_zerocheck_challenges {
		all_zerocheck_challenges.push(*big_field_challenge);
	}

	let output = verify_with_transcript(
		&all_zerocheck_challenges,
		transcript,
		verifier_message_domain.clone(),
	)?;

	let verifier_mle_eval_claims = transcript.message().read_scalar_slice::<F>(3)?;

	if output.sumcheck_output.eval
		== verifier_mle_eval_claims[0] * verifier_mle_eval_claims[1] - verifier_mle_eval_claims[2]
	{
		Ok(output)
	} else {
		Err(VerificationError::AndReductionMLECheckFailed.into())
	}
}

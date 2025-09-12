// Copyright 2025 Irreducible Inc.

use binius_core::{constraint_system::ConstraintSystem, word::Word};
use binius_field::{AESTowerField8b as B8, BinaryField};
use binius_math::{
	BinarySubspace, FieldBuffer,
	inner_product::inner_product_subfield,
	multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate_inplace},
	ntt::domain_context::GenericOnTheFly,
	univariate::lagrange_evals,
};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::checked_arithmetics::{checked_log_2, log2_ceil_usize};
use digest::{Digest, Output, core_api::BlockSizeUser};
use itertools::{Itertools, izip};

use super::{VerificationError, error::Error, pcs};
use crate::{
	and_reduction::verifier::{AndCheckOutput, verify_with_transcript},
	config::{
		B1, B128, LOG_WORD_SIZE_BITS, LOG_WORDS_PER_ELEM, PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES,
		WORD_SIZE_BITS,
	},
	fri::{FRIParams, FRIVerifier},
	hash::PseudoCompressionFunction,
	protocols::{
		intmul::{IntMulOutput, verify as verify_intmul_reduction},
		pubcheck::VerifyOutput,
		shift::{OperatorData, verify as verify_shift_reduction},
	},
};

pub const SECURITY_BITS: usize = 96;

/// Struct for verifying instances of a particular constraint system.
///
/// The [`Self::setup`] constructor determines public parameters for proving instances of the given
/// constraint system. Then [`Self::verify`] is called one or more times with individual instances.
#[derive(Debug, Clone)]
pub struct Verifier<H, C> {
	constraint_system: ConstraintSystem,
	fri_params: FRIParams<B128, H, C>,
	log_public_words: usize,
}

impl<H, C> Verifier<H, C>
where
	H: Digest + BlockSizeUser,
	C: PseudoCompressionFunction<Output<H>, 2>,
{
	/// Constructs a verifier for a constraint system.
	///
	/// See [`Verifier`] struct documentation for details.
	pub fn setup(
		mut constraint_system: ConstraintSystem,
		log_inv_rate: usize,
		compression: C,
	) -> Result<Self, Error> {
		constraint_system.validate_and_prepare()?;

		// Use offset_witness which is guaranteed to be power of two and be at least one full
		// element.
		let n_public = constraint_system.value_vec_layout.offset_witness;
		let log_public_words = log2_ceil_usize(n_public);
		assert!(n_public.is_power_of_two());
		assert!(log_public_words >= LOG_WORDS_PER_ELEM);

		// The number of field elements that constitute the packed witness.
		let log_witness_words =
			log2_ceil_usize(constraint_system.value_vec_len()).max(LOG_WORDS_PER_ELEM);
		let log_witness_elems = log_witness_words - LOG_WORDS_PER_ELEM;

		let fold_arity =
			FRIParams::<B128, H, C>::estimate_optimal_arity(log_witness_elems, log_inv_rate);
		let subspace = BinarySubspace::with_dim(log_witness_elems + log_inv_rate - fold_arity)?;
		let fri_params = FRIParams::new_with_constant_arity(
			compression,
			log_witness_elems,
			log_inv_rate,
			subspace,
			fold_arity,
			SECURITY_BITS,
		);

		Ok(Self {
			constraint_system,
			fri_params,
			log_public_words,
		})
	}

	/// Returns log2 of the number of words in the witness.
	pub fn log_witness_words(&self) -> usize {
		self.log_witness_elems() + LOG_WORDS_PER_ELEM
	}

	/// Returns log2 of the number of field elements in the packed trace.
	pub fn log_witness_elems(&self) -> usize {
		self.fri_params.log_msg_len()
	}

	/// Returns the constraint system.
	pub fn constraint_system(&self) -> &ConstraintSystem {
		&self.constraint_system
	}

	/// Returns the chosen FRI parameters.
	pub fn fri_params(&self) -> &FRIParams<B128, H, C> {
		&self.fri_params
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
		let _verify_guard =
			tracing::info_span!("verify", operation = "verify", perfetto_category = "operation")
				.entered();

		// Check that the public input length is correct
		if public.len() != 1 << self.log_public_words() {
			return Err(Error::IncorrectPublicInputLength {
				expected: 1 << self.log_public_words(),
				actual: public.len(),
			});
		}

		// Receive the trace commitment.
		let subspace = self.fri_params.rs_code().subspace();
		let domain_context = GenericOnTheFly::generate_from_subspace(subspace);
		let mut fri_verifier = FRIVerifier::new(&self.fri_params, domain_context);
		fri_verifier.read_initial_commitment(&mut transcript.message());

		// [phase] Verify IntMul Reduction - multiplication constraint verification
		let intmul_guard = tracing::info_span!(
			"[phase] Verify IntMul Reduction",
			phase = "verify_intmul_reduction",
			perfetto_category = "phase",
			n_constraints = self.constraint_system.n_mul_constraints()
		)
		.entered();
		let log_n_constraints = checked_log_2(self.constraint_system.n_mul_constraints());
		let intmul_output =
			verify_intmul_reduction(LOG_WORD_SIZE_BITS, log_n_constraints, transcript)?;
		drop(intmul_guard);

		// [phase] Verify BitAnd Reduction - AND constraint verification
		let bitand_guard = tracing::info_span!(
			"[phase] Verify BitAnd Reduction",
			phase = "verify_bitand_reduction",
			perfetto_category = "phase",
			n_constraints = self.constraint_system.n_and_constraints()
		)
		.entered();
		let bitand_claim = {
			let log_n_constraints = checked_log_2(self.constraint_system.n_and_constraints());
			let AndCheckOutput {
				a_eval,
				b_eval,
				c_eval,
				z_challenge,
				eval_point,
			}: AndCheckOutput<B128> = verify_bitand_reduction(log_n_constraints, transcript)?;
			OperatorData::new(z_challenge, eval_point, [a_eval, b_eval, c_eval])
		};
		drop(bitand_guard);

		// Build `OperatorData` for IntMul using the same `r_zhat_prime`
		// challenge as in BitAnd. Sharing this univariate challenge
		// improves prover ShiftReduction perf.
		let intmul_claim = {
			let IntMulOutput {
				a_evals,
				b_evals,
				c_lo_evals,
				c_hi_evals,
				eval_point,
			} = intmul_output;

			let r_zhat_prime = bitand_claim.r_zhat_prime;
			let subspace = BinarySubspace::<B8>::with_dim(LOG_WORD_SIZE_BITS)?.isomorphic();
			let l_tilde = lagrange_evals(&subspace, r_zhat_prime);
			let make_final_claim = |evals| izip!(evals, &l_tilde).map(|(x, y)| x * y).sum();
			OperatorData::new(
				r_zhat_prime,
				eval_point,
				[
					make_final_claim(a_evals),
					make_final_claim(b_evals),
					make_final_claim(c_lo_evals),
					make_final_claim(c_hi_evals),
				],
			)
		};

		// [phase] Verify Shift Reduction - shift operations and constraint validation
		let constraint_guard = tracing::info_span!(
			"[phase] Verify Shift Reduction",
			phase = "verify_shift_reduction",
			perfetto_category = "phase"
		)
		.entered();
		let VerifyOutput {
			witness_eval,
			public_eval,
			eval_point,
		} = verify_shift_reduction(self.constraint_system(), bitand_claim, intmul_claim, transcript)?;
		drop(constraint_guard);

		// [phase] Verify Public Input - public input verification
		let public_guard = tracing::info_span!(
			"[phase] Verify Public Input",
			phase = "verify_public_input",
			perfetto_category = "phase"
		)
		.entered();
		let (z_challenge, y_challenge) = eval_point.split_at(LOG_WORD_SIZE_BITS);
		let expected_public_eval =
			evaluate_public_mle(public, z_challenge, &y_challenge[..self.log_public_words()]);
		if public_eval != expected_public_eval {
			return Err(VerificationError::PublicInputCheckFailed.into());
		}
		drop(public_guard);

		// [phase] Verify PCS Opening - polynomial commitment verification
		let pcs_guard = tracing::info_span!(
			"[phase] Verify PCS Opening",
			phase = "verify_pcs_opening",
			perfetto_category = "phase"
		)
		.entered();
		pcs::verify(transcript, witness_eval, &eval_point, fri_verifier)?;
		drop(pcs_guard);

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
pub fn evaluate_public_mle<F: BinaryField>(public: &[Word], z_coords: &[F], y_coords: &[F]) -> F {
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

fn verify_bitand_reduction<F: BinaryField + From<B8>, Challenger_: Challenger>(
	log_constraint_count: usize,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<AndCheckOutput<F>, Error> {
	// The structure of the AND reduction requires that it verifies at least 2^3 word-level
	// constraints, you can zero-pad if necessary to reach this minimum
	assert!(log_constraint_count >= checked_log_2(binius_core::consts::MIN_AND_CONSTRAINTS));

	let big_field_zerocheck_challenges = transcript.sample_vec(log_constraint_count - 3);

	let mut all_zerocheck_challenges = vec![];

	let small_field_zerocheck_challenges = PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES
		.into_iter()
		.map(F::from)
		.collect_vec();

	let verifier_message_domain = BinarySubspace::<B8>::with_dim(LOG_WORD_SIZE_BITS + 1)
		.expect("dim is positive and less than field dim")
		.isomorphic();

	for small_field_challenge in small_field_zerocheck_challenges {
		all_zerocheck_challenges.push(small_field_challenge);
	}

	for big_field_challenge in &big_field_zerocheck_challenges {
		all_zerocheck_challenges.push(*big_field_challenge);
	}

	verify_with_transcript(&all_zerocheck_challenges, transcript, verifier_message_domain)
}

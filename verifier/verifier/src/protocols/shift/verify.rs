// Copyright 2025 Irreducible Inc.

use binius_core::constraint_system::{AndConstraint, ConstraintSystem, MulConstraint};
use binius_field::{AESTowerField8b, BinaryField, Field};
use binius_math::{multilinear::eq::eq_ind, univariate::evaluate_univariate};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::checked_arithmetics::strict_log_2;
use getset::CopyGetters;
use itertools::Itertools;

use super::{BITAND_ARITY, INTMUL_ARITY, error::Error, evaluate_monster_multilinear_for_operation};
use crate::{
	config::LOG_WORD_SIZE_BITS,
	protocols::sumcheck::{SumcheckOutput, verify as verify_sumcheck},
};

/// Verifier data for an operation with the specified arity.
///
/// Contains the challenge points and evaluation claims needed by the verifier.
/// The verifier receives these values during the protocol and uses them to
/// verify the monster multilinear evaluations.
///
/// # Fields
///
/// - `r_x_prime`: multilinear challenge point from the protocol
/// - `r_zhat_prime`: univariate challenge point
/// - `lambda`: random linear combination coefficient for operand weighting
/// - `evals`: array of evaluation claims, one per operand position
#[derive(Debug, Clone)]
pub struct OperatorData<F, const ARITY: usize> {
	pub r_x_prime: Vec<F>,
	pub r_zhat_prime: F,
	pub evals: [F; ARITY],
}

impl<F: Field, const ARITY: usize> OperatorData<F, ARITY> {
	// Constructs a new operator data instance encoding
	// evaluation claim with univariate challenge `r_zhat_prime`
	// multilinear challenge `r_x_prime`, and evaluations `evals`
	// with one eval for each operand of the operation.
	pub fn new(r_zhat_prime: F, r_x_prime: Vec<F>, evals: [F; ARITY]) -> Self {
		Self {
			r_x_prime,
			r_zhat_prime,
			evals,
		}
	}

	// Batching is scaled by random lambda and therefore this batched
	// evaluation claim can be added to other batched evaluation claims
	// without further random scaling.
	fn batched_eval(&self, lambda: F) -> F {
		lambda * evaluate_univariate(&self.evals, lambda)
	}
}

/// Output of the shift reduction verification protocol.
///
/// Contains all the challenge points, evaluation claims, and random coefficients
/// produced during the shift reduction protocol. These values are used for subsequent
/// verification steps including public input checking and PCS verification.
#[derive(Debug, CopyGetters)]
pub struct VerifyOutput<F: Field> {
	/// Random coefficient for batching AND constraint evaluations.
	bitand_lambda: F,
	/// Random coefficient for batching MUL constraint evaluations.
	intmul_lambda: F,
	/// Random coefficient for batching shift and public input checks.
	batch_coeff: F,
	/// Challenge point for the bit index variables (length `LOG_WORD_SIZE_BITS`).
	pub r_j: Vec<F>,
	/// Challenge point for the shift variables (length `LOG_WORD_SIZE_BITS`).
	pub r_s: Vec<F>,
	/// Challenge point for the word index variables (length `log_word_count`).
	pub r_y: Vec<F>,
	/// Final evaluation claim from the second sumcheck.
	eval: F,
	/// The claimed witness evaluation at the challenge point.
	#[getset(get_copy = "pub")]
	pub witness_eval: F,
	/// Challenge point for the public input/output variables.
	pub inout_eval_point: Vec<F>,
}

impl<F: Field> VerifyOutput<F> {
	/// Returns the challenge point for bit index variables.
	///
	/// This corresponds to the first `LOG_WORD_SIZE_BITS` variables
	/// in the witness encoding, indexing individual bits within words.
	pub fn r_j(&self) -> &[F] {
		&self.r_j
	}

	/// Returns the challenge point for shift variables.
	///
	/// This corresponds to `LOG_WORD_SIZE_BITS` variables encoding
	/// the shift operations in the constraint system.
	pub fn r_s(&self) -> &[F] {
		&self.r_s
	}

	/// Returns the challenge point for word index variables.
	///
	/// This corresponds to `log_word_count` variables indexing
	/// the words in the witness vector.
	pub fn r_y(&self) -> &[F] {
		&self.r_y
	}

	/// Returns the challenge point for public input/output variables.
	///
	/// This point is used for verifying consistency between the witness
	/// and public input multilinears.
	pub fn inout_eval_point(&self) -> &[F] {
		&self.inout_eval_point
	}
}

/// Verifies the shift protocol using a two-phase sumcheck approach.
///
/// # Protocol Overview
/// 1. **Sampling Phase**: Samples random lambda coefficients for batching bitand and intmul
///    evaluation claims across operands.
/// 2. **First Sumcheck**: Verifies the batched evaluation claim over `LOG_WORD_SIZE_BITS * 2`
///    variables
/// 3. **Challenge Splitting**: Splits sumcheck challenges into `r_j` and `r_s` components
/// 4. **Second Sumcheck**: Verifies the gamma claim over `log_word_count` variables
/// 5. **Monster Multilinear Verification**: Checks that the claimed evaluations match expected
///    monster multilinear evaluations for both AND constraints (bitand) and MUL constraints
///    (intmul)
///
/// # Parameters
/// - `constraint_system`: The constraint system containing AND and MUL constraints (consumed)
/// - `bitand_data`: Operator data for bit multiplication operations
/// - `intmul_data`: Operator data for integer multiplication operations
/// - `transcript`: Interactive transcript for challenge sampling and message reading
///
/// # Returns
/// Returns [`VerifyOutput`] containing the final challenges and witness evaluation,
/// or an error if verification fails.
///
/// # Errors
/// - Returns `Error::VerificationFailure` if monster multilinear evaluations don't match expected
///   values
/// - Propagates sumcheck verification errors
pub fn verify<F: BinaryField, C: Challenger>(
	constraint_system: &ConstraintSystem,
	bitand_data: &OperatorData<F, BITAND_ARITY>,
	intmul_data: &OperatorData<F, INTMUL_ARITY>,
	transcript: &mut VerifierTranscript<C>,
) -> Result<VerifyOutput<F>, Error> {
	let bitand_lambda = transcript.sample();
	let intmul_lambda = transcript.sample();

	let eval = bitand_data.batched_eval(bitand_lambda) + intmul_data.batched_eval(intmul_lambda);

	let SumcheckOutput {
		eval: gamma,
		challenges: mut r_jr_s,
	} = verify_sumcheck(LOG_WORD_SIZE_BITS * 2, 2, eval, transcript)?;

	r_jr_s.reverse();
	// Split challenges as `r_j,r_s` where `r_j` is the first `LOG_WORD_SIZE_BITS`
	// variables and `r_s` is the last `LOG_WORD_SIZE_BITS` variables
	// Thus `r_s` are the more significant variables.
	let r_s = r_jr_s.split_off(LOG_WORD_SIZE_BITS);
	let r_j = r_jr_s;

	let log_word_count = strict_log_2(constraint_system.value_vec_layout.committed_total_len)
		.expect("constraints preprocessed");
	let inout_n_vars = strict_log_2(constraint_system.value_vec_layout.offset_witness)
		.expect("constraints preprocessed");

	let inout_eval_point: Vec<F> = transcript.sample_vec(inout_n_vars);

	// Batch the `gamma` as the eval claim for the shift prover
	// together with zero as the eval claim for the inout prover.
	let batch_coeff: F = transcript.sample();
	let sum = gamma + batch_coeff * F::ZERO;

	let SumcheckOutput {
		eval,
		challenges: mut r_y,
	} = verify_sumcheck(log_word_count, 2, sum, transcript)?;

	r_y.reverse();

	let witness_eval = transcript.message().read::<F>()?;

	Ok(VerifyOutput {
		bitand_lambda,
		intmul_lambda,
		batch_coeff,
		r_j,
		r_y,
		r_s,
		eval,
		witness_eval,
		inout_eval_point,
	})
}

/// Validates the evaluation claims from the shift reduction protocol.
///
/// After the shift reduction protocol completes, this function checks that the
/// prover-provided witness evaluation is consistent with the expected values.
/// It computes the monster multilinear evaluations for both AND and MUL constraints
/// and verifies the final equation relating the witness, public, and monster evaluations.
///
/// # Protocol Details
///
/// The function verifies that:
/// ```text
/// eval = witness_eval * monster_eval + batch_coeff * eq_eval * (witness_eval - public_eval)
/// ```
///
/// Where:
/// - `monster_eval` is the sum of evaluations for AND and MUL constraint polynomials
/// - `eq_eval` is the evaluation of the equality indicator at the zero-padded public point
/// - `batch_coeff` is a random batching coefficient from the protocol
///
/// # Arguments
///
/// * `constraint_system` - The constraint system containing AND and MUL constraints
/// * `bitand_data` - Operator data for AND constraints (bit multiplication operations)
/// * `intmul_data` - Operator data for MUL constraints (integer multiplication operations)
/// * `output` - The output from the [`verify`] function containing challenge points and evaluations
/// * `public_eval` - The evaluation of the public input multilinear at the challenge point
///
/// # Returns
///
/// Returns `Ok(())` if the evaluation check passes, or `Error::VerificationFailure` if
/// the computed evaluation doesn't match the expected value.
///
/// # Errors
///
/// - `Error::VerificationFailure` if the evaluation equation doesn't hold
/// - Propagates errors from monster multilinear evaluation
pub fn check_eval<F>(
	constraint_system: &ConstraintSystem,
	bitand_data: &OperatorData<F, BITAND_ARITY>,
	intmul_data: &OperatorData<F, INTMUL_ARITY>,
	output: &VerifyOutput<F>,
	public_eval: F,
) -> Result<(), Error>
where
	F: BinaryField + From<AESTowerField8b>,
{
	let VerifyOutput {
		bitand_lambda,
		intmul_lambda,
		batch_coeff,
		eval,
		r_j,
		r_s,
		r_y,
		witness_eval,
		inout_eval_point,
	} = output;

	// Compute monster multilinear evaluation
	let monster_eval_for_bitand = {
		let (a, b, c) = constraint_system
			.and_constraints
			.iter()
			.map(|AndConstraint { a, b, c }| (a, b, c))
			.multiunzip();
		evaluate_monster_multilinear_for_operation(
			&[a, b, c],
			bitand_data,
			*bitand_lambda,
			r_j,
			r_s,
			r_y,
		)
	}?;
	let monster_eval_for_intmul = {
		let (a, b, lo, hi) = constraint_system
			.mul_constraints
			.iter()
			.map(|MulConstraint { a, b, hi, lo }| (a, b, lo, hi))
			.multiunzip();
		evaluate_monster_multilinear_for_operation(
			&[a, b, lo, hi],
			intmul_data,
			*intmul_lambda,
			r_j,
			r_s,
			r_y,
		)
	}?;
	let monster_eval = monster_eval_for_bitand + monster_eval_for_intmul;

	// Compute the evaluation of the eq indicator with r_y and the zero-padded inout point.
	let (r_y_head, r_y_tail) = r_y.split_at(inout_eval_point.len());
	let eq_eval_head = eq_ind(inout_eval_point, r_y_head);
	let eq_eval_tail = eq_ind(&vec![F::ZERO; r_y_tail.len()], r_y_tail);
	let eq_eval = eq_eval_head * eq_eval_tail;

	// Check if the prover-provided witness value is satisfying.
	//
	// The protocol could compute this witness value instead of reading it from the prover. This
	// would require inverting a random element, however, making the protocol incomplete with
	// negligible probability. As a matter of taste, we read the witness value from the prover.
	let expected_eval =
		*witness_eval * monster_eval + *batch_coeff * eq_eval * (*witness_eval - public_eval);
	if *eval != expected_eval {
		return Err(Error::VerificationFailure);
	}

	Ok(())
}

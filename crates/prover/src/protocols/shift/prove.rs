// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, Field, PackedField};
use binius_frontend::word::Word;
use binius_math::univariate::evaluate_univariate;
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::sumcheck::SumcheckOutput;
use tracing::instrument;

use super::{
	error::Error, phase_1::prove_phase_1, phase_2::prove_phase_2, record::ProverConstraintSystem,
	utils::tensor_expand_scalar,
};

/// Holds the prover data for an operator.
/// For an operator of arity ARITY, there are ARITY
/// columns with an oblong evaluation claim on each one.
/// The evaluations of these claims go in the `evals` field.
/// The univariate variable in the oblong evaluation point is
/// `r_zhat_prime`, and the multilinear variable is `r_x_prime`.
/// These two variables are already populated when the prover begins.
/// The prover will sample and assign `lambda`,
/// as well as compute the tensor expansion of `r_x_prime`.
/// The `records` hold preprocessed constraint system
/// information on each operand for the operator.
#[derive(Debug, Clone)]
pub struct OperatorData<F> {
	pub evals: Vec<F>,
	pub r_zhat_prime: F,
	pub r_x_prime: Vec<F>,
	// These fields filled at runtime
	pub r_x_prime_tensor: Vec<F>,
	pub lambda: F,
}

impl<F: Field> OperatorData<F> {
	// makes a new operator data instance, which
	pub fn new(r_zhat_prime: F, r_x_prime: Vec<F>, evals: Vec<F>) -> Self {
		let r_x_prime_tensor = tensor_expand_scalar(&r_x_prime, r_x_prime.len());

		Self {
			evals,
			lambda: F::ZERO,
			r_zhat_prime,
			r_x_prime,
			r_x_prime_tensor,
		}
	}

	/// Returns the batched evaluation of the oblong evaluation claims.
	/// Since the univariate evaluation of the evals at lambda is
	/// further multiplied by lambda, the batched evaluation claims
	/// for different operators can soundly be added without further
	/// random scaling.
	pub fn batched_eval(&self) -> F {
		self.lambda * evaluate_univariate(&self.evals, self.lambda)
	}
}

/// Proves the shift reduction.
///
/// Reduce the bitmul and intmul eval claims to a single multilinear claim on the witness
///
/// Assumptions:
/// - `words` has power-of-2 length
/// -
/// -
#[instrument(skip_all, name = "prove")]
pub fn prove<F: BinaryField, P: PackedField<Scalar = F>, C: Challenger>(
	record: ProverConstraintSystem,
	words: &[Word],
	inout_n_vars: usize,
	mut bitmul_data: OperatorData<F>,
	mut intmul_data: OperatorData<F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error> {
	// Sample and assign lambdas, one for each operator.
	bitmul_data.lambda = transcript.sample();
	intmul_data.lambda = transcript.sample();

	// Prove the first phase, receiving a `SumcheckOutput`
	// with challenges made of `r_j` and `r_s` (see below),
	// and eval equal to `gamma` (see paper).
	let phase_1_output =
		prove_phase_1::<_, P, C>(&record, words, &bitmul_data, &intmul_data, transcript)?;

	// Prove the second phase, receiving a `SumcheckOutput`
	// with challenges `r_y` and eval the evaluation of
	// the witness at oblong point had by univariate
	// variable `r_j` and multilinear variable `r_y`.
	let SumcheckOutput {
		challenges: r_y,
		eval,
	} = prove_phase_2::<_, P, C>(
		&record,
		inout_n_vars,
		words,
		&bitmul_data,
		&intmul_data,
		phase_1_output,
		transcript,
	)?;

	// Return evaluation claim on the witness.
	Ok(SumcheckOutput {
		challenges: r_y,
		eval,
	})
}

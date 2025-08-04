// Copyright 2025 Irreducible Inc.

use binius_field::Field;
use binius_math::{
	FieldBuffer, multilinear::eq::eq_ind_partial_eval, univariate::evaluate_univariate,
};

/// Holds the prover data for an operator.
///
/// Contains evaluation claims and challenge points for an operation.
///
/// Each operator (AND/MUL) has multiple operand positions, each with an oblong evaluation claim.
/// The `evals` field stores these claim evaluations. The evaluation points consist of:
/// - `r_zhat_prime`: univariate challenge point (pre-populated)
/// - `r_x_prime`: multilinear challenge point (pre-populated)
///
/// During proving, the prover samples `lambda` for operand weighting and computes the
/// tensor expansion of `r_x_prime` for efficient proving in both phases.
#[derive(Debug, Clone)]
pub struct OperatorData<F: Field> {
	pub evals: Vec<F>,
	pub r_zhat_prime: F,
	pub r_x_prime: Vec<F>,
	// These fields filled at runtime
	pub r_x_prime_tensor: FieldBuffer<F>,
	pub lambda: F,
}

impl<F: Field> OperatorData<F> {
	// Constructs a new operator data instance encoding
	// evaluation claim with univariate challenge `r_zhat_prime`
	// multilinear challenge `r_x_prime`, and evaluations `evals`
	// with one eval for each operand of the operation.
	pub fn new(r_zhat_prime: F, r_x_prime: Vec<F>, evals: Vec<F>) -> Self {
		let r_x_prime_tensor = eq_ind_partial_eval::<F>(&r_x_prime);

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

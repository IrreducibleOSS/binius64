// Copyright 2025 Irreducible Inc.

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
pub struct OperatorData<F> {
	pub evals: Vec<F>,
	pub r_zhat_prime: F,
	pub r_x_prime: Vec<F>,
	// These fields filled at runtime
	pub r_x_prime_tensor: Vec<F>,
	pub lambda: F,
}

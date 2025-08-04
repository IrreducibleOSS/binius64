// Copyright 2025 Irreducible Inc.

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
	pub lambda: F,
	pub evals: [F; ARITY],
}

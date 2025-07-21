use binius_field::Field;
use binius_math::{FieldBuffer, multilinear::eq::tensor_prod_eq_ind};

// given two lagrange basis coefficients and the leading coefficient for a
// univariate polynomial, compute the unique degree 2 polynomial intpolating
// (0, y_0), (1, y_1), and evaluate at x
pub fn evaluate_round_polynomial_at<F: Field>(x: F, round_msg: Vec<F>) -> F {
	let _span = tracing::debug_span!("evaluate round polynomial").entered();

	let (x_0, y_0) = (F::ZERO, round_msg[0]);
	let (x_1, y_1) = (F::ONE, round_msg[1]);

	let y_leading_coeff = round_msg[2];

	// lagrange basis polynomials
	let l_0 = (x - x_1)
		* (x_0 - x_1)
			.invert()
			.expect("x_0 - x_1 should be non-zero (x_0=0, x_1=1)");
	let l_1 = (x - x_0)
		* (x_1 - x_0)
			.invert()
			.expect("x_1 - x_0 should be non-zero (x_0=0, x_1=1)");
	let poly_with_leading_coeff = (x - x_0) * (x - x_1);

	l_0 * y_0 + l_1 * y_1 + poly_with_leading_coeff * y_leading_coeff
}

pub fn verify_sumcheck_round<F: Field>(
	round_sum_claim: F,
	expected_round_claim: F,
	round_msg: Vec<F>,
	sumcheck_challenge: F,
) -> F {
	let _span = tracing::debug_span!("verify round").entered();

	// first two coefficients of round message should match the sum claim
	// these are the evaluations of the univariate polynomial at 0, 1 and
	// (even/odd sum of boolean hypercube evals)
	assert_eq!(round_msg[0] + round_msg[1], round_sum_claim);

	// When the verifier receives the round message, it represents the coefficients
	// of the current univariate, partially specialized composition polynomial. By
	// evaluating this polynomial at the challenge, we determine what the honest
	// prover will claim as the sum for the next round. This is because the when
	// we fold the challenge into the multilinear, it is the same as partially
	// specializing the current composition polynomial w/ the challenge point.
	assert_eq!(expected_round_claim, round_sum_claim);

	// compute expected next round claim
	evaluate_round_polynomial_at(sumcheck_challenge, round_msg)
}

pub fn compute_mle_eq_sum<BigField: Field>(
	mle_values: &[BigField],
	eq_values: &[BigField],
) -> BigField {
	mle_values.iter().zip(eq_values).map(|(m, e)| *m * *e).sum()
}

pub fn eval_eq<F: Field>(zerocheck_challenges: &[F], eval_point: &[F]) -> F {
	zerocheck_challenges
		.iter()
		.zip(eval_point)
		.map(|(a, b)| F::ONE + a + b)
		.product()
}

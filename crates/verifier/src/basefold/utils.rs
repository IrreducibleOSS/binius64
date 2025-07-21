use binius_field::Field;

// given two lagrange basis coefficients and the leading coefficient for a
// univariate polynomial, compute the unique degree 2 polynomial intpolating
// (0, y_0), (1, y_1), and evaluate at x
pub fn evaluate_round_polynomial_at<F: Field>(
	x: F,
	round_msg: Vec<F>,
) -> F {
	let (x_0, y_0) = (F::ZERO, round_msg[0]);
	let (x_1, y_1) = (F::ONE, round_msg[1]);
	let y_leading_coeff = round_msg[2];

	// lagrange basis polynomials
	let l_0 = (x - x_1) * (x_0 - x_1).invert().unwrap();
	let l_1 = (x - x_0) * (x_1 - x_0).invert().unwrap();
	let poly_with_leading_coeff = (x - x_0) * (x - x_1);

	l_0 * y_0 + l_1 * y_1 + poly_with_leading_coeff * y_leading_coeff
}

pub fn verify_sumcheck_round<F: Field>(
	round_sum_claim: F,
	expected_round_claim: F,
	round_msg: Vec<F>,
	sumcheck_challenge: F,
) -> F {
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

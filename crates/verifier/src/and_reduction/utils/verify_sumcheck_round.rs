use binius_field::Field;

// given 4 lagrange basis coefficients for a univariate polynomial, compute
// lagrange basis polynomials and evaluate at x the resulting polynomial
fn evaluate_round_polynomial_at<F: Field>(x: F, zerocheck_challenge: F, round_msg: Vec<F>) -> F {
	let (x_0, y_0) = (F::ZERO, round_msg[0]);
	let (x_1, y_1) = (F::ONE, round_msg[1]);

	let leading_coeff = round_msg[2];

	// we are only interested in the multilinear composition (A * B - C) * eq_r,
	// we can factor eq_r = eq(x_0, x_1, ..., x_{n-1}, r_0, r_1, ..., r_{n-1})
	// into eq(x_0, r_0) * eq(x_1, .. x_{n-1}, r_1, .. r_{n-1}), of which
	// eq(x_0, r_0) = (1 - x_0)(1 - r_0) + (x_0)(r_0) = 1 - x_0 - r_0 + 2 * (x_0 * r_0)
	// However, because we are in a binary field, 2 * (x_0 * r_0) = 0, so we can simplify to
	// eq(x_0, r_0) = 1 - x_0 - r_0 = x_0 - (r_0 + 1)
	// This reveals to use that there is a root of the polynomial at x = r_0 + 1
	// meaning that the prover does not need to send this value explicitly, rather
	// the verifier can determine this evaluation by inference from the current
	// zerocheck challenge.
	let (x_2, y_2) = (zerocheck_challenge + F::ONE, F::ZERO);

	// lagrange basis polynomials
	let l_0 = ((x - x_1) * (x - x_2)) * ((x_0 - x_1) * (x_0 - x_2)).invert().unwrap();
	let l_1 = ((x - x_0) * (x - x_2)) * ((x_1 - x_0) * (x_1 - x_2)).invert().unwrap();
	let l_2 = ((x - x_0) * (x - x_1)) * ((x_2 - x_0) * (x_2 - x_1)).invert().unwrap();

	let vanishing_poly = (x - x_0) * (x - x_1) * (x - x_2);

	l_0 * y_0 + l_1 * y_1 + l_2 * y_2 + vanishing_poly * leading_coeff
}

// verifier checks for correctness of round message and claim
pub fn verify_round<F: Field>(
	round_sum_claim: F,
	round_msg: Vec<F>,
	sumcheck_challenge: F,
	zerocheck_challenge: F,
) -> F {
	// first two coefficients of round message should match the sum claim
	// these are the evaluations of the univariate polynomial at 0, 1 and
	// (even/odd sum of boolean hypercube evals)
	assert_eq!(round_msg[0] + round_msg[1], round_sum_claim);

	// compute expected next round claim
	evaluate_round_polynomial_at(sumcheck_challenge, zerocheck_challenge, round_msg)
}
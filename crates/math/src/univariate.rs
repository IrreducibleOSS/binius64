// Copyright 2023-2025 Irreducible Inc.

pub fn evaluate_univariate<F: binius_field::Field>(coeffs: &[F], x: F) -> F {
	// Evaluate using Horner's method
	coeffs
		.iter()
		.rfold(F::ZERO, |eval, &coeff| eval * x + coeff)
}

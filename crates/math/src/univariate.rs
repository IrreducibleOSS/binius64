use binius_field::Field;

/// Evaluate a univariate polynomial specified by its monomial coefficients.
///
/// # Arguments
/// * `coeffs` - Slice of coefficients ordered from low-degree terms to high-degree terms
/// * `x` - Point at which to evaluate the polynomial
pub fn evaluate_univariate<F: Field>(coeffs: &[F], x: F) -> F {
	let Some((&highest_degree, rest)) = coeffs.split_last() else {
		return F::ZERO;
	};

	// Evaluate using Horner's method
	rest.iter()
		.rev()
		.fold(highest_degree, |acc, &coeff| acc * x + coeff)
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash, Field, Random, util::powers};
	use rand::prelude::*;

	use super::*;
	use crate::{inner_product::inner_product, test_utils::random_scalars};

	fn evaluate_univariate_with_powers<F: Field>(coeffs: &[F], x: F) -> F {
		inner_product(coeffs.iter().copied(), powers(x).take(coeffs.len()))
	}

	type F = BinaryField128bGhash;

	#[test]
	fn test_evaluate_univariate_against_reference() {
		let mut rng = StdRng::seed_from_u64(0);

		for n_coeffs in [0, 1, 2, 5, 10] {
			let coeffs = random_scalars(&mut rng, n_coeffs);
			let x = F::random(&mut rng);
			assert_eq!(
				evaluate_univariate(&coeffs, x),
				evaluate_univariate_with_powers(&coeffs, x)
			);
		}
	}
}

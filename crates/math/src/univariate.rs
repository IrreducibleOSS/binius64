use binius_field::{BinaryField, Field};

use crate::Error;

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

/// Creates a subspace of dimension `dim` by enumerating all binary combinations
/// of the first `dim` basis elements. Returns a vector of 2^dim elements.
///
/// ## Throws
///
/// * `Error::DomainSizeTooLarge` if `dim` is greater than the field dimension.
pub fn make_subspace<F: BinaryField>(dim: usize) -> Result<Vec<F>, Error> {
	let basis: Vec<F> = (0..dim)
		.map(|i| F::basis_checked(i).map_err(|_| Error::DomainSizeTooLarge))
		.collect::<Result<Vec<_>, _>>()?;

	let subspace = (0..1 << dim)
		.map(|combination| {
			basis
				.iter()
				.enumerate()
				.filter_map(|(i, &b)| ((combination >> i) & 1 == 1).then_some(b))
				.sum()
		})
		.collect();

	Ok(subspace)
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

	#[test]
	fn test_make_subspace() {
		fn compare_subspace_with_direct_construction(dim: usize) {
			let subspace = make_subspace::<F>(dim).unwrap();
			let direct_subspace = (0..1 << dim).map(|i| F::new(i)).collect::<Vec<_>>();
			assert_eq!(subspace, direct_subspace);
		}
		compare_subspace_with_direct_construction(0);
		compare_subspace_with_direct_construction(1);
		compare_subspace_with_direct_construction(2);
		compare_subspace_with_direct_construction(6);
	}
}

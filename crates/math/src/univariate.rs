// Copyright 2025 Irreducible Inc.

use binius_field::Field;

use super::Error;

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

/// Computes barycentric weights for Lagrange interpolation.
///
/// Given a set of distinct interpolation points π₀, π₁, ..., πₙ₋₁, the barycentric weight
/// for point πᵢ is defined as:
///
/// ```text
/// wᵢ = 1 / ∏(j≠i) (πᵢ - πⱼ)
/// ```
///
/// These weights are used in barycentric Lagrange interpolation to efficiently evaluate
/// polynomials at arbitrary points without recomputing the full Lagrange basis.
///
/// # Mathematical Background
///
/// The Lagrange interpolating polynomial through points (π₀, y₀), ..., (πₙ₋₁, yₙ₋₁)
/// can be written in barycentric form as:
///
/// ```text
/// P(x) = (∑ᵢ wᵢ·yᵢ/(x - πᵢ)) / (∑ᵢ wᵢ/(x - πᵢ))
/// ```
///
/// where wᵢ are the barycentric weights computed by this function.
///
/// # Arguments
///
/// * `points` - A slice of distinct field elements representing the interpolation domain
///
/// # Returns
///
/// A vector of barycentric weights, where `weights[i]` corresponds to `points[i]`
///
/// # Panics
///
/// Panics if any two points in the domain are identical (duplicate domain points),
/// as this would make the interpolation problem ill-defined.
///
/// # Complexity
///
/// Time: O(n²) where n is the number of points
/// Space: O(n) for the output vector
fn compute_barycentric_weights<F: Field>(points: &[F]) -> Result<Vec<F>, Error> {
	let n = points.len();
	(0..n)
		.map(|i| {
			// Compute ∏(j≠i) (πᵢ - πⱼ)
			let product = (0..n)
				.filter(|&j| j != i)
				.map(|j| points[i] - points[j])
				.product::<F>();
			// Return wᵢ = 1 / ∏(j≠i) (πᵢ - πⱼ)
			product.invert().ok_or(Error::DuplicateDomainPoint)
		})
		.collect()
}

/// Compute a vector of Lagrange polynomial evaluations in $O(N)$ at a given point `x`.
///
/// For an evaluation domain consisting of points $\pi_i$ Lagrange polynomials $L_i(x)$
/// are defined by
/// $$L_i(x) = \sum_{j \neq i}\frac{x - \pi_j}{\pi_i - \pi_j}$$
pub fn lagrange_evals<F: Field>(points: &[F], x: F) -> Result<Vec<F>, Error> {
	let num_evals = points.len();

	let mut result: Vec<F> = vec![F::ONE; num_evals];

	// Multiply the product suffixes
	for i in (1..num_evals).rev() {
		result[i - 1] = result[i] * (x - points[i]);
	}

	let mut prefix = F::ONE;

	let weights = compute_barycentric_weights(points)?;

	// Multiply the product prefixes and weights
	for ((r, point), weight) in result.iter_mut().zip(points).zip(weights) {
		*r *= prefix * weight;
		prefix *= x - point;
	}

	Ok(result)
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

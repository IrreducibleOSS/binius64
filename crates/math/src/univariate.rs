// Copyright 2024-2025 Irreducible Inc.

use binius_field::{BinaryField, Field};

use super::BinarySubspace;

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

/// Optimized Lagrange evaluation for power-of-2 domains in binary fields.
///
/// Computes the Lagrange polynomial evaluations L̃(z, i) for a power-of-2 domain at point `z`.
/// Uses the provided binary subspace as the evaluation domain.
///
/// # Key Optimization
/// For power-of-2 domains, all barycentric weights are identical due to the additive group
/// structure. For each i ∈ {0, ..., 2^k - 1}, the set {i ⊕ j | j ≠ i} = {1, ..., 2^k - 1}.
/// This allows us to:
/// 1. Compute a single barycentric weight w = 1 / ∏_{j=1}^{n-1} j
/// 2. Use prefix/suffix products to avoid redundant computation
/// 3. Replace inversions with multiplications for better performance
///
/// # Complexity
/// - Time: O(n) where n = subspace size, using 4n - 2 multiplications and 1 inversion
/// - Space: O(n) for prefix/suffix arrays
///
/// # Parameters
/// - `subspace`: The binary subspace defining the evaluation domain
/// - `z`: The evaluation point
///
/// # Returns
/// A vector of Lagrange polynomial evaluations, one for each domain element
pub fn lagrange_evals<F: BinaryField>(subspace: &BinarySubspace<F>, z: F) -> Vec<F> {
	let domain: Vec<F> = subspace.iter().collect();
	let n = domain.len();

	// Compute single barycentric weight for the additive subgroup
	// All points have the same weight due to subgroup structure
	let w = domain[1..]
		.iter()
		.fold(F::ONE, |acc, &d| acc * d)
		.invert()
		.unwrap_or(F::ONE);

	// Compute prefix products: prefix[i] = ∏_{j=0}^{i-1} (z - domain[j])
	let mut prefixes = vec![F::ONE; n];
	for i in 1..n {
		prefixes[i] = prefixes[i - 1] * (z - domain[i - 1]);
	}

	// Compute suffix products: suffix[i] = ∏_{j=i+1}^{n-1} (z - domain[j])
	let mut suffixes = vec![F::ONE; n];
	for i in (0..n - 1).rev() {
		suffixes[i] = suffixes[i + 1] * (z - domain[i + 1]);
	}

	// Combine prefix, suffix, and weight: L_i(z) = prefix[i] * suffix[i] * w
	let mut result = vec![F::ZERO; n];
	for i in 0..n {
		result[i] = prefixes[i] * suffixes[i] * w;
	}

	result
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField128bGhash, Field, Random, util::powers};
	use rand::prelude::*;

	use super::*;
	use crate::{BinarySubspace, inner_product::inner_product, test_utils::random_scalars};

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
	fn test_lagrange_evals() {
		let mut rng = StdRng::seed_from_u64(0);

		// Test mathematical properties across different domain sizes
		for log_domain_size in [3, 4, 5, 6] {
			// Create subspace for this test
			let subspace = BinarySubspace::<F>::with_dim(log_domain_size).unwrap();
			let domain: Vec<F> = subspace.iter().collect();

			// Test 1: Partition of Unity - Lagrange polynomials sum to 1
			let eval_point = F::random(&mut rng);
			let lagrange_coeffs = lagrange_evals(&subspace, eval_point);
			let sum: F = lagrange_coeffs.iter().copied().sum();
			assert_eq!(
				sum,
				F::ONE,
				"Partition of unity failed for domain size {}",
				1 << log_domain_size
			);

			// Test 2: Interpolation Property - L_i(x_j) = δ_ij
			for (j, &domain_point) in domain.iter().enumerate() {
				let lagrange_at_domain = lagrange_evals(&subspace, domain_point);
				for (i, &coeff) in lagrange_at_domain.iter().enumerate() {
					let expected = if i == j { F::ONE } else { F::ZERO };
					assert_eq!(
						coeff, expected,
						"Interpolation property failed: L_{i}({j}) ≠ {expected}"
					);
				}
			}
		}

		// Test 3: Polynomial Interpolation Accuracy
		let log_domain_size = 6;
		let subspace = BinarySubspace::<F>::with_dim(log_domain_size).unwrap();
		let domain: Vec<F> = subspace.iter().collect();
		let coeffs = random_scalars(&mut rng, 10);

		// Evaluate polynomial at domain points
		let domain_evals: Vec<F> = domain
			.iter()
			.map(|&point| evaluate_univariate(&coeffs, point))
			.collect();

		// Test interpolation at random point
		let test_point = F::random(&mut rng);
		let lagrange_coeffs = lagrange_evals(&subspace, test_point);
		let interpolated =
			inner_product(domain_evals.iter().copied(), lagrange_coeffs.iter().copied());
		let direct = evaluate_univariate(&coeffs, test_point);

		assert_eq!(interpolated, direct, "Polynomial interpolation accuracy failed");
	}
}

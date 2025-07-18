// Copyright 2025 Irreducible Inc.

use binius_field::Field;

/// Evaluates the less-than-or-equal indicator multilinear polynomial.
///
/// This is an $n$-variate multilinear polynomial parameterized by an $n$-bit threshold. This is
/// the multilinear extension of the function mapping hypercube vertex $i$ to the boolean
/// $i \le \texttt{threshold}$.
///
/// ## Algorithm
///
/// The evaluation works by processing the binary representation of the threshold bit by bit.
/// For each coordinate $x_j$ in the evaluation point, we update the result based on whether
/// the $j$-th bit of the threshold (counting from LSB) is 0 or 1:
/// - If bit is 1: interpolate a line that is 1 at $x_j = 0$ and `result` at $x_j = 1$
/// - If bit is 0: interpolate a line that is `result` at $x_j = 0$ and 0 at $x_j = 1$
///
/// ## Example
///
/// For `threshold = 5` (binary: 101) and `n = 3`:
/// - On hypercube: maps (0,0,0) → 1, (1,0,0) → 1, ..., (1,0,1) → 1, (0,1,1) → 0, (1,1,1) → 0
/// - The multilinear extension interpolates these values
///
/// ## Panics
///
/// Panics if `threshold >= 2^n`, where `n` is the length of `point`.
pub fn less_than_or_equal_ind<F: Field>(threshold: usize, point: &[F]) -> F {
	let n = point.len();
	assert!(
		threshold < (1 << n),
		"threshold must be less than 2^n where n is the number of variables"
	);

	let mut k = threshold;
	let mut result = F::ONE;

	for coord in point {
		if k & 1 == 1 {
			// Current bit is 1: interpolate a line that is 1 at 0 and `result` at 1
			result = (F::ONE - coord) + result * coord;
		} else {
			// Current bit is 0: interpolate a line that is `result` at 0 and 0 at 1
			result *= F::ONE - coord;
		}
		k >>= 1;
	}

	result
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField1b, BinaryField128bGhash};
	use proptest::prelude::*;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::test_utils::{index_to_hypercube_point, random_scalars};

	// Custom strategy for generating (n_vars, threshold, vertex_index) triples
	fn test_parameters() -> impl Strategy<Value = (usize, usize, usize)> {
		(0usize..10).prop_flat_map(|n_vars| {
			let max_value = 1 << n_vars;
			(Just(n_vars), 0usize..max_value, 0usize..max_value)
		})
	}

	proptest! {
		#[test]
		fn test_less_than_or_equal_ind_hypercube_vertices(
			(n_vars, threshold, vertex_index) in test_parameters()
		) {
			let vertex = index_to_hypercube_point::<BinaryField1b>(n_vars, vertex_index);
			let result = less_than_or_equal_ind(threshold, &vertex);
			let expected = if vertex_index <= threshold {
				BinaryField1b::ONE
			} else {
				BinaryField1b::ZERO
			};

			prop_assert_eq!(
				result, expected,
				"Failed for n_vars={}, threshold={}, vertex_index={}",
				n_vars, threshold, vertex_index
			);
		}
	}

	#[test]
	fn test_less_than_or_equal_ind_multilinearity() {
		// Test that the polynomial is indeed multilinear by checking degree in each variable
		let mut rng = StdRng::seed_from_u64(0);

		// For n=3, threshold=5
		let n = 3;
		let threshold = 5;

		// Generate random evaluation points
		let x = random_scalars::<BinaryField128bGhash>(&mut rng, n);

		// Check linearity in each variable
		for i in 0..n {
			let mut x_at_0 = x.clone();
			x_at_0[i] = BinaryField128bGhash::ZERO;
			let mut x_at_1 = x.clone();
			x_at_1[i] = BinaryField128bGhash::ONE;

			let f_at_0 = less_than_or_equal_ind(threshold, &x_at_0);
			let f_at_1 = less_than_or_equal_ind(threshold, &x_at_1);
			let f_at_y = less_than_or_equal_ind(threshold, &x);

			// Linear interpolation: f(y_i) = f(0)*(1-y_i) + f(1)*y_i
			let expected = f_at_0 * (BinaryField128bGhash::ONE - x[i]) + f_at_1 * x[i];
			assert_eq!(f_at_y, expected, "Not linear in variable {i}");
		}
	}

	#[test]
	#[should_panic(expected = "threshold must be less than 2^n")]
	fn test_less_than_or_equal_ind_panic_threshold_too_large() {
		// For n=3, threshold must be < 8
		less_than_or_equal_ind(8, &[BinaryField1b::ZERO; 3]);
	}
}

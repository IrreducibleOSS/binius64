// Copyright 2025 Irreducible Inc.

use binius_field::Field;
use itertools::izip;

/// Expands a vector into a multilinear tensor (using Ben's Python algo)
pub fn tensor_expand<F: Field>(x: &[F], n_vars: usize) -> Vec<F> {
	let mut result = vec![F::ONE; 1 << n_vars];

	for i in 0..n_vars {
		for j in 0..(1 << i) {
			result[(1 << i) | j] = result[j] * x[i];
			let temp = result[(1 << i) | j];
			result[j] -= temp;
		}
	}

	result
}

/// Take the inner product of two field slices.
/// If the slices are not the same length, the smaller one is padded with zeros.
pub fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
	izip!(a, b).map(|(&a, &b)| a * b).sum()
}

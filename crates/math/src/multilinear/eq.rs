// Copyright 2024-2025 Irreducible Inc.

use std::{iter, ops::DerefMut};

use binius_field::{Field, PackedField};
use binius_maybe_rayon::prelude::*;

use crate::{Error, FieldBuffer};

/// Tensor of values with the eq indicator evaluated at extra_query_coordinates.
///
/// Let $n$ be log_n_values, $p$, $k$ be the lengths of `packed_values` and
/// `extra_query_coordinates`. Requires
///     * $n \geq k$
///     * p = max(1, 2^{n+k} / P::WIDTH)
/// Let $v$ be a vector corresponding to the first $2^n$ scalar values of `values`.
/// Let $r = (r_0, \ldots, r_{k-1})$ be the vector of `extra_query_coordinates`.
///
/// # Formal Definition
/// `values` is updated to contain the result of:
/// $v \otimes (1 - r_0, r_0) \otimes \ldots \otimes (1 - r_{k-1}, r_{k-1})$
/// which is now a vector of length $2^{n+k}$. If 2^{n+k} < P::WIDTH, then
/// the result is packed into a single element of `values` where only the first
/// 2^{n+k} elements have meaning.
///
/// # Interpretation
/// Let $f$ be an $n$ variate multilinear polynomial that has evaluations over
/// the $n$ dimensional hypercube corresponding to $v$.
/// Then `values` is updated to contain the evaluations of $g$ over the $n+k$-dimensional
/// hypercube where
/// * $g(x_0, \ldots, x_{n+k-1}) = f(x_0, \ldots, x_{n-1}) * eq(x_n, \ldots, x_{n+k-1}, r)$
pub fn tensor_prod_eq_ind<P: PackedField, Data: DerefMut<Target = [P]>>(
	log_n_values: usize,
	values: &mut FieldBuffer<P, Data>,
	extra_query_coordinates: &[P::Scalar],
) -> Result<(), Error> {
	let n_extra = extra_query_coordinates.len();
	let new_n_vars = log_n_values + n_extra;
	let expected_len = 1 << new_n_vars;
	if values.len() != expected_len {
		return Err(Error::IncorrectArgumentLength {
			arg: "packed_values".to_string(),
			expected: expected_len,
		});
	}

	if extra_query_coordinates.is_empty() {
		return Ok(());
	}

	values.split_half_mut(|lo, hi| {
		tensor_prod_eq_ind(log_n_values, lo, &extra_query_coordinates[..n_extra - 1])?;

		let r_i = &extra_query_coordinates[n_extra - 1];
		let packed_r_i = P::broadcast(*r_i);

		lo.as_mut()
			.par_iter_mut()
			.zip(hi.as_mut().par_iter_mut())
			.for_each(|(lo_i, hi_i)| {
				let prod = (*lo_i) * packed_r_i;
				*lo_i -= prod;
				*hi_i = prod;
			});

		Ok(())
	})??;

	Ok(())
}

/// Computes the partial evaluation of the equality indicator polynomial.
///
/// Given an $n$-coordinate point $r_0, ..., r_n$, this computes the partial evaluation of the
/// equality indicator polynomial $\widetilde{eq}(X_0, ..., X_{n-1}, r_0, ..., r_{n-1})$ and
/// returns its values over the $n$-dimensional hypercube.
///
/// The returned values are equal to the tensor product
///
/// $$
/// (1 - r_0, r_0) \otimes ... \otimes (1 - r_{n-1}, r_{n-1}).
/// $$
///
/// See [DP23], Section 2.1 for more information about the equality indicator polynomial.
///
/// [DP23]: <https://eprint.iacr.org/2023/1784>
pub fn eq_ind_partial_eval<P: PackedField>(point: &[P::Scalar]) -> FieldBuffer<P> {
	// The buffer needs to have the correct size: 2^max(point.len(), P::LOG_WIDTH) elements
	// but since tensor_prod_eq_ind starts with log_n_values=0, we need the final size
	let log_size = point.len();
	let mut buffer = FieldBuffer::zeros(log_size);
	buffer
		.set(0, P::Scalar::ONE)
		.expect("buffer has length at least 1");
	tensor_prod_eq_ind(0, &mut buffer, point).expect("buffer is allocated with the correct length");
	buffer
}

/// Evaluates the 2-variate multilinear which indicates the equality condition over the hypercube.
///
/// This evaluates the bivariate polynomial
///
/// $$
/// \widetilde{eq}(X, Y) = X Y + (1 - X) (1 - Y)
/// $$
///
/// In the special case of binary fields, the evaluation can be simplified to
///
/// $$
/// \widetilde{eq}(X, Y) = X + Y + 1
/// $$
#[inline(always)]
pub fn eq_one_var<F: Field>(x: F, y: F) -> F {
	if F::CHARACTERISTIC == 2 {
		// Optimize away the multiplication for binary fields
		x + y + F::ONE
	} else {
		x * y + (F::ONE - x) * (F::ONE - y)
	}
}

/// Evaluates the equality indicator multilinear at a pair of coordinates.
///
/// This evaluates the 2n-variate multilinear polynomial
///
/// $$
/// \widetilde{eq}(X_0, \ldots, X_{n-1}, Y_0, \ldots, Y_{n-1}) = \prod_{i=0}^{n-1} X_i Y_i + (1 -
/// X_i) (1 - Y_i) $$
///
/// In the special case of binary fields, the evaluation can be simplified to
///
/// See [DP23], Section 2.1 for more information about the equality indicator polynomial.
///
/// [DP23]: <https://eprint.iacr.org/2023/1784>
pub fn eq_ind<F: Field>(x: &[F], y: &[F]) -> F {
	assert_eq!(x.len(), y.len(), "pre-condition: x and y must be the same length");
	iter::zip(x, y).map(|(&x, &y)| eq_one_var(x, y)).product()
}

#[cfg(test)]
mod tests {
	use binius_field::{Field, PackedBinaryField4x32b};
	use rand::prelude::*;

	use super::*;

	type P = PackedBinaryField4x32b;
	type F = <P as PackedField>::Scalar;

	#[test]
	fn test_tensor_prod_eq_ind() {
		let v0 = F::from(1);
		let v1 = F::from(2);
		let query = vec![v0, v1];
		// log_n_values = 0, query.len() = 2, so total log_len = 2
		let mut result = FieldBuffer::zeros(query.len());
		result.set(0, F::ONE).unwrap();
		tensor_prod_eq_ind(0, &mut result, &query).unwrap();
		let result_vec: Vec<F> = P::iter_slice(result.as_ref()).collect();
		assert_eq!(
			result_vec,
			vec![
				(F::ONE - v0) * (F::ONE - v1),
				v0 * (F::ONE - v1),
				(F::ONE - v0) * v1,
				v0 * v1
			]
		);
	}

	#[test]
	fn test_eq_ind_partial_eval_empty() {
		let result = eq_ind_partial_eval::<P>(&[]);
		// For P with LOG_WIDTH = 2, the minimum buffer size is 4 elements
		assert_eq!(result.log_len(), 0);
		assert_eq!(result.len(), 1);
		let mut result_mut = result;
		assert_eq!(result_mut.get(0).unwrap(), F::ONE);
	}

	#[test]
	fn test_eq_ind_partial_eval_single_var() {
		// Only one query coordinate
		let r0 = F::new(2);
		let result = eq_ind_partial_eval::<P>(&[r0]);
		assert_eq!(result.log_len(), 1);
		assert_eq!(result.len(), 2);
		let mut result_mut = result;
		assert_eq!(result_mut.get(0).unwrap(), F::ONE - r0);
		assert_eq!(result_mut.get(1).unwrap(), r0);
	}

	#[test]
	fn test_eq_ind_partial_eval_two_vars() {
		// Two query coordinates
		let r0 = F::new(2);
		let r1 = F::new(3);
		let result = eq_ind_partial_eval::<P>(&[r0, r1]);
		assert_eq!(result.log_len(), 2);
		assert_eq!(result.len(), 4);
		let result_vec: Vec<F> = P::iter_slice(result.as_ref()).collect();
		let expected = vec![
			(F::ONE - r0) * (F::ONE - r1),
			r0 * (F::ONE - r1),
			(F::ONE - r0) * r1,
			r0 * r1,
		];
		assert_eq!(result_vec, expected);
	}

	#[test]
	fn test_eq_ind_partial_eval_three_vars() {
		// Case with three query coordinates
		let r0 = F::new(2);
		let r1 = F::new(3);
		let r2 = F::new(5);
		let result = eq_ind_partial_eval::<P>(&[r0, r1, r2]);
		assert_eq!(result.log_len(), 3);
		assert_eq!(result.len(), 8);
		let result_vec: Vec<F> = P::iter_slice(result.as_ref()).collect();

		let expected = vec![
			(F::ONE - r0) * (F::ONE - r1) * (F::ONE - r2),
			r0 * (F::ONE - r1) * (F::ONE - r2),
			(F::ONE - r0) * r1 * (F::ONE - r2),
			r0 * r1 * (F::ONE - r2),
			(F::ONE - r0) * (F::ONE - r1) * r2,
			r0 * (F::ONE - r1) * r2,
			(F::ONE - r0) * r1 * r2,
			r0 * r1 * r2,
		];
		assert_eq!(result_vec, expected);
	}

	// Property-based test that eq_ind_partial_eval is consistent with eq_ind at a random index.
	#[test]
	fn test_eq_ind_partial_eval_consistent_on_hypercube() {
		let mut rng = StdRng::seed_from_u64(0);

		// Create a random 5-variate point
		let point: Vec<F> = (0..5).map(|_| <F as Field>::random(&mut rng)).collect();

		// Call eq_ind_partial_eval
		let result = eq_ind_partial_eval::<P>(&point);
		assert_eq!(result.log_len(), 5);
		assert_eq!(result.len(), 32);

		// Choose a random index between 0 and 31
		let index: usize = rng.random_range(0..32);

		// Query the value at that index
		let mut result_mut = result;
		let partial_eval_value = result_mut.get(index).unwrap();

		// Decompose the index as a slice of F::ZERO and F::ONE bits
		let index_bits: Vec<F> = (0..5)
			.map(|i| {
				if (index >> i) & 1 == 1 {
					F::ONE
				} else {
					F::ZERO
				}
			})
			.collect();

		// Call eq_ind with the point and the index bits
		let eq_ind_value = eq_ind(&point, &index_bits);

		// Assert that both values are equal
		assert_eq!(partial_eval_value, eq_ind_value);
	}
}

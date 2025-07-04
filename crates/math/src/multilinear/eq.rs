// Copyright 2024-2025 Irreducible Inc.

use std::cmp::max;

use binius_field::{Field, PackedField};
use binius_maybe_rayon::prelude::*;
use bytemuck::zeroed_vec;

use crate::Error;

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
pub fn tensor_prod_eq_ind<P: PackedField>(
	log_n_values: usize,
	packed_values: &mut [P],
	extra_query_coordinates: &[P::Scalar],
) -> Result<(), Error> {
	let new_n_vars = log_n_values + extra_query_coordinates.len();
	let expected_len = 1 << max(new_n_vars, P::LOG_WIDTH);
	if packed_values.len() != 1 << new_n_vars.saturating_sub(P::LOG_WIDTH) {
		return Err(Error::IncorrectArgumentLength {
			arg: "packed_values".to_string(),
			expected: expected_len,
		});
	}

	for (i, r_i) in extra_query_coordinates.iter().enumerate() {
		let prev_length = 1 << (log_n_values + i);
		if prev_length < P::WIDTH {
			let q = &mut packed_values[0];
			for h in 0..prev_length {
				let x = q.get(h);
				let prod = x * r_i;
				q.set(h, x - prod);
				q.set(prev_length | h, prod);
			}
		} else {
			let prev_packed_length = prev_length / P::WIDTH;
			let packed_r_i = P::broadcast(*r_i);
			let (xs, ys) = packed_values.split_at_mut(prev_packed_length);
			assert!(xs.len() <= ys.len());

			// These magic numbers were chosen experimentally to have a reasonable performance
			// for the calls with small number of elements.
			xs.par_iter_mut()
				.zip(ys.par_iter_mut())
				.with_min_len(64)
				.for_each(|(x, y)| {
					// x = x * (1 - packed_r_i) = x - x * packed_r_i
					// y = x * packed_r_i
					// Notice that we can reuse the multiplication: (x * packed_r_i)
					let prod = (*x) * packed_r_i;
					*x -= prod;
					*y = prod;
				});
		}
	}
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
pub fn eq_ind_partial_eval<P: PackedField>(point: &[P::Scalar]) -> Vec<P> {
	let n = point.len();
	let len = 1 << n.saturating_sub(P::LOG_WIDTH);
	let mut buffer = zeroed_vec::<P>(len);
	buffer[0].set(0, P::Scalar::ONE);
	tensor_prod_eq_ind(0, &mut buffer, point).expect("buffer is allocated with the correct length");
	buffer
}

#[cfg(test)]
mod tests {
	use binius_field::{Field, PackedBinaryField4x32b, packed::set_packed_slice};
	use itertools::Itertools;

	use super::*;

	type P = PackedBinaryField4x32b;
	type F = <P as PackedField>::Scalar;

	#[test]
	fn test_tensor_prod_eq_ind() {
		let v0 = F::from(1);
		let v1 = F::from(2);
		let query = vec![v0, v1];
		let mut result = vec![P::default(); 1 << (query.len() - P::LOG_WIDTH)];
		set_packed_slice(&mut result, 0, F::ONE);
		tensor_prod_eq_ind(0, &mut result, &query).unwrap();
		let result = PackedField::iter_slice(&result).collect_vec();
		assert_eq!(
			result,
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
		let expected = vec![P::set_single(F::ONE)];
		assert_eq!(result, expected);
	}

	#[test]
	fn test_eq_ind_partial_eval_single_var() {
		// Only one query coordinate
		let r0 = F::new(2);
		let result = eq_ind_partial_eval::<P>(&[r0]);
		let expected = vec![(F::ONE - r0), r0, F::ZERO, F::ZERO];
		let result = PackedField::iter_slice(&result).collect_vec();
		assert_eq!(result, expected);
	}

	#[test]
	fn test_eq_ind_partial_eval_two_vars() {
		// Two query coordinates
		let r0 = F::new(2);
		let r1 = F::new(3);
		let result = eq_ind_partial_eval::<P>(&[r0, r1]);
		let result = PackedField::iter_slice(&result).collect_vec();
		let expected = vec![
			(F::ONE - r0) * (F::ONE - r1),
			r0 * (F::ONE - r1),
			(F::ONE - r0) * r1,
			r0 * r1,
		];
		assert_eq!(result, expected);
	}

	#[test]
	fn test_eq_ind_partial_eval_three_vars() {
		// Case with three query coordinates
		let r0 = F::new(2);
		let r1 = F::new(3);
		let r2 = F::new(5);
		let result = eq_ind_partial_eval::<P>(&[r0, r1, r2]);
		let result = PackedField::iter_slice(&result).collect_vec();

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
		assert_eq!(result, expected);
	}
}

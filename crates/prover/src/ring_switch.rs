// Copyright 2025 Irreducible Inc.

use binius_field::{
	BinaryField, ExtensionField, Field, PackedExtension, PackedField, PackedSubfield,
};
use binius_math::{
	FieldBuffer, inner_product::inner_product_subfield, multilinear::eq::eq_ind_partial_eval,
};
use binius_utils::rayon::prelude::*;
use binius_verifier::config::B1;

/// Compute the multilinear extension of the ring switching equality indicator.
///
/// The ring switching equality indicator is the multilinear function $A$ from [DP24],
/// Construction 3.1. Its multilinear extension is computed by basis decomposing the
/// field extension elements of the tensor expanded z_vals point, then recombining
/// the sub field basis elements with the large field tensor expanded row batching
/// scalars.
///
/// ## Arguments
///
/// * `batching_challenges` - the scaling elements for row-batching
/// * `z_vals` - the vertical evaluation point, with $\ell'$ components
///
/// ## Pre-conditions
///
/// * the length of batching challenges must equal `FE::LOG_DEGREE`
///
/// [DP24]: <https://eprint.iacr.org/2024/504>
pub fn rs_eq_ind<F: BinaryField>(batching_challenges: &[F], z_vals: &[F]) -> FieldBuffer<F> {
	assert_eq!(batching_challenges.len(), F::LOG_DEGREE);

	let z_vals_eq_ind = eq_ind_partial_eval::<F>(z_vals);
	let row_batching_query = eq_ind_partial_eval::<F>(batching_challenges);
	fold_elems_inplace(z_vals_eq_ind, &row_batching_query)
}

/// Transforms a [`FieldBuffer`] by mapping every scalar to the inner product of its B1 components
/// and a given vector of field elements.
//
/// ## Preconditions
/// * `vec` has length equal to the extension degree of `F` over `B1`
pub fn fold_elems_inplace<F, P>(mut elems: FieldBuffer<P>, vec: &FieldBuffer<F>) -> FieldBuffer<P>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	assert_eq!(vec.log_len(), F::LOG_DEGREE); // precondition

	// TODO: Try optimizing this using the Method of Four Russians. The trait interfaces for
	// byte-decomposing the packed elements `P` are missing.
	elems.as_mut().par_iter_mut().for_each(|packed_elem| {
		*packed_elem = P::from_scalars(packed_elem.into_iter().map(|scalar| {
			inner_product_subfield(scalar.into_iter_bases(), vec.as_ref().iter().copied())
		}));
	});

	elems
}

/// Computes the linear combination of the rows of a B1 matrix by an extension field coefficient
/// vector.
///
/// The matrix `mat` is a B1 matrix, packed in row-major order. The number of columns is equal to
/// the extension degree of `F` over [`B1`]. The row coefficients are packed in the vector `vec`.
///
/// ## Arguments
///
/// * `mat` - the [`B1`] matrix, with `F::N_BITS` columns
/// * `vec` - the row coefficients
///
/// ## Preconditions
///
/// * the length of the matrix, in `B1` elements, must equal vector length, in `F` elements, times
///   the field extension degree
pub fn fold_1b_rows<F, P>(
	mat: &FieldBuffer<PackedSubfield<P, B1>>,
	vec: &FieldBuffer<P>,
) -> FieldBuffer<F>
where
	F: BinaryField,
	P: PackedExtension<B1> + PackedField<Scalar = F>,
{
	let log_scalar_bit_width = <F as ExtensionField<B1>>::LOG_DEGREE;
	assert_eq!(mat.log_len(), log_scalar_bit_width + vec.log_len()); // precondition

	let mat = mat.as_ref();

	// partial evals at high variables, since this is a partial eval, it will not
	// be a packed field element since it deals with the internal scalars
	let mut s_hat_v_buffer = FieldBuffer::zeros(log_scalar_bit_width);
	let s_hat_v = s_hat_v_buffer.as_mut();

	let bits_per_packed_elem: usize = mat[0].iter().count();
	let bits_per_variable: usize = bits_per_packed_elem / P::WIDTH;

	// combine eq w/ mle
	for (packed_idx, packed_elem) in mat.iter().enumerate() {
		for high_offset in 0..P::WIDTH {
			// get eq index
			let eq_idx = packed_idx * P::WIDTH + high_offset;
			let eq_at_high_value = vec.get(eq_idx).expect("eq_idx in range");

			// bit index range for where the b128 scalars are located in the packed element
			let bit_start = high_offset * bits_per_variable;
			let bit_end = bit_start + bits_per_variable;

			for (i, bit) in packed_elem.iter().enumerate() {
				if bit == B1::ONE && i >= bit_start && i < bit_end {
					let low_vars_idx = i - bit_start;

					s_hat_v[low_vars_idx] += eq_at_high_value;
				}
			}
		}
	}

	s_hat_v_buffer
}

#[cfg(test)]
mod test {
	use binius_field::{
		BinaryField128bGhash, ExtensionField, PackedBinaryGhash2x128b, PackedExtension,
		PackedField, PackedSubfield,
	};
	use binius_math::{
		FieldBuffer,
		inner_product::inner_product_buffers,
		multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate_inplace},
		test_utils::{index_to_hypercube_point, random_field_buffer, random_scalars},
	};
	use binius_verifier::{config::B1, ring_switch::verifier::eval_rs_eq};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	type F = BinaryField128bGhash;

	#[test]
	fn test_consistent_with_tensor_alg() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars_big_field = 3;

		let z_vals: Vec<F> = random_scalars(&mut rng, n_vars_big_field);

		let row_batching_challenges: Vec<F> =
			random_scalars(&mut rng, <F as ExtensionField<B1>>::LOG_DEGREE);

		let row_batching_expanded_query = eq_ind_partial_eval(&row_batching_challenges);

		let rs_eq = rs_eq_ind::<F>(&row_batching_challenges, &z_vals);

		// test all points points in the boolean hypercube
		for hypercube_point in 0..1 << 3 {
			let evaluated_at_pt = eval_rs_eq::<F>(
				&z_vals,
				&index_to_hypercube_point::<F>(3, hypercube_point),
				row_batching_expanded_query.as_ref(),
			);

			assert_eq!(rs_eq.get(hypercube_point).unwrap(), evaluated_at_pt);
		}
	}

	#[test]
	fn test_out_of_range_evaluation() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars_big_field = 3;

		// setup ring switch eq mle
		let z_vals: Vec<F> = random_scalars(&mut rng, n_vars_big_field);

		let row_batching_challenges: Vec<F> =
			random_scalars(&mut rng, <F as ExtensionField<B1>>::LOG_DEGREE);

		let row_batching_expanded_query: FieldBuffer<F> =
			eq_ind_partial_eval(&row_batching_challenges);

		let rs_eq = rs_eq_ind::<F>(&row_batching_challenges, &z_vals);

		// out of range eval point
		let eval_point: Vec<F> = random_scalars(&mut rng, n_vars_big_field);

		// compare eval against inner product w/ eq ind mle of eval point

		let tensor_expanded_eval_point = eq_ind_partial_eval::<F>(&eval_point);
		let expected_eval = inner_product_buffers(&rs_eq, &tensor_expanded_eval_point);

		let actual_eval =
			eval_rs_eq::<F>(&z_vals, &eval_point, row_batching_expanded_query.as_ref());

		assert_eq!(expected_eval, actual_eval);
	}

	#[test]
	fn test_fold_tensor_product() {
		let mut rng = StdRng::seed_from_u64(0);

		type P = PackedBinaryGhash2x128b;

		// Parameters
		let n = 10;
		let log_degree = <F as ExtensionField<B1>>::LOG_DEGREE;

		// Generate a random B1 bit matrix with 2^(n + log_degree) bits
		let bit_matrix = random_field_buffer::<PackedSubfield<P, B1>>(&mut rng, n + log_degree);

		// Generate a random evaluation point with n + log_degree coordinates
		let eval_point: Vec<F> = random_scalars(&mut rng, n + log_degree);

		// Split the evaluation point into prefix and suffix
		let (prefix, suffix) = eval_point.split_at(log_degree);

		// Method 1 (Reference): Tensor expand the full challenge and compute inner product
		let full_tensor = eq_ind_partial_eval::<F>(&eval_point);
		let reference_result = inner_product_subfield(
			PackedField::iter_slice(bit_matrix.as_ref()),
			PackedField::iter_slice(full_tensor.as_ref()),
		);

		// Method 2: Tensor expand prefix, call fold_elems_inplace, then evaluate_inplace on suffix
		let prefix_tensor = eq_ind_partial_eval::<F>(prefix);
		let bit_matrix_packed = FieldBuffer::new(
			n,
			bit_matrix
				.as_ref()
				.iter()
				.map(|&bits_packed| P::cast_ext(bits_packed))
				.collect(),
		)
		.unwrap();
		let folded_method2 = fold_elems_inplace(bit_matrix_packed, &prefix_tensor);
		let method2_result = evaluate_inplace(folded_method2, suffix).unwrap();

		// Method 3: Tensor expand suffix, call fold_1b_rows, then evaluate_inplace on prefix
		let suffix_tensor = eq_ind_partial_eval::<P>(suffix);
		let folded_method3 = fold_1b_rows::<F, P>(&bit_matrix, &suffix_tensor);
		let method3_result = evaluate_inplace(folded_method3, prefix).unwrap();

		// Compare all three results
		assert_eq!(reference_result, method2_result, "Method 2 does not match reference");
		assert_eq!(reference_result, method3_result, "Method 3 does not match reference");
	}
}

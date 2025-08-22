// Copyright 2025 Irreducible Inc.

use std::{iter, ops::Deref};

use binius_field::{
	BinaryField, ExtensionField, Field, PackedExtension, PackedField, UnderlierWithBitOps,
	WithUnderlier,
	byte_iteration::{
		ByteIteratorCallback, can_iterate_bytes, create_partial_sums_lookup_tables, iterate_bytes,
	},
};
use binius_math::{
	FieldBuffer, inner_product::inner_product_subfield, multilinear::eq::eq_ind_partial_eval,
};
use binius_utils::{checked_arithmetics::checked_log_2, rayon::prelude::*};
use binius_verifier::config::{B1, B128};
use itertools::izip;

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

	let lookup_table = if can_iterate_bytes::<F>() {
		create_partial_sums_lookup_tables::<F>(vec.as_ref())
	} else {
		Vec::new()
	};

	elems.as_mut().par_iter_mut().for_each(|packed_elem| {
		*packed_elem = P::from_scalars(packed_elem.into_iter().map(|scalar| {
			// The first branch is an optimized version of the second one for the case
			// when `F` can be byte-iterated.
			if can_iterate_bytes::<F>() {
				struct Callback<'a, F: Field> {
					accumulator: F,
					lookup_table: &'a [F],
				}

				impl<'a, F: Field> ByteIteratorCallback for Callback<'a, F> {
					fn call(&mut self, bytes: impl Iterator<Item = u8>) {
						assert_eq!(self.lookup_table.len(), 256 * std::mem::size_of::<F>());

						for (i, byte) in bytes.enumerate() {
							self.accumulator +=
								// Safety: the size of the table is checked by the assert above
								unsafe {
								*self.lookup_table.get_unchecked(i * 256 + (byte as usize))
							};
						}
					}
				}

				let mut callback = Callback {
					accumulator: F::ZERO,
					lookup_table: &lookup_table,
				};
				iterate_bytes(&[scalar], &mut callback);
				callback.accumulator
			} else {
				// Fallback to the inner product with the basis elements.
				inner_product_subfield(scalar.into_iter_bases(), vec.as_ref().iter().copied())
			}
		}));
	});

	elems
}

/// Computes the linear combination of the rows of a B1 matrix by an extension field coefficient
/// vector.
///
/// The matrix `mat` is a B1 matrix row-major order, with coefficients packed into `F` elements.
/// The number of columns is equal to the extension degree of `F` over [`B1`]. The row coefficients
/// are `F` extension field elements in the vector `vec`.
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
pub fn fold_1b_rows<F, P, Data>(mat: &FieldBuffer<P, Data>, vec: &FieldBuffer<P>) -> FieldBuffer<F>
where
	F: BinaryField + WithUnderlier<Underlier: UnderlierWithBitOps>,
	P: PackedField<Scalar = F>,
	Data: Deref<Target = [P]>,
{
	let log_scalar_bit_width = <F as ExtensionField<B1>>::LOG_DEGREE;
	assert_eq!(mat.log_len(), vec.log_len()); // precondition

	(vec.as_ref(), mat.as_ref())
		.into_par_iter()
		.fold(
			|| FieldBuffer::zeros(log_scalar_bit_width),
			|mut acc, (vec_packed_i, mat_packed_i)| {
				for (vec_i, mat_i) in iter::zip(vec_packed_i.iter(), mat_packed_i.iter()) {
					// The first branch is an optimized version of the second one for the case
					// when `F` can be byte-iterated.
					// Use a precompute mask table to get 8 masks for every byte in `F`.
					if can_iterate_bytes::<F>() {
						struct Callback<'a, P: PackedField<Scalar: WithUnderlier>> {
							vec_i: <P::Scalar as WithUnderlier>::Underlier,
							acc: &'a mut FieldBuffer<P>,
						}

						impl<P: PackedField<Scalar: WithUnderlier<Underlier: UnderlierWithBitOps>>>
							ByteIteratorCallback for Callback<'_, P>
						{
							#[inline]
							fn call(&mut self, bytes: impl Iterator<Item = u8>) {
								let mask_map =
									<P::Scalar as WithUnderlier>::Underlier::BYTE_MASK_MAP;

								for (byte_index, byte) in bytes.enumerate() {
									let offset = byte_index * 8;
									let masks = &mask_map[byte as usize];

									for (bit_index, &mask) in masks.iter().enumerate() {
										unsafe {
											*self
												.acc
												.as_mut()
												.get_unchecked_mut(offset + bit_index) += P::Scalar::from_underlier(self.vec_i & mask)
										}
									}
								}
							}
						}

						iterate_bytes(
							&[mat_i],
							&mut Callback {
								vec_i: vec_i.to_underlier(),
								acc: &mut acc,
							},
						);
					} else {
						for (acc_i, bit_i) in iter::zip(acc.as_mut(), mat_i.iter_bases()) {
							*acc_i += vec_i * bit_i;
						}
					}
				}
				acc
			},
		)
		.reduce(
			|| FieldBuffer::zeros(log_scalar_bit_width),
			|mut lhs, rhs| {
				for (lhs_i, &rhs_i) in izip!(lhs.as_mut(), rhs.as_ref()) {
					*lhs_i += rhs_i;
				}
				lhs
			},
		)
}

/// Optimized version of [`fold_1b_rows`] specifically for B128 fields.
///
/// This function computes the linear combination of the rows of a B1 matrix by B128 extension
/// field coefficient vectors. It implements the same computation as [`fold_1b_rows`] but uses
/// the Method of Four Russians optimization to achieve better performance for B128 fields.
///
/// The optimization works by:
/// 1. Processing 4 elements at a time (2^2 chunks) for better cache locality
/// 2. Precomputing a lookup table of 16 partial sums for 4-bit chunks
/// 3. Bit-transpose 4-bit matrix chunks to get lookup indices
/// 4. Using the lookup table to compute dot products via table lookups instead of multiplications
///
/// ## Arguments
///
/// * `mat` - the [`B1`] matrix packed into B128 elements, with 128 columns
/// * `vec` - the row coefficients as B128 elements
///
/// ## Returns
///
/// A buffer containing the linear combination result
///
/// ## Preconditions
///
/// * `mat` and `vec` must have the same log length
pub fn fold_1b_rows_for_b128<P, Data>(
	mat: &FieldBuffer<P, Data>,
	vec: &FieldBuffer<P>,
) -> FieldBuffer<B128>
where
	P: PackedField<Scalar = B128>,
	Data: Deref<Target = [P]>,
{
	let log_scalar_bit_width = <B128 as ExtensionField<B1>>::LOG_DEGREE;
	assert_eq!(mat.log_len(), vec.log_len()); // precondition

	// Group bits into 4-bit nibbles for the lookups.
	const LOG_CHUNK_BITS: usize = 2;
	const CHUNK_BITS: usize = 1 << LOG_CHUNK_BITS;

	(vec.as_ref().par_chunks(CHUNK_BITS), mat.as_ref().par_chunks(CHUNK_BITS))
		.into_par_iter()
		.fold(
			|| FieldBuffer::zeros(log_scalar_bit_width),
			|mut acc, (vec_chunk, mat_chunk)| {
				let mut vec_chunk_iter = P::iter_slice(vec_chunk);
				let mut mat_chunk_iter = P::iter_slice(mat_chunk);

				for _ in 0..P::WIDTH {
					// Copy from slices to arrays. This works even when the inputs are less than the
					// chunk size.
					let mut vec_scalars = [B128::ZERO; CHUNK_BITS];
					iter::zip(&mut vec_scalars, &mut vec_chunk_iter)
						.for_each(|(dst, src)| *dst = src);

					let mut mat_scalars = [B128::ZERO; CHUNK_BITS];
					iter::zip(&mut mat_scalars, &mut mat_chunk_iter)
						.for_each(|(dst, src)| *dst = src);

					// Build the lookup table of subset sums of the vector chunk elements.
					let lookup =
						expand_subset_sums::<_, CHUNK_BITS, { 1 << CHUNK_BITS }>(vec_scalars);

					square_transpose_const_size::<_, LOG_CHUNK_BITS, CHUNK_BITS>(
						mat_scalars
							.each_mut()
							.map(<B128 as PackedExtension<B1>>::cast_base_mut),
					);

					{
						let acc = acc.as_mut();
						for (j, mat_elem) in mat_scalars.iter().enumerate() {
							let elem_bytes = mat_elem.val().to_le_bytes();
							for (i, &byte) in elem_bytes.iter().enumerate() {
								acc[(i << 3) | j] += lookup[byte as usize & 0x0F];
								acc[(i << 3) | (1 << 2) | j] += lookup[byte as usize >> 4];
							}
						}
					}
				}

				acc
			},
		)
		.reduce(
			|| FieldBuffer::zeros(log_scalar_bit_width),
			|mut lhs, rhs| {
				for (lhs_i, &rhs_i) in izip!(lhs.as_mut(), rhs.as_ref()) {
					*lhs_i += rhs_i;
				}
				lhs
			},
		)
}

/// Expands an array of field elements into all possible subset sums.
///
/// For an input array `[a, b, c]`, this computes all possible sums of subsets:
/// `[0, a, b, a+b, c, a+c, b+c, a+b+c]`
///
/// This is used to create lookup tables for the Method of Four Russians optimization,
/// where we precompute all possible combinations of a small set of values to avoid
/// doing the additions at runtime.
///
/// ## Type Parameters
///
/// * `F` - The field element type
/// * `N` - Size of the input array
/// * `N_EXP2` - Size of the output array, must be 2^N
///
/// ## Arguments
///
/// * `elems` - Input array of N field elements
///
/// ## Returns
///
/// An array of size N_EXP2 containing all possible subset sums of the input elements
///
/// ## Preconditions
///
/// * N_EXP2 must equal 2^N
///
/// ## Example
///
/// ```ignore
/// let input = [F::ONE, F::from(2)];
/// let sums = expand_subset_sums(input);
/// // sums = [F::ZERO, F::ONE, F::from(2), F::from(3)]
/// ```
fn expand_subset_sums<F: Field, const N: usize, const N_EXP2: usize>(elems: [F; N]) -> [F; N_EXP2] {
	// TODO: deduplicate this code with `fold_words` and `create_partial_sums_lookup_tables`
	assert_eq!(N_EXP2, 1 << N);

	let mut expanded = [F::ZERO; N_EXP2];
	for (i, elem_i) in elems.into_iter().enumerate() {
		let span = &mut expanded[..1 << (i + 1)];
		let (lo_half, hi_half) = span.split_at_mut(1 << i);
		for (lo_half_i, hi_half_i) in iter::zip(lo_half, hi_half) {
			*hi_half_i = *lo_half_i + elem_i;
		}
	}
	expanded
}

/// Transpose square blocks of elements within packed field elements in place.
///
/// This is similar to [`binius_field::transpose::square_transpose`] but uses const generic
/// parameters for the array size and block dimension. The const generics enable the compiler
/// to unroll loops and optimize the transpose operation more aggressively.
///
/// ## Type Parameters
///
/// * `P` - The packed field type
/// * `LOG_N` - Base-2 logarithm of the dimension of the square blocks to transpose
/// * `S` - Size of the array (must be a power of 2)
///
/// ## Arguments
///
/// * `elems` - Array of packed field elements to transpose in place
///
/// ## Preconditions
///
/// * `S` must be a power of two
/// * `LOG_N` must be less than or equal to `P::LOG_WIDTH`
/// * `LOG_N` must be less than or equal to `log2(S)`
fn square_transpose_const_size<P: PackedField, const LOG_N: usize, const S: usize>(
	elems: [&mut P; S],
) {
	let log_size = checked_log_2(S);

	assert!(LOG_N <= P::LOG_WIDTH);
	assert!(LOG_N <= log_size);

	let log_w = log_size - LOG_N;

	// See Hacker's Delight, Section 7-3.
	// https://dl.acm.org/doi/10.5555/2462741
	for i in 0..LOG_N {
		for j in 0..1 << (LOG_N - i - 1) {
			for k in 0..1 << (log_w + i) {
				let idx0 = (j << (log_w + i + 1)) | k;
				let idx1 = idx0 | (1 << (log_w + i));

				let v0 = *elems[idx0];
				let v1 = *elems[idx1];
				let (v0, v1) = v0.interleave(v1, i);
				*elems[idx0] = v0;
				*elems[idx1] = v1;
			}
		}
	}
}

#[cfg(test)]
mod test {
	use binius_field::{
		BinaryField128bGhash, ExtensionField, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b,
		PackedExtension, PackedField, PackedSubfield,
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
		let folded_method2 = fold_elems_inplace(bit_matrix_packed.clone(), &prefix_tensor);
		let method2_result = evaluate_inplace(folded_method2, suffix).unwrap();

		// Method 3: Tensor expand suffix, call fold_1b_rows, then evaluate_inplace on prefix
		let suffix_tensor = eq_ind_partial_eval::<P>(suffix);
		let folded_method3 = fold_1b_rows(&bit_matrix_packed, &suffix_tensor);
		let method3_result = evaluate_inplace(folded_method3, prefix).unwrap();

		// Compare all three results
		assert_eq!(reference_result, method2_result, "Method 2 does not match reference");
		assert_eq!(reference_result, method3_result, "Method 3 does not match reference");
	}

	#[test]
	fn test_fold_1b_rows_for_b128_consistency() {
		let mut rng = StdRng::seed_from_u64(0);
		type P = PackedBinaryGhash4x128b;

		// Parameters - test with various sizes
		for n in [4, 6, 8, 10] {
			// Generate a random B128 matrix with 2^n elements
			let mat = random_field_buffer::<P>(&mut rng, n);

			// Generate a random B128 vector with 2^n elements
			let vec = random_field_buffer::<P>(&mut rng, n);

			// Call the generic fold_1b_rows function
			let result_generic = fold_1b_rows(&mat, &vec);

			// Call the specialized fold_1b_rows_for_b128 function
			let result_specialized = fold_1b_rows_for_b128(&mat, &vec);

			// Both results should be identical
			assert_eq!(
				result_generic.as_ref(),
				result_specialized.as_ref(),
				"fold_1b_rows_for_b128 does not match fold_1b_rows for n = {}",
				n
			);
		}
	}
}

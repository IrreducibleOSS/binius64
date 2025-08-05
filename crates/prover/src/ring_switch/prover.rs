// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, PackedField};
use binius_math::{
	FieldBuffer, inner_product::inner_product_subfield, multilinear::eq::eq_ind_partial_eval,
};
use binius_utils::rayon::prelude::*;

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

#[cfg(test)]
mod test {
	use binius_field::{BinaryField128b, ExtensionField};
	use binius_math::{
		FieldBuffer,
		inner_product::inner_product_buffers,
		multilinear::eq::eq_ind_partial_eval,
		test_utils::{index_to_hypercube_point, random_scalars},
	};
	use binius_verifier::{config::B1, ring_switch::verifier::eval_rs_eq};
	use rand::{SeedableRng, rngs::StdRng};

	use super::rs_eq_ind;

	type F = BinaryField128b;

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
}

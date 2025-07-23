use binius_field::{ExtensionField, Field};
use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};

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
pub fn rs_eq_ind<F, FE>(batching_challenges: &[FE], z_vals: &[FE]) -> FieldBuffer<FE>
where
	F: Field,
	FE: Field + binius_field::ExtensionField<F>,
{
	assert_eq!(batching_challenges.len(), FE::LOG_DEGREE);

	let big_field_hypercube_vertices = 1 << z_vals.len();

	// MLE-random-linear-combination of bit-slices of the eq_ind for z_vals
	let z_vals_eq_ind = eq_ind_partial_eval::<FE>(z_vals);

	let row_batching_query = eq_ind_partial_eval::<FE>(batching_challenges);

	let mut rs_eq_mle = FieldBuffer::<FE>::zeros(z_vals.len());

	for big_field_hypercube_vertex in 0..big_field_hypercube_vertices {
		for (index, bit) in <FE as ExtensionField<F>>::into_iter_bases(
			z_vals_eq_ind.as_ref()[big_field_hypercube_vertex],
		)
		.enumerate()
		{
			if bit == F::ONE {
				rs_eq_mle.as_mut()[big_field_hypercube_vertex] +=
					row_batching_query.as_ref()[index];
			}
		}
	}

	rs_eq_mle
}

#[cfg(test)]
mod test {
	use std::iter::repeat_with;

	use binius_field::{BinaryField1b, BinaryField128b, ExtensionField, Random};
	use binius_math::{
		FieldBuffer, inner_product::inner_product_packed, multilinear::eq::eq_ind_partial_eval,
		test_utils::index_to_hypercube_point,
	};
	use binius_verifier::ring_switch::verifier::eval_rs_eq;
	use rand::{SeedableRng, rngs::StdRng};

	use super::rs_eq_ind;

	type F = BinaryField1b;
	type FE = BinaryField128b;

	#[test]
	fn test_consistent_with_tensor_alg() {
		let mut rng = StdRng::from_seed([0; 32]);

		let n_vars_big_field = 3;

		let z_vals: Vec<_> = repeat_with(|| FE::random(&mut rng))
			.take(n_vars_big_field)
			.collect();

		let row_batching_challenges: Vec<FE> = repeat_with(|| FE::random(&mut rng))
			.take(<FE as ExtensionField<F>>::LOG_DEGREE)
			.collect();

		let row_batching_expanded_query = eq_ind_partial_eval(&row_batching_challenges);

		let rs_eq = rs_eq_ind::<F, FE>(&row_batching_challenges, &z_vals);

		// test all points points in the boolean hypercube
		for hypercube_point in 0..1 << 3 {
			let evaluated_at_pt = eval_rs_eq::<F, FE>(
				&z_vals,
				&index_to_hypercube_point::<FE>(3, hypercube_point),
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
		let z_vals: Vec<_> = repeat_with(|| FE::random(&mut rng))
			.take(n_vars_big_field)
			.collect();

		let row_batching_challenges: Vec<FE> = repeat_with(|| FE::random(&mut rng))
			.take(<FE as ExtensionField<F>>::LOG_DEGREE)
			.collect();

		let row_batching_expanded_query: FieldBuffer<FE> =
			eq_ind_partial_eval(&row_batching_challenges);

		let rs_eq = rs_eq_ind::<F, FE>(&row_batching_challenges, &z_vals);

		// out of range eval point
		let eval_point: Vec<FE> = repeat_with(|| FE::random(&mut rng))
			.take(n_vars_big_field)
			.collect();

		// compare eval against inner product w/ eq ind mle of eval point

		let tensor_expanded_eval_point = eq_ind_partial_eval::<FE>(&eval_point);
		let expected_eval = inner_product_packed(&rs_eq, &tensor_expanded_eval_point);

		let actual_eval =
			eval_rs_eq::<F, FE>(&z_vals, &eval_point, row_batching_expanded_query.as_ref());

		assert_eq!(expected_eval, actual_eval);
	}
}

use binius_field::{ExtensionField, Field};
use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};

/// Generate the ring switching equality indicator for a given query and z_vals
///
/// Used by the prover within the the one bit pcs prover during the setup for the
/// large field pcs.
pub fn rs_eq_ind<F, FE>(batching_challenges: &[FE], z_vals: &[FE]) -> FieldBuffer<FE>
where
	F: Field,
	FE: Field + binius_field::ExtensionField<F>,
{
	let big_field_hypercube_vertices = 1 << z_vals.len();

	// MLE-random-linear-combination of bit-slices of the eq_ind for z_vals
	let z_vals_eq_ind = eq_ind_partial_eval::<FE>(z_vals);

	let row_batching_query = eq_ind_partial_eval::<FE>(batching_challenges);

	let mut rs_eq_mle = FieldBuffer::<FE>::zeros(big_field_hypercube_vertices);

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

	use binius_field::{BinaryField1b, BinaryField128b, Field, Random};
	use binius_math::multilinear::eq::eq_ind_partial_eval;
	use binius_verifier::ring_switch::verifier::eval_rs_eq;
	use rand::{SeedableRng, rngs::StdRng};

	use super::rs_eq_ind;

	type F = BinaryField1b;
	type FE = BinaryField128b;

	fn hypercube_query<FE: Field + binius_field::ExtensionField<F>>(
		idx: usize,
		query_len: usize,
	) -> Vec<FE> {
		let mut result = vec![];

		for i in 0..query_len {
			if idx & 1 << i == 0 {
				result.push(FE::ZERO);
			} else {
				result.push(FE::ONE);
			}
		}

		result
	}

	#[test]
	fn consistent_with_tensor_alg() {
		let n_vars_big_field = 3;
		let mut rng = StdRng::from_seed([0; 32]);
		let z_vals: Vec<_> = repeat_with(|| FE::random(&mut rng))
			.take(n_vars_big_field)
			.collect();

		let row_batching_challenges: Vec<_> =
			repeat_with(|| FE::random(&mut rng)).take(7).collect();

		let row_batching_expanded_query = eq_ind_partial_eval(&row_batching_challenges);

		let mle = rs_eq_ind::<F, FE>(&row_batching_challenges, &z_vals);

		for hypercube_point in 0..1 << 3 {
			let evaluated_at_pt = eval_rs_eq::<F, FE>(
				&z_vals,
				&hypercube_query(hypercube_point, 3),
				row_batching_expanded_query.as_ref(),
			);

			assert_eq!(mle.get(hypercube_point).unwrap(), evaluated_at_pt);
		}
	}
}

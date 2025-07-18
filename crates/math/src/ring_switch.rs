use std::iter;

use binius_field::{BinaryField1b, BinaryField128b, ExtensionField, Field, PackedExtension};

use crate::{FieldBuffer, multilinear::eq::tensor_prod_eq_ind, tensor_algebra::TensorAlgebra};

pub type B1 = BinaryField1b;
pub type B128 = BinaryField128b;

pub fn eq_ind_mle<F: Field>(zerocheck_challenges: &[F]) -> FieldBuffer<F> {
	let mut mle = FieldBuffer::<F>::zeros(zerocheck_challenges.len());
	let _ = mle.set(0, F::ONE);
	let _ = tensor_prod_eq_ind(0, &mut mle, zerocheck_challenges);
	mle
}

pub fn rs_eq_ind<BF: Field + ExtensionField<B1> + PackedExtension<B1>>(
	batching_challenges: &[BF],
	z_vals: &[BF],
) -> FieldBuffer<BF> {
	let big_field_hypercube_vertices = 1 << z_vals.len();

	// MLE-random-linear-combination of bit-slices of the eq_ind for z_vals
	let z_vals_eq_ind = eq_ind_mle(z_vals);

	let row_batching_query = eq_ind_mle::<BF>(batching_challenges);

	let mut rs_eq_mle = FieldBuffer::<BF>::zeros(z_vals.len());

	for big_field_hypercube_vertex in 0..big_field_hypercube_vertices {
		for (index, bit) in <BF as ExtensionField<BinaryField1b>>::into_iter_bases(
			z_vals_eq_ind.as_ref()[big_field_hypercube_vertex],
		)
		.enumerate()
		{
			if bit == BinaryField1b::ONE {
				rs_eq_mle.as_mut()[big_field_hypercube_vertex] +=
					row_batching_query.as_ref()[index];
			}
		}
	}

	rs_eq_mle
}

pub fn eval_rs_eq<BF: Field + ExtensionField<B1> + PackedExtension<B1>>(
	z_vals: &[BF],
	query: &[BF],
	expanded_row_batch_query: &[BF],
) -> BF {
	let tensor_eval = iter::zip(z_vals, query).fold(
		<TensorAlgebra<B1, BF>>::from_vertical(BF::ONE),
		|eval, (&vert_i, &hztl_i)| {
			// This formula is specific to characteristic 2 fields
			// Here we know that $h v + (1 - h) (1 - v) = 1 + h + v$.
			let vert_scaled = eval.clone().scale_vertical(vert_i);

			// println!("vert scaled: {:?}", vert_scaled);
			let hztl_scaled = eval.clone().scale_horizontal(hztl_i);
			// println!("hztl scaled: {:?}", hztl_scaled);

			eval + &vert_scaled + &hztl_scaled
		},
	);

	tensor_eval.fold_vertical(expanded_row_batch_query)
}

// basis decompose/recombine list of big field elements across opposite dimension
pub fn construct_s_hat_u<
	SmallField: Field,
	BigField: Field + ExtensionField<SmallField> + PackedExtension<SmallField>,
>(
	s_hat_v: Vec<BigField>,
) -> Vec<BigField> {
	<TensorAlgebra<SmallField, BigField>>::new(s_hat_v)
		.transpose()
		.elems
}

#[cfg(test)]
mod test {
	use std::iter::repeat_with;

	use binius_field::{BinaryField128b, Field, Random};
	use rand::{SeedableRng, rngs::StdRng};

	use super::{eq_ind_mle, eval_rs_eq, rs_eq_ind};

	type BF = BinaryField128b;

	fn hypercube_query<BF: Field + binius_field::ExtensionField<binius_field::BinaryField1b>>(
		idx: usize,
		query_len: usize,
	) -> Vec<BF> {
		let mut result = vec![];

		for i in 0..query_len {
			if idx & 1 << i == 0 {
				result.push(BF::ZERO);
			} else {
				result.push(BF::ONE);
			}
		}

		result
	}

	#[test]
	fn consistent_with_tensor_alg() {
		let n_vars_big_field = 3;
		let mut rng = StdRng::from_seed([0; 32]);
		let z_vals: Vec<_> = repeat_with(|| BF::random(&mut rng))
			.take(n_vars_big_field)
			.collect();

		let row_batching_challenges: Vec<_> =
			repeat_with(|| BF::random(&mut rng)).take(7).collect();

		let row_batching_expanded_query = eq_ind_mle(&row_batching_challenges);

		let mle = rs_eq_ind(&row_batching_challenges, &z_vals);

		for hypercube_point in 0..1 << 3 {
			let evaluated_at_pt = eval_rs_eq(
				&z_vals,
				&hypercube_query(hypercube_point, 3),
				row_batching_expanded_query.as_ref(),
			);

			assert_eq!(mle.get(hypercube_point).unwrap(), evaluated_at_pt);
		}
	}
}

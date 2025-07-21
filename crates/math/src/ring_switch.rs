use std::iter;

use binius_field::{BinaryField1b as B1, ExtensionField, Field, PackedExtension, PackedField, BinaryField};
use binius_utils::rayon::prelude::{
	IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use crate::{FieldBuffer, multilinear::eq::eq_ind_partial_eval, tensor_algebra::TensorAlgebra};

pub fn rs_eq_ind<BF>(batching_challenges: &[BF], z_vals: &[BF]) -> FieldBuffer<BF>
where
	BF: BinaryField + PackedExtension<B1> + PackedField<Scalar = BF>,
{
	// MLE-random-linear-combination of bit-slices of the eq_ind for z_vals
	let z_vals_eq_ind = eq_ind_partial_eval(z_vals);

	let row_batching_query = eq_ind_partial_eval::<BF>(batching_challenges);

	let mut rs_eq_mle = FieldBuffer::<BF>::zeros(z_vals.len());

	rs_eq_mle
		.as_mut()
		.par_iter_mut()
		.zip(z_vals_eq_ind.as_ref().par_iter())
		.for_each(|(rs_eq_val, eq_val)| {
			for (index, bit) in <BF as ExtensionField<B1>>::into_iter_bases(*eq_val).enumerate() {
				if bit == B1::ONE {
					*rs_eq_val += row_batching_query.as_ref()[index];
				}
			}
		});

	rs_eq_mle
}

pub fn eval_rs_eq<BF: BinaryField + PackedExtension<B1>>(
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

			let hztl_scaled = eval.clone().scale_horizontal(hztl_i);

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

	use binius_field::{BinaryField128b, Random};
	use rand::{SeedableRng, rngs::StdRng};

	use crate::test_utils::index_to_hypercube_point;

	use super::{eq_ind_partial_eval, eval_rs_eq, rs_eq_ind};

	type BF = BinaryField128b;

	#[test]
	fn consistent_with_tensor_alg() {
		let n_vars_big_field = 3;
		let mut rng = StdRng::from_seed([0; 32]);
		let z_vals: Vec<_> = repeat_with(|| BF::random(&mut rng))
			.take(n_vars_big_field)
			.collect();

		let row_batching_challenges: Vec<_> =
			repeat_with(|| BF::random(&mut rng)).take(7).collect();

		let row_batching_expanded_query = eq_ind_partial_eval(&row_batching_challenges);

		let mle = rs_eq_ind(&row_batching_challenges, &z_vals);

		let n_vars = 3;
		for hypercube_point in 0..1 << n_vars {
			let evaluated_at_pt = eval_rs_eq(
				&z_vals,
				&index_to_hypercube_point(n_vars, hypercube_point),
				row_batching_expanded_query.as_ref(),
			);

			assert_eq!(mle.get(hypercube_point).unwrap(), evaluated_at_pt);
		}
	}
}

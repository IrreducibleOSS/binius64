use binius_field::{
	BinaryField, BinaryField1b as B1, ExtensionField, Field, PackedExtension, PackedField,
};
use binius_utils::rayon::prelude::{
	IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use crate::{FieldBuffer, multilinear::eq::eq_ind_partial_eval, tensor_algebra::TensorAlgebra};

pub fn rs_eq_ind<P>(batching_challenges: &[P], z_vals: &[P]) -> FieldBuffer<P>
where
	P: BinaryField + PackedExtension<B1> + PackedField<Scalar = P>,
{
	// MLE-random-linear-combination of bit-slices of the eq_ind for z_vals
	let z_vals_eq_ind = eq_ind_partial_eval(z_vals);

	let row_batching_query = eq_ind_partial_eval::<P>(batching_challenges);

	let mut rs_eq_mle = FieldBuffer::<P>::zeros(z_vals.len());

	rs_eq_mle
		.as_mut()
		.par_iter_mut()
		.zip(z_vals_eq_ind.as_ref().par_iter())
		.for_each(|(rs_eq_val, eq_val)| {
			for (index, bit) in <P as ExtensionField<B1>>::into_iter_bases(*eq_val).enumerate() {
				if bit == B1::ONE {
					*rs_eq_val += row_batching_query.as_ref()[index];
				}
			}
		});

	rs_eq_mle
}

/// Each s_hat_v is a partial evaluation of our 1- bit poly t at l-kappa variables
/// We take the prover's claims s_hat_v for v in {0,..,2^kappa-1} and bit-slice them.
/// These bit-sliced claims
/// are called s_hat_u for u in {0,..,2^kappa-1}, and are computed by both the prover and verifier.
/// After this, the prover proves the correctness of the s_hat_u values WRT t with a sumcheck
pub fn construct_bitsliced_claims<
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
	use binius_math::multilinear::eq::eq_ind;
	use rand::{SeedableRng, rngs::StdRng};

	use super::rs_eq_ind;
	use crate::test_utils::index_to_hypercube_point;

	#[test]
	fn consistent_with_tensor_alg() {
		let n_vars_big_field = 3;
		let mut rng = StdRng::from_seed([0; 32]);
		let z_vals: Vec<_> = repeat_with(|| BinaryField128b::random(&mut rng))
			.take(n_vars_big_field)
			.collect();

		let row_batching_challenges: Vec<_> = repeat_with(|| BinaryField128b::random(&mut rng))
			.take(7)
			.collect();

		let mle = rs_eq_ind(&row_batching_challenges, &z_vals);

		let n_vars = 3;
		for hypercube_point in 0..1 << n_vars {
			let evaluated_at_pt =
				eq_ind(&z_vals, &index_to_hypercube_point(n_vars, hypercube_point));

			assert_eq!(mle.get(hypercube_point).unwrap(), evaluated_at_pt);
		}
	}
}
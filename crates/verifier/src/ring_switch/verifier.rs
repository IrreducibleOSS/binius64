use std::iter;

use binius_field::{ExtensionField, Field};
use binius_math::tensor_algebra::TensorAlgebra;

/// Evaluate the ring switching equality indicator at a given point.
///
/// The ring switching equality indicator is the multilinear function $A$ from [DP24],
/// Construction 3.1. It is evaluated succinctly by computing the equality indicator over the
/// tensor algebra, where the first components live in the vertical subring and the later
/// components live in the vertical subring. Then we apply row-batching to the tensor algebra
/// element.
///
/// ## Arguments
///
/// * `z_vals` - the vertical evaluation point, with $\ell'$ components
/// * `query` - the horizontal evaluation point
/// * `expanded_row_batch_query` - the scaling elements for row-batching
///
/// ## Pre-conditions
///
/// * the lengths of `z_vals` and `query` are equal
/// * the length of `expanded_row_batch_query` must equal `FE::DEGREE`
///
/// [DP24]: <https://eprint.iacr.org/2024/504>
pub fn eval_rs_eq<F, FE>(z_vals: &[FE], query: &[FE], expanded_row_batch_query: &[FE]) -> FE
where
	F: Field,
	FE: Field + ExtensionField<F>,
{
	assert_eq!(z_vals.len(), query.len()); // pre-condition
	assert_eq!(expanded_row_batch_query.len(), FE::DEGREE); // pre-condition

	let tensor_eval = iter::zip(z_vals, query).fold(
		<TensorAlgebra<F, FE>>::from_vertical(FE::ONE),
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

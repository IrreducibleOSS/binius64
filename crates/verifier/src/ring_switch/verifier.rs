use std::iter;

use binius_field::{ExtensionField, Field, PackedExtension};
use binius_math::tensor_algebra::TensorAlgebra;

/// Evaluate the ring switching equality indicator for a given query and z_vals
///
/// Used by the verifier within the the one bit pcs verifier during the
/// verification of the large field pcs.
pub fn eval_rs_eq<F, FE>(z_vals: &[FE], query: &[FE], expanded_row_batch_query: &[FE]) -> FE
where
	F: Field,
	FE: Field + ExtensionField<F> + PackedExtension<F>,
{
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

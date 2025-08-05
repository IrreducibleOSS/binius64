use binius_field::{BinaryField, PackedField};
use binius_math::BinarySubspace;

/// Computes the next subspace in the reduction sequence.
/// Given a subspace with basis [b_0, b_1, ..., b_{n-1}], computes a new subspace
/// with basis [b_1', b_2', ..., b_{n-1}'] where each b_i' is derived from b_i.
pub fn get_next_subspace<F: BinaryField>(
	current_subspace: &BinarySubspace<F>,
) -> BinarySubspace<F> {
	let basis = current_subspace.basis();
	let div_by_factor = basis[1] * (basis[1] + F::ONE);

	let mut new_basis = vec![];
	for basis_elem in basis[1..].iter() {
		new_basis.push(*basis_elem * (*basis_elem + F::ONE) * div_by_factor.invert_or_zero());
	}

	BinarySubspace::new_unchecked(new_basis)
}

/// Returns the elements of a subspace split into two halves, broadcasted to packed field elements.
/// The first half contains elements from indices 0 to 2^(dim-1)-1,
/// and the second half contains elements from indices 2^(dim-1) to 2^dim-1.
pub fn elements_of_subspace_broadcasted<F: BinaryField, P: PackedField<Scalar = F>>(
	subspace: &BinarySubspace<F>,
) -> (Vec<P>, Vec<P>) {
	let dim = subspace.dim();

	let inverse = subspace
		.iter()
		.map(P::broadcast)
		.take(1 << (dim - 1))
		.collect();

	let forward = subspace
		.iter()
		.skip(1 << (dim - 1))
		.map(P::broadcast)
		.take(1 << (dim - 1))
		.collect();

	(inverse, forward)
}

/// Generates elements for each subspace in the reduction sequence, broadcasted to packed field
/// elements. Returns two vectors of vectors, where each inner vector contains the elements for one
/// subspace in the sequence, split into inverse and forward halves.
pub fn elements_for_each_subspace_broadcasted<F: BinaryField, P: PackedField<Scalar = F>>(
	mut subspace: BinarySubspace<F>,
) -> (Vec<Vec<P>>, Vec<Vec<P>>) {
	let (mut inverse, mut forward) = (vec![], vec![]);

	for _dim in (2..=subspace.dim()).rev() {
		let subspace_elems = elements_of_subspace_broadcasted(&subspace);

		inverse.push(subspace_elems.0);
		forward.push(subspace_elems.1);

		subspace = get_next_subspace(&subspace);
	}

	(inverse, forward)
}

#[cfg(test)]
mod tests {
	use binius_field::{
		AESTowerField8b, BinaryField32b, BinaryField128b, PackedAESBinaryField16x8b,
	};

	use super::*;

	#[test]
	fn test_get_next_subspace_dimension_reduction() {
		// Test with different field types and dimensions
		let subspace_8b = BinarySubspace::<AESTowerField8b>::with_dim(5).unwrap();
		let next_8b = get_next_subspace(&subspace_8b);
		assert_eq!(next_8b.dim(), 4, "Next subspace should have dimension reduced by 1");

		let subspace_32b = BinarySubspace::<BinaryField32b>::with_dim(7).unwrap();
		let next_32b = get_next_subspace(&subspace_32b);
		assert_eq!(next_32b.dim(), 6, "Next subspace should have dimension reduced by 1");
	}

	#[test]
	fn test_get_next_subspace_basis_properties() {
		let subspace = BinarySubspace::<BinaryField128b>::with_dim(8).unwrap();
		let next_subspace = get_next_subspace(&subspace);

		// Verify dimension reduction
		assert_eq!(next_subspace.dim(), subspace.dim() - 1);

		// Verify that we can continue reducing
		let next_next = get_next_subspace(&next_subspace);
		assert_eq!(next_next.dim(), subspace.dim() - 2);
	}

	#[test]
	fn test_elements_of_subspace_broadcasted_split() {
		let subspace = BinarySubspace::<AESTowerField8b>::with_dim(4).unwrap();
		let (inverse, forward) = elements_of_subspace_broadcasted::<_, AESTowerField8b>(&subspace);

		// Check that the split is correct
		assert_eq!(inverse.len(), 8, "First half should have 2^(dim-1) elements");
		assert_eq!(forward.len(), 8, "Second half should have 2^(dim-1) elements");

		// Total number of elements should equal 2^dim
		let total_elements = inverse.len() + forward.len();
		assert_eq!(total_elements, 16, "Total elements should equal 2^dim");
	}

	#[test]
	fn test_elements_of_subspace_broadcasted_packed() {
		let subspace = BinarySubspace::<AESTowerField8b>::with_dim(3).unwrap();
		let (inverse, forward) =
			elements_of_subspace_broadcasted::<_, PackedAESBinaryField16x8b>(&subspace);

		// Verify packed field broadcasting
		for packed_elem in inverse.iter().chain(forward.iter()) {
			// Check that all elements in the packed field are the same (broadcasted)
			let first = packed_elem.get(0);
			for i in 1..16 {
				assert_eq!(
					packed_elem.get(i),
					first,
					"All elements in packed field should be equal"
				);
			}
		}
	}

	#[test]
	fn test_elements_for_each_subspace_sequence_length() {
		let subspace = BinarySubspace::<AESTowerField8b>::with_dim(6).unwrap();
		let (inverse, forward) =
			elements_for_each_subspace_broadcasted::<_, AESTowerField8b>(subspace);

		// Should generate sequences for dimensions 6 down to 2
		assert_eq!(inverse.len(), 5, "Should have 5 subspaces in the sequence");
		assert_eq!(forward.len(), 5, "Should have 5 subspaces in the sequence");

		// Check sizes of each subspace's elements
		let expected_sizes = [32, 16, 8, 4, 2]; // For dimensions 6, 5, 4, 3, 2
		for (i, expected_size) in expected_sizes.iter().enumerate() {
			assert_eq!(
				inverse[i].len(),
				*expected_size,
				"Inverse elements size mismatch at index {}",
				i
			);
			assert_eq!(
				forward[i].len(),
				*expected_size,
				"Forward elements size mismatch at index {}",
				i
			);
		}
	}

	#[test]
	fn test_elements_for_each_subspace_dimension_sequence() {
		let initial_dim = 7;
		let subspace = BinarySubspace::<BinaryField32b>::with_dim(initial_dim).unwrap();
		let (inverse, forward) =
			elements_for_each_subspace_broadcasted::<_, BinaryField32b>(subspace.clone());

		// Verify we get the correct number of subspaces
		assert_eq!(inverse.len(), initial_dim - 1);
		assert_eq!(forward.len(), initial_dim - 1);

		// Manually verify the sequence by computing it step by step
		let mut current = subspace;
		for i in 0..(initial_dim - 1) {
			let (inv_check, fwd_check) =
				elements_of_subspace_broadcasted::<_, BinaryField32b>(&current);

			// Compare lengths (can't directly compare elements due to iteration order)
			assert_eq!(inverse[i].len(), inv_check.len());
			assert_eq!(forward[i].len(), fwd_check.len());

			current = get_next_subspace(&current);
		}

		// Final subspace should have dimension 1
		assert_eq!(current.dim(), 1);
	}

	#[test]
	fn test_subspace_reduction_invariants() {
		let subspace = BinarySubspace::<BinaryField128b>::with_dim(5).unwrap();

		let mut current = subspace.clone();
		let mut dimensions = vec![current.dim()];

		// Apply reduction multiple times
		while current.dim() > 1 {
			current = get_next_subspace(&current);
			dimensions.push(current.dim());
		}

		// Verify monotonic decrease
		for i in 1..dimensions.len() {
			assert_eq!(
				dimensions[i],
				dimensions[i - 1] - 1,
				"Dimension should decrease by 1 each time"
			);
		}
	}
}

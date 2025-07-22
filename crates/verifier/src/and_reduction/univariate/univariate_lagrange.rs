use binius_field::{AESTowerField8b, Field};

use crate::and_reduction::univariate::subfield_isomorphism::SubfieldIsomorphismLookup;

fn products_excluding_one_element<F: Field>(input: &[F]) -> Vec<F> {
	let mut results = vec![F::ONE; input.len()];
	for i in (0..(input.len() - 1)).rev() {
		results[i] = results[i + 1] * input[i + 1];
	}

	let mut forward_product = F::ONE;

	for i in 1..input.len() {
		forward_product *= input[i - 1];
		results[i] *= forward_product;
	}

	results
}

pub fn lexicographic_lagrange_denominator(log_basis_size: usize) -> AESTowerField8b {
	(1..=((1 << log_basis_size) - 1) as u8)
		.map(AESTowerField8b::new)
		.product::<AESTowerField8b>()
}

pub fn lexicographic_lagrange_numerators_polyval<F: Field>(
	basis_size: usize,
	eval_point: F,
	iso_lookup: &SubfieldIsomorphismLookup<F>,
) -> Vec<F> {
	let basis_point_differences: Vec<_> = (0..=(basis_size - 1) as u8)
		.map(|i| eval_point - iso_lookup.lookup_8b_value(AESTowerField8b::new(i)))
		.collect();

	products_excluding_one_element(&basis_point_differences)
}

pub fn lexicographic_lagrange_numerators_8b(
	basis_size: usize,
	eval_point: AESTowerField8b,
) -> Vec<AESTowerField8b> {
	let basis_point_differences: Vec<_> = (0..basis_size as u8)
		.map(|i| eval_point - AESTowerField8b::new(i))
		.collect();
	products_excluding_one_element(&basis_point_differences)
}

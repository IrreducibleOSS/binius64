use binius_field::Field;

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

pub fn lexicographic_lagrange_denominator<FNTTDomain: Field + From<u8>>(
	log_basis_size: usize,
) -> FNTTDomain {
	(1..=((1 << log_basis_size) - 1) as u8)
		.map(FNTTDomain::from)
		.product::<FNTTDomain>()
}

pub fn lexicographic_lagrange_numerators_polyval<
	FNTTDomain: Field + From<u8>,
	FChallenge: Field + From<FNTTDomain>,
>(
	basis_size: usize,
	eval_point: FChallenge,
) -> Vec<FChallenge> {
	let basis_point_differences: Vec<_> = (0..=(basis_size - 1) as u8)
		.map(|i| eval_point - FChallenge::from(FNTTDomain::from(i)))
		.collect();

	products_excluding_one_element(&basis_point_differences)
}

pub fn lexicographic_lagrange_numerators_8b<F: Field + From<u8>>(
	basis_size: usize,
	eval_point: F,
) -> Vec<F> {
	let basis_point_differences: Vec<_> = (0..basis_size as u8)
		.map(|i| eval_point - F::from(i))
		.collect();
	products_excluding_one_element(&basis_point_differences)
}

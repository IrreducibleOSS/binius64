use binius_field::{AESTowerField8b, BinaryField, PackedField};
use binius_math::BinarySubspace;

/// Precomputed domains for NTT operations
pub struct NttDomains<P: PackedField<Scalar = AESTowerField8b>> {
	pub domain_0: [P; 64],
	pub domain_1: [P; 32],
	pub domain_2: [P; 16],
	pub domain_3: [P; 8],
	pub domain_4: [P; 4],
	pub domain_5: [P; 2],
}

fn get_next_subspace<F: BinaryField>(current_subspace: &BinarySubspace<F>) -> BinarySubspace<F> {
	let basis = current_subspace.basis();
	let div_by_factor = basis[1] * (basis[1] + F::ONE);

	let mut new_basis = vec![];
	for basis_elem in basis[1..].iter() {
		new_basis.push(*basis_elem * (*basis_elem + F::ONE) * div_by_factor.invert_or_zero());
	}

	BinarySubspace::new_unchecked(new_basis)
}

fn elements_of_subspace_broadcasted<F: BinaryField, P: PackedField<Scalar = F>>(
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

fn elements_for_each_subspace_broadcasted<F: BinaryField, P: PackedField<Scalar = F>>(
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

/// Generate NTT domains for a given subspace
pub fn generate_ntt_domains<P: PackedField<Scalar = AESTowerField8b>>(
	subspace: BinarySubspace<AESTowerField8b>,
) -> (NttDomains<P>, NttDomains<P>) {
	let (inverse_domains, forward_domains) = elements_for_each_subspace_broadcasted(subspace);

	// Convert vectors to fixed-size arrays
	let intt_domains = NttDomains {
		domain_0: inverse_domains[0]
			.as_slice()
			.try_into()
			.expect("Domain 0 should have 64 elements"),
		domain_1: inverse_domains[1]
			.as_slice()
			.try_into()
			.expect("Domain 1 should have 32 elements"),
		domain_2: inverse_domains[2]
			.as_slice()
			.try_into()
			.expect("Domain 2 should have 16 elements"),
		domain_3: inverse_domains[3]
			.as_slice()
			.try_into()
			.expect("Domain 3 should have 8 elements"),
		domain_4: inverse_domains[4]
			.as_slice()
			.try_into()
			.expect("Domain 4 should have 4 elements"),
		domain_5: inverse_domains[5]
			.as_slice()
			.try_into()
			.expect("Domain 5 should have 2 elements"),
	};

	let fntt_domains = NttDomains {
		domain_0: forward_domains[0]
			.as_slice()
			.try_into()
			.expect("Domain 0 should have 64 elements"),
		domain_1: forward_domains[1]
			.as_slice()
			.try_into()
			.expect("Domain 1 should have 32 elements"),
		domain_2: forward_domains[2]
			.as_slice()
			.try_into()
			.expect("Domain 2 should have 16 elements"),
		domain_3: forward_domains[3]
			.as_slice()
			.try_into()
			.expect("Domain 3 should have 8 elements"),
		domain_4: forward_domains[4]
			.as_slice()
			.try_into()
			.expect("Domain 4 should have 4 elements"),
		domain_5: forward_domains[5]
			.as_slice()
			.try_into()
			.expect("Domain 5 should have 2 elements"),
	};

	(intt_domains, fntt_domains)
}

/// Fast specialized inverse NTT for 2^6 size with provided domains
#[inline]
pub fn fast_inverse_ntt_64<P: PackedField<Scalar = AESTowerField8b>>(
	polynomial_evals: &mut [P; 64],
	domains: &NttDomains<P>,
) {
	let mut temp = [P::zero(); 64];

	// Round 0: domain size 64, 1 chunk of 64 elements
	{
		let domain = &domains.domain_0;
		let half_len = 32;
		for i in 0..half_len {
			temp[half_len | i] = polynomial_evals[(i << 1) | 1] - polynomial_evals[i << 1];
			temp[i] = domain[i << 1] * temp[half_len | i] + polynomial_evals[i << 1];
		}
		*polynomial_evals = temp;
	}

	// Round 1: domain size 32, 2 chunks of 32 elements each
	{
		let domain = &domains.domain_1;
		for chunk in 0..2 {
			let offset = chunk * 32;
			let half_len = 16;
			for i in 0..half_len {
				temp[offset | half_len | i] =
					polynomial_evals[offset | (i << 1) | 1] - polynomial_evals[offset | i << 1];
				temp[offset | i] = domain[i << 1] * temp[offset | half_len | i]
					+ polynomial_evals[offset | i << 1];
			}
		}
		*polynomial_evals = temp;
	}

	// Round 2: domain size 16, 4 chunks of 16 elements each
	{
		let domain = &domains.domain_2;
		for chunk in 0..4 {
			let offset = chunk * 16;
			let half_len = 8;
			for i in 0..half_len {
				temp[offset | half_len | i] =
					polynomial_evals[offset | (i << 1) | 1] - polynomial_evals[offset | i << 1];
				temp[offset | i] = domain[i << 1] * temp[offset | half_len | i]
					+ polynomial_evals[offset | i << 1];
			}
		}
		*polynomial_evals = temp;
	}

	// Round 3: domain size 8, 8 chunks of 8 elements each
	{
		let domain = &domains.domain_3;
		for chunk in 0..8 {
			let offset = chunk * 8;
			let half_len = 4;
			for i in 0..half_len {
				temp[offset | half_len | i] =
					polynomial_evals[offset | (i << 1) | 1] - polynomial_evals[offset | i << 1];
				temp[offset | i] = domain[i << 1] * temp[offset | half_len | i]
					+ polynomial_evals[offset | i << 1];
			}
		}
		*polynomial_evals = temp;
	}

	// Round 4: domain size 4, 16 chunks of 4 elements each
	{
		let domain = &domains.domain_4;
		for chunk in 0..16 {
			let offset = chunk * 4;
			let half_len = 2;
			for i in 0..half_len {
				temp[offset | half_len | i] =
					polynomial_evals[offset | (i << 1) | 1] - polynomial_evals[offset | i << 1];
				temp[offset | i] = domain[i << 1] * temp[offset | half_len | i]
					+ polynomial_evals[offset | i << 1];
			}
		}
		*polynomial_evals = temp;
	}

	// Round 5: domain size 2, 32 chunks of 2 elements each
	{
		let domain = &domains.domain_5;
		for chunk in 0..32 {
			let offset = chunk * 2;
			temp[offset | 1] = polynomial_evals[offset | 1] - polynomial_evals[offset];
			temp[offset] = domain[0] * temp[offset | 1] + polynomial_evals[offset];
		}
		*polynomial_evals = temp;
	}
}

/// Fast specialized forward NTT for 2^6 size with provided domains
#[inline]
pub fn fast_forward_ntt_64<P: PackedField<Scalar = AESTowerField8b>>(
	polynomial_evals: &mut [P; 64],
	domains: &NttDomains<P>,
) {
	let mut temp = [P::zero(); 64];

	// Round 0: domain size 2, 32 chunks of 2 elements each
	{
		let domain = &domains.domain_5;
		for chunk in 0..32 {
			let offset = chunk * 2;
			let half_len = 1;
			for i in 0..half_len {
				temp[offset | i << 1] = domain[i << 1] * polynomial_evals[offset | half_len | i]
					+ polynomial_evals[offset | i];
				temp[offset | (i << 1) | 1] =
					temp[offset | i << 1] + polynomial_evals[offset | half_len | i];
			}
		}

		*polynomial_evals = temp;
	}

	// Round 1: domain size 4, 16 chunks of 4 elements each
	{
		let domain = &domains.domain_4;
		for chunk in 0..16 {
			let offset = chunk * 4;
			let half_len = 2;
			for i in 0..half_len {
				temp[offset | i << 1] = domain[i << 1] * polynomial_evals[offset | half_len | i]
					+ polynomial_evals[offset | i];
				temp[offset | (i << 1) | 1] =
					temp[offset | i << 1] + polynomial_evals[offset | half_len | i];
			}
		}

		*polynomial_evals = temp;
	}

	// Round 2: domain size 8, 8 chunks of 8 elements each
	{
		let domain = &domains.domain_3;
		for chunk in 0..8 {
			let offset = chunk * 8;
			let half_len = 4;
			for i in 0..half_len {
				temp[offset | i << 1] = domain[i << 1] * polynomial_evals[offset | half_len | i]
					+ polynomial_evals[offset | i];
				temp[offset | (i << 1) | 1] =
					temp[offset | i << 1] + polynomial_evals[offset | half_len | i];
			}
		}

		*polynomial_evals = temp;
	}

	// Round 3: domain size 16, 4 chunks of 16 elements each
	{
		let domain = &domains.domain_2;
		for chunk in 0..4 {
			let offset = chunk * 16;
			let half_len = 8;
			for i in 0..half_len {
				temp[offset | i << 1] = domain[i << 1] * polynomial_evals[offset | half_len | i]
					+ polynomial_evals[offset | i];
				temp[offset | (i << 1) | 1] =
					temp[offset | i << 1] + polynomial_evals[offset | half_len | i];
			}
		}

		*polynomial_evals = temp;
	}

	// Round 4: domain size 32, 2 chunks of 32 elements each
	{
		let domain = &domains.domain_1;
		for chunk in 0..2 {
			let offset = chunk * 32;
			let half_len = 16;
			for i in 0..half_len {
				temp[offset | i << 1] = domain[i << 1] * polynomial_evals[offset | half_len | i]
					+ polynomial_evals[offset | i];
				temp[offset | (i << 1) | 1] =
					temp[offset | i << 1] + polynomial_evals[offset | half_len | i];
			}
		}

		*polynomial_evals = temp;
	}

	// Round 5: domain size 64, 1 chunk of 64 elements
	{
		let domain = &domains.domain_0;
		let half_len = 32;
		for i in 0..half_len {
			temp[i << 1] = domain[i << 1] * polynomial_evals[half_len | i] + polynomial_evals[i];
			temp[(i << 1) | 1] = temp[i << 1] + polynomial_evals[half_len | i];
		}
		*polynomial_evals = temp;
	}
}

/// Fast specialized NTT for 2^6 size with provided domains
#[inline]
pub fn fast_ntt_64<P: PackedField<Scalar = AESTowerField8b>>(
	polynomial_evals: &mut [P; 64],
	intt_domains: &NttDomains<P>,
	fntt_domains: &NttDomains<P>,
) {
	fast_inverse_ntt_64(polynomial_evals, intt_domains);
	fast_forward_ntt_64(polynomial_evals, fntt_domains);
}

#[cfg(test)]
mod tests {
	use binius_field::{Field, Random, PackedAESBinaryField16x8b};
	use binius_math::BinarySubspace;
	use binius_verifier::and_reduction::univariate::univariate_poly::{
		GenericPo2UnivariatePoly, UnivariatePolyIsomorphic,
	};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	#[test]
	fn test_fast_ntt_64_correctness() {
		let mut rng = StdRng::seed_from_u64(0);
		let subspace = BinarySubspace::<AESTowerField8b>::with_dim(7).unwrap();
		let input_space = subspace.reduce_dim(6).unwrap();

		let poly = GenericPo2UnivariatePoly::new(
			(0..64)
				.map(|_| AESTowerField8b::random(&mut rng))
				.collect_vec(),
			input_space.clone(),
		);

		let last_basis_vec = subspace.basis()[subspace.basis().len() - 1];

		// Generate domains using elements_for_each_subspace
		let (intt_domains, fntt_domains) = generate_ntt_domains(subspace.clone());

		// Test with fast NTT
		let mut polynomial_evals: [AESTowerField8b; 64] =
			poly.iter().copied().collect_vec().try_into().unwrap();
		fast_ntt_64(&mut polynomial_evals, &intt_domains, &fntt_domains);

		// Verify correctness
		for (i, input_domain_elem) in input_space.iter().enumerate() {
			let result = poly.evaluate_at_challenge(input_domain_elem + last_basis_vec);
			assert_eq!(result, polynomial_evals[i], "Fast NTT result mismatch at index {}", i);
		}
	}

	#[test]
	fn test_fast_ntt_linearity() {
		let mut rng = StdRng::seed_from_u64(42);
		let subspace = BinarySubspace::<AESTowerField8b>::with_dim(7).unwrap();

		// Generate domains using elements_for_each_subspace
		let (intt_domains, fntt_domains) = generate_ntt_domains(subspace);

		// Create two random polynomials
		let mut poly_a: [AESTowerField8b; 64] = [AESTowerField8b::ZERO; 64];
		let mut poly_b: [AESTowerField8b; 64] = [AESTowerField8b::ZERO; 64];
		for i in 0..64 {
			poly_a[i] = AESTowerField8b::random(&mut rng);
			poly_b[i] = AESTowerField8b::random(&mut rng);
		}

		// Compute NTT(a + b)
		let mut poly_sum: [AESTowerField8b; 64] = [AESTowerField8b::ZERO; 64];
		for i in 0..64 {
			poly_sum[i] = poly_a[i] + poly_b[i];
		}
		fast_ntt_64(&mut poly_sum, &intt_domains, &fntt_domains);

		// Compute NTT(a) + NTT(b)
		let mut ntt_a = poly_a.clone();
		let mut ntt_b = poly_b.clone();
		fast_ntt_64(&mut ntt_a, &intt_domains, &fntt_domains);
		fast_ntt_64(&mut ntt_b, &intt_domains, &fntt_domains);

		let mut ntt_sum: [AESTowerField8b; 64] = [AESTowerField8b::ZERO; 64];
		for i in 0..64 {
			ntt_sum[i] = ntt_a[i] + ntt_b[i];
		}

		// Check linearity: NTT(a + b) = NTT(a) + NTT(b)
		assert_eq!(poly_sum, ntt_sum, "NTT should be linear");
	}

	#[test]
	fn test_fast_ntt_64_packed_16x8b_correctness() {
		let mut rng = StdRng::seed_from_u64(0);
		let subspace = BinarySubspace::<AESTowerField8b>::with_dim(7).unwrap();
		let input_space = subspace.reduce_dim(6).unwrap();

		// Create random packed field values
		let mut packed_poly: [PackedAESBinaryField16x8b; 64] = [PackedAESBinaryField16x8b::zero(); 64];
		for i in 0..64 {
			packed_poly[i] = PackedAESBinaryField16x8b::random(&mut rng);
		}

		// Generate domains for packed field type
		let (intt_domains, fntt_domains) = generate_ntt_domains::<PackedAESBinaryField16x8b>(subspace.clone());

		// Perform NTT on packed values
		let mut ntt_result = packed_poly.clone();
		fast_ntt_64(&mut ntt_result, &intt_domains, &fntt_domains);

		// Extract individual elements from packed fields and verify
		for elem_idx in 0..16 {
			// Extract element at position elem_idx from each packed field
			let mut single_poly_coeffs = vec![];
			for i in 0..64 {
				single_poly_coeffs.push(packed_poly[i].get(elem_idx));
			}

			// Create univariate polynomial from extracted elements
			let single_poly = GenericPo2UnivariatePoly::new(
				single_poly_coeffs,
				input_space.clone(),
			);

			// Verify evaluations match extracted elements from NTT result
			let last_basis_vec = subspace.basis()[subspace.basis().len() - 1];
			for (i, input_domain_elem) in input_space.iter().enumerate() {
				let expected = single_poly.evaluate_at_challenge(input_domain_elem + last_basis_vec);
				let actual = ntt_result[i].get(elem_idx);
				assert_eq!(expected, actual, 
					"Mismatch at element {} of packed field index {}", elem_idx, i);
			}
		}
	}
}

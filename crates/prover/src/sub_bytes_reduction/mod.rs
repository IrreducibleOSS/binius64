
pub mod fast_ntt_64;

#[cfg(test)]
mod test {
	use binius_field::{
		AESTowerField8b, BinaryField, Field, Random,
	};
	use binius_math::BinarySubspace;
	use binius_verifier::and_reduction::univariate::univariate_poly::{
		GenericPo2UnivariatePoly, UnivariatePolyIsomorphic,
	};
	use itertools::Itertools;
	use rand::{rngs::StdRng, SeedableRng};

	fn get_next_subspace<F: BinaryField>(
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

	fn elements_of_subspace<F: BinaryField>(subspace: &BinarySubspace<F>) -> (Vec<F>, Vec<F>) {
		let dim = subspace.dim();

		let inverse = subspace.iter().take(1 << (dim - 1)).collect();

		let fowrard = subspace
			.iter()
			.skip(1 << (dim - 1))
			.take(1 << (dim - 1))
			.collect();

		(inverse, fowrard)
	}

	fn single_foward_ntt_round_one_polynomial<F: BinaryField>(
		polynomial_evals: &[F],
		domain: &[F],
	) -> Vec<F> {
		assert_eq!(
			polynomial_evals.len(),
			domain.len(),
			"polynomial_evals and domain must have the same length"
		);

		let mut result = vec![F::ZERO; domain.len()];

		let half_len = result.len() >> 1;

		for i in 0..half_len {
			result[i << 1] = domain[i << 1] * polynomial_evals[i + half_len] + polynomial_evals[i];
			result[(i << 1) + 1] = result[i << 1] + polynomial_evals[i + half_len];
		}

		result
	}

	fn single_inverse_ntt_round_one_polynomial<F: BinaryField>(
		polynomial_evals: &[F],
		domain: &[F],
	) -> Vec<F> {
		let mut result = vec![F::ZERO; domain.len()];

		let half_len = result.len() >> 1;

		for i in 0..half_len {
			result[i + half_len] = polynomial_evals[(i << 1) + 1] - polynomial_evals[i << 1];
			result[i] = domain[i << 1] * result[i + half_len] + polynomial_evals[i << 1];
		}

		result
	}

	fn single_inverse_ntt_round_full<F: BinaryField>(
		polynomial_evals: &[F],
		domain: &[F],
	) -> Vec<F> {
		let domain_len = domain.len();
		let num_chunks = polynomial_evals.len() / domain_len;
		let mut result = vec![F::ZERO; polynomial_evals.len()];

		for chunk_idx in 0..num_chunks {
			let start = chunk_idx * domain_len;
			let end = start + domain_len;
			let chunk_result =
				single_inverse_ntt_round_one_polynomial(&polynomial_evals[start..end], domain);
			result[start..end].copy_from_slice(&chunk_result);
		}

		result
	}

	fn single_forward_ntt_round_full<F: BinaryField>(
		polynomial_evals: &[F],
		domain: &[F],
	) -> Vec<F> {
		let domain_len = domain.len();
		let num_chunks = polynomial_evals.len() / domain_len;
		let mut result = vec![F::ZERO; polynomial_evals.len()];

		for chunk_idx in 0..num_chunks {
			let start = chunk_idx * domain_len;
			let end = start + domain_len;
			let chunk_result =
				single_foward_ntt_round_one_polynomial(&polynomial_evals[start..end], domain);
			result[start..end].copy_from_slice(&chunk_result);
		}

		result
	}


	fn inverse_ntt<F: BinaryField>(polynomial_evals: &mut [F], subspace: BinarySubspace<F>) {
		let (domains, _) = elements_for_each_subspace(subspace.clone());
		for domain in domains {
			let new_poly_evals = single_inverse_ntt_round_full(polynomial_evals, &domain);
			polynomial_evals.copy_from_slice(&new_poly_evals);
			println!("domain intt: {:?}", domain);
		}
	}

	fn forward_ntt<F: BinaryField>(polynomial_evals: &mut [F], subspace: BinarySubspace<F>) {
		let (_, domains) = elements_for_each_subspace(subspace.clone());
		for domain in domains.iter().rev() {
			let new_poly_evals = single_forward_ntt_round_full(polynomial_evals, &domain);
			polynomial_evals.copy_from_slice(&new_poly_evals);
			println!("domain fntt: {:?}", domain);
		}
	}


	fn ntt<F: BinaryField>(polynomial_evals: &mut [F], subspace: BinarySubspace<F>) {
		inverse_ntt(polynomial_evals, subspace.clone());
		println!("in between : {:?}", polynomial_evals);
		forward_ntt(polynomial_evals, subspace);
	}

	fn elements_for_each_subspace<F: BinaryField>(
		mut subspace: BinarySubspace<F>,
	) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
		let (mut inverse, mut forward) = (vec![], vec![]);

		for _dim in (2..=subspace.dim()).rev() {
			let subspace_elems = elements_of_subspace(&subspace);

			inverse.push(subspace_elems.0);
			forward.push(subspace_elems.1);

			subspace = get_next_subspace(&subspace);
		}

		(inverse, forward)
	}

	#[test]
	fn test_forward_inverse_are_inverses_one_poly() {
		// Test with different subspace dimensions
		for dim in 3..=8 {
			let subspace = BinarySubspace::<AESTowerField8b>::with_dim(dim).unwrap();

			// Use subspace.iter().collect() as requested by user
			let domain: Vec<AESTowerField8b> = subspace.iter().collect();

			// Create test polynomial evaluations with same size as domain
			let poly_size = domain.len();
			let mut test_poly = vec![AESTowerField8b::ZERO; poly_size];

			// Initialize with some non-zero values
			for i in 0..poly_size {
				test_poly[i] = AESTowerField8b::new(i as u8);
			}

			// Apply forward NTT
			let forward_result = single_foward_ntt_round_one_polynomial(&test_poly, &domain);

			// Apply inverse NTT using the same domain
			let inverse_result = single_inverse_ntt_round_one_polynomial(&forward_result, &domain);

			// Check that we get back the original polynomial
			assert_eq!(
				test_poly, inverse_result,
				"Forward and inverse NTT should be inverses for dimension {}",
				dim
			);
		}
	}

	#[test]
	fn test_forward_inverse_are_inverses_full_round() {
		// Test with different subspace dimensions
		for dim in 3..=8 {
			let subspace = BinarySubspace::<AESTowerField8b>::with_dim(dim).unwrap();

			// Use subspace.iter().collect() as requested by user
			let domain: Vec<AESTowerField8b> = subspace.iter().collect();

			// Create test polynomial evaluations with same size as domain
			let poly_size = domain.len() * 8;
			let mut test_poly = vec![AESTowerField8b::ZERO; poly_size];

			// Initialize with some non-zero values
			for i in 0..poly_size {
				test_poly[i] = AESTowerField8b::new(i as u8);
			}

			// Apply forward NTT
			let forward_result = single_forward_ntt_round_full(&test_poly, &domain);

			// Apply inverse NTT using the same domain
			let inverse_result = single_inverse_ntt_round_full(&forward_result, &domain);

			// Check that we get back the original polynomial
			assert_eq!(
				test_poly, inverse_result,
				"Forward and inverse NTT should be inverses for dimension {}",
				dim
			);
		}
	}

	#[test]
	fn test_get_next_subspace() {
		// Test that get_next_subspace reduces dimension by 1
		for start_dim in 3..=8 {
			let subspace = BinarySubspace::<AESTowerField8b>::with_dim(start_dim).unwrap();
			let next_subspace = get_next_subspace(&subspace);

			assert_eq!(
				next_subspace.dim(),
				start_dim - 1,
				"get_next_subspace should reduce dimension by 1"
			);

			// Verify the next subspace has valid basis
			assert_eq!(
				next_subspace.basis().len(),
				start_dim - 1,
				"Next subspace basis should have dimension - 1 elements"
			);
		}
	}

	#[test]
	fn test_ntt() {
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

		let mut polynomial_evals = poly.iter().copied().collect_vec();

		ntt(&mut polynomial_evals, subspace.clone());

		for (i, input_domain_elem) in input_space.iter().enumerate() {
			let result = poly.evaluate_at_challenge(input_domain_elem + last_basis_vec);

			assert_eq!(result, polynomial_evals[i])
		}
	}
	
	#[test]
	fn test_fast_ntt_64() {
		use crate::sub_bytes_reduction::fast_ntt_64::fast_ntt_64;
		
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

		// Test with generic NTT
		let mut polynomial_evals_generic = poly.iter().copied().collect_vec();
		ntt(&mut polynomial_evals_generic, subspace.clone());

		// Test with fast specialized NTT
		let mut polynomial_evals_fast: [AESTowerField8b; 64] = poly.iter().copied().collect_vec().try_into().unwrap();
		fast_ntt_64(&mut polynomial_evals_fast, &crate::sub_bytes_reduction::fast_ntt_64::DEFAULT_INTT_DOMAINS, &crate::sub_bytes_reduction::fast_ntt_64::DEFAULT_FNTT_DOMAINS);
		
		// Verify they produce the same results
		assert_eq!(&polynomial_evals_generic[..], &polynomial_evals_fast[..], "Fast NTT should produce same results as generic NTT");

		// Also verify correctness
		for (i, input_domain_elem) in input_space.iter().enumerate() {
			let result = poly.evaluate_at_challenge(input_domain_elem + last_basis_vec);
			assert_eq!(result, polynomial_evals_fast[i])
		}
	}

	#[test]
	fn test_elements_of_subspace() {
		// Test elements_of_subspace returns correct split
		for dim in 2..=8 {
			let subspace = BinarySubspace::<AESTowerField8b>::with_dim(dim).unwrap();
			let (inverse, forward) = elements_of_subspace(&subspace);

			// Check that both halves have correct size
			let expected_half_size = 1 << (dim - 1);
			assert_eq!(
				inverse.len(),
				expected_half_size,
				"Inverse elements should have size 2^(dim-1)"
			);
			assert_eq!(
				forward.len(),
				expected_half_size,
				"Forward elements should have size 2^(dim-1)"
			);

			// Verify that inverse contains first half of subspace elements
			let subspace_elems: Vec<_> = subspace.iter().collect();
			assert_eq!(
				&inverse[..],
				&subspace_elems[..expected_half_size],
				"Inverse should contain first half of subspace elements"
			);
			assert_eq!(
				&forward[..],
				&subspace_elems[expected_half_size..2 * expected_half_size],
				"Forward should contain second half of subspace elements"
			);
		}
	}

	#[test]
	fn test_forward_ntt_specific_values() {
		// Test that forward NTT of [1,0,0,0] produces [1,1,1,1]
		let mut polynomial_evals = vec![
			AESTowerField8b::ONE,
			AESTowerField8b::ZERO,
			AESTowerField8b::ZERO,
			AESTowerField8b::ZERO,
		];

		let subspace = BinarySubspace::<AESTowerField8b>::with_dim(3).unwrap();
		forward_ntt(&mut polynomial_evals, subspace);

		let expected = vec![
			AESTowerField8b::ONE,
			AESTowerField8b::ONE,
			AESTowerField8b::ONE,
			AESTowerField8b::ONE,
		];

		assert_eq!(polynomial_evals, expected, "Forward NTT of [1,0,0,0] should produce [1,1,1,1]");
	}

	#[test]
	fn test_inverse_ntt_specific_values() {
		// Test that inverse NTT of [1,1,1,1] produces [1,0,0,0]
		let mut polynomial_evals = vec![
			AESTowerField8b::ONE,
			AESTowerField8b::ONE,
			AESTowerField8b::ONE,
			AESTowerField8b::ONE,
		];

		let subspace = BinarySubspace::<AESTowerField8b>::with_dim(3).unwrap();
		inverse_ntt(&mut polynomial_evals, subspace);

		let expected = vec![
			AESTowerField8b::ONE,
			AESTowerField8b::ZERO,
			AESTowerField8b::ZERO,
			AESTowerField8b::ZERO,
		];

		assert_eq!(polynomial_evals, expected, "Inverse NTT of [1,1,1,1] should produce [1,0,0,0]");
	}
}

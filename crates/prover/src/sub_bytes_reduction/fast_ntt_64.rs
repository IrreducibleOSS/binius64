use binius_field::{AESTowerField8b, BinaryField};

// Precomputed inverse NTT domains for 2^6 size
const INTT_DOMAIN_0: [AESTowerField8b; 64] = [AESTowerField8b::new(0x00), AESTowerField8b::new(0x01), AESTowerField8b::new(0x02), AESTowerField8b::new(0x03), AESTowerField8b::new(0x04), AESTowerField8b::new(0x05), AESTowerField8b::new(0x06), AESTowerField8b::new(0x07), AESTowerField8b::new(0x08), AESTowerField8b::new(0x09), AESTowerField8b::new(0x0a), AESTowerField8b::new(0x0b), AESTowerField8b::new(0x0c), AESTowerField8b::new(0x0d), AESTowerField8b::new(0x0e), AESTowerField8b::new(0x0f), AESTowerField8b::new(0x10), AESTowerField8b::new(0x11), AESTowerField8b::new(0x12), AESTowerField8b::new(0x13), AESTowerField8b::new(0x14), AESTowerField8b::new(0x15), AESTowerField8b::new(0x16), AESTowerField8b::new(0x17), AESTowerField8b::new(0x18), AESTowerField8b::new(0x19), AESTowerField8b::new(0x1a), AESTowerField8b::new(0x1b), AESTowerField8b::new(0x1c), AESTowerField8b::new(0x1d), AESTowerField8b::new(0x1e), AESTowerField8b::new(0x1f), AESTowerField8b::new(0x20), AESTowerField8b::new(0x21), AESTowerField8b::new(0x22), AESTowerField8b::new(0x23), AESTowerField8b::new(0x24), AESTowerField8b::new(0x25), AESTowerField8b::new(0x26), AESTowerField8b::new(0x27), AESTowerField8b::new(0x28), AESTowerField8b::new(0x29), AESTowerField8b::new(0x2a), AESTowerField8b::new(0x2b), AESTowerField8b::new(0x2c), AESTowerField8b::new(0x2d), AESTowerField8b::new(0x2e), AESTowerField8b::new(0x2f), AESTowerField8b::new(0x30), AESTowerField8b::new(0x31), AESTowerField8b::new(0x32), AESTowerField8b::new(0x33), AESTowerField8b::new(0x34), AESTowerField8b::new(0x35), AESTowerField8b::new(0x36), AESTowerField8b::new(0x37), AESTowerField8b::new(0x38), AESTowerField8b::new(0x39), AESTowerField8b::new(0x3a), AESTowerField8b::new(0x3b), AESTowerField8b::new(0x3c), AESTowerField8b::new(0x3d), AESTowerField8b::new(0x3e), AESTowerField8b::new(0x3f)];
const INTT_DOMAIN_1: [AESTowerField8b; 32] = [AESTowerField8b::new(0x00), AESTowerField8b::new(0x01), AESTowerField8b::new(0x06), AESTowerField8b::new(0x07), AESTowerField8b::new(0x1c), AESTowerField8b::new(0x1d), AESTowerField8b::new(0x1a), AESTowerField8b::new(0x1b), AESTowerField8b::new(0x78), AESTowerField8b::new(0x79), AESTowerField8b::new(0x7e), AESTowerField8b::new(0x7f), AESTowerField8b::new(0x64), AESTowerField8b::new(0x65), AESTowerField8b::new(0x62), AESTowerField8b::new(0x63), AESTowerField8b::new(0xeb), AESTowerField8b::new(0xea), AESTowerField8b::new(0xed), AESTowerField8b::new(0xec), AESTowerField8b::new(0xf7), AESTowerField8b::new(0xf6), AESTowerField8b::new(0xf1), AESTowerField8b::new(0xf0), AESTowerField8b::new(0x93), AESTowerField8b::new(0x92), AESTowerField8b::new(0x95), AESTowerField8b::new(0x94), AESTowerField8b::new(0x8f), AESTowerField8b::new(0x8e), AESTowerField8b::new(0x89), AESTowerField8b::new(0x88)];
const INTT_DOMAIN_2: [AESTowerField8b; 16] = [AESTowerField8b::new(0x00), AESTowerField8b::new(0x01), AESTowerField8b::new(0x16), AESTowerField8b::new(0x17), AESTowerField8b::new(0x67), AESTowerField8b::new(0x66), AESTowerField8b::new(0x71), AESTowerField8b::new(0x70), AESTowerField8b::new(0x52), AESTowerField8b::new(0x53), AESTowerField8b::new(0x44), AESTowerField8b::new(0x45), AESTowerField8b::new(0x35), AESTowerField8b::new(0x34), AESTowerField8b::new(0x23), AESTowerField8b::new(0x22)];
const INTT_DOMAIN_3: [AESTowerField8b; 8] = [AESTowerField8b::new(0x00), AESTowerField8b::new(0x01), AESTowerField8b::new(0x0d), AESTowerField8b::new(0x0c), AESTowerField8b::new(0xc8), AESTowerField8b::new(0xc9), AESTowerField8b::new(0xc5), AESTowerField8b::new(0xc4)];
const INTT_DOMAIN_4: [AESTowerField8b; 4] = [AESTowerField8b::new(0x00), AESTowerField8b::new(0x01), AESTowerField8b::new(0x53), AESTowerField8b::new(0x52)];
const INTT_DOMAIN_5: [AESTowerField8b; 2] = [AESTowerField8b::new(0x00), AESTowerField8b::new(0x01)];

// Precomputed forward NTT domains for 2^6 size
const FNTT_DOMAIN_0: [AESTowerField8b; 64] = [AESTowerField8b::new(0x40), AESTowerField8b::new(0x41), AESTowerField8b::new(0x42), AESTowerField8b::new(0x43), AESTowerField8b::new(0x44), AESTowerField8b::new(0x45), AESTowerField8b::new(0x46), AESTowerField8b::new(0x47), AESTowerField8b::new(0x48), AESTowerField8b::new(0x49), AESTowerField8b::new(0x4a), AESTowerField8b::new(0x4b), AESTowerField8b::new(0x4c), AESTowerField8b::new(0x4d), AESTowerField8b::new(0x4e), AESTowerField8b::new(0x4f), AESTowerField8b::new(0x50), AESTowerField8b::new(0x51), AESTowerField8b::new(0x52), AESTowerField8b::new(0x53), AESTowerField8b::new(0x54), AESTowerField8b::new(0x55), AESTowerField8b::new(0x56), AESTowerField8b::new(0x57), AESTowerField8b::new(0x58), AESTowerField8b::new(0x59), AESTowerField8b::new(0x5a), AESTowerField8b::new(0x5b), AESTowerField8b::new(0x5c), AESTowerField8b::new(0x5d), AESTowerField8b::new(0x5e), AESTowerField8b::new(0x5f), AESTowerField8b::new(0x60), AESTowerField8b::new(0x61), AESTowerField8b::new(0x62), AESTowerField8b::new(0x63), AESTowerField8b::new(0x64), AESTowerField8b::new(0x65), AESTowerField8b::new(0x66), AESTowerField8b::new(0x67), AESTowerField8b::new(0x68), AESTowerField8b::new(0x69), AESTowerField8b::new(0x6a), AESTowerField8b::new(0x6b), AESTowerField8b::new(0x6c), AESTowerField8b::new(0x6d), AESTowerField8b::new(0x6e), AESTowerField8b::new(0x6f), AESTowerField8b::new(0x70), AESTowerField8b::new(0x71), AESTowerField8b::new(0x72), AESTowerField8b::new(0x73), AESTowerField8b::new(0x74), AESTowerField8b::new(0x75), AESTowerField8b::new(0x76), AESTowerField8b::new(0x77), AESTowerField8b::new(0x78), AESTowerField8b::new(0x79), AESTowerField8b::new(0x7a), AESTowerField8b::new(0x7b), AESTowerField8b::new(0x7c), AESTowerField8b::new(0x7d), AESTowerField8b::new(0x7e), AESTowerField8b::new(0x7f)];
const FNTT_DOMAIN_1: [AESTowerField8b; 32] = [AESTowerField8b::new(0xa1), AESTowerField8b::new(0xa0), AESTowerField8b::new(0xa7), AESTowerField8b::new(0xa6), AESTowerField8b::new(0xbd), AESTowerField8b::new(0xbc), AESTowerField8b::new(0xbb), AESTowerField8b::new(0xba), AESTowerField8b::new(0xd9), AESTowerField8b::new(0xd8), AESTowerField8b::new(0xdf), AESTowerField8b::new(0xde), AESTowerField8b::new(0xc5), AESTowerField8b::new(0xc4), AESTowerField8b::new(0xc3), AESTowerField8b::new(0xc2), AESTowerField8b::new(0x4a), AESTowerField8b::new(0x4b), AESTowerField8b::new(0x4c), AESTowerField8b::new(0x4d), AESTowerField8b::new(0x56), AESTowerField8b::new(0x57), AESTowerField8b::new(0x50), AESTowerField8b::new(0x51), AESTowerField8b::new(0x32), AESTowerField8b::new(0x33), AESTowerField8b::new(0x34), AESTowerField8b::new(0x35), AESTowerField8b::new(0x2e), AESTowerField8b::new(0x2f), AESTowerField8b::new(0x28), AESTowerField8b::new(0x29)];
const FNTT_DOMAIN_2: [AESTowerField8b; 16] = [AESTowerField8b::new(0xbc), AESTowerField8b::new(0xbd), AESTowerField8b::new(0xaa), AESTowerField8b::new(0xab), AESTowerField8b::new(0xdb), AESTowerField8b::new(0xda), AESTowerField8b::new(0xcd), AESTowerField8b::new(0xcc), AESTowerField8b::new(0xee), AESTowerField8b::new(0xef), AESTowerField8b::new(0xf8), AESTowerField8b::new(0xf9), AESTowerField8b::new(0x89), AESTowerField8b::new(0x88), AESTowerField8b::new(0x9f), AESTowerField8b::new(0x9e)];
const FNTT_DOMAIN_3: [AESTowerField8b; 8] = [AESTowerField8b::new(0x3f), AESTowerField8b::new(0x3e), AESTowerField8b::new(0x32), AESTowerField8b::new(0x33), AESTowerField8b::new(0xf7), AESTowerField8b::new(0xf6), AESTowerField8b::new(0xfa), AESTowerField8b::new(0xfb)];
const FNTT_DOMAIN_4: [AESTowerField8b; 4] = [AESTowerField8b::new(0xd7), AESTowerField8b::new(0xd6), AESTowerField8b::new(0x84), AESTowerField8b::new(0x85)];
const FNTT_DOMAIN_5: [AESTowerField8b; 2] = [AESTowerField8b::new(0xb7), AESTowerField8b::new(0xb6)];

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
			single_forward_ntt_round_one_polynomial(&polynomial_evals[start..end], domain);
		result[start..end].copy_from_slice(&chunk_result);
	}

	result
}

fn single_forward_ntt_round_one_polynomial<F: BinaryField>(
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

/// Fast specialized inverse NTT for 2^6 size with precomputed domains
pub fn fast_inverse_ntt_64(polynomial_evals: &mut [AESTowerField8b; 64]) {
	let new_poly_evals = single_inverse_ntt_round_full(polynomial_evals, &INTT_DOMAIN_0);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_inverse_ntt_round_full(polynomial_evals, &INTT_DOMAIN_1);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_inverse_ntt_round_full(polynomial_evals, &INTT_DOMAIN_2);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_inverse_ntt_round_full(polynomial_evals, &INTT_DOMAIN_3);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_inverse_ntt_round_full(polynomial_evals, &INTT_DOMAIN_4);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_inverse_ntt_round_full(polynomial_evals, &INTT_DOMAIN_5);
	polynomial_evals.copy_from_slice(&new_poly_evals);
}

/// Fast specialized forward NTT for 2^6 size with precomputed domains
pub fn fast_forward_ntt_64(polynomial_evals: &mut [AESTowerField8b; 64]) {
	let new_poly_evals = single_forward_ntt_round_full(polynomial_evals, &FNTT_DOMAIN_5);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_forward_ntt_round_full(polynomial_evals, &FNTT_DOMAIN_4);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_forward_ntt_round_full(polynomial_evals, &FNTT_DOMAIN_3);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_forward_ntt_round_full(polynomial_evals, &FNTT_DOMAIN_2);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_forward_ntt_round_full(polynomial_evals, &FNTT_DOMAIN_1);
	polynomial_evals.copy_from_slice(&new_poly_evals);
	
	let new_poly_evals = single_forward_ntt_round_full(polynomial_evals, &FNTT_DOMAIN_0);
	polynomial_evals.copy_from_slice(&new_poly_evals);
}

/// Fast specialized NTT for 2^6 size with precomputed domains
pub fn fast_ntt_64(polynomial_evals: &mut [AESTowerField8b; 64]) {
	fast_inverse_ntt_64(polynomial_evals);
	fast_forward_ntt_64(polynomial_evals);
}

#[cfg(test)]
mod tests {
	use super::*;
	use binius_field::{Field, Random};
	use binius_math::BinarySubspace;
	use binius_verifier::and_reduction::univariate::univariate_poly::{
		GenericPo2UnivariatePoly, UnivariatePolyIsomorphic,
	};
	use itertools::Itertools;
	use rand::{rngs::StdRng, SeedableRng};

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

		// Test with fast NTT
		let mut polynomial_evals: [AESTowerField8b; 64] = poly.iter().copied().collect_vec().try_into().unwrap();
		fast_ntt_64(&mut polynomial_evals);

		// Verify correctness
		for (i, input_domain_elem) in input_space.iter().enumerate() {
			let result = poly.evaluate_at_challenge(input_domain_elem + last_basis_vec);
			assert_eq!(result, polynomial_evals[i], "Fast NTT result mismatch at index {}", i);
		}
	}

	#[test]
	fn test_fast_ntt_linearity() {
		let mut rng = StdRng::seed_from_u64(42);
		
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
		fast_ntt_64(&mut poly_sum);
		
		// Compute NTT(a) + NTT(b)
		let mut ntt_a = poly_a.clone();
		let mut ntt_b = poly_b.clone();
		fast_ntt_64(&mut ntt_a);
		fast_ntt_64(&mut ntt_b);
		
		let mut ntt_sum: [AESTowerField8b; 64] = [AESTowerField8b::ZERO; 64];
		for i in 0..64 {
			ntt_sum[i] = ntt_a[i] + ntt_b[i];
		}
		
		// Check linearity: NTT(a + b) = NTT(a) + NTT(b)
		assert_eq!(poly_sum, ntt_sum, "NTT should be linear");
	}
}
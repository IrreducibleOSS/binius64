//! Fast Number Theoretic Transform (NTT) implementation for polynomials of size 64.
//!
//! This module provides specialized NTT algorithms optimized for 64-element polynomials
//! over binary fields. The implementation uses precomputed domain elements to achieve
//! high performance through loop unrolling and fixed-size arrays.
//!
//! # Overview
//!
//! The NTT is a fundamental operation in polynomial arithmetic that transforms between
//! coefficient and evaluation representations. This implementation specifically handles:
//! - Fixed size of 64 elements (2^6)
//! - Binary field arithmetic using AESTowerField8b
//! - Support for packed field operations for SIMD efficiency
//!
//! # Algorithm
//!
//! The implementation uses a decimation-in-time (DIT) approach with 6 rounds:
//! - Round 0: 1 chunk of 64 elements
//! - Round 1: 2 chunks of 32 elements
//! - Round 2: 4 chunks of 16 elements
//! - Round 3: 8 chunks of 8 elements
//! - Round 4: 16 chunks of 4 elements
//! - Round 5: 32 chunks of 2 elements
//!
//! Each round applies the butterfly operation using precomputed domain elements.

use binius_field::{BinaryField, PackedField};
use binius_math::BinarySubspace;

use crate::sub_bytes_reduction::subspace_utils::elements_for_each_subspace_broadcasted;

/// Precomputed domain elements for efficient NTT operations.
///
/// Contains evaluation points for each round of the NTT algorithm, organized by
/// decreasing domain sizes. The domains are precomputed to avoid repeated
/// calculations during NTT operations.
///
/// # Important Requirements
///
/// - All P elements in an NttDomain must be broadcasted values of P::Scalar
/// - Each NttDomain must contain P::one() among its elements
///
/// # Fields
///
/// - `domain_0`: 64 elements for the first round (largest domain)
/// - `domain_1`: 32 elements for the second round
/// - `domain_2`: 16 elements for the third round
/// - `domain_3`: 8 elements for the fourth round
/// - `domain_4`: 4 elements for the fifth round
/// - `domain_5`: 2 elements for the final round (smallest domain)
pub struct NttDomains<P: PackedField<Scalar: BinaryField>> {
	pub domain_0: [P; 64],
	pub domain_1: [P; 32],
	pub domain_2: [P; 16],
	pub domain_3: [P; 8],
	pub domain_4: [P; 4],
	pub domain_5: [P; 2],
}

/// Generates precomputed domain elements for both inverse and forward NTT operations.
///
/// This function creates two sets of domain elements from a given binary subspace,
/// one for inverse NTT (INTT) and one for forward NTT (FNTT). The domains are
/// structured hierarchically, with each layer containing half the elements of the
/// previous layer.
///
/// # Arguments
///
/// * `subspace` - A binary subspace of dimension 7 over `AESTowerField8b`. This subspace defines
///   the overall evaluation domain for the NTT. The function will generate a sequence of
///   progressively smaller subspaces by repeatedly applying dimension reduction.
///
/// # Returns
///
/// A tuple `(intt_domains, fntt_domains)` where:
/// * `intt_domains` - Domain elements for inverse NTT operations
/// * `fntt_domains` - Domain elements for forward NTT operations
///
/// # Domain Properties
///
/// The generated domains satisfy the following properties:
/// - All P elements are broadcasted values of P::Scalar
/// - Each domain contains P::one() among its elements
///
/// # Domain Structure
///
/// For each layer i (0 to 5), the domains contain:
/// - Layer 0: Elements from the first/second half of the full subspace (64 elements)
/// - Layer 1: Elements from the first/second half of the reduced subspace (32 elements)
/// - And so on, halving at each layer
///
/// The inverse and forward domains at each layer are complementary subsets that
/// together form the complete subspace at that layer.
///
/// # Panics
///
/// Panics if the generated domains don't have the expected sizes (64, 32, 16, 8, 4, 2).
pub fn generate_ntt_domains<P: PackedField<Scalar: BinaryField>>(
	subspace: BinarySubspace<P::Scalar>,
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

/// Performs a fast inverse Number Theoretic Transform on a 64-element array.
///
/// This function transforms polynomial evaluations back to coefficient representation
/// using precomputed domain elements. It implements an optimized inverse NTT specifically
/// for size 64 (2^6) using loop unrolling and fixed-size arrays.
///
/// # Arguments
///
/// * `polynomial_evals` - Mutable array of 64 packed field elements containing polynomial
///   evaluations. This array is modified in-place to contain the coefficients after the transform.
///
/// * `domains` - Precomputed domain elements for the inverse NTT operations. These should be the
///   inverse domains generated by `generate_ntt_domains`.
///
/// # Output
///
/// After execution, `polynomial_evals` contains the polynomial coefficients in the
/// novel polynomial basis. This is NOT the standard monomial basis, but rather a
/// specialized basis adapted to the binary field structure that enables efficient
/// butterfly operations in the NTT algorithm.
///
/// # Algorithm
///
/// The inverse NTT uses a decimation-in-time approach with 6 rounds:
/// - Round 0: Processes 1 chunk of 64 elements using domain_0
/// - Round 1: Processes 2 chunks of 32 elements using domain_1
/// - Round 2: Processes 4 chunks of 16 elements using domain_2
/// - Round 3: Processes 8 chunks of 8 elements using domain_3
/// - Round 4: Processes 16 chunks of 4 elements using domain_4
/// - Round 5: Processes 32 chunks of 2 elements using domain_5
///
/// Each round applies butterfly operations that combine pairs of elements using
/// the corresponding domain values.
#[inline(always)]
pub fn fast_inverse_ntt_64<P: PackedField<Scalar: BinaryField>>(
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

/// Performs a fast forward Number Theoretic Transform on a 64-element array.
///
/// This function transforms polynomial coefficients in the novel polynomial basis
/// to evaluation representation using precomputed domain elements. It implements
/// an optimized forward NTT specifically for size 64 (2^6) using loop unrolling
/// and fixed-size arrays.
///
/// # Arguments
///
/// * `polynomial_evals` - Mutable array of 64 packed field elements containing polynomial
///   coefficients in the novel polynomial basis (as output by `fast_inverse_ntt_64`). This array is
///   modified in-place to contain the evaluations after the transform.
///
/// * `domains` - Precomputed domain elements for the forward NTT operations. These should be the
///   forward domains generated by `generate_ntt_domains`.
///
/// # Output
///
/// After execution, `polynomial_evals` contains the polynomial evaluations at the
/// points in the output domain. The output domain is a shifted version of the input
/// domain - specifically, each evaluation point is an element from the input subspace
/// plus the last basis vector of the enclosing subspace.
///
/// # Algorithm
///
/// The forward NTT reverses the operations of the inverse NTT, using 6 rounds:
/// - Round 0: Processes 32 chunks of 2 elements using domain_5
/// - Round 1: Processes 16 chunks of 4 elements using domain_4
/// - Round 2: Processes 8 chunks of 8 elements using domain_3
/// - Round 3: Processes 4 chunks of 16 elements using domain_2
/// - Round 4: Processes 2 chunks of 32 elements using domain_1
/// - Round 5: Processes 1 chunk of 64 elements using domain_0
///
/// Each round applies butterfly operations that split elements using the
/// corresponding domain values.
#[inline(always)]
pub fn fast_forward_ntt_64<P: PackedField<Scalar: BinaryField>>(
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

/// Performs a complete NTT transform by applying inverse NTT followed by forward NTT.
///
/// This function is useful for changing the evaluation domain of a polynomial. It first
/// converts the evaluations to the novel polynomial basis using inverse NTT, then
/// re-evaluates at a different set of points using forward NTT.
///
/// # Arguments
///
/// * `polynomial_evals` - Mutable array of 64 packed field elements containing polynomial
///   evaluations at the input domain points. After execution, contains evaluations at the output
///   domain points.
///
/// * `intt_domains` - Precomputed domain elements for the inverse NTT operation. These define the
///   input evaluation domain.
///
/// * `fntt_domains` - Precomputed domain elements for the forward NTT operation. These define the
///   output evaluation domain.
///
/// # Domain Relationship
///
/// The input and output domains are related as follows:
/// - Both domains have the same size (64 elements)
/// - The output domain is a shifted version of the input domain
/// - Specifically: output_point = input_point + shift_vector
/// - The union of input and output domains forms a larger binary subspace
///
/// # Example Use Case
///
/// This function is typically used in cryptographic protocols where polynomial
/// evaluations need to be transformed from one coset of a subspace to another
/// coset of the same subspace.
#[inline(always)]
pub fn fast_ntt_64<P: PackedField<Scalar: BinaryField>>(
	polynomial_evals: &mut [P; 64],
	intt_domains: &NttDomains<P>,
	fntt_domains: &NttDomains<P>,
) {
	fast_inverse_ntt_64(polynomial_evals, intt_domains);
	fast_forward_ntt_64(polynomial_evals, fntt_domains);
}

#[cfg(test)]
mod tests {
	use binius_field::{Field, PackedAESBinaryField16x8b, Random};
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
			assert_eq!(result, polynomial_evals[i], "Fast NTT result mismatch at index {i}");
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
		let mut ntt_a = poly_a;
		let mut ntt_b = poly_b;
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
		let mut packed_poly: [PackedAESBinaryField16x8b; 64] =
			[PackedAESBinaryField16x8b::zero(); 64];
		for i in 0..64 {
			packed_poly[i] = PackedAESBinaryField16x8b::random(&mut rng);
		}

		// Generate domains for packed field type
		let (intt_domains, fntt_domains) =
			generate_ntt_domains::<PackedAESBinaryField16x8b>(subspace.clone());

		// Perform NTT on packed values
		let mut ntt_result = packed_poly;
		fast_ntt_64(&mut ntt_result, &intt_domains, &fntt_domains);

		// Extract individual elements from packed fields and verify
		for elem_idx in 0..16 {
			// Extract element at position elem_idx from each packed field
			let mut single_poly_coeffs = vec![];
			for i in 0..64 {
				single_poly_coeffs.push(packed_poly[i].get(elem_idx));
			}

			// Create univariate polynomial from extracted elements
			let single_poly =
				GenericPo2UnivariatePoly::new(single_poly_coeffs, input_space.clone());

			// Verify evaluations match extracted elements from NTT result
			let last_basis_vec = subspace.basis()[subspace.basis().len() - 1];
			for (i, input_domain_elem) in input_space.iter().enumerate() {
				let expected =
					single_poly.evaluate_at_challenge(input_domain_elem + last_basis_vec);
				let actual = ntt_result[i].get(elem_idx);
				assert_eq!(
					expected, actual,
					"Mismatch at element {elem_idx} of packed field index {i}"
				);
			}
		}
	}
}

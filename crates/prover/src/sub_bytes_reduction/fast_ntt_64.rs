use binius_field::{AESTowerField8b, Field, PackedField};

/// Precomputed domains for NTT operations
pub struct NttDomains<P: PackedField<Scalar = AESTowerField8b>> {
	pub domain_0: [P; 64],
	pub domain_1: [P; 32],
	pub domain_2: [P; 16],
	pub domain_3: [P; 8],
	pub domain_4: [P; 4],
	pub domain_5: [P; 2],
}

// Precomputed inverse NTT domains for 2^6 size
const INTT_DOMAIN_0: [AESTowerField8b; 64] = [
	AESTowerField8b::new(0x00),
	AESTowerField8b::new(0x01),
	AESTowerField8b::new(0x02),
	AESTowerField8b::new(0x03),
	AESTowerField8b::new(0x04),
	AESTowerField8b::new(0x05),
	AESTowerField8b::new(0x06),
	AESTowerField8b::new(0x07),
	AESTowerField8b::new(0x08),
	AESTowerField8b::new(0x09),
	AESTowerField8b::new(0x0a),
	AESTowerField8b::new(0x0b),
	AESTowerField8b::new(0x0c),
	AESTowerField8b::new(0x0d),
	AESTowerField8b::new(0x0e),
	AESTowerField8b::new(0x0f),
	AESTowerField8b::new(0x10),
	AESTowerField8b::new(0x11),
	AESTowerField8b::new(0x12),
	AESTowerField8b::new(0x13),
	AESTowerField8b::new(0x14),
	AESTowerField8b::new(0x15),
	AESTowerField8b::new(0x16),
	AESTowerField8b::new(0x17),
	AESTowerField8b::new(0x18),
	AESTowerField8b::new(0x19),
	AESTowerField8b::new(0x1a),
	AESTowerField8b::new(0x1b),
	AESTowerField8b::new(0x1c),
	AESTowerField8b::new(0x1d),
	AESTowerField8b::new(0x1e),
	AESTowerField8b::new(0x1f),
	AESTowerField8b::new(0x20),
	AESTowerField8b::new(0x21),
	AESTowerField8b::new(0x22),
	AESTowerField8b::new(0x23),
	AESTowerField8b::new(0x24),
	AESTowerField8b::new(0x25),
	AESTowerField8b::new(0x26),
	AESTowerField8b::new(0x27),
	AESTowerField8b::new(0x28),
	AESTowerField8b::new(0x29),
	AESTowerField8b::new(0x2a),
	AESTowerField8b::new(0x2b),
	AESTowerField8b::new(0x2c),
	AESTowerField8b::new(0x2d),
	AESTowerField8b::new(0x2e),
	AESTowerField8b::new(0x2f),
	AESTowerField8b::new(0x30),
	AESTowerField8b::new(0x31),
	AESTowerField8b::new(0x32),
	AESTowerField8b::new(0x33),
	AESTowerField8b::new(0x34),
	AESTowerField8b::new(0x35),
	AESTowerField8b::new(0x36),
	AESTowerField8b::new(0x37),
	AESTowerField8b::new(0x38),
	AESTowerField8b::new(0x39),
	AESTowerField8b::new(0x3a),
	AESTowerField8b::new(0x3b),
	AESTowerField8b::new(0x3c),
	AESTowerField8b::new(0x3d),
	AESTowerField8b::new(0x3e),
	AESTowerField8b::new(0x3f),
];
const INTT_DOMAIN_1: [AESTowerField8b; 32] = [
	AESTowerField8b::new(0x00),
	AESTowerField8b::new(0x01),
	AESTowerField8b::new(0x06),
	AESTowerField8b::new(0x07),
	AESTowerField8b::new(0x1c),
	AESTowerField8b::new(0x1d),
	AESTowerField8b::new(0x1a),
	AESTowerField8b::new(0x1b),
	AESTowerField8b::new(0x78),
	AESTowerField8b::new(0x79),
	AESTowerField8b::new(0x7e),
	AESTowerField8b::new(0x7f),
	AESTowerField8b::new(0x64),
	AESTowerField8b::new(0x65),
	AESTowerField8b::new(0x62),
	AESTowerField8b::new(0x63),
	AESTowerField8b::new(0xeb),
	AESTowerField8b::new(0xea),
	AESTowerField8b::new(0xed),
	AESTowerField8b::new(0xec),
	AESTowerField8b::new(0xf7),
	AESTowerField8b::new(0xf6),
	AESTowerField8b::new(0xf1),
	AESTowerField8b::new(0xf0),
	AESTowerField8b::new(0x93),
	AESTowerField8b::new(0x92),
	AESTowerField8b::new(0x95),
	AESTowerField8b::new(0x94),
	AESTowerField8b::new(0x8f),
	AESTowerField8b::new(0x8e),
	AESTowerField8b::new(0x89),
	AESTowerField8b::new(0x88),
];
const INTT_DOMAIN_2: [AESTowerField8b; 16] = [
	AESTowerField8b::new(0x00),
	AESTowerField8b::new(0x01),
	AESTowerField8b::new(0x16),
	AESTowerField8b::new(0x17),
	AESTowerField8b::new(0x67),
	AESTowerField8b::new(0x66),
	AESTowerField8b::new(0x71),
	AESTowerField8b::new(0x70),
	AESTowerField8b::new(0x52),
	AESTowerField8b::new(0x53),
	AESTowerField8b::new(0x44),
	AESTowerField8b::new(0x45),
	AESTowerField8b::new(0x35),
	AESTowerField8b::new(0x34),
	AESTowerField8b::new(0x23),
	AESTowerField8b::new(0x22),
];
const INTT_DOMAIN_3: [AESTowerField8b; 8] = [
	AESTowerField8b::new(0x00),
	AESTowerField8b::new(0x01),
	AESTowerField8b::new(0x0d),
	AESTowerField8b::new(0x0c),
	AESTowerField8b::new(0xc8),
	AESTowerField8b::new(0xc9),
	AESTowerField8b::new(0xc5),
	AESTowerField8b::new(0xc4),
];
const INTT_DOMAIN_4: [AESTowerField8b; 4] = [
	AESTowerField8b::new(0x00),
	AESTowerField8b::new(0x01),
	AESTowerField8b::new(0x53),
	AESTowerField8b::new(0x52),
];
const INTT_DOMAIN_5: [AESTowerField8b; 2] =
	[AESTowerField8b::new(0x00), AESTowerField8b::new(0x01)];

// Precomputed forward NTT domains for 2^6 size
const FNTT_DOMAIN_0: [AESTowerField8b; 64] = [
	AESTowerField8b::new(0x40),
	AESTowerField8b::new(0x41),
	AESTowerField8b::new(0x42),
	AESTowerField8b::new(0x43),
	AESTowerField8b::new(0x44),
	AESTowerField8b::new(0x45),
	AESTowerField8b::new(0x46),
	AESTowerField8b::new(0x47),
	AESTowerField8b::new(0x48),
	AESTowerField8b::new(0x49),
	AESTowerField8b::new(0x4a),
	AESTowerField8b::new(0x4b),
	AESTowerField8b::new(0x4c),
	AESTowerField8b::new(0x4d),
	AESTowerField8b::new(0x4e),
	AESTowerField8b::new(0x4f),
	AESTowerField8b::new(0x50),
	AESTowerField8b::new(0x51),
	AESTowerField8b::new(0x52),
	AESTowerField8b::new(0x53),
	AESTowerField8b::new(0x54),
	AESTowerField8b::new(0x55),
	AESTowerField8b::new(0x56),
	AESTowerField8b::new(0x57),
	AESTowerField8b::new(0x58),
	AESTowerField8b::new(0x59),
	AESTowerField8b::new(0x5a),
	AESTowerField8b::new(0x5b),
	AESTowerField8b::new(0x5c),
	AESTowerField8b::new(0x5d),
	AESTowerField8b::new(0x5e),
	AESTowerField8b::new(0x5f),
	AESTowerField8b::new(0x60),
	AESTowerField8b::new(0x61),
	AESTowerField8b::new(0x62),
	AESTowerField8b::new(0x63),
	AESTowerField8b::new(0x64),
	AESTowerField8b::new(0x65),
	AESTowerField8b::new(0x66),
	AESTowerField8b::new(0x67),
	AESTowerField8b::new(0x68),
	AESTowerField8b::new(0x69),
	AESTowerField8b::new(0x6a),
	AESTowerField8b::new(0x6b),
	AESTowerField8b::new(0x6c),
	AESTowerField8b::new(0x6d),
	AESTowerField8b::new(0x6e),
	AESTowerField8b::new(0x6f),
	AESTowerField8b::new(0x70),
	AESTowerField8b::new(0x71),
	AESTowerField8b::new(0x72),
	AESTowerField8b::new(0x73),
	AESTowerField8b::new(0x74),
	AESTowerField8b::new(0x75),
	AESTowerField8b::new(0x76),
	AESTowerField8b::new(0x77),
	AESTowerField8b::new(0x78),
	AESTowerField8b::new(0x79),
	AESTowerField8b::new(0x7a),
	AESTowerField8b::new(0x7b),
	AESTowerField8b::new(0x7c),
	AESTowerField8b::new(0x7d),
	AESTowerField8b::new(0x7e),
	AESTowerField8b::new(0x7f),
];
const FNTT_DOMAIN_1: [AESTowerField8b; 32] = [
	AESTowerField8b::new(0xa1),
	AESTowerField8b::new(0xa0),
	AESTowerField8b::new(0xa7),
	AESTowerField8b::new(0xa6),
	AESTowerField8b::new(0xbd),
	AESTowerField8b::new(0xbc),
	AESTowerField8b::new(0xbb),
	AESTowerField8b::new(0xba),
	AESTowerField8b::new(0xd9),
	AESTowerField8b::new(0xd8),
	AESTowerField8b::new(0xdf),
	AESTowerField8b::new(0xde),
	AESTowerField8b::new(0xc5),
	AESTowerField8b::new(0xc4),
	AESTowerField8b::new(0xc3),
	AESTowerField8b::new(0xc2),
	AESTowerField8b::new(0x4a),
	AESTowerField8b::new(0x4b),
	AESTowerField8b::new(0x4c),
	AESTowerField8b::new(0x4d),
	AESTowerField8b::new(0x56),
	AESTowerField8b::new(0x57),
	AESTowerField8b::new(0x50),
	AESTowerField8b::new(0x51),
	AESTowerField8b::new(0x32),
	AESTowerField8b::new(0x33),
	AESTowerField8b::new(0x34),
	AESTowerField8b::new(0x35),
	AESTowerField8b::new(0x2e),
	AESTowerField8b::new(0x2f),
	AESTowerField8b::new(0x28),
	AESTowerField8b::new(0x29),
];
const FNTT_DOMAIN_2: [AESTowerField8b; 16] = [
	AESTowerField8b::new(0xbc),
	AESTowerField8b::new(0xbd),
	AESTowerField8b::new(0xaa),
	AESTowerField8b::new(0xab),
	AESTowerField8b::new(0xdb),
	AESTowerField8b::new(0xda),
	AESTowerField8b::new(0xcd),
	AESTowerField8b::new(0xcc),
	AESTowerField8b::new(0xee),
	AESTowerField8b::new(0xef),
	AESTowerField8b::new(0xf8),
	AESTowerField8b::new(0xf9),
	AESTowerField8b::new(0x89),
	AESTowerField8b::new(0x88),
	AESTowerField8b::new(0x9f),
	AESTowerField8b::new(0x9e),
];
const FNTT_DOMAIN_3: [AESTowerField8b; 8] = [
	AESTowerField8b::new(0x3f),
	AESTowerField8b::new(0x3e),
	AESTowerField8b::new(0x32),
	AESTowerField8b::new(0x33),
	AESTowerField8b::new(0xf7),
	AESTowerField8b::new(0xf6),
	AESTowerField8b::new(0xfa),
	AESTowerField8b::new(0xfb),
];
const FNTT_DOMAIN_4: [AESTowerField8b; 4] = [
	AESTowerField8b::new(0xd7),
	AESTowerField8b::new(0xd6),
	AESTowerField8b::new(0x84),
	AESTowerField8b::new(0x85),
];
const FNTT_DOMAIN_5: [AESTowerField8b; 2] =
	[AESTowerField8b::new(0xb7), AESTowerField8b::new(0xb6)];

/// Default inverse NTT domains for 2^6 size
pub const DEFAULT_INTT_DOMAINS: NttDomains<AESTowerField8b> = NttDomains {
	domain_0: INTT_DOMAIN_0,
	domain_1: INTT_DOMAIN_1,
	domain_2: INTT_DOMAIN_2,
	domain_3: INTT_DOMAIN_3,
	domain_4: INTT_DOMAIN_4,
	domain_5: INTT_DOMAIN_5,
};

/// Default forward NTT domains for 2^6 size
pub const DEFAULT_FNTT_DOMAINS: NttDomains<AESTowerField8b> = NttDomains {
	domain_0: FNTT_DOMAIN_0,
	domain_1: FNTT_DOMAIN_1,
	domain_2: FNTT_DOMAIN_2,
	domain_3: FNTT_DOMAIN_3,
	domain_4: FNTT_DOMAIN_4,
	domain_5: FNTT_DOMAIN_5,
};

/// Fast specialized inverse NTT for 2^6 size with provided domains
#[inline]
pub fn fast_inverse_ntt_64(
	polynomial_evals: &mut [AESTowerField8b; 64],
	domains: &NttDomains<AESTowerField8b>,
) {
	let mut temp = [AESTowerField8b::ZERO; 64];

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
				let idx1 = offset + (i << 1);
				let idx2 = idx1 + 1;
				temp[offset | half_len | i] = polynomial_evals[idx2] - polynomial_evals[idx1];
				temp[offset | i] =
					domain[i << 1] * temp[offset | half_len | i] + polynomial_evals[idx1];
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
				let idx1 = offset + (i << 1);
				let idx2 = idx1 + 1;
				temp[offset | half_len | i] = polynomial_evals[idx2] - polynomial_evals[idx1];
				temp[offset | i] =
					domain[i << 1] * temp[offset | half_len | i] + polynomial_evals[idx1];
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
				let idx1 = offset + (i << 1);
				let idx2 = idx1 + 1;
				temp[offset | half_len | i] = polynomial_evals[idx2] - polynomial_evals[idx1];
				temp[offset | i] =
					domain[i << 1] * temp[offset | half_len | i] + polynomial_evals[idx1];
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
				let idx1 = offset + (i << 1);
				let idx2 = idx1 + 1;
				temp[offset | half_len | i] = polynomial_evals[idx2] - polynomial_evals[idx1];
				temp[offset | i] =
					domain[i << 1] * temp[offset | half_len | i] + polynomial_evals[idx1];
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
pub fn fast_forward_ntt_64(
	polynomial_evals: &mut [AESTowerField8b; 64],
	domains: &NttDomains<AESTowerField8b>,
) {
	let mut temp = [AESTowerField8b::ZERO; 64];

	// Round 0: domain size 2, 32 chunks of 2 elements each
	{
		let domain = &domains.domain_5;
		for chunk in 0..32 {
			let offset = chunk * 2;
			let half_len = 1;
			for i in 0..half_len {
				temp[offset | i << 1] = domain[i << 1] * polynomial_evals[offset | half_len | i]
					+ polynomial_evals[offset | i];
				temp[offset | (i << 1) | 1] = temp[offset | i << 1] + polynomial_evals[offset | half_len | i];
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
				temp[offset| i << 1] = domain[i << 1] * polynomial_evals[offset | half_len | i]
					+ polynomial_evals[offset | i];
				temp[offset|(i << 1) | 1] = temp[offset| i << 1] + polynomial_evals[offset | half_len | i];
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
				temp[offset| i << 1] = domain[i << 1] * polynomial_evals[offset | half_len | i]
					+ polynomial_evals[offset | i];
				temp[offset|(i << 1) | 1] = temp[offset|i << 1] + polynomial_evals[offset | half_len | i];
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
pub fn fast_ntt_64(
	polynomial_evals: &mut [AESTowerField8b; 64],
	intt_domains: &NttDomains<AESTowerField8b>,
	fntt_domains: &NttDomains<AESTowerField8b>,
) {
	fast_inverse_ntt_64(polynomial_evals, intt_domains);
	fast_forward_ntt_64(polynomial_evals, fntt_domains);
}

#[cfg(test)]
mod tests {
	use binius_field::{Field, Random};
	use binius_math::BinarySubspace;
	use binius_verifier::and_reduction::univariate::univariate_poly::{
		GenericPo2UnivariatePoly, UnivariatePolyIsomorphic,
	};
	use itertools::Itertools;
	use rand::{rngs::StdRng, SeedableRng};

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

		// Test with fast NTT
		let mut polynomial_evals: [AESTowerField8b; 64] =
			poly.iter().copied().collect_vec().try_into().unwrap();
		fast_ntt_64(&mut polynomial_evals, &DEFAULT_INTT_DOMAINS, &DEFAULT_FNTT_DOMAINS);

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
		fast_ntt_64(&mut poly_sum, &DEFAULT_INTT_DOMAINS, &DEFAULT_FNTT_DOMAINS);

		// Compute NTT(a) + NTT(b)
		let mut ntt_a = poly_a.clone();
		let mut ntt_b = poly_b.clone();
		fast_ntt_64(&mut ntt_a, &DEFAULT_INTT_DOMAINS, &DEFAULT_FNTT_DOMAINS);
		fast_ntt_64(&mut ntt_b, &DEFAULT_INTT_DOMAINS, &DEFAULT_FNTT_DOMAINS);

		let mut ntt_sum: [AESTowerField8b; 64] = [AESTowerField8b::ZERO; 64];
		for i in 0..64 {
			ntt_sum[i] = ntt_a[i] + ntt_b[i];
		}

		// Check linearity: NTT(a + b) = NTT(a) + NTT(b)
		assert_eq!(poly_sum, ntt_sum, "NTT should be linear");
	}
}

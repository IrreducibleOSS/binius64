use std::vec;

use binius_field::{
	BinaryField, BinaryField1b, Field, PackedBinaryField8x1b, PackedField, packed::set_packed_slice,
};
use binius_verifier::and_reduction::{
	univariate::univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_8b,
	},
	utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
};

pub struct NTTLookup<P>(Vec<Vec<Vec<P>>>);

impl<PNTTDomain> NTTLookup<PNTTDomain>
where
	PNTTDomain: PackedField,
	PNTTDomain::Scalar: BinaryField + Field + From<u8>,
{
	// first index is the idx of the 8 bit chunk that we're in
	// second index is the bit string
	//
	// ASSUME: Each lagrange basis vector thats being ntt'ed has size 2^SKIPPED_VARS
	// ASSUME: Lagrange basis domain is simply FNTTDomain(0..64)
	pub fn new(lexicographic_ntt_domain: &[PNTTDomain::Scalar]) -> Self {
		assert_eq!(PNTTDomain::WIDTH, 16);
		let _span = tracing::debug_span!("precompute_lookup").entered();

		let mut lookup =
			vec![
				vec![
					vec![PNTTDomain::zero(); lexicographic_ntt_domain.len() / PNTTDomain::WIDTH];
					1 << 8
				];
				ROWS_PER_HYPERCUBE_VERTEX / 8
			];
		let lagrange_basis_domain: Vec<_> = (0..ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| PNTTDomain::Scalar::from(x as u8))
			.collect();

		let mut eval_point_basis_point_to_numerator =
			vec![
				vec![PNTTDomain::Scalar::ZERO; lagrange_basis_domain.len()];
				lexicographic_ntt_domain.len()
			];
		let denominator: PNTTDomain::Scalar = lexicographic_lagrange_denominator(SKIPPED_VARS);

		let inverse_denominator = denominator.invert_or_zero();
		for (eval_point_idx, eval_point) in lexicographic_ntt_domain.iter().enumerate() {
			eval_point_basis_point_to_numerator[eval_point_idx] =
				lexicographic_lagrange_numerators_8b(ROWS_PER_HYPERCUBE_VERTEX, *eval_point);
		}

		for eight_bit_chunk_idx in 0..ROWS_PER_HYPERCUBE_VERTEX / 8 {
			for log_coefficient_as_bit_string in 0..8 {
				let coefficient_as_bit_string = 1 << log_coefficient_as_bit_string;
				let nonzero_lagrange_basis_coeffs: Vec<_> =
					PackedBinaryField8x1b::from_underlier(coefficient_as_bit_string)
						.iter()
						.collect();
				let mut lagrange_basis_coeffs = [BinaryField1b::ZERO; ROWS_PER_HYPERCUBE_VERTEX];

				for (i, nonzero_lagrange_basis_coeff) in
					nonzero_lagrange_basis_coeffs.into_iter().enumerate()
				{
					lagrange_basis_coeffs[eight_bit_chunk_idx * 8 + i] =
						nonzero_lagrange_basis_coeff;
				}

				#[allow(clippy::needless_range_loop)]
				for eval_point_idx in 0..lexicographic_ntt_domain.len() {
					let mut result = PNTTDomain::Scalar::ZERO;
					for basis_point_idx in 0..lagrange_basis_domain.len() {
						result += (eval_point_basis_point_to_numerator[eval_point_idx]
							[basis_point_idx] * lagrange_basis_coeffs[basis_point_idx])
							* inverse_denominator;
					}
					set_packed_slice(
						&mut lookup[eight_bit_chunk_idx][coefficient_as_bit_string as usize],
						eval_point_idx,
						result,
					);
				}
			}
		}

		for this_byte_lookup in lookup.iter_mut() {
			for coefficient_as_bit_string in 0..1 << 8 {
				let mut result =
					vec![PNTTDomain::zero(); lexicographic_ntt_domain.len() / PNTTDomain::WIDTH];
				for bit_in_string in 0..8 {
					let this_one_hot = coefficient_as_bit_string & 1 << bit_in_string;
					for (i, result_packed_elem) in result.iter_mut().enumerate() {
						*result_packed_elem += this_byte_lookup[this_one_hot][i];
					}
				}
				this_byte_lookup[coefficient_as_bit_string] = result;
			}
		}
		NTTLookup(lookup)
	}

	#[inline]
	pub fn ntt(
		&self,
		coeffs_in_byte_chunks: impl Iterator<Item = u8>,
	) -> [PNTTDomain; ROWS_PER_HYPERCUBE_VERTEX / 16] {
		let mut result = [PNTTDomain::zero(); ROWS_PER_HYPERCUBE_VERTEX / 16];

		for (eight_bit_chunk_idx, eight_bit_chunk) in coeffs_in_byte_chunks.enumerate() {
			for j in 0..ROWS_PER_HYPERCUBE_VERTEX / 16 {
				result[j] += self.0[eight_bit_chunk_idx][eight_bit_chunk as usize][j];
			}
		}

		result
	}
}

#[cfg(test)]
mod test {
	use std::iter::repeat_with;

	use binius_field::{
		AESTowerField8b, Field, PackedAESBinaryField16x8b, PackedBinaryField8x1b, PackedField,
		Random,
		packed::{get_packed_slice, set_packed_slice},
	};
	use binius_math::{
		BinarySubspace,
		ntt::{AdditiveNTT, NTTShape, SingleThreadedNTT},
	};
	use binius_verifier::{and_reduction::utils::constants::SKIPPED_VARS, fields::B1};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::{NTTLookup, ROWS_PER_HYPERCUBE_VERTEX};

	#[test]
	fn assert_accurate_ntt_on_well_known_poly() {
		let output_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| AESTowerField8b::new(x as u8))
			.collect();

		let lookup = NTTLookup::new(&output_domain);

		let slice_to_ntt: [u8; _] = [1, 0, 0, 0, 0, 0, 0, 0];
		let results: [PackedAESBinaryField16x8b; _] = lookup.ntt(slice_to_ntt.into_iter());

		for (i, input) in output_domain.iter().enumerate() {
			let expected_result = (1..ROWS_PER_HYPERCUBE_VERTEX)
				.map(|basis_idx| {
					let field_elem = AESTowerField8b::new(basis_idx as u8);
					(*input - field_elem) * field_elem.invert_or_zero()
				})
				.product::<AESTowerField8b>();

			assert_eq!(get_packed_slice(&results, i), expected_result);
		}
	}

	#[test]
	fn test_against_binius_ntt() {
		let mut rng = StdRng::from_seed([0; 32]);
		let mut coeffs = (0..ROWS_PER_HYPERCUBE_VERTEX)
			.map(|_| AESTowerField8b::from(B1::random(&mut rng)))
			.collect_vec();

		let mut coeffs_packed = vec![PackedBinaryField8x1b::zero(); ROWS_PER_HYPERCUBE_VERTEX / 8];

		for (i, coeff) in coeffs.iter().enumerate() {
			set_packed_slice(&mut coeffs_packed, i, B1::from(u8::from(*coeff)));
		}

		let coeffs_packed_iter_u8 = coeffs_packed.iter().map(|i| i.to_underlier());

		let ntt_lookup = NTTLookup::<PackedAESBinaryField16x8b>::new(
			&(0..ROWS_PER_HYPERCUBE_VERTEX)
				.map(|i| AESTowerField8b::from((ROWS_PER_HYPERCUBE_VERTEX + i) as u8))
				.collect_vec(),
		);

		let ntt_lookup_result = ntt_lookup.ntt(coeffs_packed_iter_u8);

		let input_subspace = BinarySubspace::new_unchecked(
			(0..SKIPPED_VARS)
				.map(|i| AESTowerField8b::from(1 << i))
				.collect_vec(),
		);

		let input_ntt = SingleThreadedNTT::with_subspace(&input_subspace).unwrap();

		input_ntt
			.inverse_transform(
				&mut coeffs,
				NTTShape {
					log_x: 0,
					log_y: SKIPPED_VARS,
					log_z: 0,
				},
				0,
				0,
				0,
			)
			.unwrap();

		let output_subspace = BinarySubspace::new_unchecked(
			(0..SKIPPED_VARS + 1)
				.map(|i| AESTowerField8b::from((1 << i) as u8))
				.collect_vec(),
		);

		coeffs.extend(repeat_with(|| AESTowerField8b::ZERO).take(ROWS_PER_HYPERCUBE_VERTEX));

		let output_ntt = SingleThreadedNTT::with_subspace(&output_subspace).unwrap();

		output_ntt
			.forward_transform(
				&mut coeffs,
				NTTShape {
					log_x: 0,
					log_y: SKIPPED_VARS + 1,
					log_z: 0,
				},
				0,
				0,
				0,
			)
			.unwrap();

		for (i, coeff) in coeffs.iter().skip(ROWS_PER_HYPERCUBE_VERTEX).enumerate() {
			let lookup_result = get_packed_slice(&ntt_lookup_result, i);
			assert_eq!(lookup_result, *coeff);
		}
	}
}

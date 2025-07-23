use std::vec;

use binius_field::{
	AESTowerField8b, BinaryField1b, Field, PackedAESBinaryField16x8b, PackedBinaryField8x1b,
	PackedField, packed::set_packed_slice,
};
use binius_verifier::and_reduction::{
	univariate::univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_8b,
	},
	utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
};

pub type NTTLookup = Vec<Vec<Vec<PackedAESBinaryField16x8b>>>;

// first index is the idx of the 8 bit chunk that we're in
// second index is the bit string
//
// ASSUME: Each lagrange basis vector thats being ntt'ed has size 2^SKIPPED_VARS
// ASSUME: Lagrange basis domain is simply AESTowerField8b(0..64)
pub fn precompute_lookup(onto_domain: &[AESTowerField8b]) -> NTTLookup {
	let _span = tracing::debug_span!("precompute_lookup").entered();

	let mut lookup = vec![
		vec![
			vec![
				PackedAESBinaryField16x8b::zero();
				onto_domain.len() / PackedAESBinaryField16x8b::WIDTH
			];
			1 << 8
		];
		ROWS_PER_HYPERCUBE_VERTEX / 8
	];
	let lagrange_basis_domain: Vec<_> = (0..ROWS_PER_HYPERCUBE_VERTEX)
		.map(|x| AESTowerField8b::new(x as u8))
		.collect();

	let mut eval_point_basis_point_to_numerator =
		vec![vec![AESTowerField8b::ZERO; lagrange_basis_domain.len()]; onto_domain.len()];
	let denominator: AESTowerField8b = lexicographic_lagrange_denominator(SKIPPED_VARS);

	let inverse_denominator = denominator.invert_or_zero();
	for (eval_point_idx, eval_point) in onto_domain.iter().enumerate() {
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
				lagrange_basis_coeffs[eight_bit_chunk_idx * 8 + i] = nonzero_lagrange_basis_coeff;
			}

			#[allow(clippy::needless_range_loop)]
			for eval_point_idx in 0..onto_domain.len() {
				let mut result = AESTowerField8b::ZERO;
				for basis_point_idx in 0..lagrange_basis_domain.len() {
					result += lagrange_basis_coeffs[basis_point_idx]
						* eval_point_basis_point_to_numerator[eval_point_idx][basis_point_idx]
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
			let mut result = vec![
				PackedAESBinaryField16x8b::zero();
				onto_domain.len() / PackedAESBinaryField16x8b::WIDTH
			];
			for bit_in_string in 0..8 {
				let this_one_hot = coefficient_as_bit_string & 1 << bit_in_string;
				for (i, result_packed_elem) in result.iter_mut().enumerate() {
					*result_packed_elem += this_byte_lookup[this_one_hot][i];
				}
			}
			this_byte_lookup[coefficient_as_bit_string] = result;
		}
	}
	lookup
}

#[cfg(test)]
mod test {
	use binius_field::{
		AESTowerField8b, arithmetic_traits::InvertOrZero, packed::get_packed_slice,
	};

	use super::ROWS_PER_HYPERCUBE_VERTEX;
	use crate::and_reduction::univariate::ntt_lookup::precompute_lookup;

	#[test]
	fn assert_accurate_ntt_on_well_known_poly() {
		let output_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| AESTowerField8b::new(x as u8))
			.collect();

		let lookup = precompute_lookup(&output_domain);

		let results = lookup[0][1].clone();

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
}

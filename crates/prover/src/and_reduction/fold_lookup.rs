use binius_field::Field;
use binius_verifier::and_reduction::{
	univariate::univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_polyval,
	},
	utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
};

pub struct FoldLookup<F>(Vec<Vec<F>>);

impl<F> FoldLookup<F>
where
	F: Field,
{
	pub fn new<FDomain>(challenge: F) -> Self
	where
		F: From<FDomain>,
		FDomain: From<u8> + Field,
	{
		let _span = tracing::debug_span!("precompute_fold_lookup").entered();

		let mut lookup_table = vec![vec![F::ZERO; 1 << 8]; ROWS_PER_HYPERCUBE_VERTEX / 8];

		let numerators = lexicographic_lagrange_numerators_polyval::<FDomain, F>(
			ROWS_PER_HYPERCUBE_VERTEX,
			challenge,
		);

		let denominator_inv =
			F::from(lexicographic_lagrange_denominator::<FDomain>(SKIPPED_VARS).invert_or_zero());

		let lagrange_coeffs: Vec<_> = numerators
			.into_iter()
			.map(|n| n * denominator_inv)
			.collect();

		for (chunk_idx, this_byte_lookup) in lookup_table.iter_mut().enumerate() {
			let _span = tracing::debug_span!("chunk_idx: {}", chunk_idx).entered();

			let offset = 8 * chunk_idx;

			for (lookup_table_idx, this_bit_string_fold_result) in
				this_byte_lookup.iter_mut().enumerate()
			{
				for bit_position in 0..8 {
					if lookup_table_idx & 1 << bit_position != 0 {
						*this_bit_string_fold_result += lagrange_coeffs[offset + bit_position];
					}
				}
			}
		}

		Self(lookup_table)
	}

	pub fn fold_one_bit_univariate(&self, coeffs_byte_chunks: impl Iterator<Item = u8>) -> F {
		coeffs_byte_chunks
			.enumerate()
			.map(|(byte_chunk_idx, eight_coeffs)| self.0[byte_chunk_idx][eight_coeffs as usize])
			.sum()
	}
}

use binius_field::{Field, arithmetic_traits::InvertOrZero};
use crate::protocols::sumcheck::and_reduction::univariate::{
	ntt_lookup::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
	subfield_isomorphism::SubfieldIsomorphismLookup,
	univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_polyval,
	},
};

pub type FoldLookup<F> = Vec<Vec<F>>;

pub fn precompute_fold_lookup<F: Field>(
	challenge: F,
	iso_lookup: &SubfieldIsomorphismLookup<F>,
) -> FoldLookup<F>
{
	let mut lookup = vec![vec![F::ZERO; 256]; ROWS_PER_HYPERCUBE_VERTEX / 8];

	let numerators = lexicographic_lagrange_numerators_polyval(ROWS_PER_HYPERCUBE_VERTEX, challenge, iso_lookup);
	let denom_inv = iso_lookup.lookup_8b_value(lexicographic_lagrange_denominator(SKIPPED_VARS).invert_or_zero());
	let coeffs: Vec<_> = numerators.into_iter().map(|n| n * denom_inv).collect();

	for (chunk_idx, chunk) in lookup.iter_mut().enumerate() {
		let offset = chunk_idx << 3;
		for (byte_val, result) in chunk.iter_mut().enumerate() {
			for bit in 0..8 {
				if byte_val & (1 << bit) != 0 {
					*result += coeffs[offset + bit];
				}
			}
		}
	}

	lookup
}

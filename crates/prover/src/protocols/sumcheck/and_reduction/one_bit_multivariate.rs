use binius_field::{
	BinaryField1b, ExtensionField, Field, PackedAESBinaryField16x8b, PackedBinaryField128x1b,
	PackedExtension, arithmetic_traits::InvertOrZero, packed::iter_packed_slice_with_offset,
};
use binius_math::FieldBuffer;
use binius_utils::rayon::prelude::{
	IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use crate::protocols::sumcheck::and_reduction::{
	fold_lookups::FoldLookup,
	univariate::{
		ntt_lookup::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
		subfield_isomorphism::SubfieldIsomorphismLookup,
		univariate_lagrange::{
			lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_polyval,
		},
	},
};

// ALL FOLDING IS LOW TO HIGH
#[derive(Debug, Clone)]
pub struct OneBitMultivariate {
	pub log_num_rows: usize,
	pub packed_evals: Vec<PackedBinaryField128x1b>,
}

impl OneBitMultivariate {
	pub fn fold_naive<F>(
		&self,
		challenge: F,
		iso_lookup: &SubfieldIsomorphismLookup<F>,
	) -> FieldBuffer<F>
	where
		F: ExtensionField<BinaryField1b> + Field,
	{
		let mut multilin = FieldBuffer::zeros(self.log_num_rows - SKIPPED_VARS);

		let numerators = lexicographic_lagrange_numerators_polyval(
			ROWS_PER_HYPERCUBE_VERTEX,
			challenge,
			iso_lookup,
		);

		let denom_inv = iso_lookup
			.lookup_8b_value(lexicographic_lagrange_denominator(SKIPPED_VARS).invert_or_zero());

		multilin.as_mut().par_iter_mut().enumerate().for_each(
			|(group_idx, hyprecube_vertex_val)| {
				let coeffs = iter_packed_slice_with_offset(
					&self.packed_evals,
					group_idx * ROWS_PER_HYPERCUBE_VERTEX,
				);

				*hyprecube_vertex_val = numerators
					.iter()
					.zip(coeffs)
					.map(|(n, coeff)| *n * denom_inv * coeff)
					.sum();
			},
		);
		multilin
	}

	pub fn fold<F>(&self, lookup: &FoldLookup<F>) -> FieldBuffer<F>
	where
		F: Field + std::iter::Sum<F>,
	{
		let mut multilin = FieldBuffer::zeros(self.log_num_rows - SKIPPED_VARS);

		let packed_evals_as_bytes =
			<PackedAESBinaryField16x8b as PackedExtension<BinaryField1b>>::cast_exts(
				&self.packed_evals,
			);

		multilin
			.as_mut()
			.par_iter_mut()
			.enumerate()
			.for_each(|(group_idx, vertex_val)| {
				let bytes = iter_packed_slice_with_offset(
					packed_evals_as_bytes,
					group_idx * ROWS_PER_HYPERCUBE_VERTEX / 8,
				)
				.take(ROWS_PER_HYPERCUBE_VERTEX / 8);

				*vertex_val = bytes
					.enumerate()
					.map(|(idx, byte)| lookup[idx][Into::<u8>::into(byte) as usize])
					.sum();
			});
		multilin
	}
}

#[cfg(test)]
mod test {
	use binius_field::{
		AESTowerField128b, BinaryField128bPolyval, PackedBinaryField128x1b, Random,
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::OneBitMultivariate;
	use crate::protocols::sumcheck::and_reduction::{
		fold_lookups::precompute_fold_lookup,
		univariate::{ntt_lookup::SKIPPED_VARS, subfield_isomorphism::SubfieldIsomorphismLookup},
	};

	#[test]
	fn test_lookup_fold() {
		let log_num_rows = 10;
		let mut rng = StdRng::from_seed([0; 32]);
		let mlv = OneBitMultivariate {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|_| PackedBinaryField128x1b::random(&mut rng))
				.collect(),
		};

		let challenge = BinaryField128bPolyval::random(&mut rng);

		let iso_lookup = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

		let lookup = precompute_fold_lookup(challenge, &iso_lookup);
		let folded_naive = mlv.fold_naive(challenge, &iso_lookup);
		let folded_smart = mlv.fold(&lookup);

		for i in 0..1 << (log_num_rows - SKIPPED_VARS) {
			assert_eq!(folded_naive.as_ref()[i], folded_smart.as_ref()[i]);
		}
	}
}

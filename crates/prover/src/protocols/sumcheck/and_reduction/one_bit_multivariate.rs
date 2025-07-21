use binius_field::{
    BinaryField1b, BinaryField128bPolyval, Field, PackedAESBinaryField16x8b,
    PackedBinaryField128x1b, PackedExtension, PackedField, packed::iter_packed_slice_with_offset,
    ExtensionField,
};
use binius_math::{FieldBuffer, Error};
use binius_maybe_rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

use crate::{
    protocols::sumcheck::and_reduction::univariate::subfield_isomorphism::SubfieldIsomorphismLookup,
    protocols::sumcheck::and_reduction::univariate::univariate_lagrange::{
        lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_polyval,
    },
    protocols::sumcheck::and_reduction::fold_lookups::FoldLookup,
    protocols::sumcheck::and_reduction::univariate::ntt_lookup::{
        ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS,
    },
};

// ALL FOLDING IS LOW TO HIGH
#[derive(Debug, Clone)]
pub struct OneBitMultivariate {
    pub log_num_rows: usize,
    pub packed_evals: Vec<PackedBinaryField128x1b>,
}

impl OneBitMultivariate {
    #[allow(clippy::modulo_one)]
    pub fn fold_naive<F>(&self, challenge: F, iso_lookup: &SubfieldIsomorphismLookup<F>) -> FieldBuffer<F>
    where F: ExtensionField<BinaryField1b> + Field{
        let _span = tracing::debug_span!("fold_naive").entered();

        let new_n_vars = self.log_num_rows - SKIPPED_VARS;
        let mut multilin = FieldBuffer::zeros(new_n_vars);

        let numerators = lexicographic_lagrange_numerators_polyval(
            ROWS_PER_HYPERCUBE_VERTEX,
            challenge,
            iso_lookup,
        );

        let denominator = lexicographic_lagrange_denominator(SKIPPED_VARS);
        let inverse_denominator = iso_lookup.lookup_8b_value(denominator.invert_or_zero());
        let lagrange_basis_vectors: Vec<_> = numerators
            .iter()
            .map(|n| *n * inverse_denominator)
            .collect();

        multilin.as_mut().par_iter_mut().enumerate().for_each(
            |(group_idx, hyprecube_vertex_val)| {
                let this_group_bit_coefficients = iter_packed_slice_with_offset(
                    &self.packed_evals,
                    group_idx * ROWS_PER_HYPERCUBE_VERTEX,
                );

                *hyprecube_vertex_val = lagrange_basis_vectors
                    .iter()
                    .zip(this_group_bit_coefficients)
                    .map(|(basis_vec, coeff)| *basis_vec * coeff)
                    .sum();
            },
        );
        multilin
    }

    #[allow(clippy::modulo_one)]
    pub fn fold<F>(&self, lookup: &FoldLookup<F>) -> FieldBuffer<F>
    where
        F: Field + std::iter::Sum<F>,
    {
        let _span = tracing::debug_span!("fold").entered();

        let new_n_vars = self.log_num_rows - SKIPPED_VARS;
        let mut multilin = FieldBuffer::zeros(new_n_vars);

        let bytes_per_group = ROWS_PER_HYPERCUBE_VERTEX / 8;

        let packed_evals_as_bytes =
            <PackedAESBinaryField16x8b as PackedExtension<BinaryField1b>>::cast_exts(
                &self.packed_evals,
            );

        multilin.as_mut().par_iter_mut().enumerate().for_each(
            |(group_idx, hyprecube_vertex_val)| {
                let this_group_byte_chunks = iter_packed_slice_with_offset(
                    packed_evals_as_bytes,
                    group_idx * bytes_per_group,
                )
                .take(bytes_per_group);

                *hyprecube_vertex_val = this_group_byte_chunks
                    .enumerate()
                    .map(|(byte_chunk_idx, byte_field_elem)| {
                        lookup[byte_chunk_idx][Into::<u8>::into(byte_field_elem) as usize]
                    })
                    .sum();
            },
        );
        multilin
    }
}


#[cfg(test)]
mod test {
    use binius_field::{BinaryField128bPolyval, PackedBinaryField128x1b, Random, AESTowerField128b};
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{
        protocols::sumcheck::and_reduction::fold_lookups::precompute_fold_lookup,
        protocols::sumcheck::and_reduction::univariate::subfield_isomorphism::SubfieldIsomorphismLookup,
        protocols::sumcheck::and_reduction::univariate::ntt_lookup::SKIPPED_VARS,
    };

    use super::OneBitMultivariate;

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

        let fp_lookup = precompute_fold_lookup(challenge, &iso_lookup);

        let polyval_lookup = precompute_fold_lookup(challenge, &iso_lookup);

        let folded_naive = mlv.fold_naive(challenge, &iso_lookup);

        let fp_folded_smart = mlv.fold(&fp_lookup);

        let polyval_folded_smart = mlv.fold(&polyval_lookup);

        for i in 0..1 << (log_num_rows - SKIPPED_VARS) {
            assert_eq!(
                polyval_folded_smart.as_ref()[i],
                fp_folded_smart.as_ref()[i]
            );
            assert_eq!(
                folded_naive.as_ref()[i],
                fp_folded_smart.as_ref()[i]
            );
        }
    }
}
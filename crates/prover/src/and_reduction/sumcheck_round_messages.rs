use binius_field::{
    AESTowerField8b, BinaryField1b, BinaryField128bPolyval, Field, PackedAESBinaryField16x8b,
    PackedBinaryField128x1b, PackedExtension, PackedField, packed::get_packed_slice,
};

use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};
use binius_utils::rayon::prelude::{IntoParallelIterator, ParallelIterator};
use binius_verifier::and_reduction::{utils::{subfield_isomorphism::SubfieldIsomorphismLookup, constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS}}, univariate::{univariate_poly::{GenericPo2UnivariatePoly, UnivariatePoly}, delta::delta_poly}};
use itertools::izip;

use super::{utils::multivariate::OneBitMultivariate, univariate::ntt_lookup::NTTLookup};

// Sends evaluations of the 3*|D|-1 degree polynomial
#[allow(clippy::too_many_arguments)]
pub fn univariate_round_message<'a,FChallenge>(
    first_col: &OneBitMultivariate,
    second_col: &OneBitMultivariate,
    third_col: &OneBitMultivariate,
    eq_ind_big_field_challenges: &FieldBuffer<FChallenge>,
    ntt_lookup: &NTTLookup,
    small_field_zerocheck_challenges: &[AESTowerField8b],
    univariate_zerocheck_challenge: FChallenge,
    subfield_iso_lookup: &'a SubfieldIsomorphismLookup<FChallenge>,
) -> GenericPo2UnivariatePoly<'a, FChallenge, FChallenge> 
where FChallenge: Field{
    let _span = tracing::debug_span!("univariate_round_message").entered();

    let log_num_rows = first_col.log_num_rows;
    let num_rows = 1 << log_num_rows;

    let hot_loop_ntt_points = 2 * ROWS_PER_HYPERCUBE_VERTEX;
    let prover_message_num_points = 4 * ROWS_PER_HYPERCUBE_VERTEX;
    let num_vars_on_hypercube = log_num_rows - SKIPPED_VARS;

    let mut pre_delta_prover_message = vec![FChallenge::ZERO; hot_loop_ntt_points];

    let mut composition_col = bytemuck::zeroed_vec(num_rows / PackedBinaryField128x1b::WIDTH);

    for (i, composition_row_val) in composition_col.iter_mut().enumerate() {
        *composition_row_val =
            first_col.packed_evals[i] * second_col.packed_evals[i] - third_col.packed_evals[i];
    }

    let bytes_per_hypercube_vertex = 1 << (SKIPPED_VARS - 3);
    let first_col_bytes = <PackedAESBinaryField16x8b as PackedExtension<BinaryField1b>>::cast_exts(
        &first_col.packed_evals,
    );

    let second_col_bytes = <PackedAESBinaryField16x8b as PackedExtension<BinaryField1b>>::cast_exts(
        &second_col.packed_evals,
    );

    let third_col_bytes = <PackedAESBinaryField16x8b as PackedExtension<BinaryField1b>>::cast_exts(
        &third_col.packed_evals,
    );

    let small_field_zerocheck_challenges_tensor_expansion: Vec<PackedAESBinaryField16x8b> =
        eq_ind_partial_eval(small_field_zerocheck_challenges)
            .as_ref()
            .into_iter()
            .map(|item: &AESTowerField8b| PackedAESBinaryField16x8b::broadcast(*item))
            .collect();

    // Execute the NTTs at each hypercube vertex
    let _span = tracing::debug_span!("execute NTTs at each hypercube vertex").entered();

    let pre_delta_prover_message_extension_domain = (0..1 << (num_vars_on_hypercube - 3))
        .into_par_iter()
        .map(|subcube_idx| {
            let mut small_field_query_summed_ntt_packed = [PackedAESBinaryField16x8b::zero();
                ROWS_PER_HYPERCUBE_VERTEX / PackedAESBinaryField16x8b::WIDTH];

            #[allow(clippy::needless_range_loop)]
            for point_idx_within_subcube in 0..1 << 3 {
                let hypercube_point_idx = subcube_idx << 3 | point_idx_within_subcube;
                let byte_offset = hypercube_point_idx * bytes_per_hypercube_vertex;
                // NTT these size-ROWS_PER_HYPERCUBE_VERTEX chunks of the columns using lookup table
                // These are the values of the polys on domain ROWS_PER_HYPERCUBE_VERTEX..2*ROWS_PER_HYPERCUBE_VERTEX
                let mut first_column_ntted = [PackedAESBinaryField16x8b::zero();
                    ROWS_PER_HYPERCUBE_VERTEX / PackedAESBinaryField16x8b::WIDTH];
                for (i, this_byte_lookup) in ntt_lookup.iter().enumerate() {
                    let column_ntted =
                        &this_byte_lookup[Into::<u8>::into(get_packed_slice(first_col_bytes, byte_offset + i)) as usize];
                    for j in 0..(ROWS_PER_HYPERCUBE_VERTEX / PackedAESBinaryField16x8b::WIDTH) {
                        first_column_ntted[j] += column_ntted[j];
                    }
                }

                let mut second_column_ntted = [PackedAESBinaryField16x8b::zero();
                    ROWS_PER_HYPERCUBE_VERTEX / PackedAESBinaryField16x8b::WIDTH];
                for (i, this_byte_lookup) in ntt_lookup.iter().enumerate() {
                    let column_ntted =
                        &this_byte_lookup[Into::<u8>::into(get_packed_slice(second_col_bytes, byte_offset + i)) as usize];
                    for j in 0..(ROWS_PER_HYPERCUBE_VERTEX / PackedAESBinaryField16x8b::WIDTH) {
                        second_column_ntted[j] += column_ntted[j];
                    }
                }

                let mut third_column_ntted = [PackedAESBinaryField16x8b::zero();
                    ROWS_PER_HYPERCUBE_VERTEX / PackedAESBinaryField16x8b::WIDTH];
                for (i, this_byte_lookup) in ntt_lookup.iter().enumerate() {
                    let column_ntted =
                        &this_byte_lookup[Into::<u8>::into(get_packed_slice(third_col_bytes, byte_offset + i)) as usize];
                    for j in 0..(ROWS_PER_HYPERCUBE_VERTEX / PackedAESBinaryField16x8b::WIDTH) {
                        third_column_ntted[j] += column_ntted[j];
                    }
                }

                let composition_ntted_packed: Vec<_> =
                    izip!(first_column_ntted, second_column_ntted, third_column_ntted)
                        .map(|(first, second, third)| first * second - third)
                        .collect();

                for i in 0..(ROWS_PER_HYPERCUBE_VERTEX / PackedAESBinaryField16x8b::WIDTH) {
                    small_field_query_summed_ntt_packed[i] += composition_ntted_packed[i]
                        * small_field_zerocheck_challenges_tensor_expansion
                            [point_idx_within_subcube];
                }
            }

            let eq_ind_this_subcube_value = eq_ind_big_field_challenges.as_ref()[subcube_idx];

            let mut pre_delta_prover_message_ext_domain_this_thread =
                [FChallenge::ZERO; ROWS_PER_HYPERCUBE_VERTEX];

            for (b, this_coefficient_of_pre_delta_prover_message_ext_domain_this_thread) in
                pre_delta_prover_message_ext_domain_this_thread
                    .iter_mut()
                    .enumerate()
            {
                *this_coefficient_of_pre_delta_prover_message_ext_domain_this_thread =
                    eq_ind_this_subcube_value
                        * subfield_iso_lookup.lookup_8b_value(get_packed_slice(
                            &small_field_query_summed_ntt_packed,
                            b,
                        ));
            }

            pre_delta_prover_message_ext_domain_this_thread
        })
        .reduce(
            || [FChallenge::ZERO; ROWS_PER_HYPERCUBE_VERTEX],
            |mut acc, delta| {
                for (i, val) in delta.into_iter().enumerate() {
                    acc[i] += val;
                }
                acc
            },
        );

    pre_delta_prover_message[ROWS_PER_HYPERCUBE_VERTEX..(2 * ROWS_PER_HYPERCUBE_VERTEX)]
        .copy_from_slice(&pre_delta_prover_message_extension_domain[..ROWS_PER_HYPERCUBE_VERTEX]);

    let pre_delta_prover_message_poly =
        GenericPo2UnivariatePoly::new(pre_delta_prover_message, subfield_iso_lookup);

    let delta_polynomial = delta_poly(
        univariate_zerocheck_challenge,
        SKIPPED_VARS,
        subfield_iso_lookup,
    );

    let final_prover_message_evals = (0..prover_message_num_points)
        .map(|i| {
            let point = subfield_iso_lookup.lookup_8b_value(AESTowerField8b::new(i as u8));
            pre_delta_prover_message_poly.evaluate_at_subfield_point(point)
                * delta_polynomial.evaluate_at_subfield_point(point)
        })
        .collect();

    GenericPo2UnivariatePoly::new(final_prover_message_evals, subfield_iso_lookup)
}

// Sends the sum claim from first multilinear round (second overall round)
pub fn sum_claim<BF: Field + From<BinaryField128bPolyval>>(
    first_col: &FieldBuffer<BF>,
    second_col: &FieldBuffer<BF>,
    third_col: &FieldBuffer<BF>,
    eq_ind: &FieldBuffer<BF>,
) -> BF {
    let _span = tracing::debug_span!("sum_claim").entered();

    let mut sum = BF::ZERO;
    for (row_from_first, row_from_second, row_from_third, row_from_eq) in izip!(
        first_col.as_ref(),
        second_col.as_ref(),
        third_col.as_ref(),
        eq_ind.as_ref(),
    ) {
        sum += (*row_from_first * *row_from_second - *row_from_third) * *row_from_eq;
    }

    sum.iter().sum()
}

#[cfg(test)]
mod test {
    use binius_field::{AESTowerField8b, BinaryField128bPolyval, PackedBinaryField128x1b, Random, AESTowerField128b};

    use binius_math::multilinear::eq::eq_ind_partial_eval;
    use binius_verifier::and_reduction::{utils::{constants::{SKIPPED_VARS, ROWS_PER_HYPERCUBE_VERTEX}, subfield_isomorphism::SubfieldIsomorphismLookup}, univariate::{univariate_poly::UnivariatePoly, delta::delta_poly}};
    use rand::{SeedableRng, rngs::StdRng};

    use crate::and_reduction::{utils::multivariate::OneBitMultivariate, univariate::ntt_lookup::precompute_lookup, fold_lookup::precompute_fold_lookup, sumcheck_round_messages::sum_claim};

    use super::univariate_round_message;

    #[test]
    fn test_first_round_message_matches_next_round_sum_claim() {
        let log_num_rows = 10;
        let mut rng = StdRng::from_seed([0; 32]);
        let big_field_zerocheck_challenges =
            vec![BinaryField128bPolyval::random(&mut rng); (log_num_rows - SKIPPED_VARS - 3) + 1];

        let small_field_zerocheck_challenges = [
            AESTowerField8b::new(2),
            AESTowerField8b::new(4),
            AESTowerField8b::new(16),
        ];
        let first_mlv = OneBitMultivariate {
            log_num_rows,
            packed_evals: (0..1 << log_num_rows)
                .map(|_| PackedBinaryField128x1b::random(&mut rng))
                .collect(),
        };

        let second_mlv = OneBitMultivariate {
            log_num_rows,
            packed_evals: (0..1 << log_num_rows)
                .map(|_| PackedBinaryField128x1b::random(&mut rng))
                .collect(),
        };

        let third_mlv = OneBitMultivariate {
            log_num_rows,
            packed_evals: (0..1 << log_num_rows)
                .map(|i| first_mlv.packed_evals[i] * second_mlv.packed_evals[i])
                .collect(),
        };

        let eq_ind_only_big = eq_ind_partial_eval(&big_field_zerocheck_challenges[1..]);
        let onto_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
            .map(|x| AESTowerField8b::new(x as u8))
            .collect();

        let iso_lookup = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

        let ntt_lookup = precompute_lookup(&onto_domain);

        let first_round_message = univariate_round_message(
            &first_mlv,
            &second_mlv,
            &third_mlv,
            &eq_ind_only_big,
            &ntt_lookup,
            &small_field_zerocheck_challenges,
            big_field_zerocheck_challenges[0],
            &iso_lookup,
        );

        let first_sumcheck_challenge = BinaryField128bPolyval::random(&mut rng);
        let expected_next_round_sum =
            first_round_message.evaluate_at_challenge(first_sumcheck_challenge);

        let lookup = precompute_fold_lookup(first_sumcheck_challenge, &iso_lookup);

        let folded_first_mle = first_mlv.fold(&lookup);
        let folded_second_mle = second_mlv.fold(&lookup);
        let folded_third_mle = third_mlv.fold(&lookup);

        let delta_mul_by =
            delta_poly(big_field_zerocheck_challenges[0], SKIPPED_VARS, &iso_lookup)
                .evaluate_at_challenge(first_sumcheck_challenge);

        let upcasted_small_field_challenges: Vec<_> = small_field_zerocheck_challenges
            .into_iter()
            .map(|i| iso_lookup.lookup_8b_value(i))
            .collect();

        let polyval_zerocheck_challenges: Vec<_> = upcasted_small_field_challenges
            .iter()
            .chain(big_field_zerocheck_challenges[1..].iter())
            .copied()
            .collect();

        let polyval_eq = eq_ind_partial_eval(&polyval_zerocheck_challenges);
        let actual_next_round_sum =
            sum_claim(
                &folded_first_mle,
                &folded_second_mle,
                &folded_third_mle,
                &polyval_eq,
            ) * std::convert::Into::<BinaryField128bPolyval>::into(delta_mul_by);

        assert_eq!(expected_next_round_sum, actual_next_round_sum);
    }
}

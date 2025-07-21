// use crate::utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS};
// use crate::univariate::delta::delta_poly;
// use crate::utils::eq_ind::eq_ind_mle;
// use crate::fold_lookup::precompute_fold_lookup;
// use crate::multilinear_sumcheck::multilinear_sumcheck::{multilinear_sumcheck, MultilinearSumcheckProver, FoldDirection};
// use crate::utils::multivariate::{OneBitMultivariate, field_buffer_to_mle};
// use crate::univariate::ntt_lookup::precompute_lookup;
// use crate::utils::subfield_isomorphism_lookup::SubfieldIsomorphismLookup;
// use crate::univariate::univariate_poly::UnivariatePoly;
// use binius_field::{AESTowerField8b, BinaryField128bPolyval, PackedBinaryField128x1b, Random, AESTowerField128b};
// use rand::{SeedableRng, rngs::StdRng};

// use crate::sumcheck_round_messages::sum_claim;
// use crate::sumcheck_round_messages::univariate_round_message;

// fn test_do_claims_match(fold_direction: FoldDirection) {
//     let log_num_rows = 10;
//     let mut rng = StdRng::from_seed([0; 32]);
//     let big_field_zerocheck_challenges =
//         vec![BinaryField128bPolyval::new(13929123); (log_num_rows - SKIPPED_VARS - 3) + 1];

//     let small_field_zerocheck_challenges = vec![
//         AESTowerField8b::new(2),
//         AESTowerField8b::new(4),
//         AESTowerField8b::new(16),
//     ];

//     let iso_lookup = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

//     let first_mlv = OneBitMultivariate {
//         log_num_rows,
//         packed_evals: (0..1 << log_num_rows)
//             .map(|_| PackedBinaryField128x1b::random(&mut rng))
//             .collect(),
//     };

//     let second_mlv = OneBitMultivariate {
//         log_num_rows,
//         packed_evals: (0..1 << log_num_rows)
//             .map(|_| PackedBinaryField128x1b::random(&mut rng))
//             .collect(),
//     };

//     let third_mlv = OneBitMultivariate {
//         log_num_rows,
//         packed_evals: (0..1 << log_num_rows)
//             .map(|i| first_mlv.packed_evals[i] * second_mlv.packed_evals[i])
//             .collect(),
//     };

//     let eq_ind_only_big = eq_ind_mle(&big_field_zerocheck_challenges[1..]);
//     let onto_domain: Vec<_> = (
//         ROWS_PER_HYPERCUBE_VERTEX..2*ROWS_PER_HYPERCUBE_VERTEX
//     ).map(|x| AESTowerField8b::new(x as u8)).collect();

//     let lookup = precompute_lookup(&onto_domain);

//     let first_round_message = univariate_round_message(
//         &first_mlv,
//         &second_mlv,
//         &third_mlv,
//         &eq_ind_only_big,
//         &lookup,
//         &small_field_zerocheck_challenges,
//         big_field_zerocheck_challenges[0],
//         &iso_lookup,
//     );

//     let first_sumcheck_challenge = BinaryField128bPolyval::random(&mut rng);

//     let fold_lookup_polyval = precompute_fold_lookup(first_sumcheck_challenge, &iso_lookup);

//     let expected_next_round_sum =
//         first_round_message.evaluate_at_challenge(first_sumcheck_challenge);

//     let folded_first_mle = first_mlv.fold(&fold_lookup_polyval);
//     let folded_second_mle = second_mlv.fold(&fold_lookup_polyval);
//     let folded_third_mle = third_mlv.fold(&fold_lookup_polyval);

//     let delta_mul_by = delta_poly(big_field_zerocheck_challenges[0], SKIPPED_VARS, &iso_lookup)
//         .evaluate_at_challenge(first_sumcheck_challenge);

//     let upcasted_small_field_challenges: Vec<_> = small_field_zerocheck_challenges
//         .into_iter()
//         .map(|i| iso_lookup.lookup_8b_value(i))
//         .collect();

//     let polyval_zerocheck_challenges: Vec<_> = upcasted_small_field_challenges
//         .iter()
//         .chain(big_field_zerocheck_challenges[1..].iter())
//         .copied()
//         .collect();

//     let polyval_eq = eq_ind_mle(&polyval_zerocheck_challenges);

//     let actual_next_round_sum = sum_claim(
//         &folded_first_mle,
//         &folded_second_mle,
//         &folded_third_mle,
//         &polyval_eq,
//     );

//     assert_eq!(
//         expected_next_round_sum,
//         std::convert::Into::<BinaryField128bPolyval>::into(actual_next_round_sum) * delta_mul_by
//     );

//     let mut prover = MultilinearSumcheckProver::new(
//         vec![field_buffer_to_mle( folded_first_mle).unwrap(), 
//         field_buffer_to_mle( folded_second_mle).unwrap(), field_buffer_to_mle(folded_third_mle).unwrap()],
//         polyval_zerocheck_challenges,
//         actual_next_round_sum,
//         log_num_rows - SKIPPED_VARS,
//         fold_direction,
//     );

//     multilinear_sumcheck(prover);
// }

// #[test]
// fn test_do_claims_match_low_to_high() {
//     test_do_claims_match(FoldDirection::LowToHigh);
// }

// #[test]
// fn test_do_claims_match_high_to_low() {
//     test_do_claims_match(FoldDirection::HighToLow);
// }
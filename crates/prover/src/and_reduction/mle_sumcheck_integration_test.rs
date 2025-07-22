#[cfg(test)]
mod test {
	use binius_field::{
		AESTowerField8b, AESTowerField128b, BinaryField128bPolyval, Field, PackedBinaryField128x1b,
		Random,
	};
	use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};
	use binius_verifier::and_reduction::{
		univariate::{delta::delta_poly, univariate_poly::UnivariatePoly},
		utils::{
			constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
			subfield_isomorphism::SubfieldIsomorphismLookup,
		},
	};
	use itertools::izip;
	use rand::{SeedableRng, rngs::StdRng};

	use crate::{
		and_reduction::{
			fold_lookup::precompute_fold_lookup, sumcheck_round_messages::univariate_round_message,
			univariate::ntt_lookup::precompute_lookup, utils::multivariate::OneBitMultivariate,
		},
		protocols::sumcheck::and_reduction::prover::{
			AndReductionProver, test::multilinear_sumcheck,
		},
	};

	// Sends the sum claim from first multilinear round (second overall round)
	pub fn sum_claim<BF: Field + From<BinaryField128bPolyval>>(
		first_col: &FieldBuffer<BF>,
		second_col: &FieldBuffer<BF>,
		third_col: &FieldBuffer<BF>,
		eq_ind: &FieldBuffer<BF>,
	) -> BF {
		izip!(first_col.as_ref(), second_col.as_ref(), third_col.as_ref(), eq_ind.as_ref())
			.map(|(a, b, c, eq)| (*a * *b - *c) * *eq)
			.sum()
	}

	fn random_one_bit_multivariate(log_num_rows: usize) -> OneBitMultivariate {
		let mut rng = StdRng::from_seed([0; 32]);
		OneBitMultivariate {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|_| PackedBinaryField128x1b::random(&mut rng))
				.collect(),
		}
	}

	#[test]
	fn test_do_claims_match() {
		let log_num_rows = 10;
		let mut rng = StdRng::from_seed([0; 32]);
		let big_field_zerocheck_challenges =
			vec![BinaryField128bPolyval::new(13929123); (log_num_rows - SKIPPED_VARS - 3) + 1];

		let small_field_zerocheck_challenges = vec![
			AESTowerField8b::new(2),
			AESTowerField8b::new(4),
			AESTowerField8b::new(16),
		];

		let iso_lookup = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

		let mlv_1 = random_one_bit_multivariate(log_num_rows);
		let mlv_2 = random_one_bit_multivariate(log_num_rows);
		let mlv_3 = random_one_bit_multivariate(log_num_rows);

		let eq_ind_only_big = eq_ind_partial_eval(&big_field_zerocheck_challenges[1..]);
		let onto_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| AESTowerField8b::new(x as u8))
			.collect();

		let lookup = precompute_lookup(&onto_domain);

		let first_round_message = univariate_round_message(
			&mlv_1,
			&mlv_2,
			&mlv_3,
			&eq_ind_only_big,
			&lookup,
			&small_field_zerocheck_challenges,
			big_field_zerocheck_challenges[0],
			&iso_lookup,
		);

		let first_sumcheck_challenge = BinaryField128bPolyval::random(&mut rng);

		let fold_lookup_polyval = precompute_fold_lookup(first_sumcheck_challenge, &iso_lookup);

		let expected_next_round_sum =
			first_round_message.evaluate_at_challenge(first_sumcheck_challenge);

		let folded_first_mle: FieldBuffer<BinaryField128bPolyval> =
			mlv_1.fold(&fold_lookup_polyval);
		let folded_second_mle: FieldBuffer<BinaryField128bPolyval> =
			mlv_2.fold(&fold_lookup_polyval);
		let folded_third_mle: FieldBuffer<BinaryField128bPolyval> =
			mlv_3.fold(&fold_lookup_polyval);

		let delta_mul_by = delta_poly(big_field_zerocheck_challenges[0], SKIPPED_VARS, &iso_lookup)
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
			sum_claim(&folded_first_mle, &folded_second_mle, &folded_third_mle, &polyval_eq);

		assert_eq!(
			expected_next_round_sum,
			std::convert::Into::<BinaryField128bPolyval>::into(actual_next_round_sum)
				* delta_mul_by
		);

		let mles = vec![folded_first_mle, folded_second_mle, folded_third_mle];

		let prover = AndReductionProver::new(
			mles,
			polyval_zerocheck_challenges,
			actual_next_round_sum,
			log_num_rows - SKIPPED_VARS,
		);

		multilinear_sumcheck(prover);
	}
}

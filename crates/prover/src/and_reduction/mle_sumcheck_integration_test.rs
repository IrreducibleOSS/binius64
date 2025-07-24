#[cfg(test)]
mod test {
	use binius_field::{
		AESTowerField8b, Field, PackedAESBinaryField16x8b, PackedBinaryField128x1b, Random,
		arithmetic_traits::TaggedInvertOrZero,
	};
	use binius_math::{
		FieldBuffer,
		multilinear::{
			eq::{eq_ind, eq_ind_partial_eval},
			evaluate::evaluate,
		},
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		and_reduction::{
			univariate::{delta::delta_poly, univariate_poly::UnivariatePoly},
			utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
		},
		config::StdChallenger,
		fields::B128,
		protocols::sumcheck::verify,
	};
	use itertools::{Itertools, izip};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use crate::{
		and_reduction::{
			fold_lookup::FoldLookup, sumcheck_round_messages::univariate_round_message,
			univariate::ntt_lookup::NTTLookup, utils::multivariate::OneBitMultivariate,
		},
		protocols::sumcheck::{and_reduction::prover::AndReductionProver, prove_single},
	};

	// Sends the sum claim from first multilinear round (second overall round)
	pub fn sum_claim<BF: Field + From<B128>>(
		first_col: &FieldBuffer<BF>,
		second_col: &FieldBuffer<BF>,
		third_col: &FieldBuffer<BF>,
		eq_ind: &FieldBuffer<BF>,
	) -> BF {
		izip!(first_col.as_ref(), second_col.as_ref(), third_col.as_ref(), eq_ind.as_ref())
			.map(|(a, b, c, eq)| (*a * *b - *c) * *eq)
			.sum()
	}

	fn random_one_bit_multivariate(log_num_rows: usize, mut rng: impl Rng) -> OneBitMultivariate {
		OneBitMultivariate {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|_| PackedBinaryField128x1b::random(&mut rng))
				.collect(),
		}
	}

	#[test]
	fn test_integration() {
		let log_num_rows = 10;
		let mut rng = StdRng::from_seed([0; 32]);
		let big_field_zerocheck_challenges =
			vec![B128::new(13929123); (log_num_rows - SKIPPED_VARS - 3) + 1];

		let small_field_zerocheck_challenges = vec![
			AESTowerField8b::new(2),
			AESTowerField8b::new(4),
			AESTowerField8b::new(16),
		];

		let mlv_1 = random_one_bit_multivariate(log_num_rows, &mut rng);
		let mlv_2 = random_one_bit_multivariate(log_num_rows, &mut rng);
		let mlv_3 = OneBitMultivariate {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|i| mlv_1.packed_evals[i] * mlv_2.packed_evals[i])
				.collect(),
		};

		let eq_ind_only_big = eq_ind_partial_eval(&big_field_zerocheck_challenges[1..]);
		let onto_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| AESTowerField8b::new(x as u8))
			.collect();

		let ntt_lookup = NTTLookup::<PackedAESBinaryField16x8b>::new(&onto_domain);

		let first_round_message = univariate_round_message(
			&mlv_1,
			&mlv_2,
			&mlv_3,
			&eq_ind_only_big,
			&ntt_lookup,
			&small_field_zerocheck_challenges,
			big_field_zerocheck_challenges[0],
		);

		let first_sumcheck_challenge = B128::random(&mut rng);

		let fold_lookup_polyval = FoldLookup::new::<AESTowerField8b>(first_sumcheck_challenge);

		let delta_mul_by =
			delta_poly::<AESTowerField8b, B128>(big_field_zerocheck_challenges[0], SKIPPED_VARS)
				.evaluate_at_challenge(first_sumcheck_challenge);

		let expected_next_round_sum = first_round_message
			.evaluate_at_challenge(first_sumcheck_challenge)
			* delta_mul_by.invert_or_zero();

		let folded_first_mle: FieldBuffer<B128> = mlv_1.fold(&fold_lookup_polyval);
		let folded_second_mle: FieldBuffer<B128> = mlv_2.fold(&fold_lookup_polyval);
		let folded_third_mle: FieldBuffer<B128> = mlv_3.fold(&fold_lookup_polyval);

		let upcasted_small_field_challenges: Vec<_> = small_field_zerocheck_challenges
			.into_iter()
			.map(|i| B128::from(i))
			.collect();

		let polyval_zerocheck_challenges: Vec<_> = upcasted_small_field_challenges
			.iter()
			.chain(big_field_zerocheck_challenges[1..].iter())
			.copied()
			.collect();

		let polyval_eq = eq_ind_partial_eval(&polyval_zerocheck_challenges);

		let actual_next_round_sum =
			sum_claim(&folded_first_mle, &folded_second_mle, &folded_third_mle, &polyval_eq);

		assert_eq!(expected_next_round_sum, actual_next_round_sum);

		let mles = vec![folded_first_mle, folded_second_mle, folded_third_mle];

		let prover = AndReductionProver::new(
			mles.clone(),
			polyval_zerocheck_challenges.clone(),
			actual_next_round_sum,
			log_num_rows - SKIPPED_VARS,
		);

		let mut transcript_for_sumcheck = ProverTranscript::new(StdChallenger::default());

		// run sumcheck
		let prove_output = prove_single(prover, &mut transcript_for_sumcheck).unwrap();

		let l2h_query_for_evaluation_point = prove_output
			.challenges
			.clone()
			.into_iter()
			.rev()
			.collect_vec();

		transcript_for_sumcheck
			.message()
			.write_slice(&prove_output.multilinear_evals);

		let mut verifier_transcript = transcript_for_sumcheck.into_verifier();

		let output = verify(
			polyval_zerocheck_challenges.len(),
			3,
			actual_next_round_sum,
			&mut verifier_transcript,
		)
		.unwrap();

		let verifier_mle_eval_claims = verifier_transcript
			.message()
			.read_scalar_slice::<B128>(4)
			.unwrap();

		for (i, eval) in verifier_mle_eval_claims.iter().enumerate().take(3) {
			assert_eq!(evaluate(&mles[i], &l2h_query_for_evaluation_point).unwrap(), *eval);
		}

		assert_eq!(
			verifier_mle_eval_claims[3],
			eq_ind(&l2h_query_for_evaluation_point, &polyval_zerocheck_challenges)
		);

		assert_eq!(
			output.eval,
			(verifier_mle_eval_claims[0] * verifier_mle_eval_claims[1]
				- verifier_mle_eval_claims[2])
				* verifier_mle_eval_claims[3]
		);

		assert_eq!(output.challenges, prove_output.challenges);
	}
}

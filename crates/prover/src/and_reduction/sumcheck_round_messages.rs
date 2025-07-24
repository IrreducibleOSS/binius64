use binius_field::{
	BinaryField, Field, PackedBinaryField128x1b, PackedExtension,
	packed::{get_packed_slice, iter_packed_slice_with_offset},
};
use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};
use binius_utils::rayon::prelude::{IntoParallelIterator, ParallelIterator};
use binius_verifier::{
	and_reduction::{
		univariate::{
			delta::delta_poly,
			univariate_poly::{GenericPo2UnivariatePoly, UnivariatePoly},
		},
		utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
	},
	fields::B1,
};

use super::{univariate::ntt_lookup::NTTLookup, utils::multivariate::OneBitMultivariate};

const BYTES_PER_HYPERCUBE_VERTEX: usize = 1 << (SKIPPED_VARS - 3);
const NTT_DOMAIN_SIZE: usize = ROWS_PER_HYPERCUBE_VERTEX;
const HOT_LOOP_NTT_POINTS: usize = 2 * ROWS_PER_HYPERCUBE_VERTEX;
const PROVER_MESSAGE_NUM_POINTS: usize = 4 * ROWS_PER_HYPERCUBE_VERTEX;

// Sends evaluations of the 3*(|D| - 1) degree polynomial
#[allow(clippy::too_many_arguments)]
pub fn univariate_round_message<'a, FChallenge, PNTTDomain>(
	first_col: &OneBitMultivariate,
	second_col: &OneBitMultivariate,
	third_col: &OneBitMultivariate,
	eq_ind_big_field_challenges: &FieldBuffer<FChallenge>,
	ntt_lookup: &NTTLookup<PNTTDomain>,
	small_field_zerocheck_challenges: &[PNTTDomain::Scalar],
	univariate_zerocheck_challenge: FChallenge,
) -> GenericPo2UnivariatePoly<FChallenge, PNTTDomain::Scalar>
where
	FChallenge: Field + From<PNTTDomain::Scalar>,
	PNTTDomain: PackedExtension<B1, PackedSubfield = PackedBinaryField128x1b>,
	u8: From<<PNTTDomain as binius_field::PackedField>::Scalar>,
	<PNTTDomain as binius_field::PackedField>::Scalar: From<u8> + BinaryField,
{
	assert!(PNTTDomain::WIDTH == 16);

	let log_num_rows = first_col.log_num_rows;
	let num_vars_on_hypercube = log_num_rows - SKIPPED_VARS;

	let mut pre_delta_prover_message = vec![FChallenge::ZERO; HOT_LOOP_NTT_POINTS];

	let col_1_bytes = <PNTTDomain as PackedExtension<B1>>::cast_exts(&first_col.packed_evals);
	let col_2_bytes = <PNTTDomain as PackedExtension<B1>>::cast_exts(&second_col.packed_evals);
	let col_3_bytes = <PNTTDomain as PackedExtension<B1>>::cast_exts(&third_col.packed_evals);

	let eq_ind_small: Vec<PNTTDomain> = eq_ind_partial_eval(small_field_zerocheck_challenges)
		.as_ref()
		.iter()
		.map(|&item| PNTTDomain::broadcast(item))
		.collect();

	// Execute the NTTs at each hypercube vertex
	let pre_delta_prover_message_extension_domain = (0..1 << (num_vars_on_hypercube - 3))
		.into_par_iter()
		.map(|subcube_idx| {
			let mut summed_ntt = [PNTTDomain::zero(); NTT_DOMAIN_SIZE / 16];

			for point_idx_within_subcube in 0..1 << 3 {
				let hypercube_point_idx = subcube_idx << 3 | point_idx_within_subcube;
				let byte_offset = hypercube_point_idx * BYTES_PER_HYPERCUBE_VERTEX;

				let first_col_ntt = ntt_lookup.ntt(
					iter_packed_slice_with_offset(col_1_bytes, byte_offset)
						.take(BYTES_PER_HYPERCUBE_VERTEX)
						.map(u8::from),
				);
				let second_col_ntt = ntt_lookup.ntt(
					iter_packed_slice_with_offset(col_2_bytes, byte_offset)
						.take(BYTES_PER_HYPERCUBE_VERTEX)
						.map(u8::from),
				);
				let third_col_ntt = ntt_lookup.ntt(
					iter_packed_slice_with_offset(col_3_bytes, byte_offset)
						.take(BYTES_PER_HYPERCUBE_VERTEX)
						.map(u8::from),
				);

				let weight = eq_ind_small[point_idx_within_subcube];
				for i in 0..NTT_DOMAIN_SIZE / 16 {
					summed_ntt[i] +=
						(first_col_ntt[i] * second_col_ntt[i] - third_col_ntt[i]) * weight;
				}
			}

			let eq_weight = eq_ind_big_field_challenges.as_ref()[subcube_idx];
			let mut result = [FChallenge::ZERO; ROWS_PER_HYPERCUBE_VERTEX];

			for (i, val) in result.iter_mut().enumerate() {
				*val = eq_weight * FChallenge::from(get_packed_slice(&summed_ntt, i));
			}

			result
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

	pre_delta_prover_message[ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX]
		.copy_from_slice(&pre_delta_prover_message_extension_domain);

	let pre_delta_poly = GenericPo2UnivariatePoly::new(pre_delta_prover_message);

	let delta = delta_poly(univariate_zerocheck_challenge, SKIPPED_VARS);

	let final_evals = (0..PROVER_MESSAGE_NUM_POINTS)
		.map(|i| {
			let point = FChallenge::from(PNTTDomain::Scalar::from(i as u8));
			pre_delta_poly.evaluate_at_challenge(point) * delta.evaluate_at_challenge(point)
		})
		.collect();

	GenericPo2UnivariatePoly::new(final_evals)
}

#[cfg(test)]
mod test {
	use binius_field::{
		AESTowerField8b, Field, PackedAESBinaryField16x8b, PackedBinaryField128x1b, Random,
	};
	use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};
	use binius_verifier::{
		and_reduction::{
			univariate::{delta::delta_poly, univariate_poly::UnivariatePoly},
			utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
		},
		fields::B128,
	};
	use itertools::izip;
	use rand::{SeedableRng, rngs::StdRng};

	use super::univariate_round_message;
	use crate::and_reduction::{
		fold_lookup::FoldLookup, univariate::ntt_lookup::NTTLookup,
		utils::multivariate::OneBitMultivariate,
	};

	fn random_one_bit_multivariate(log_num_rows: usize) -> OneBitMultivariate {
		let mut rng = StdRng::from_seed([0; 32]);
		OneBitMultivariate {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|_| PackedBinaryField128x1b::random(&mut rng))
				.collect(),
		}
	}

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

	#[test]
	fn test_first_round_message_matches_next_round_sum_claim() {
		let log_num_rows = 10;
		let mut rng = StdRng::from_seed([0; 32]);

		let big_field_zerocheck_challenges =
			vec![B128::random(&mut rng); (log_num_rows - SKIPPED_VARS - 3) + 1];

		let small_field_zerocheck_challenges = [
			AESTowerField8b::new(2),
			AESTowerField8b::new(4),
			AESTowerField8b::new(16),
		];

		let mlv_1 = random_one_bit_multivariate(log_num_rows);
		let mlv_2 = random_one_bit_multivariate(log_num_rows);
		let mlv_3 = random_one_bit_multivariate(log_num_rows);

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
		let expected_next_round_sum =
			first_round_message.evaluate_at_challenge(first_sumcheck_challenge);

		let lookup = FoldLookup::new::<AESTowerField8b>(first_sumcheck_challenge);

		let folded_first_mle = mlv_1.fold(&lookup);
		let folded_second_mle = mlv_2.fold(&lookup);
		let folded_third_mle = mlv_3.fold(&lookup);

		let eq_ind_mul_by =
			delta_poly::<AESTowerField8b, _>(big_field_zerocheck_challenges[0], SKIPPED_VARS)
				.evaluate_at_challenge(first_sumcheck_challenge);

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
			sum_claim(&folded_first_mle, &folded_second_mle, &folded_third_mle, &polyval_eq)
				* std::convert::Into::<B128>::into(eq_ind_mul_by);

		assert_eq!(expected_next_round_sum, actual_next_round_sum);
	}
}

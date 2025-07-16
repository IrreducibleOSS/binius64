use std::vec;

use binius_field::Field;
use binius_math::{Error, FieldBuffer};
use rayon::prelude::*;

use crate::multilinear_sumcheck::sumcheck_prover::SumcheckProver;

// ! Field Buffer MLE Sumcheck Prover

pub enum FoldDirection {
	LowToHigh,
	HighToLow,
}

pub struct MultilinearSumcheckProver<BF: Field> {
	pub multilinears: Vec<FieldBuffer<BF>>,
	pub overall_claim: BF,
	pub log_n: usize,
	pub current_round_claim: BF,
	pub fold_direction: FoldDirection,
}

impl<BF: Field> MultilinearSumcheckProver<BF> {
	pub fn new(
		multilinears: Vec<FieldBuffer<BF>>,
		overall_claim: BF,
		log_n: usize,
		fold_direction: FoldDirection,
	) -> Self {
		Self {
			multilinears,
			overall_claim,
			log_n,
			current_round_claim: overall_claim,
			fold_direction,
		}
	}

	// sums the composition of 2 multilinears A * B
	pub fn sum_composition(a: &FieldBuffer<BF>, b: &FieldBuffer<BF>) -> Result<BF, Error> {
		let mut sum = BF::ZERO;
		for i in 0..a.len() {
			let a_i = a.get(i)?;
			let b_i = b.get(i)?;

			sum += a_i * b_i;
		}

		Ok(sum)
	}
}

// ! temporary utility until we use monbijou fold funcs
fn fold_high_to_low<BF: Field>(mle: FieldBuffer<BF>, challenge: BF) -> FieldBuffer<BF> {
	let n = 1 << mle.log_len();
	let n_half = n >> 1;

	let mut mle = mle;
	mle.split_half_mut(|low, high| {
		for i in 0..n_half {
			let low_i = low.get(i).unwrap();
			let high_i = high.get(i).unwrap();

			low.set(i, low_i + challenge * (high_i - low_i)).unwrap();
		}
	})
	.unwrap();

	let mut out = FieldBuffer::<BF>::zeros(mle.log_len() - 1);
	for i in 0..n_half {
		out.set(i, mle.get(i).unwrap()).unwrap();
	}
	out
}

// ! temporary utility until we use monbijou fold funcs
fn fold_low_to_high<BF: Field>(mle: FieldBuffer<BF>, challenge: BF) -> FieldBuffer<BF> {
	let n = 1 << mle.log_len();
	let n_half = n >> 1;

	let mut out = FieldBuffer::<BF>::zeros(mle.log_len() - 1);
	for j in 0..n_half {
		let (low_idx, high_idx) = (2 * j, 2 * j + 1);
		let even = mle.get(low_idx).unwrap();
		let odd = mle.get(high_idx).unwrap();

		out.set(j, even + challenge * (odd - even)).unwrap();
	}

	out
}

impl<BF: Field> SumcheckProver<BF> for MultilinearSumcheckProver<BF> {
	fn fold(&mut self, challenge: BF) {
		match self.fold_direction {
			FoldDirection::HighToLow => {
				for m in self.multilinears.iter_mut() {
					*m = fold_high_to_low(m.clone(), challenge); // ! temporary utility until we use monbijou fold funcs
				}
			}
			FoldDirection::LowToHigh => {
				for m in self.multilinears.iter_mut() {
					*m = fold_low_to_high(m.clone(), challenge); // ! temporary utility until we use monbijou fold funcs
				}
			}
		}
	}

	fn round_message(&self) -> Vec<BF> {
		let log_n = self.multilinears[0].log_len();
		let n = 1 << log_n;
		let n_half = n >> 1;

		let a = &self.multilinears[0];
		let b = &self.multilinears[1];

		match self.fold_direction {
			FoldDirection::HighToLow => {
				// With high-to-low indexing:
				// - g_of_zero: sum over indices 0..n_half (first variable = 0)
				// - g_of_one: sum over indices n_half..n (first variable = 1)
				let g_of_zero: BF = (0..n_half)
					.into_par_iter()
					.map(|i| a.get(i).unwrap() * b.get(i).unwrap())
					.sum();

				let g_of_one: BF = (n_half..n)
					.into_par_iter()
					.map(|i| a.get(i).unwrap() * b.get(i).unwrap())
					.sum();

				let g_leading: BF = (0..n_half)
					.into_par_iter()
					.zip((n_half..n).into_par_iter())
					.map(|(low, high)| {
						(a.get(low).unwrap() + a.get(high).unwrap())
							* (b.get(low).unwrap() + b.get(high).unwrap())
					})
					.sum();

				// return round message
				let mut round_msg = Vec::with_capacity(3);
				round_msg.extend([g_of_zero, g_of_one, g_leading]);
				round_msg
			}
			FoldDirection::LowToHigh => {
				// With low-to-high indexing:
				// - g_of_zero: sum over even indices (last bit = 0)
				// - g_of_one: sum over odd indices (last bit = 1)
				let (g_of_zero, g_of_one, g_leading) = (0..n_half)
					.into_par_iter()
					.map(|i| {
						let even = a.get(2 * i).unwrap() * b.get(2 * i).unwrap();
						let odd = a.get(2 * i + 1).unwrap() * b.get(2 * i + 1).unwrap();
						let cross = (a.get(2 * i).unwrap() + a.get(2 * i + 1).unwrap())
							* (b.get(2 * i).unwrap() + b.get(2 * i + 1).unwrap());
						(even, odd, cross)
					})
					.reduce(
						|| (BF::ZERO, BF::ZERO, BF::ZERO),
						|(e1, o1, c1), (e2, o2, c2)| (e1 + e2, o1 + o2, c1 + c2),
					);

				vec![g_of_zero, g_of_one, g_leading]
			}
		}
	}

	fn final_eval_claims(self) -> Vec<BF> {
		vec![
			self.multilinears[0].get(0).unwrap(),
			self.multilinears[1].get(0).unwrap(),
		]
	}
}

#[cfg(test)]
pub mod test {
	use std::array;

	use binius_field::{BinaryField128b, ExtensionField, Random};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::utils::utils::{evaluate_round_polynomial_at, verify_sumcheck_round};

	type BF = BinaryField128b;

	fn random_challenge() -> BF {
		let mut rng = StdRng::from_seed([0; 32]);
		BF::random(&mut rng)
	}

	fn two_random_field_buffers(log_n: usize) -> [FieldBuffer<BF>; 2] {
		let mut rng = StdRng::from_seed([0; 32]);
		let n = 1 << log_n;
		array::from_fn(|_| {
			FieldBuffer::from_values(&(0..n).map(|_| BF::random(&mut rng)).collect::<Vec<BF>>())
				.unwrap()
		})
	}

	pub fn eq_ind<F: Field, BF>(zerocheck_challenges: &[F]) -> FieldBuffer<BF>
	where
		BF: ExtensionField<F>,
	{
		let mut mle = bytemuck::zeroed_vec(1 << zerocheck_challenges.len());

		mle[0] = BF::ONE;
		for (curr_log_len, challenge) in zerocheck_challenges.iter().enumerate() {
			let (mle_lower, mle_upper) = mle.split_at_mut(1 << curr_log_len);

			mle_lower
				.par_iter_mut()
				.zip(mle_upper.par_iter_mut())
				.for_each(|(low, up)| {
					let multiplied = *low * *challenge;
					*up = multiplied;
					*low -= multiplied;
				});
		}

		FieldBuffer::from_values(&mle).unwrap()
	}

	// runs sumcheck interactive protocol for multilinear composition (A * B - C) * eq_r
	// eq_r is the multilinear equality indicator for some vector of log_n zerocheck challenges
	pub fn sumcheck_interactive_protocol(
		prover: &mut MultilinearSumcheckProver<BF>,
	) -> Result<(BF, Vec<BF>), Error> {
		let log_n = prover.log_n;

		let mut expected_next_round_claim = prover.overall_claim;
		let mut sumcheck_challenges = Vec::with_capacity(log_n);

		for _ in 0..log_n {
			// verifier sends sumcheck challenge
			let sumcheck_challenge = random_challenge();
			sumcheck_challenges.push(sumcheck_challenge);

			// prover computes round message
			let round_msg = prover.round_message();

			// verifier checks round message against claim
			expected_next_round_claim = verify_sumcheck_round(
				prover.current_round_claim,
				expected_next_round_claim,
				round_msg.clone(),
				sumcheck_challenge,
			);

			// prover sets next round claim
			prover.current_round_claim =
				evaluate_round_polynomial_at(sumcheck_challenge, round_msg.clone());

			// prover folds challenge into multilinear
			prover.fold(sumcheck_challenge);
		}

		Ok((expected_next_round_claim, sumcheck_challenges))
	}

	fn test_sumcheck_interactive_protocol(
		multilinears: [FieldBuffer<BF>; 2],
		fold_direction: FoldDirection,
	) -> Result<(), Error> {
		let log_n = multilinears[0].log_len();

		// compute overall sumcheck claim for composition A * eq_r
		let overall_claim =
			MultilinearSumcheckProver::sum_composition(&multilinears[0], &multilinears[1])?;

		// create multilinear sumcheck prover
		let mut prover = MultilinearSumcheckProver::new(
			multilinears.to_vec(),
			overall_claim,
			log_n,
			fold_direction,
		);

		// run sumcheck
		let (final_sumcheck_msg, sumcheck_challenges) = sumcheck_interactive_protocol(&mut prover)?;

		// gather final eval claims
		let _final_eval_claims = prover.final_eval_claims();

		// test that the final sumcheck message is indeed the evaluation of the
		// multilinear at the sumcheck challenges
		let sumcheck_challenges_tensor_expansion: FieldBuffer<BF> =
			eq_ind(&sumcheck_challenges.into_iter().rev().collect::<Vec<_>>());

		let (mut eval_a, mut eval_b) = (BF::ZERO, BF::ZERO);
		for i in 0..1 << log_n {
			eval_a += multilinears[0].get(i).unwrap()
				* sumcheck_challenges_tensor_expansion.get(i).unwrap();
			eval_b += multilinears[1].get(i).unwrap()
				* sumcheck_challenges_tensor_expansion.get(i).unwrap();
		}

		assert_eq!(eval_a * eval_b, final_sumcheck_msg);

		Ok(())
	}

	#[test]
	fn test_sumcheck_low_to_high() {
		let log_n = 5;
		let multilinears = two_random_field_buffers(log_n);
		test_sumcheck_interactive_protocol(multilinears, FoldDirection::LowToHigh).unwrap();
	}

	#[test]
	fn test_sumcheck_high_to_low() {
		let log_n = 5;
		let multilinears = two_random_field_buffers(log_n);
		test_sumcheck_interactive_protocol(multilinears, FoldDirection::HighToLow).unwrap();
	}

	#[test]
	fn test_composition_even_odd_sum() {
		let mut rng = StdRng::from_seed([0; 32]);

		let log_n = 5;
		let n = 1 << log_n;

		let multilinear = two_random_field_buffers(log_n)[0].clone();

		let challenges = (0..log_n)
			.map(|_| BF::random(&mut rng))
			.collect::<Vec<BF>>();

		let eq_r: FieldBuffer<BF> = eq_ind(&challenges.clone());

		let overall_sum = MultilinearSumcheckProver::sum_composition(&multilinear, &eq_r).unwrap();

		// produce g(0), g(1) by summing over evals where first var is 0, 1
		let mut g_of_zero = BF::ZERO;
		let mut g_of_one = BF::ZERO;
		for i in 0..n {
			let a = multilinear.get(i).unwrap();
			let eq_r_i = eq_r.get(i).unwrap();

			if i.is_multiple_of(2) {
				g_of_zero += a * eq_r_i;
			} else {
				g_of_one += a * eq_r_i;
			}
		}

		assert_eq!(overall_sum, g_of_zero + g_of_one);
	}
}

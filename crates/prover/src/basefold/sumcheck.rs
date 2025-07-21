use binius_field::Field;
use binius_math::FieldBuffer;
use binius_utils::rayon::{
	iter::{IntoParallelIterator, ParallelIterator},
	prelude::{IndexedParallelIterator, IntoParallelRefMutIterator},
	slice::ParallelSlice,
};
use binius_verifier::protocols::sumcheck::RoundCoeffs;
use binius_verifier::basefold::utils::evaluate_round_polynomial_at;
use crate::protocols::sumcheck::{common::SumcheckProver, error::Error};

/// Exposes a round-by-round interface to prove the sum of A(X) * B(X) for
/// some multilinears A and B over all hypercube points X
pub struct MultilinearSumcheckProver<F: Field> {
	multilinears: [FieldBuffer<F>; 2],
	log_n: usize,
	current_round_claim: F,
	round_message: Option<Vec<F>>,
}

impl<F: Field> MultilinearSumcheckProver<F> {
	pub fn new(multilinears: [FieldBuffer<F>; 2], overall_claim: F, log_n: usize) -> Self {
		Self {
			multilinears,
			log_n,
			current_round_claim: overall_claim,
			round_message: None,
		}
	}

	// sums the composition of 2 multilinears A * B
	pub fn sum_composition(a: &FieldBuffer<F>, b: &FieldBuffer<F>) -> Result<F, Error> {
		let mut sum = F::ZERO;
		for i in 0..a.len() {
			let a_i = a.get(i)?;
			let b_i = b.get(i)?;

			sum += a_i * b_i;
		}

		Ok(sum)
	}
}

fn fold_low_to_high<F: Field>(
	multilinear_extension: FieldBuffer<F>,
	challenge: F,
) -> Result<FieldBuffer<F>, Error> {
	let mut out = FieldBuffer::<F>::zeros(multilinear_extension.log_len() - 1);
	out.as_mut()
		.par_iter_mut()
		.zip(multilinear_extension.as_ref().par_chunks(2))
		.for_each(|(output, input)| {
			let (even, odd) = (input[0], input[1]);
			*output = even + challenge * (odd - even)
		});

	Ok(out)
}

impl<F: Field> SumcheckProver<F> for MultilinearSumcheckProver<F> {
	fn n_vars(&self) -> usize {
		self.log_n
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		let log_n = self.multilinears[0].log_len();
		let n = 1 << log_n;
		let n_half = n >> 1;

		let a = &self.multilinears[0];
		let b = &self.multilinears[1];

		// helper func to multiply two field elements
		let get_and_multiply = |i: usize| {
			let a_i = a.get(i).expect("out of bounds");
			let b_i = b.get(i).expect("out of bounds");
			a_i * b_i
		};

		// With low-to-high indexing:
		// - g_of_zero: sum over even indices (last bit = 0)
		// - g_of_one: sum over odd indices (last bit = 1)

		let (g_of_one, g_leading) = (0..n_half)
			.into_par_iter()
			.map(|i| {
				let odd = get_and_multiply(2 * i + 1);

				let cross = (a.get(2 * i).expect("out of bounds")
					+ a.get(2 * i + 1).expect("out of bounds"))
					* (b.get(2 * i).expect("out of bounds")
						+ b.get(2 * i + 1).expect("out of bounds"));
				(odd, cross)
			})
			.reduce(|| (F::ZERO, F::ZERO), |(o1, c1), (o2, c2)| (o1 + o2, c1 + c2));

		let g_of_zero = self.current_round_claim - g_of_one;

		self.round_message = Some(vec![g_of_zero, g_of_one, g_leading]);
		Ok(vec![RoundCoeffs::<F>(vec![g_of_zero, g_of_one, g_leading])])
	}

	fn fold(&mut self, challenge: F) -> Result<(), Error> {
		for m in self.multilinears.iter_mut() {
			*m = fold_low_to_high(m.clone(), challenge)?;
		}

		let round_msg = self
			.round_message
			.clone()
			.expect("prover must be executed before fold");
		self.current_round_claim = evaluate_round_polynomial_at(challenge, round_msg);

		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		Ok(vec![self.multilinears[0].get(0)?, self.multilinears[1].get(0)?])
	}
}

#[cfg(test)]
pub mod test {
	use super::*;

    use binius_field::{BinaryField128b, Random};
    use binius_math::{multilinear::eq::eq_ind_partial_eval, test_utils::random_field_buffer};
	use rand::{SeedableRng, rngs::StdRng};
	use binius_verifier::basefold::utils::verify_sumcheck_round;

	type F = BinaryField128b;

	fn random_challenge() -> F {
		let mut rng = StdRng::from_seed([0; 32]);
		F::random(&mut rng)
	}

	// runs sumcheck interactive protocol for multilinear composition (A * B - C) * eq_r
	// eq_r is the multilinear equality indicator for some vector of log_n zerocheck challenges
	pub fn sumcheck_interactive_protocol(
		prover: &mut MultilinearSumcheckProver<F>,
	) -> Result<(F, Vec<F>), Error> {
		let log_n = prover.log_n;

		let mut expected_next_round_claim =
			prover.execute().unwrap()[0].0[0] + prover.execute().unwrap()[0].0[1];
		let mut sumcheck_challenges = Vec::with_capacity(log_n);

		for _ in 0..log_n {
			// verifier sends sumcheck challenge
			let sumcheck_challenge = random_challenge();
			sumcheck_challenges.push(sumcheck_challenge);

			// prover computes round message
			let round_msg: Vec<RoundCoeffs<F>> = prover.execute()?;
			let round_msg: RoundCoeffs<F> = round_msg[0].clone();
			let round_msg: Vec<F> = round_msg.0;

			// verifier checks round message against claim
			expected_next_round_claim = verify_sumcheck_round(
				prover.current_round_claim,
				expected_next_round_claim,
				round_msg.clone(),
				sumcheck_challenge,
			);

			// prover folds challenge into multilinear
			prover.fold(sumcheck_challenge)?;
		}

		Ok((expected_next_round_claim, sumcheck_challenges))
	}

	fn test_sumcheck_interactive_protocol(multilinears: [FieldBuffer<F>; 2]) -> Result<(), Error> {
		let log_n = multilinears[0].log_len();

		// compute overall sumcheck claim for composition A * eq_r
		let overall_claim =
			MultilinearSumcheckProver::sum_composition(&multilinears[0], &multilinears[1])?;

		// create multilinear sumcheck prover
		let mut prover = MultilinearSumcheckProver::new(multilinears.clone(), overall_claim, log_n);

		// run sumcheck
		let (final_sumcheck_msg, sumcheck_challenges) = sumcheck_interactive_protocol(&mut prover)?;

		// gather final eval claims
		let final_eval_claims = prover.finish()?;

		// test that the final sumcheck message is indeed the evaluation of the
		// multilinear at the sumcheck challenges
		let sumcheck_challenges_tensor_expansion: FieldBuffer<F> =
			eq_ind_partial_eval(&sumcheck_challenges.into_iter().rev().collect::<Vec<_>>());

		let (mut eval_a, mut eval_b) = (F::ZERO, F::ZERO);
		for i in 0..1 << log_n {
			eval_a += multilinears[0].get(i).expect("out of bounds")
				* sumcheck_challenges_tensor_expansion.get(i)?;
			eval_b += multilinears[1].get(i).expect("out of bounds")
				* sumcheck_challenges_tensor_expansion.get(i)?;
		}

		assert_eq!(eval_a * eval_b, final_sumcheck_msg);
		assert_eq!(final_eval_claims[0] * final_eval_claims[1], final_sumcheck_msg);

		Ok(())
	}

	#[test]
	fn test_sumcheck_low_to_high() {
		let rng = StdRng::from_seed([0; 32]);

		let log_n = 5;
		let a = random_field_buffer(rng.clone(), log_n);
		let b = random_field_buffer(rng, log_n);
		let multilinears = [a, b];
		test_sumcheck_interactive_protocol(multilinears).expect("sumcheck failed");
	}

	#[test]
	fn test_composition_even_odd_sum() {
		let mut rng = StdRng::from_seed([0; 32]);

		let log_n = 5;
		let n = 1 << log_n;

		let multilinear = random_field_buffer(rng.clone(), log_n);

		let challenges = (0..log_n).map(|_| F::random(&mut rng)).collect::<Vec<F>>();

		let eq_r: FieldBuffer<F> = eq_ind_partial_eval(&challenges.clone());

		let overall_sum = MultilinearSumcheckProver::sum_composition(&multilinear, &eq_r)
			.expect("failed to sum composition");

		// produce g(0), g(1) by summing over evals where first var is 0, 1
		let mut g_of_zero = F::ZERO;
		let mut g_of_one = F::ZERO;
		for i in 0..n {
			let a = multilinear.get(i).expect("out of bounds");
			let eq_r_i = eq_r.get(i).expect("out of bounds");

			if i.is_multiple_of(2) {
				g_of_zero += a * eq_r_i;
			} else {
				g_of_one += a * eq_r_i;
			}
		}

		assert_eq!(overall_sum, g_of_zero + g_of_one);
	}
}
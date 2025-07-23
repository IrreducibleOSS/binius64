use std::vec;

use binius_field::Field;
use binius_math::{
	FieldBuffer,
	multilinear::{eq::eq_ind_partial_eval, fold::fold_highest_var_inplace},
};
use binius_utils::rayon::prelude::{IntoParallelIterator, ParallelIterator};
use binius_verifier::protocols::sumcheck::RoundCoeffs;

use crate::protocols::sumcheck::{common::SumcheckProver, error::Error};

enum RoundCoeffsOrSum<F: Field> {
	Coeffs(RoundCoeffs<F>),
	Sum(F),
}

/// Prover for the AND reduction sumcheck protocol.
///
/// This prover implements a sumcheck protocol for proving the sum of a multilinear
/// polynomial composition of the form `(A * B - C) * D`, where A, B, C are witness
/// multilinears and D is the equality indicator polynomial `eq_r`.
///
/// The protocol reduces the verification of the sum to checking a single evaluation
/// of the composed polynomial at a random point chosen by the verifier through
/// interactive challenges.
///
/// # Protocol Overview
///
/// The prover engages in `log_n` rounds of interaction with the verifier:
/// 1. In each round, the prover sends a univariate polynomial's evaluations
/// 2. The verifier checks consistency and sends back a challenge
/// 3. The prover "folds" the multilinears using the challenge
/// 4. After all rounds, the claim is reduced to a single point evaluation
pub struct AndReductionProver<F: Field> {
	multilinears: Vec<FieldBuffer<F>>,
	log_n: usize,
	zerocheck_challenges: Vec<F>,
	round_coeffs_or_sum: RoundCoeffsOrSum<F>,
	round_index: usize,
	eq_factor: F,
}

impl<F: Field> AndReductionProver<F> {
	/// Creates a new AND reduction sumcheck prover.
	///
	/// # Arguments
	///
	/// * `multilinears` - The witness multilinears [A, B, C] for the composition (A * B - C)
	/// * `zerocheck_challenges` - Challenges from the zerocheck protocol used to construct eq_r
	/// * `overall_claim` - The claimed sum of (A * B - C) * eq_r over the boolean hypercube
	/// * `log_n` - The number of variables in the multilinear polynomials
	///
	/// # Panics
	///
	/// Panics in debug mode if `multilinears.len() != 3`
	pub fn new(
		multilinears: Vec<FieldBuffer<F>>,
		zerocheck_challenges: Vec<F>,
		overall_claim: F,
		log_n: usize,
	) -> Self {
		debug_assert_eq!(multilinears.len(), 3);

		// compute eq indicator from zerocheck challenges, add to multilinears for folding
		let eq_r: FieldBuffer<F> = eq_ind_partial_eval(&zerocheck_challenges);

		let mut multilinears = multilinears;
		multilinears.push(eq_r);

		Self {
			multilinears,
			log_n,
			zerocheck_challenges,
			round_coeffs_or_sum: RoundCoeffsOrSum::Sum(overall_claim),
			eq_factor: F::ONE,
			round_index: 0,
		}
	}

	/// Returns the index of the current zerocheck challenge to use.
	fn zerocheck_challenge_idx(&self) -> usize {
		self.log_n - self.round_index - 1
	}
}

impl<F: Field> SumcheckProver<F> for AndReductionProver<F> {
	/// Returns the number of variables in the multilinear polynomials.
	fn n_vars(&self) -> usize {
		self.multilinears[0].log_len()
	}

	/// Folds the multilinear polynomials using the sumcheck challenge.
	///
	/// This method performs the key step in the sumcheck protocol where the prover
	/// "folds" the multilinear polynomials by fixing one variable to the challenge
	/// value, effectively reducing the problem size by half.
	///
	/// # Arguments
	///
	/// * `sumcheck_challenge` - The challenge value from the verifier for this round
	///
	/// # Returns
	///
	/// Returns `Ok(())` on success, or an error if the round message is missing
	fn fold(&mut self, sumcheck_challenge: F) -> Result<(), Error> {
		for m in self.multilinears.iter_mut() {
			fold_highest_var_inplace(m, sumcheck_challenge)
				.expect("Fold should only be called on non-degenerate MLE");
		}

		let round_message = match &self.round_coeffs_or_sum {
			RoundCoeffsOrSum::Coeffs(round_message) => round_message,
			RoundCoeffsOrSum::Sum(_) => return Err(Error::ExpectedExecute),
		};

		self.round_coeffs_or_sum =
			RoundCoeffsOrSum::Sum(round_message.evaluate(sumcheck_challenge));

		self.round_index += 1;

		Ok(())
	}

	/// Computes the univariate polynomial coefficients for the current round.
	///
	/// This method evaluates the composition polynomial (A * B - C) * D at the
	/// points needed to construct the univariate polynomial that the verifier
	/// will use to check consistency.
	///
	/// # Returns
	///
	/// Returns a vector containing the round coefficients: [g(0), g(1), leading_coefficient]
	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		let (a_low, a_high) = &self.multilinears[0].split_half()?;
		let (b_low, b_high) = &self.multilinears[1].split_half()?;
		let (c_low, _) = &self.multilinears[2].split_half()?;
		let (d_low, d_high) = &self.multilinears[3].split_half()?;

		let (mut g_of_zero, mut g_leading_coeff) = (
			a_low.as_ref(),
			b_low.as_ref(),
			c_low.as_ref(),
			d_low.as_ref(),
			a_high.as_ref(),
			b_high.as_ref(),
			d_high.as_ref(),
		)
			.into_par_iter()
			.map(|(a_low, b_low, c_low, d_low, a_high, b_high, d_high)| {
				let g_of_zero = (*a_low * *b_low - *c_low) * *d_low;
				let g_leading_coeff = (*a_low + *a_high) * (*b_low + *b_high) * (*d_low + *d_high);

				(g_of_zero, g_leading_coeff)
			})
			.reduce(|| (F::ZERO, F::ZERO), |(sum0, sum1), (x0, x1)| (sum0 + x0, sum1 + x1));

		// multiply by eq_factor
		g_of_zero *= self.eq_factor;
		g_leading_coeff *= self.eq_factor;

		let current_round_claim = match &self.round_coeffs_or_sum {
			RoundCoeffsOrSum::Coeffs(_) => return Err(Error::ExpectedFold),
			RoundCoeffsOrSum::Sum(current_round_claim) => current_round_claim,
		};

		// g(1) = current_round_claim - g(0)
		let g_of_one = *current_round_claim - g_of_zero;

		let root_of_g = self.zerocheck_challenges[self.zerocheck_challenge_idx()] + F::ONE;

		// let g = a+bx+cx^2+dx^3, we know a = g_of_zero, d = g_leading_coeff

		let (a, d) = (g_of_zero, g_leading_coeff);

		let b_plus_c = g_of_one - g_of_zero - g_leading_coeff;

		let b_plus_root_times_c =
			g_of_zero * root_of_g.invert_or_zero() + root_of_g.square() * g_leading_coeff;

		let root_plus_one_all_times_c = b_plus_c + b_plus_root_times_c;

		let c = root_plus_one_all_times_c * (root_of_g + F::ONE).invert_or_zero();

		let b = b_plus_c - c;
		// save round message for optimization
		self.round_coeffs_or_sum = RoundCoeffsOrSum::Coeffs(RoundCoeffs(vec![a, b, c, d]));

		Ok(vec![RoundCoeffs(vec![a, b, c, d])])
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		let final_folded_evals = vec![
			self.multilinears[0].get(0)?,
			self.multilinears[1].get(0)?,
			self.multilinears[2].get(0)?,
			self.multilinears[3].get(0)? * self.eq_factor,
		];
		let out = ((final_folded_evals[0] * final_folded_evals[1]) - final_folded_evals[2])
			* final_folded_evals[3];

		let current_round_claim = match &self.round_coeffs_or_sum {
			RoundCoeffsOrSum::Coeffs(_) => return Err(Error::ExpectedFold),
			RoundCoeffsOrSum::Sum(current_round_claim) => current_round_claim,
		};
		assert_eq!(out, *current_round_claim);

		Ok(final_folded_evals)
	}
}

#[cfg(test)]
pub mod test {
	use binius_field::Random;
	use binius_math::{multilinear::{eq::eq_ind, evaluate::evaluate}, test_utils::random_field_buffer};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{config::StdChallenger, fields::B128, protocols::sumcheck::verify};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::protocols::sumcheck::prove_single;

	// sums the composition of 4 multilinears (A * B - C) * D
	pub fn sum_composition<F: Field>(
		a: &FieldBuffer<F>,
		b: &FieldBuffer<F>,
		c: &FieldBuffer<F>,
		d: &FieldBuffer<F>,
	) -> Result<F, Error> {
		let n = 1 << a.log_len();
		let mut sum = F::ZERO;
		for i in 0..n {
			let a_i = a.get(i)?;
			let b_i = b.get(i)?;
			let c_i = c.get(i)?;
			let d_i = d.get(i)?;

			sum += (a_i * b_i - c_i) * d_i;
		}

		Ok(sum)
	}

	/// Sets up and runs the sumcheck protocol for a 4 column composition polynomial (A * B - C) *
	/// eq_r
	#[test]
	fn test_sumcheck_with_transcript() {
		let mut rng = StdRng::from_seed([0; 32]);

		let log_n = 5;

		// zerocheck challenges (polyval)
		let zerocheck_challenges = (0..log_n)
			.map(|_| B128::random(&mut rng))
			.collect::<Vec<B128>>();

		let multilinears: Vec<FieldBuffer<B128>> = (0..3).map(|_|random_field_buffer(&mut rng, log_n)).collect();

		let composition = itertools::izip!(multilinears[0].as_ref(), multilinears[1].as_ref(), multilinears[2].as_ref())
		.map(|(&a, &b,&c)| a*b-c)
		.collect_vec();

		let composition_buffer = FieldBuffer::new(log_n, composition).unwrap();

		// compute overall sum claim for (A * B - C) * eq_r
		let overall_claim = evaluate(&composition_buffer, &zerocheck_challenges).unwrap();

		// create multilinear sumcheck prover
		let prover = AndReductionProver::new(
			multilinears.clone(),
			zerocheck_challenges.clone(),
			overall_claim,
			log_n,
		);

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());

		// run sumcheck
		let prove_output = prove_single(prover, &mut prover_transcript).unwrap();

		let l2h_query_for_evaluation_point = prove_output
			.challenges
			.clone()
			.into_iter()
			.rev()
			.collect_vec();

		prover_transcript
			.message()
			.write_slice(&prove_output.multilinear_evals);

		let mut verifier_transcript = prover_transcript.into_verifier();

		let output = verify(log_n, 3, overall_claim, &mut verifier_transcript).unwrap();

		let verifier_mle_eval_claims = verifier_transcript
			.message()
			.read_scalar_slice::<B128>(4)
			.unwrap();

		for (i, eval) in verifier_mle_eval_claims.iter().enumerate().take(3) {
			assert_eq!(evaluate(&multilinears[i], &l2h_query_for_evaluation_point).unwrap(), *eval);
		}

		assert_eq!(
			verifier_mle_eval_claims[3],
			eq_ind(&l2h_query_for_evaluation_point, &zerocheck_challenges)
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

use std::vec;

use binius_field::Field;
use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};
use binius_utils::rayon::prelude::{
	IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use binius_verifier::protocols::sumcheck::RoundCoeffs;

use crate::protocols::sumcheck::{common::SumcheckProver, error::Error};

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
#[allow(unused)]
pub struct AndReductionProver<F: Field> {
	multilinears: Vec<FieldBuffer<F>>,
	overall_claim: F,
	log_n: usize,
	zerocheck_challenges: Vec<F>,
	round_message: Option<RoundCoeffs<F>>,
	round_index: usize,
	current_round_claim: F,
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
			overall_claim,
			log_n,
			zerocheck_challenges,
			current_round_claim: overall_claim,
			eq_factor: F::ONE,
			round_message: None,
			round_index: 0,
		}
	}

	/// Returns the index of the current zerocheck challenge to use.
	fn zerocheck_challenge_idx(&self) -> usize {
		self.log_n - self.round_index - 1
	}

	/// Returns the current round's claim value.
	pub fn current_round_claim(&self) -> F {
		self.current_round_claim
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
		let n = 1 << self.multilinears[0].log_len();
		let n_half = n >> 1;

		for m in self.multilinears.iter_mut() {
			let mut new_buf = bytemuck::zeroed_vec::<F>(n_half);

			new_buf.par_iter_mut().enumerate().for_each(|(j, elm)| {
				let low_elm = m.get(j).unwrap();
				let high_elm = m.get(j + n_half).unwrap();
				*elm = low_elm + sumcheck_challenge * (high_elm - low_elm);
			});

			*m = FieldBuffer::from_values(&new_buf).unwrap();
		}

		let zerocheck_challenge = self.zerocheck_challenges[self.zerocheck_challenge_idx()];

		let round_message = match self.round_message.clone() {
			Some(round_message) => round_message,
			None => return Err(Error::ExpectedExecute),
		};

		self.current_round_claim = evaluate_round_polynomial_at(
			sumcheck_challenge,
			zerocheck_challenge,
			round_message.0.clone(),
		);

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

		// g(1) = current_round_claim - g(0)
		let g_of_one = self.current_round_claim - g_of_zero;

		// save round message for optimization
		self.round_message = Some(RoundCoeffs(vec![g_of_zero, g_of_one, g_leading_coeff]));

		Ok(vec![self.round_message.clone().unwrap()])
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		Ok(vec![
			self.multilinears[0].get(0)?,
			self.multilinears[1].get(0)?,
			self.multilinears[2].get(0)?,
			self.multilinears[3].get(0)? * self.eq_factor,
		])
	}
}

/// Evaluates a univariate polynomial at a given point from coordinates lagrange basis.
///
/// This function computes the value of the univariate polynomial at a given point
/// using the Lagrange basis polynomials. It uses a leading coefficient optimization
/// to avoid sending all three univariate polynomial coefficients.
fn evaluate_round_polynomial_at<F: Field>(x: F, zerocheck_challenge: F, round_msg: Vec<F>) -> F {
	let _span = tracing::debug_span!("evaluate round polynomial").entered();

	let (x_0, y_0) = (F::ZERO, round_msg[0]);
	let (x_1, y_1) = (F::ONE, round_msg[1]);

	let leading_coeff = round_msg[2];

	// we are only interested in the multilinear composition (A * B - C) * eq_r,
	// we can factor eq_r = eq(x_0, x_1, ..., x_{n-1}, r_0, r_1, ..., r_{n-1})
	// into eq(x_0, r_0) * eq(x_1, .. x_{n-1}, r_1, .. r_{n-1}), of which
	// eq(x_0, r_0) = (1 - x_0)(1 - r_0) + (x_0)(r_0) = 1 - x_0 - r_0 + 2 * (x_0 * r_0)
	// However, because we are in a binary field, 2 * (x_0 * r_0) = 0, so we can simplify to
	// eq(x_0, r_0) = 1 - x_0 - r_0 = x_0 - (r_0 + 1)
	// This reveals to use that there is a root of the polynomial at x = r_0 + 1
	// meaning that the prover does not need to send this value explicitly, rather
	// the verifier can determine this evaluation by inference from the current
	// zerocheck challenge.
	let (x_2, y_2) = (zerocheck_challenge + F::ONE, F::ZERO);

	// lagrange basis polynomials
	let l_0 = ((x - x_1) * (x - x_2)) * ((x_0 - x_1) * (x_0 - x_2)).invert().unwrap();
	let l_1 = ((x - x_0) * (x - x_2)) * ((x_1 - x_0) * (x_1 - x_2)).invert().unwrap();
	let l_2 = ((x - x_0) * (x - x_1)) * ((x_2 - x_0) * (x_2 - x_1)).invert().unwrap();

	let vanishing_poly = (x - x_0) * (x - x_1) * (x - x_2);

	l_0 * y_0 + l_1 * y_1 + l_2 * y_2 + vanishing_poly * leading_coeff
}

/// Verifies the correctness of the round message and claim.
///
/// This function checks that the round message is consistent with the sum claim
/// and that the univariate polynomial is correctly constructed.
pub fn verify_round<F: Field>(
	round_sum_claim: F,
	round_msg: Vec<F>,
	sumcheck_challenge: F,
	zerocheck_challenge: F,
) -> F {
	let _span = tracing::debug_span!("verify round").entered();

	// first two coefficients of round message should match the sum claim
	// these are the evaluations of the univariate polynomial at 0, 1 and
	// (even/odd sum of boolean hypercube evals)
	assert_eq!(round_msg[0] + round_msg[1], round_sum_claim);

	// compute expected next round claim
	evaluate_round_polynomial_at(sumcheck_challenge, zerocheck_challenge, round_msg)
}

#[cfg(test)]
pub mod test {
	use binius_field::{BinaryField128bPolyval, Random};

	use super::*;
	type BF = BinaryField128bPolyval;
	use rand::{SeedableRng, rngs::StdRng};

	fn random_challenge<F: Field>() -> F {
		let mut rng = StdRng::from_seed([0; 32]);
		F::random(&mut rng)
	}

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

	/// Drives the sumcheck interactive protocol for the multilinear composition (A * B - C) * eq_r.
	///
	/// This function runs the sumcheck interactive protocol for the multilinear composition
	/// (A * B - C) * eq_r, where eq_r is the multilinear equality indicator for some vector
	/// of log_n zerocheck challenges.
	///
	/// # Returns
	///
	/// Returns a tuple containing the expected next round claim and the sumcheck challenges
	pub fn multilinear_sumcheck<F: Field>(mut prover: AndReductionProver<F>) -> (F, Vec<F>) {
		let _span = tracing::debug_span!("multilinear_sumcheck").entered();
		let log_n = prover.log_n;

		let mut expected_next_round_claim = prover.overall_claim;
		let mut sumcheck_challenges = Vec::with_capacity(log_n);

		for round_idx in 0..log_n {
			let _span = tracing::debug_span!("multilinear sumcheck round").entered();

			let challenge_idx = log_n - round_idx - 1;

			// verifier sends sumcheck challenge
			let sumcheck_challenge = random_challenge();
			sumcheck_challenges.push(sumcheck_challenge);

			// prover computes round message
			let round_msg = prover.execute().unwrap();

			// verifier checks round message against claim
			expected_next_round_claim = verify_round(
				expected_next_round_claim,
				round_msg[0].0.clone(),
				sumcheck_challenge,
				prover.zerocheck_challenges[challenge_idx],
			);

			let _ = prover.fold(sumcheck_challenge);
		}

		let a = prover.finish().unwrap();
		let out = ((a[0] * a[1]) - a[2]) * a[3];
		assert_eq!(out, expected_next_round_claim);

		(expected_next_round_claim, sumcheck_challenges)
	}

	// generate multiple random multilinears of log_n variables
	pub fn random_field_buffer(num_multilinears: usize, log_n: usize) -> Vec<FieldBuffer<BF>> {
		let mut rng = StdRng::from_seed([0; 32]);

		let n = 1 << log_n;
		let mut multilinears = Vec::with_capacity(num_multilinears);
		for _ in 0..num_multilinears {
			let multilinear = FieldBuffer::from_values(
				&(0..n).map(|_| BF::random(&mut rng)).collect::<Vec<BF>>(),
			)
			.unwrap();

			multilinears.push(multilinear);
		}

		multilinears
	}

	/// Sets up and runs the sumcheck protocol for a 4 column composition polynomial (A * B - C) *
	/// eq_r
	#[test]
	fn test_sumcheck() {
		let mut rng = StdRng::from_seed([0; 32]);

		let log_n = 5;
		let num_multilinears = 3;

		// zerocheck challenges (polyval)
		let zerocheck_challenges = (0..log_n)
			.map(|_| BinaryField128bPolyval::random(&mut rng))
			.collect::<Vec<BF>>();

		let multilinears: Vec<FieldBuffer<BF>> = random_field_buffer(num_multilinears, log_n);

		// eq_r is the multilinear equality indicator for some vector of log_n zerocheck challenges
		let eq_r: FieldBuffer<BF> = eq_ind_partial_eval(&zerocheck_challenges.clone());

		// compute overall sum claim for (A * B - C) * eq_r
		let overall_claim =
			sum_composition(&multilinears[0], &multilinears[1], &multilinears[2], &eq_r).unwrap();

		// create multilinear sumcheck prover
		let prover = AndReductionProver::new(
			multilinears,
			zerocheck_challenges.clone(),
			overall_claim,
			log_n,
		);

		// run sumcheck
		multilinear_sumcheck(prover);
	}

	#[test]
	fn test_composition_even_odd_sum() {
		let log_n = 5;
		let n = 1 << log_n;

		let num_multilinears = 4;

		let multilinears: Vec<FieldBuffer<BF>> = random_field_buffer(num_multilinears, log_n);

		let overall_sum =
			sum_composition(&multilinears[0], &multilinears[1], &multilinears[2], &multilinears[3])
				.unwrap();

		// produce g(0), g(1) by summing over evals where first var is 0, 1
		let mut g_of_zero = BF::ZERO;
		let mut g_of_one = BF::ZERO;
		for j in 0..n {
			let a = multilinears[0].get(j).unwrap();
			let b = multilinears[1].get(j).unwrap();
			let c = multilinears[2].get(j).unwrap();
			let d = multilinears[3].get(j).unwrap();

			if j.is_multiple_of(2) {
				g_of_zero += (a * b - c) * d;
			} else {
				g_of_one += (a * b - c) * d;
			}
		}

		assert_eq!(overall_sum, g_of_zero + g_of_one);
	}
}

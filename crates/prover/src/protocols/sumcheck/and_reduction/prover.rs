use std::vec;

use binius_field::Field;
use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};
use binius_maybe_rayon::prelude::{
	IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
	ParallelSliceMut,
};
use binius_verifier::protocols::sumcheck::RoundCoeffs;
use rand::{SeedableRng, rngs::StdRng};

use crate::protocols::sumcheck::{common::SumcheckProver, error::Error};

#[derive(Debug, Clone)]
pub struct BigFieldMultilinear<F: Field> {
	pub n_vars: usize,
	pub packed_evals: Vec<F>,
}

pub fn mle_to_field_buffer<F: Field>(
	mle: &BigFieldMultilinear<F>,
) -> Result<FieldBuffer<F>, Error> {
	Ok(FieldBuffer::from_values(&mle.packed_evals).unwrap())
}

pub fn field_buffer_to_mle<F: Field>(buf: FieldBuffer<F>) -> Result<BigFieldMultilinear<F>, Error> {
	let mut values = vec![];
	for i in 0..buf.len() {
		values.push(buf.get(i).unwrap());
	}
	Ok(BigFieldMultilinear {
		n_vars: buf.log_len(),
		packed_evals: values,
	})
}

pub enum FoldDirection {
	LowToHigh,
	HighToLow,
}
pub struct AndReductionProver<F: Field> {
	multilinears: Vec<FieldBuffer<F>>,
	overall_claim: F,
	log_n: usize,
	zerocheck_challenges: Vec<F>,
	fold_direction: FoldDirection,
	round_message: Option<RoundCoeffs<F>>,
	round_index: usize,
	current_round_claim: F,
	eq_factor: F,
}

impl<F: Field> AndReductionProver<F> {
	pub fn new(
		multilinears: Vec<FieldBuffer<F>>,
		zerocheck_challenges: Vec<F>,
		overall_claim: F,
		log_n: usize,
		fold_direction: FoldDirection,
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
			fold_direction,
			round_message: None,
			round_index: 0,
		}
	}

	// sums the composition of 4 multilinears (A * B - C) * D
	pub fn sum_composition(
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

	fn zerocheck_challenge_idx(&self) -> usize {
		match self.fold_direction {
			FoldDirection::LowToHigh => self.round_index,
			FoldDirection::HighToLow => self.log_n - self.round_index - 1,
		}
	}
}

impl<F: Field> SumcheckProver<F> for AndReductionProver<F> {
	fn n_vars(&self) -> usize {
		self.multilinears[0].log_len()
	}

	// folds challenge into multilinears
	fn fold(&mut self, sumcheck_challenge: F) -> Result<(), Error> {
		let n = 1 << self.multilinears[0].log_len();
		let n_half = n >> 1;

		match self.fold_direction {
			FoldDirection::LowToHigh => {
				self.multilinears
					.par_iter_mut()
					.enumerate()
					.for_each(|(i, multilinear)| {
						if i < 3 {
							for j in 0..n_half {
								let (low_idx, high_idx) = (2 * j, 2 * j + 1);
								let even = multilinear.get(low_idx).unwrap();
								let odd = multilinear.get(high_idx).unwrap();
								multilinear
									.set(j, even + sumcheck_challenge * (odd - even))
									.unwrap();
							}
						} else {
							for j in 0..n_half {
								let (low_idx, high_idx) = (2 * j, 2 * j + 1);
								let even = multilinear.get(low_idx).unwrap();
								let odd = multilinear.get(high_idx).unwrap();
								multilinear.set(j, even + odd).unwrap();
							}
						}

						// ! replace w/ truncate method once available
						let mut new = vec![];
						for i in 0..n_half {
							new.push(multilinear.get(i).unwrap());
						}

						*multilinear = FieldBuffer::from_values(&new).unwrap();
					});

				// optimization, handle eq differently w/ cheeky factorization
				self.eq_factor *=
					self.zerocheck_challenges[self.round_index] + sumcheck_challenge + F::ONE;
			}
			FoldDirection::HighToLow => {
				for m in self.multilinears.iter_mut() {
					let mut new_buf = bytemuck::zeroed_vec::<F>(n_half);

					new_buf.par_iter_mut().enumerate().for_each(|(j, elm)| {
						let low_elm = m.get(j).unwrap();
						let high_elm = m.get(j + n_half).unwrap();
						*elm = low_elm + sumcheck_challenge * (high_elm - low_elm);
					});

					*m = FieldBuffer::from_values(&new_buf).unwrap();
				}
			}
		}

		let zerocheck_challenge = self.zerocheck_challenges[self.zerocheck_challenge_idx()];

		let round_message = match self.round_message.clone() {
			Some(round_message) => round_message,
			None => todo!(), // error
		};

		self.current_round_claim = evaluate_round_polynomial_at(
			sumcheck_challenge,
			zerocheck_challenge,
			round_message.0.clone(),
		);

		self.round_index += 1;

		Ok(())
	}

	// computes univariate round message for the current round
	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		let log_n = self.multilinears[0].log_len();
		let n = 1 << log_n;
		let n_half = n >> 1;

		let a = &self.multilinears[0];
		let b = &self.multilinears[1];
		let c = &self.multilinears[2];
		let d = &self.multilinears[3];

		// compute indices for either high to low or low to high
		let compute_idx: fn((usize, usize)) -> (usize, usize) = match self.fold_direction {
			FoldDirection::LowToHigh => |(j, _)| (2 * j, 2 * j + 1),
			FoldDirection::HighToLow => |(j, n)| (j, n + j),
		};

		// chunk indices into 1024 chunks
		let (mut g_of_zero, mut g_leading_coeff) = (0..n_half)
			.into_par_iter()
			.chunks(1024)
			.map(|chunk| {
				let mut acc_g_of_zero = F::ZERO;
				let mut acc_g_leading_coeff = F::ZERO;

				for j in chunk {
					let (low_idx, high_idx) = compute_idx((j, n_half));

					let a_lower = a.get(low_idx).expect("out of bounds");
					let b_lower = b.get(low_idx).expect("out of bounds");
					let c_lower = c.get(low_idx).expect("out of bounds");
					let d_lower = d.get(low_idx).expect("out of bounds");

					let a_upper = a.get(high_idx).expect("out of bounds");
					let b_upper = b.get(high_idx).expect("out of bounds");
					let d_upper = d.get(high_idx).expect("out of bounds");

					acc_g_of_zero += (a_lower * b_lower - c_lower) * d_lower;
					acc_g_leading_coeff +=
						(a_lower + a_upper) * (b_lower + b_upper) * (d_lower + d_upper);
				}

				(acc_g_of_zero, acc_g_leading_coeff)
			})
			.reduce(|| (F::ZERO, F::ZERO), |(sum0, sum1), (x0, x1)| (sum0 + x0, sum1 + x1));

		// multiply by eq_factor
		g_of_zero *= self.eq_factor;
		g_leading_coeff *= self.eq_factor;

		// g(1) = current_round_claim - g(0)
		let g_of_one = self.current_round_claim - g_of_zero;

		// save round message for optimization
		self.round_message = Some(RoundCoeffs {
			0: vec![g_of_zero, g_of_one, g_leading_coeff],
		});

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

// since it could let us abstract concepts like rng from the implementation
fn random_challenge<F: Field>() -> F {
	let mut rng = StdRng::from_seed([0; 32]);
	F::random(&mut rng)
}

// given 4 lagrange basis coefficients for a univariate polynomial, compute
// lagrange basis polynomials and evaluate at x the resulting polynomial
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

// verifier checks for correctness of round message and claim
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

// runs sumcheck interactive protocol for multilinear composition (A * B - C) * eq_r
// eq_r is the multilinear equality indicator for some vector of log_n zerocheck challenges
pub fn multilinear_sumcheck<F: Field>(mut prover: AndReductionProver<F>) -> (F, Vec<F>) {
	let _span = tracing::debug_span!("multilinear_sumcheck").entered();
	let log_n = prover.log_n;

	let mut expected_next_round_claim = prover.overall_claim;
	let mut sumcheck_challenges = Vec::with_capacity(log_n);

	for round_idx in 0..log_n {
		let _span = tracing::debug_span!("multilinear sumcheck round").entered();

		let challenge_idx = match prover.fold_direction {
			FoldDirection::LowToHigh => round_idx,
			FoldDirection::HighToLow => log_n - round_idx - 1,
		};

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

#[cfg(test)]
pub mod test {
	use binius_field::{AESTowerField128b, BinaryField128bPolyval, Random};

	use super::*;
	type BF = BinaryField128bPolyval;

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

	// runs sumcheck protocol for a 4 column composition polynomial (A * B - C) * eq_r
	// tests both high to low and low to high fold directions
	fn sumcheck_four_column(fold_direction: FoldDirection) {
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
		let overall_claim = AndReductionProver::<BF>::sum_composition(
			&multilinears[0],
			&multilinears[1],
			&multilinears[2],
			&eq_r,
		)
		.unwrap();

		// create multilinear sumcheck prover
		let mut prover = AndReductionProver::new(
			multilinears,
			zerocheck_challenges.clone(),
			overall_claim,
			log_n,
			fold_direction,
		);

		// run sumcheck
		multilinear_sumcheck(prover);
	}

	#[test]
	fn test_and_reduction_sumcheck_high_to_low() {
		sumcheck_four_column(FoldDirection::HighToLow);
	}

	#[test]
	fn test_and_reduction_sumcheck_low_to_high() {
		sumcheck_four_column(FoldDirection::LowToHigh);
	}

	#[test]
	fn test_composition_even_odd_sum() {
		let log_n = 5;
		let n = 1 << log_n;

		let num_multilinears = 4;

		let multilinears: Vec<FieldBuffer<BF>> = random_field_buffer(num_multilinears, log_n);

		let overall_sum = AndReductionProver::sum_composition(
			&multilinears[0],
			&multilinears[1],
			&multilinears[2],
			&multilinears[3],
		)
		.unwrap();

		// produce g(0), g(1) by summing over evals where first var is 0, 1
		let mut g_of_zero = BF::ZERO;
		let mut g_of_one = BF::ZERO;
		for j in 0..n {
			let a = multilinears[0].get(j).unwrap();
			let b = multilinears[1].get(j).unwrap();
			let c = multilinears[2].get(j).unwrap();
			let d = multilinears[3].get(j).unwrap();

			if j % 2 == 0 {
				g_of_zero += (a * b - c) * d;
			} else {
				g_of_one += (a * b - c) * d;
			}
		}

		assert_eq!(overall_sum, g_of_zero + g_of_one);
	}
}

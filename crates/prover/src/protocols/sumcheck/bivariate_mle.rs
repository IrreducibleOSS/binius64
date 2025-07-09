// Copyright 2023-2025 Irreducible Inc.

#![allow(dead_code)]

use std::{cmp::max, ops::Add};

use binius_field::{Field, PackedField};
use binius_math::{
	FieldBuffer,
	multilinear::{
		eq::{eq_ind_partial_eval, eq_ind_truncate_low_inplace, eq_one_var},
		fold::fold_highest_var_inplace,
	},
};
use binius_maybe_rayon::prelude::*;
use binius_verifier::protocols::sumcheck::{EvaluationOrder, RoundCoeffs};
use itertools::{Itertools, izip};

use super::{common::SumcheckProver, error::Error};

type FieldBufferPair<P> = (FieldBuffer<P>, FieldBuffer<P>);

enum RoundCoeffsOrSums<F: Field> {
	Coeffs(Vec<RoundCoeffs<F>>),
	Sums(Vec<F>),
}

pub struct BivariateMlecheckProver<P: PackedField> {
	n_vars: usize,
	n_rounds_remaining: usize,
	multilinears: Vec<FieldBuffer<P>>,
	last_coeffs_or_sums: RoundCoeffsOrSums<P::Scalar>,
	eval_point: Vec<P::Scalar>,
	eq_expansion: FieldBuffer<P>,
	eq_prefix_eval: P::Scalar,
}

impl<F: Field, P: PackedField<Scalar = F>> BivariateMlecheckProver<P> {
	pub fn new(
		multilinears: Vec<FieldBufferPair<P>>,
		eval_point: &[F],
		eval_claims: &[F],
	) -> Result<Self, Error> {
		let n_vars = eval_point.len();

		if multilinears
			.iter()
			.flat_map(|(l, r)| [l, r])
			.any(|multilinear| multilinear.log_len() != n_vars)
		{
			return Err(Error::MultilinearSizeMismatch);
		}

		if multilinears.len() != eval_claims.len() {
			return Err(Error::EvalClaimsNumberMismatch);
		}

		let multilinears = multilinears
			.into_iter()
			.flat_map(|(l, r)| [l, r])
			.collect_vec();
		let eq_expansion = eq_ind_partial_eval(&eval_point[..n_vars.saturating_sub(1)]);
		let last_coeffs_or_sums = RoundCoeffsOrSums::Sums(eval_claims.to_vec());

		Ok(Self {
			n_vars,
			n_rounds_remaining: n_vars,
			multilinears,
			last_coeffs_or_sums,
			eval_point: eval_point.to_vec(),
			eq_expansion,
			eq_prefix_eval: F::ONE,
		})
	}
}

#[derive(Clone, Debug, Default)]
struct RoundEvals<P: PackedField> {
	one: P,
	inf: P,
}

impl<P: PackedField> RoundEvals<P> {
	fn sum_scalars(self, log_len: usize) -> RoundEvals<P::Scalar> {
		RoundEvals {
			one: self.one.iter().take(1 << log_len).sum(),
			inf: self.inf.iter().take(1 << log_len).sum(),
		}
	}
}

impl<F: Field> RoundEvals<F> {
	fn interpolate(self, sum: F, alpha: F) -> RoundCoeffs<F> {
		let zero = (sum - self.one * alpha) * (F::ONE - alpha).invert_or_zero();
		RoundCoeffs(vec![zero, self.one - zero - self.inf, self.inf])
	}
}

impl<P: PackedField> Add<&Self> for RoundEvals<P> {
	type Output = Self;

	fn add(mut self, rhs: &Self) -> Self::Output {
		self.one += rhs.one;
		self.inf += rhs.inf;
		self
	}
}

impl<F, P> SumcheckProver<F> for BivariateMlecheckProver<P>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	fn n_vars(&self) -> usize {
		self.n_vars
	}

	fn evaluation_order(&self) -> EvaluationOrder {
		EvaluationOrder::HighToLow
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		if self.n_rounds_remaining == 0 {
			return Err(Error::ExpectedFinish);
		}

		let RoundCoeffsOrSums::Sums(sums) = &self.last_coeffs_or_sums else {
			return Err(Error::ExpectedFold);
		};

		const MAX_CHUNK_VARS: usize = 12;
		let chunk_vars = max(MAX_CHUNK_VARS, P::LOG_WIDTH).min(self.n_rounds_remaining - 1);

		let multilinear_prefixes = self.multilinears.iter().map(|multilinear| {
			multilinear
				.chunk(self.n_rounds_remaining, 0)
				.expect("n_rounds_remaining <= multilinear.log_len()")
		});

		let packed_prime_evals = (0..1 << (self.n_rounds_remaining - 1 - chunk_vars))
			.into_par_iter()
			.try_fold(
				|| vec![RoundEvals::default(); sums.len()],
				|mut packed_prime_evals: Vec<RoundEvals<P>>, chunk_index| -> Result<_, Error> {
					let eq = self.eq_expansion.chunk(chunk_vars, chunk_index)?;

					for (round_evals, (l, r)) in
						izip!(&mut packed_prime_evals, multilinear_prefixes.clone().tuples())
					{
						let (l_zero, l_one) = l.split_half()?;
						let (r_zero, r_one) = r.split_half()?;

						let l_zero = l_zero.chunk(chunk_vars, chunk_index)?;
						let r_zero = r_zero.chunk(chunk_vars, chunk_index)?;
						let l_one = l_one.chunk(chunk_vars, chunk_index)?;
						let r_one = r_one.chunk(chunk_vars, chunk_index)?;

						for (&eq, &l_zero, &r_zero, &l_one, &r_one) in izip!(
							eq.as_ref(),
							l_zero.as_ref(),
							r_zero.as_ref(),
							l_one.as_ref(),
							r_one.as_ref()
						) {
							round_evals.one += eq * l_one * r_one;
							round_evals.inf += eq * (l_zero + l_one) * (r_zero + r_one);
						}
					}

					Ok(packed_prime_evals)
				},
			)
			.try_reduce(
				|| vec![RoundEvals::default(); sums.len()],
				|lhs, rhs| Ok(izip!(lhs, rhs).map(|(l, r)| l + &r).collect()),
			)?;

		let prime_evals = packed_prime_evals
			.into_iter()
			.map(|evals| evals.sum_scalars(self.n_rounds_remaining - 1));

		let alpha = self.eval_point[self.n_rounds_remaining - 1];

		let prime_coeffs = izip!(sums, prime_evals)
			.map(|(&sum, evals)| evals.interpolate(sum, alpha))
			.collect_vec();

		let round_coeffs = prime_coeffs
			.iter()
			.map(|prime| {
				// eq(X, α) = (1 − α) + (2 α − 1) X
				// NB: In binary fields, this expression can be simplified to 1 + α + challenge.
				let (prime_by_constant_term, mut prime_by_linear_term) = if F::CHARACTERISTIC == 2 {
					(prime.clone() * (F::ONE + alpha), prime.clone())
				} else {
					(prime.clone() * (F::ONE - alpha), prime.clone() * (alpha.double() - F::ONE))
				};

				prime_by_linear_term.0.insert(0, F::ZERO); // Multiply prime polynomial by X
				(prime_by_constant_term + &prime_by_linear_term) * self.eq_prefix_eval
			})
			.collect();

		self.last_coeffs_or_sums = RoundCoeffsOrSums::Coeffs(prime_coeffs);
		Ok(round_coeffs)
	}

	fn fold(&mut self, challenge: F) -> Result<(), Error> {
		if self.n_rounds_remaining == 0 {
			return Err(Error::ExpectedFinish);
		}

		let RoundCoeffsOrSums::Coeffs(prime_coeffs) = &self.last_coeffs_or_sums else {
			return Err(Error::ExpectedExecute);
		};

		let sums = prime_coeffs
			.iter()
			.map(|coeffs| coeffs.evaluate(challenge))
			.collect();

		for multilinear in &mut self.multilinears {
			fold_highest_var_inplace(self.n_rounds_remaining, multilinear, challenge)?;
		}

		if self.n_rounds_remaining > 1 {
			eq_ind_truncate_low_inplace(
				self.n_rounds_remaining - 1,
				&mut self.eq_expansion,
				self.n_rounds_remaining - 2,
			)?;
		}

		let alpha = self.eval_point[self.n_rounds_remaining - 1];
		self.eq_prefix_eval *= eq_one_var(challenge, alpha);

		self.last_coeffs_or_sums = RoundCoeffsOrSums::Sums(sums);
		self.n_rounds_remaining -= 1;
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		if self.n_rounds_remaining > 0 {
			let error = match self.last_coeffs_or_sums {
				RoundCoeffsOrSums::Coeffs(_) => Error::ExpectedFold,
				RoundCoeffsOrSums::Sums(_) => Error::ExpectedExecute,
			};

			return Err(error);
		}

		let multilinear_evals = self
			.multilinears
			.into_iter()
			.map(|multilinear| multilinear.get(0).expect("multilinear.len()==1"))
			.collect();

		Ok(multilinear_evals)
	}
}

#[cfg(test)]
mod tests {
	use std::iter::repeat_with;

	use binius_field::PackedBinaryField8x16b;
	use binius_math::test_utils::random_scalars;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	fn test_bivariate_mlecheck_consistency_helper<F: Field, P: PackedField<Scalar = F>>(
		n_vars: usize,
		n_pairs: usize,
	) {
		// Bivariate product multiplied by equality indicator
		let degree = 3;
		let mut rng = StdRng::seed_from_u64(0);

		// Validate round polynomials by evaluating them at degree + 1 random points
		let samples = random_scalars::<F>(&mut rng, degree + 1);

		// Claim eval point
		let eval_point = random_scalars::<F>(&mut rng, n_vars);

		// A copy of 2 * n_pairs + 1 multilinears for reference logic
		let mut folded_multilinears = repeat_with(|| {
			let scalars = random_scalars::<F>(&mut rng, 1 << n_vars);
			FieldBuffer::<P>::from_values(&scalars).unwrap()
		})
		.take(n_pairs * 2)
		.collect_vec();

		// Witness copy for the prover
		let multilinears = folded_multilinears.iter().cloned().tuples().collect_vec();

		// Compute MLE of the product
		let eq_ind = eq_ind_partial_eval::<P>(&eval_point);
		let eval_claims = multilinears
			.iter()
			.map(|(l, r)| {
				izip!(eq_ind.as_ref(), l.as_ref(), r.as_ref())
					.map(|(&eq, &l, &r)| eq * l * r)
					.sum::<P>()
					.iter()
					.sum::<F>()
			})
			.collect_vec();

		let mut prover =
			BivariateMlecheckProver::new(multilinears, &eval_point, &eval_claims).unwrap();

		// Append eq indicator at the end
		folded_multilinears.push(eq_ind);

		for n_rounds_remaining in (1..=n_vars).rev() {
			// Round polynomials from the prover
			let coeffs = prover.execute().unwrap();

			// Sample the witness at different points
			for &sample in &samples {
				let sample_broadcast = P::broadcast(sample);
				let lerps = folded_multilinears
					.iter()
					.map(|multilinear| {
						let prefix = multilinear.chunk(n_rounds_remaining, 0).unwrap();
						let (zero, one) = prefix.split_half().unwrap();
						izip!(zero.as_ref(), one.as_ref())
							.map(|(&zero, &one)| zero + (one - zero) * sample_broadcast)
							.collect_vec()
					})
					.collect_vec();

				assert_eq!(lerps.len(), 2 * n_pairs + 1);
				let (eq_ind, pairs) = lerps.split_last().unwrap();

				for ((l, r), coeffs) in izip!(pairs.iter().tuples(), &coeffs) {
					assert_eq!(coeffs.0.len(), degree + 1);
					let eval = izip!(eq_ind, l, r)
						.map(|(&eq, &l, &r)| eq * l * r)
						.sum::<P>()
						.iter()
						.sum::<F>();
					assert_eq!(eval, coeffs.evaluate(sample));
				}
			}

			let challenge = F::random(&mut rng);
			prover.fold(challenge).unwrap();

			for folded in &mut folded_multilinears {
				fold_highest_var_inplace(n_rounds_remaining, folded, challenge).unwrap();
			}
		}

		let multilinear_evals = prover.finish().unwrap();
		assert_eq!(multilinear_evals.len(), n_pairs * 2);
	}

	#[test]
	fn test_bivariate_mlecheck_consistency() {
		for n_vars in 0..=7 {
			for n_pairs in 0..=3 {
				test_bivariate_mlecheck_consistency_helper::<_, PackedBinaryField8x16b>(
					n_vars, n_pairs,
				);
			}
		}
	}
}

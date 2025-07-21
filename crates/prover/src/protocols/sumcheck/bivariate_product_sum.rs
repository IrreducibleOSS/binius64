// Copyright 2023-2025 Irreducible Inc.

#![allow(dead_code)]

use std::cmp::max;

use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, multilinear::fold::fold_highest_var_inplace};
use binius_utils::rayon::prelude::*;
use binius_verifier::protocols::sumcheck::RoundCoeffs;
use itertools::{Itertools, izip};

use super::{common::SumcheckProver, error::Error, round_evals::RoundEvals2};

type FieldBufferPair<P> = (FieldBuffer<P>, FieldBuffer<P>);

enum RoundCoeffsOrSum<F: Field> {
	Coeffs(RoundCoeffs<F>),
	Sum(F),
}

pub struct BivariateProductProver<P: PackedField> {
	n_vars: usize,
	n_rounds_remaining: usize,
	multilinears: Vec<FieldBuffer<P>>,
	last_coeffs_or_sum: RoundCoeffsOrSum<P::Scalar>,
}

impl<F: Field, P: PackedField<Scalar = F>> BivariateProductProver<P> {
	pub fn new(
		n_vars: usize,
		multilinears: Vec<FieldBufferPair<P>>,
		sum: F,
	) -> Result<Self, Error> {
		if multilinears
			.iter()
			.flat_map(|(l, r)| [l, r])
			.any(|multilinear| multilinear.log_len() != n_vars)
		{
			return Err(Error::MultilinearSizeMismatch);
		}

		let multilinears = multilinears
			.into_iter()
			.flat_map(|(l, r)| [l, r])
			.collect_vec();
		let last_coeffs_or_sum = RoundCoeffsOrSum::Sum(sum);

		Ok(Self {
			n_vars,
			n_rounds_remaining: n_vars,
			multilinears,
			last_coeffs_or_sum,
		})
	}
}

impl<F, P> SumcheckProver<F> for BivariateProductProver<P>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	fn n_vars(&self) -> usize {
		self.n_vars
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		if self.n_rounds_remaining == 0 {
			return Err(Error::ExpectedFinish);
		}

		let RoundCoeffsOrSum::Sum(sum) = &self.last_coeffs_or_sum else {
			return Err(Error::ExpectedFold);
		};

		const MAX_CHUNK_VARS: usize = 12;
		let chunk_vars = max(MAX_CHUNK_VARS, P::LOG_WIDTH).min(self.n_rounds_remaining - 1);

		let evals = (0..1 << (self.n_rounds_remaining - 1 - chunk_vars))
			.into_par_iter()
			.try_fold(
				RoundEvals2::default,
				|mut packed_evals: RoundEvals2<P>, chunk_index| -> Result<_, Error> {
					for (l, r) in self.multilinears.iter().tuples() {
						let (l_zero, l_one) = l.split_half()?;
						let (r_zero, r_one) = r.split_half()?;

						let l_zero = l_zero.chunk(chunk_vars, chunk_index)?;
						let r_zero = r_zero.chunk(chunk_vars, chunk_index)?;
						let l_one = l_one.chunk(chunk_vars, chunk_index)?;
						let r_one = r_one.chunk(chunk_vars, chunk_index)?;

						for (&l_zero, &r_zero, &l_one, &r_one) in
							izip!(l_zero.as_ref(), r_zero.as_ref(), l_one.as_ref(), r_one.as_ref())
						{
							packed_evals.one += l_one * r_one;
							packed_evals.inf += (l_zero + l_one) * (r_zero + r_one);
						}
					}

					Ok(packed_evals)
				},
			)
			.try_reduce(RoundEvals2::default, |lhs, rhs| Ok(lhs + &rhs))?;

		let evals = evals.sum_scalars(self.n_rounds_remaining - 1);

		// w.h.p sum != 0; to sacrifice completeness and not soundness, if sum = 0 we set alpha = 0
		let alpha = evals.one * sum.invert_or_zero();
		let coeffs = evals.interpolate(*sum, alpha);

		self.last_coeffs_or_sum = RoundCoeffsOrSum::Coeffs(coeffs.clone());

		Ok(vec![coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), Error> {
		if self.n_rounds_remaining == 0 {
			return Err(Error::ExpectedFinish);
		}

		let RoundCoeffsOrSum::Coeffs(prime_coeffs) = &self.last_coeffs_or_sum else {
			return Err(Error::ExpectedExecute);
		};

		let sum = prime_coeffs.evaluate(challenge);

		for multilinear in &mut self.multilinears {
			fold_highest_var_inplace(multilinear, challenge)?;
		}

		self.last_coeffs_or_sum = RoundCoeffsOrSum::Sum(sum);
		self.n_rounds_remaining -= 1;
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		if self.n_rounds_remaining > 0 {
			let error = match self.last_coeffs_or_sum {
				RoundCoeffsOrSum::Coeffs(_) => Error::ExpectedFold,
				RoundCoeffsOrSum::Sum(_) => Error::ExpectedExecute,
			};

			return Err(error);
		}

		let multilinear_evals = self
			.multilinears
			.into_iter()
			.map(|multilinear| multilinear.get(0).expect("multilinear.len() == 1"))
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

		// A copy of 2 * n_pairs + 1 multilinears for reference logic
		let mut folded_multilinears = repeat_with(|| {
			let scalars = random_scalars::<F>(&mut rng, 1 << n_vars);
			FieldBuffer::<P>::from_values(&scalars).unwrap()
		})
		.take(n_pairs * 2)
		.collect_vec();

		// Witness copy for the prover
		let multilinears = folded_multilinears.iter().cloned().tuples().collect_vec();
		assert_eq!(multilinears.len(), n_pairs);

		// Compute MLE of the product
		let claim = multilinears
			.iter()
			.map(|(l, r)| {
				izip!(l.as_ref(), r.as_ref())
					.map(|(&l, &r)| l * r)
					.sum::<P>()
					.iter()
					.sum::<F>()
			})
			.sum();

		let mut prover = BivariateProductProver::new(n_vars, multilinears, claim).unwrap();

		for n_rounds_remaining in (1..=n_vars).rev() {
			// Round polynomials from the prover
			let mut coeffs = prover.execute().unwrap();
			assert_eq!(coeffs.len(), 1);
			let coeffs = coeffs.pop().unwrap();

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

				assert_eq!(lerps.len(), 2 * n_pairs);

				let mut sum = F::zero();
				for (l, r) in lerps.iter().tuples() {
					sum += izip!(l, r)
						.map(|(&l, &r)| l * r)
						.sum::<P>()
						.iter()
						.sum::<F>();
				}
				assert_eq!(sum, coeffs.evaluate(sample));
			}

			let challenge = F::random(&mut rng);
			prover.fold(challenge).unwrap();

			for folded in &mut folded_multilinears {
				fold_highest_var_inplace(folded, challenge).unwrap();
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

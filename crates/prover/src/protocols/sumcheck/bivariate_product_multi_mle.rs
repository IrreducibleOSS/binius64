// Copyright 2023-2025 Irreducible Inc.

#![allow(dead_code)]

use std::cmp::max;

use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, multilinear::fold::fold_highest_var_inplace};
use binius_utils::rayon::prelude::*;
use binius_verifier::protocols::sumcheck::RoundCoeffs;
use itertools::{Itertools, izip};

use super::{common::SumcheckProver, error::Error, gruen34::Gruen34, round_evals::RoundEvals2};

enum RoundCoeffsOrSums<F: Field> {
	Coeffs(Vec<RoundCoeffs<F>>),
	Sums(Vec<F>),
}

pub struct BivariateProductMultiMlecheckProver<P: PackedField> {
	n_vars: usize,
	multilinears: Vec<FieldBuffer<P>>,
	last_coeffs_or_sums: RoundCoeffsOrSums<P::Scalar>,
	gruen34: Gruen34<P>,
}

impl<F: Field, P: PackedField<Scalar = F>> BivariateProductMultiMlecheckProver<P> {
	pub fn new(
		multilinears: Vec<[FieldBuffer<P>; 2]>,
		eval_point: &[F],
		eval_claims: &[F],
	) -> Result<Self, Error> {
		let n_vars = eval_point.len();

		if multilinears
			.iter()
			.flatten()
			.any(|multilinear| multilinear.log_len() != n_vars)
		{
			return Err(Error::MultilinearSizeMismatch);
		}

		if multilinears.len() != eval_claims.len() {
			return Err(Error::EvalClaimsNumberMismatch);
		}

		let multilinears = multilinears.into_iter().flatten().collect_vec();
		let last_coeffs_or_sums = RoundCoeffsOrSums::Sums(eval_claims.to_vec());

		let gruen34 = Gruen34::new(eval_point);

		Ok(Self {
			n_vars,
			multilinears,
			last_coeffs_or_sums,
			gruen34,
		})
	}
}

impl<F, P> SumcheckProver<F> for BivariateProductMultiMlecheckProver<P>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	fn n_vars(&self) -> usize {
		self.gruen34.n_vars_remaining()
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		let RoundCoeffsOrSums::Sums(sums) = &self.last_coeffs_or_sums else {
			return Err(Error::ExpectedFold);
		};

		assert!(self.n_vars() > 0);

		const MAX_CHUNK_VARS: usize = 12;
		let chunk_vars = max(MAX_CHUNK_VARS, P::LOG_WIDTH).min(self.n_vars() - 1);

		let packed_prime_evals = (0..1 << (self.n_vars() - 1 - chunk_vars))
			.into_par_iter()
			.try_fold(
				|| vec![RoundEvals2::default(); sums.len()],
				|mut packed_prime_evals: Vec<RoundEvals2<P>>, chunk_index| -> Result<_, Error> {
					let eq = self.gruen34.eq_expansion().chunk(chunk_vars, chunk_index)?;

					for (round_evals, (evals_a, evals_b)) in
						izip!(&mut packed_prime_evals, self.multilinears.iter().tuples())
					{
						let (evals_a_0, evals_a_1) = evals_a.split_half()?;
						let (evals_b_0, evals_b_1) = evals_b.split_half()?;

						let evals_a_0 = evals_a_0.chunk(chunk_vars, chunk_index)?;
						let evals_b_0 = evals_b_0.chunk(chunk_vars, chunk_index)?;
						let evals_a_1 = evals_a_1.chunk(chunk_vars, chunk_index)?;
						let evals_b_1 = evals_b_1.chunk(chunk_vars, chunk_index)?;

						for (&eq, &evals_a_0_i, &evals_b_0_i, &evals_a_1_i, &evals_b_1_i) in izip!(
							eq.as_ref(),
							evals_a_0.as_ref(),
							evals_b_0.as_ref(),
							evals_a_1.as_ref(),
							evals_b_1.as_ref()
						) {
							let evals_a_inf_i = evals_a_0_i + evals_a_1_i;
							let evals_b_inf_i = evals_b_0_i + evals_b_1_i;

							round_evals.y_1 += eq * evals_a_1_i * evals_b_1_i;
							round_evals.y_inf += eq * evals_a_inf_i * evals_b_inf_i;
						}
					}

					Ok(packed_prime_evals)
				},
			)
			.try_reduce(
				|| vec![RoundEvals2::default(); sums.len()],
				|lhs, rhs| Ok(izip!(lhs, rhs).map(|(l, r)| l + &r).collect()),
			)?;

		let (prime_coeffs, round_coeffs) = izip!(sums, packed_prime_evals)
			.map(|(&sum, evals)| self.gruen34.interpolate2(sum, evals.sum_scalars()))
			.unzip::<_, _, Vec<_>, Vec<_>>();

		self.last_coeffs_or_sums = RoundCoeffsOrSums::Coeffs(prime_coeffs);
		Ok(round_coeffs)
	}

	fn fold(&mut self, challenge: F) -> Result<(), Error> {
		let RoundCoeffsOrSums::Coeffs(prime_coeffs) = &self.last_coeffs_or_sums else {
			return Err(Error::ExpectedExecute);
		};

		assert!(self.n_vars() > 0);

		let sums = prime_coeffs
			.iter()
			.map(|coeffs| coeffs.evaluate(challenge))
			.collect();

		for multilinear in &mut self.multilinears {
			fold_highest_var_inplace(multilinear, challenge)?;
		}

		self.gruen34.fold(challenge)?;
		self.last_coeffs_or_sums = RoundCoeffsOrSums::Sums(sums);
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		if self.n_vars() > 0 {
			let error = match self.last_coeffs_or_sums {
				RoundCoeffsOrSums::Coeffs(_) => Error::ExpectedFold,
				RoundCoeffsOrSums::Sums(_) => Error::ExpectedExecute,
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
	use binius_math::{
		multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate_inplace},
		test_utils::{random_field_buffer, random_scalars},
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	fn test_bivariate_product_multi_mlecheck_consistency_helper<
		F: Field,
		P: PackedField<Scalar = F>,
	>(
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
		let mut folded_multilinears = repeat_with(|| random_field_buffer::<P>(&mut rng, n_vars))
			.take(n_pairs * 2)
			.collect_vec();

		// Witness copy for the prover
		let (pairs, remainder) = folded_multilinears.as_chunks::<2>();
		assert_eq!(remainder.len(), 0);

		let multilinears = pairs.iter().cloned().collect_vec();

		// Compute MLE of the product
		let eval_claims = multilinears
			.iter()
			.map(|[l, r]| {
				let product = itertools::zip_eq(l.as_ref(), r.as_ref())
					.map(|(&l, &r)| l * r)
					.collect_vec();
				let product_buffer = FieldBuffer::new(n_vars, product).unwrap();
				evaluate_inplace(product_buffer, &eval_point).unwrap()
			})
			.collect_vec();

		let mut prover =
			BivariateProductMultiMlecheckProver::new(multilinears, &eval_point, &eval_claims)
				.unwrap();

		// Append eq indicator at the end
		folded_multilinears.push(eq_ind_partial_eval(&eval_point));

		for n_vars_remaining in (1..=n_vars).rev() {
			// Round polynomials from the prover
			let coeffs = prover.execute().unwrap();

			// Sample the witness at different points
			for &sample in &samples {
				let sample_broadcast = P::broadcast(sample);
				let lerps = folded_multilinears
					.iter()
					.map(|multilinear| {
						let (evals_0, evals_1) = multilinear.split_half().unwrap();
						izip!(evals_0.as_ref(), evals_1.as_ref())
							.map(|(&eval_0, &eval_1)| eval_0 + (eval_1 - eval_0) * sample_broadcast)
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
						.take(1 << n_vars_remaining)
						.sum::<F>();
					assert_eq!(eval, coeffs.evaluate(sample));
				}
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
	fn test_bivariate_product_multi_mlecheck_consistency() {
		for (n_vars, n_pairs) in [(0, 0), (0, 4), (1, 5), (7, 1), (3, 3)] {
			test_bivariate_product_multi_mlecheck_consistency_helper::<_, PackedBinaryField8x16b>(
				n_vars, n_pairs,
			);
		}
	}
}

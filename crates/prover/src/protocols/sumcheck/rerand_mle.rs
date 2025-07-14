// Copyright 2025 Irreducible Inc.

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
use binius_verifier::protocols::sumcheck::RoundCoeffs;
use itertools::{Itertools, izip};

use super::{common::SumcheckProver, error::Error};

enum RoundCoeffsOrSums<F: Field> {
	Coeffs(Vec<RoundCoeffs<F>>),
	Sums(Vec<F>),
}

pub struct RerandMlecheckProver<P: PackedField> {
	n_vars: usize,
	n_rounds_remaining: usize,
	multilinears: Vec<FieldBuffer<P>>,
	last_coeffs_or_sums: RoundCoeffsOrSums<P::Scalar>,
	eval_point: Vec<P::Scalar>,
	eq_expansion: FieldBuffer<P>,
	eq_prefix_eval: P::Scalar,
}

impl<F: Field, P: PackedField<Scalar = F>> RerandMlecheckProver<P> {
	pub fn new(
		multilinears: Vec<FieldBuffer<P>>,
		eval_point: &[F],
		eval_claims: &[F],
	) -> Result<Self, Error> {
		let n_vars = eval_point.len();

		if multilinears
			.iter()
			.any(|multilinear| multilinear.log_len() != n_vars)
		{
			return Err(Error::MultilinearSizeMismatch);
		}

		if multilinears.len() != eval_claims.len() {
			return Err(Error::EvalClaimsNumberMismatch);
		}

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
}

impl<P: PackedField> RoundEvals<P> {
	fn sum_scalars(self, log_len: usize) -> RoundEvals<P::Scalar> {
		RoundEvals {
			one: self.one.iter().take(1 << log_len).sum(),
		}
	}
}

impl<F: Field> RoundEvals<F> {
	fn interpolate(self, sum: F, alpha: F) -> RoundCoeffs<F> {
		let zero = (sum - self.one * alpha) * (F::ONE - alpha).invert_or_zero();
		RoundCoeffs(vec![zero, self.one])
	}
}

impl<P: PackedField> Add<&Self> for RoundEvals<P> {
	type Output = Self;

	fn add(mut self, rhs: &Self) -> Self::Output {
		self.one += rhs.one;
		self
	}
}

impl<F, P> SumcheckProver<F> for RerandMlecheckProver<P>
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

					for (round_evals, multilinear) in
						izip!(&mut packed_prime_evals, multilinear_prefixes.clone())
					{
						let (_, one) = multilinear.split_half()?;
						let one = one.chunk(chunk_vars, chunk_index)?;

						for (&eq, &one) in izip!(eq.as_ref(), one.as_ref()) {
							round_evals.one += eq * one;
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

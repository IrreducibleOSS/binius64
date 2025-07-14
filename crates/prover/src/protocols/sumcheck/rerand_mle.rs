// Copyright 2025 Irreducible Inc.

#![allow(dead_code)]

use std::cmp::max;

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

use super::{
	common::SumcheckProver,
	error::Error,
	round_evals::{RoundEvals1, round_coeffs_by_eq},
};

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

		let packed_prime_evals = (0..1 << (self.n_rounds_remaining - 1 - chunk_vars))
			.into_par_iter()
			.try_fold(
				|| vec![RoundEvals1::default(); sums.len()],
				|mut packed_prime_evals: Vec<RoundEvals1<P>>, chunk_index| -> Result<_, Error> {
					let eq = self.eq_expansion.chunk(chunk_vars, chunk_index)?;

					for (round_evals, multilinear) in
						izip!(&mut packed_prime_evals, &self.multilinears)
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
				|| vec![RoundEvals1::default(); sums.len()],
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
			.map(|prime| round_coeffs_by_eq(prime, alpha) * self.eq_prefix_eval)
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
			fold_highest_var_inplace(multilinear, challenge)?;
		}

		if self.n_rounds_remaining > 1 {
			debug_assert_eq!(self.eq_expansion.log_len(), self.n_rounds_remaining - 1);
			eq_ind_truncate_low_inplace(&mut self.eq_expansion, self.n_rounds_remaining - 2)?;
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

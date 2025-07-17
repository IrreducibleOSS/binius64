// Copyright 2023-2025 Irreducible Inc.

#![allow(dead_code)]

use std::{
	cmp::max,
	ops::{Add, BitAnd, Shr},
};

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
use itertools::izip;
use trait_set::trait_set;

use super::{common::SumcheckProver, error::Error};

trait_set! {
	pub trait Bitwise = BitAnd<Output=Self> + Shr<usize, Output=Self> + From<u8> + PartialEq<Self> + Sized + Sync + Copy;
}

pub struct Claim<F: Field> {
	point: Vec<F>,
	value: F,
}

enum RoundCoeffsOrSums<F: Field> {
	Coeffs(Vec<RoundCoeffs<F>>),
	Sums(Vec<F>),
}

struct Selector<P: PackedField> {
	eq_expansion: FieldBuffer<P>,
	eq_prefix_eval: P::Scalar,
	point: Vec<P::Scalar>,
	folded: Option<FieldBuffer<P>>,
}

pub struct SelectorMlecheckProver<'b, P: PackedField, B: Bitwise> {
	n_vars: usize,
	n_rounds_remaining: usize,
	last_coeffs_or_sums: RoundCoeffsOrSums<P::Scalar>,
	selected: FieldBuffer<P>,
	selectors: Vec<Selector<P>>,
	bitmasks: &'b [B],
	// TODO: actually implement the logic
	switchover: usize,
}

impl<'b, F: Field, P: PackedField<Scalar = F>, B: Bitwise> SelectorMlecheckProver<'b, P, B> {
	pub fn new(
		selected: FieldBuffer<P>,
		claims: Vec<Claim<F>>,
		bitmasks: &'b [B],
		switchover: usize,
	) -> Result<Self, Error> {
		let n_vars = selected.log_len();

		if claims.iter().any(|claim| claim.point.len() != n_vars) {
			return Err(Error::MultilinearSizeMismatch);
		}

		if bitmasks.len() != selected.len() {
			return Err(Error::BitmasksSizeMismatch);
		}

		let mut selectors = Vec::with_capacity(claims.len());
		let mut sums = Vec::with_capacity(claims.len());

		for Claim { point, value } in claims {
			let eq_expansion = eq_ind_partial_eval(&point[..n_vars.saturating_sub(1)]);
			selectors.push(Selector {
				eq_expansion,
				point,
				eq_prefix_eval: F::ONE,
				folded: None,
			});

			sums.push(value);
		}

		let last_coeffs_or_sums = RoundCoeffsOrSums::Sums(sums);

		Ok(Self {
			n_vars,
			n_rounds_remaining: n_vars,
			last_coeffs_or_sums,
			selected,
			selectors,
			bitmasks,
			switchover,
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

impl<'b, F, P, B> SumcheckProver<F> for SelectorMlecheckProver<'b, P, B>
where
	F: Field,
	P: PackedField<Scalar = F>,
	B: Bitwise,
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

		let selected_prefix = self.selected.chunk(self.n_rounds_remaining, 0)?;

		let is_first_round = self.n_rounds_remaining == self.n_vars;
		let scratchpad_len = 1 << chunk_vars.saturating_sub(P::LOG_WIDTH);
		let packed_prime_evals = (0..1 << (self.n_rounds_remaining - 1 - chunk_vars))
			.into_par_iter()
			.try_fold(
				|| {
					(
						vec![RoundEvals::default(); sums.len()],
						vec![P::zero(); scratchpad_len],
						vec![P::zero(); scratchpad_len],
					)
				},
				|(mut packed_prime_evals, mut scratchpad_zero, mut scratchpad_one),
				 chunk_index|
				 -> Result<_, Error> {
					let (selected_zero, selected_one) = selected_prefix.split_half()?;

					let selected_zero = selected_zero.chunk(chunk_vars, chunk_index)?;
					let selected_one = selected_one.chunk(chunk_vars, chunk_index)?;

					for (bit_offset, round_evals, selector) in
						izip!(0.., &mut packed_prime_evals, &self.selectors)
					{
						let eq = selector.eq_expansion.chunk(chunk_vars, chunk_index)?;

						if let Some(folded) = &selector.folded {
							let (folded_zero, folded_one) = folded.split_half()?;

							let folded_zero = folded_zero.chunk(chunk_vars, chunk_index)?;
							let folded_one = folded_one.chunk(chunk_vars, chunk_index)?;

							scratchpad_zero.copy_from_slice(folded_zero.as_ref());
							scratchpad_one.copy_from_slice(folded_one.as_ref());
						} else if is_first_round {
							for (
								scratchpad_zero,
								scratchpad_one,
								selected_zero,
								selected_one,
								masks,
							) in izip!(
								&mut scratchpad_zero,
								&mut scratchpad_one,
								selected_zero.as_ref(),
								selected_one.as_ref(),
								self.bitmasks.chunks(P::WIDTH)
							) {
								*scratchpad_zero = P::from_fn(|i| {
									if (masks[i] >> bit_offset) & B::from(1u8) != B::from(0u8) {
										selected_zero.get(i)
									} else {
										P::Scalar::zero()
									}
								});

								*scratchpad_one = P::from_fn(|i| {
									if (masks[i] >> bit_offset) & B::from(1u8) != B::from(0u8) {
										selected_one.get(i)
									} else {
										P::Scalar::zero()
									}
								});
							}
						} else {
							// TODO: switchover
							unreachable!();
						};

						for (
							&eq,
							&selected_zero,
							&selected_one,
							&scratchpad_zero,
							&scratchpad_one,
						) in izip!(
							eq.as_ref(),
							selected_zero.as_ref(),
							selected_one.as_ref(),
							&scratchpad_zero,
							&scratchpad_one,
						) {
							round_evals.one += eq * selected_one * scratchpad_one;
							round_evals.inf += eq
								* (selected_zero + selected_one)
								* (scratchpad_zero + scratchpad_one);
						}
					}

					Ok((packed_prime_evals, scratchpad_zero, scratchpad_one))
				},
			)
			.map(|evals| evals.map(|(evals, _, _)| evals))
			.try_reduce(
				|| vec![RoundEvals::<P>::default(); sums.len()],
				|lhs, rhs| Ok(izip!(lhs, rhs).map(|(l, r)| l + &r).collect()),
			)?;

		let prime_evals = packed_prime_evals
			.into_iter()
			.map(|evals| evals.sum_scalars(self.n_rounds_remaining - 1));

		let mut prime_coeffs = Vec::with_capacity(prime_evals.len());
		let mut round_coeffs = Vec::with_capacity(prime_evals.len());
		for (selector, &sum, evals) in izip!(&self.selectors, sums, prime_evals) {
			let alpha = selector.point[self.n_rounds_remaining - 1];
			let prime = evals.interpolate(sum, alpha);

			// eq(X, α) = (1 − α) + (2 α − 1) X
			// NB: In binary fields, this expression can be simplified to 1 + α + challenge.
			let (prime_by_constant_term, mut prime_by_linear_term) = if F::CHARACTERISTIC == 2 {
				(prime.clone() * (F::ONE + alpha), prime.clone())
			} else {
				(prime.clone() * (F::ONE - alpha), prime.clone() * (alpha.double() - F::ONE))
			};

			prime_by_linear_term.0.insert(0, F::ZERO); // Multiply prime polynomial by X

			let round = (prime_by_constant_term + &prime_by_linear_term) * selector.eq_prefix_eval;
			prime_coeffs.push(prime);
			round_coeffs.push(round);
		}

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

		for (bit_offset, selector) in izip!(0.., &mut self.selectors) {
			let alpha = selector.point[self.n_rounds_remaining - 1];
			selector.eq_prefix_eval *= eq_one_var(challenge, alpha);

			if self.n_rounds_remaining > 1 {
				eq_ind_truncate_low_inplace(
					self.n_rounds_remaining - 1,
					&mut selector.eq_expansion,
					self.n_rounds_remaining - 2,
				)?;
			}

			if selector.folded.is_none() {
				let mut folded = FieldBuffer::zeros(self.n_rounds_remaining);
				for (folded, masks) in izip!(folded.as_mut(), self.bitmasks.chunks(P::LOG_WIDTH)) {
					*folded = P::from_fn(|i| {
						if (masks[i] >> bit_offset) & B::from(1u8) != B::from(0u8) {
							P::Scalar::ONE
						} else {
							P::Scalar::ZERO
						}
					})
				}
			}

			if let Some(folded) = &mut selector.folded {
				fold_highest_var_inplace(self.n_rounds_remaining, folded, challenge)?;
			}
		}

		fold_highest_var_inplace(self.n_rounds_remaining, &mut self.selected, challenge)?;

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

		let mut multilinear_evals = Vec::with_capacity(self.selectors.len() + 1);
		multilinear_evals.push(self.selected.get(0).expect("multilinear.len() == 1"));

		for selector in self.selectors {
			let eval = selector
				.folded
				.expect("folded by this time")
				.get(0)
				.expect("multilinear.len() == 1");

			multilinear_evals.push(eval);
		}

		Ok(multilinear_evals)
	}
}

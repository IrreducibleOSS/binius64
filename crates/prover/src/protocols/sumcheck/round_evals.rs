// Copyright 2023-2025 Irreducible Inc.

use std::ops::Add;

use binius_field::{Field, PackedField};
use binius_verifier::protocols::sumcheck::RoundCoeffs;

#[derive(Clone, Debug, Default)]
pub struct RoundEvals1<P: PackedField> {
	pub one: P,
}

impl<P: PackedField> RoundEvals1<P> {
	pub fn sum_scalars(self, log_len: usize) -> RoundEvals1<P::Scalar> {
		RoundEvals1 {
			one: self.one.iter().take(1 << log_len).sum(),
		}
	}
}

impl<F: Field> RoundEvals1<F> {
	pub fn interpolate(self, sum: F, alpha: F) -> RoundCoeffs<F> {
		let zero = (sum - self.one * alpha) * (F::ONE - alpha).invert_or_zero();
		RoundCoeffs(vec![zero, self.one - zero])
	}
}

impl<P: PackedField> Add<&Self> for RoundEvals1<P> {
	type Output = Self;

	fn add(mut self, rhs: &Self) -> Self::Output {
		self.one += rhs.one;
		self
	}
}

#[derive(Clone, Debug, Default)]
pub struct RoundEvals2<P: PackedField> {
	pub one: P,
	pub inf: P,
}

impl<P: PackedField> RoundEvals2<P> {
	pub fn sum_scalars(self, log_len: usize) -> RoundEvals2<P::Scalar> {
		RoundEvals2 {
			one: self.one.iter().take(1 << log_len).sum(),
			inf: self.inf.iter().take(1 << log_len).sum(),
		}
	}
}

impl<F: Field> RoundEvals2<F> {
	pub fn interpolate(self, sum: F, alpha: F) -> RoundCoeffs<F> {
		let zero = (sum - self.one * alpha) * (F::ONE - alpha).invert_or_zero();
		RoundCoeffs(vec![zero, self.one - zero - self.inf, self.inf])
	}
}

impl<P: PackedField> Add<&Self> for RoundEvals2<P> {
	type Output = Self;

	fn add(mut self, rhs: &Self) -> Self::Output {
		self.one += rhs.one;
		self.inf += rhs.inf;
		self
	}
}

pub fn round_coeffs_by_eq<F: Field>(prime: &RoundCoeffs<F>, alpha: F) -> RoundCoeffs<F> {
	// eq(X, α) = (1 − α) + (2 α − 1) X
	// NB: In characteristic 2, this expression can be simplified to 1 + α + challenge.
	let (prime_by_constant_term, mut prime_by_linear_term) = if F::CHARACTERISTIC == 2 {
		(prime.clone() * (F::ONE + alpha), prime.clone())
	} else {
		(prime.clone() * (F::ONE - alpha), prime.clone() * (alpha.double() - F::ONE))
	};

	prime_by_linear_term.0.insert(0, F::ZERO); // Multiply prime polynomial by X
	prime_by_constant_term + &prime_by_linear_term
}

use std::ops::{Add, AddAssign, Mul, MulAssign};

use binius_field::{Field, PackedField, TowerField};
use binius_math::field_buffer::FieldBuffer;
use binius_transcript::fiat_shamir::{CanSample, Challenger};

use super::*;
use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationOrder {
	/// Substituting lower indexed variables first.
	LowToHigh,
	/// Substituting higher indexed variables first.
	HighToLow,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RoundCoeffs<F: Field>(pub Vec<F>);

impl<F: Field> Add<&Self> for RoundCoeffs<F> {
	type Output = Self;

	fn add(mut self, rhs: &Self) -> Self::Output {
		self += rhs;
		self
	}
}

impl<F: Field> AddAssign<&Self> for RoundCoeffs<F> {
	fn add_assign(&mut self, rhs: &Self) {
		if self.0.len() < rhs.0.len() {
			self.0.resize(rhs.0.len(), F::ZERO);
		}

		for (lhs_i, &rhs_i) in self.0.iter_mut().zip(rhs.0.iter()) {
			*lhs_i += rhs_i;
		}
	}
}

impl<F: Field> Mul<F> for RoundCoeffs<F> {
	type Output = Self;

	fn mul(mut self, rhs: F) -> Self::Output {
		self *= rhs;
		self
	}
}

impl<F: Field> MulAssign<F> for RoundCoeffs<F> {
	fn mul_assign(&mut self, rhs: F) {
		for coeff in &mut self.0 {
			*coeff *= rhs;
		}
	}
}
// Sumcheck Prover

pub trait SumcheckProver<F: Field> {
	/// The number of variables remaining in the multivariate polynomial.
	///
	/// This value decrements each time [`Self::fold`] is called on the instance.
	fn n_vars(&self) -> usize;

	/// Sumcheck evaluation order assumed by this specific prover.
	fn evaluation_order(&self) -> EvaluationOrder;

	/// Computes the prover message for this round as a univariate polynomial.
	///
	/// The prover message mixes the univariate polynomials of the underlying composites using the
	/// powers of `batch_coeff`.
	///
	/// Let $alpha$ refer to `batch_coeff`. If [`Self::fold`] has already been called on the prover
	/// with the values $r_0$, ..., $r_{k-1}$ and the sumcheck prover is proving the sums of the
	/// composite polynomials $C_0, ..., C_{m-1}$, then the output of this method will be the
	/// polynomial
	///
	/// $$
	/// \sum_{v \in B_{n - k - 1}} \sum_{i=0}^{m-1} \alpha^i C_i(r_0, ..., r_{k-1}, X, \{v\})
	/// $$
	fn execute(&mut self, batch_coeff: F) -> Result<RoundCoeffs<F>, Error>;

	/// Folds the sumcheck multilinears with a new verifier challenge.
	fn fold(&mut self, challenge: F) -> Result<(), Error>;

	/// Finishes the sumcheck proving protocol and returns the evaluations of all multilinears at
	/// the challenge point.
	fn finish(self: Box<Self>) -> Result<Vec<F>, Error>;
}

// Bivariate Product Prover

pub struct BivariateProductProver<'a, P: PackedField> {
	layer: Vec<(FieldBuffer<P>, FieldBuffer<P>)>,
	eval_point: &'a [P::Scalar],
	evals: &'a [P::Scalar],
}

impl<'a, P: PackedField> BivariateProductProver<'a, P> {
	pub fn new(
		layer: Vec<(FieldBuffer<P>, FieldBuffer<P>)>,
		eval_point: &'a [P::Scalar],
		evals: &'a [P::Scalar],
	) -> Self {
		// todo: check every layer field slice has log_en = eval_point.len()
		// check evals.len() == layer.len() / 2
		Self {
			layer,
			eval_point,
			evals,
		}
	}
}

impl<'a, P: PackedField> SumcheckProver<P::Scalar> for BivariateProductProver<'a, P> {
	fn n_vars(&self) -> usize {
		unimplemented!()
	}

	fn evaluation_order(&self) -> EvaluationOrder {
		unimplemented!()
	}

	fn execute(&mut self, batch_coeff: P::Scalar) -> Result<RoundCoeffs<P::Scalar>, Error> {
		unimplemented!()
	}

	fn fold(&mut self, challenge: P::Scalar) -> Result<(), Error> {
		unimplemented!()
	}

	fn finish(self: Box<Self>) -> Result<Vec<P::Scalar>, Error> {
		unimplemented!()
	}
}

// Batched Big Small Prover

pub struct VProver<'a, P: PackedField> {
	v_buffer: FieldBuffer<P>,
	exponents: &'a [u64],
	twisted_eval_points: Vec<Vec<P::Scalar>>,
	twisted_evals: Vec<P::Scalar>,
}

impl<'a, P: PackedField> VProver<'a, P> {
	pub fn new(
		v_buffer: FieldBuffer<P>,
		exponents: &'a [u64],
		twisted_eval_points: Vec<Vec<P::Scalar>>,
		twisted_evals: Vec<P::Scalar>,
	) -> Self {
		Self {
			v_buffer,
			exponents,
			twisted_eval_points,
			twisted_evals,
		}
	}
}

impl<'a, P: PackedField> SumcheckProver<P::Scalar> for VProver<'a, P> {
	fn n_vars(&self) -> usize {
		unimplemented!()
	}

	fn evaluation_order(&self) -> EvaluationOrder {
		unimplemented!()
	}

	fn execute(&mut self, batch_coeff: P::Scalar) -> Result<RoundCoeffs<P::Scalar>, Error> {
		unimplemented!()
	}

	fn fold(&mut self, challenge: P::Scalar) -> Result<(), Error> {
		unimplemented!()
	}

	fn finish(self: Box<Self>) -> Result<Vec<P::Scalar>, Error> {
		unimplemented!()
	}
}

// Rerandomization Prover

pub struct RerandomizationProver<'a, P: PackedField> {
	exponents: &'a [u64],
	eval_point: Vec<P::Scalar>,
	evals: Vec<P::Scalar>,
}

impl<'a, P: PackedField> RerandomizationProver<'a, P> {
	pub fn new(exponents: &'a [u64], eval_point: Vec<P::Scalar>, evals: Vec<P::Scalar>) -> Self {
		Self {
			exponents,
			eval_point,
			evals,
		}
	}
}

impl<'a, P: PackedField> SumcheckProver<P::Scalar> for RerandomizationProver<'a, P> {
	fn n_vars(&self) -> usize {
		unimplemented!()
	}

	fn evaluation_order(&self) -> EvaluationOrder {
		unimplemented!()
	}

	fn execute(&mut self, batch_coeff: P::Scalar) -> Result<RoundCoeffs<P::Scalar>, Error> {
		unimplemented!()
	}

	fn fold(&mut self, challenge: P::Scalar) -> Result<(), Error> {
		unimplemented!()
	}

	fn finish(self: Box<Self>) -> Result<Vec<P::Scalar>, Error> {
		unimplemented!()
	}
}

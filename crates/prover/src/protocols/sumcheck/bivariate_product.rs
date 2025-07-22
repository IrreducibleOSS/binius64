use std::array;

use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, multilinear::fold::fold_highest_var_inplace};
use binius_utils::rayon::prelude::*;
use binius_verifier::protocols::sumcheck::RoundCoeffs;

use crate::protocols::sumcheck::{common::SumcheckProver, error::Error};

/// A [`SumcheckProver`] implementation for a composite defined as the product of two multilinears.
///
/// This prover binds variables in high-to-low index order.
///
/// ## Invariants
///
/// - The length of the two multilinears is always equal
#[derive(Debug)]
pub struct BivariateProductSumcheckProver<P: PackedField> {
	n_vars: usize,
	multilinears: [FieldBuffer<P>; 2],
	last_coeffs_or_sum: RoundCoeffsOrSum<P::Scalar>,
}

impl<F: Field, P: PackedField<Scalar = F>> BivariateProductSumcheckProver<P> {
	/// Constructs a prover, given the multilinear polynomial evaluations and the sum over the
	/// boolean hypercube of their product.
	pub fn new(multilinears: [FieldBuffer<P>; 2], sum: F) -> Result<Self, Error> {
		if multilinears[0].log_len() != multilinears[1].log_len() {
			return Err(Error::MultilinearSizeMismatch);
		}

		let n_vars = multilinears[0].log_len();
		Ok(Self {
			n_vars,
			multilinears,
			last_coeffs_or_sum: RoundCoeffsOrSum::Sum(sum),
		})
	}

	/// Returns the number of variables remaining to be bound.
	fn n_vars_remaining(&self) -> usize {
		self.multilinears[0].log_len()
	}
}

impl<F: Field, P: PackedField<Scalar = F>> SumcheckProver<F> for BivariateProductSumcheckProver<P> {
	fn n_vars(&self) -> usize {
		self.n_vars
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		let RoundCoeffsOrSum::Sum(last_sum) = &self.last_coeffs_or_sum else {
			return Err(Error::ExpectedFold);
		};

		// Multilinear inputs are the same length by invariant
		debug_assert_eq!(self.multilinears[0].len(), self.multilinears[1].len());

		let n_vars_remaining = self.n_vars_remaining();
		assert!(n_vars_remaining > 0);

		let (evals_a_0, evals_a_1) = self.multilinears[0].split_half()?;
		let (evals_b_0, evals_b_1) = self.multilinears[1].split_half()?;

		// Compute F(1) and F(∞) where F = ∑_{v ∈ B} A(v || X) B(v || X)
		let [y_1_packed, y_inf_packed] =
			(evals_a_0.as_ref(), evals_a_1.as_ref(), evals_b_0.as_ref(), evals_b_1.as_ref())
				.into_par_iter()
				.map(|(&evals_a_0_i, &evals_a_1_i, &evals_b_0_i, &evals_b_1_i)| {
					// Evaluate M(∞) = M(0) + M(1)
					let evals_a_inf_i = evals_a_0_i + evals_a_1_i;
					let evals_b_inf_i = evals_b_0_i + evals_b_1_i;

					let prod_1_i = evals_a_1_i * evals_b_1_i;
					let prod_inf_i = evals_a_inf_i * evals_b_inf_i;

					[prod_1_i, prod_inf_i]
				})
				.reduce(|| [P::zero(); 2], |lhs, rhs| array::from_fn(|i| lhs[i] + rhs[i]));

		let y_1 = y_1_packed.into_iter().sum();
		let y_inf = y_inf_packed.into_iter().sum();

		let y_0 = *last_sum - y_1;
		let round_coeffs = calculate_round_coeffs_from_evals(y_0, y_1, y_inf);

		self.last_coeffs_or_sum = RoundCoeffsOrSum::Coeffs(round_coeffs.clone());
		Ok(vec![round_coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), Error> {
		let RoundCoeffsOrSum::Coeffs(last_coeffs) = self.last_coeffs_or_sum.clone() else {
			return Err(Error::ExpectedExecute);
		};

		for multilin in &mut self.multilinears {
			fold_highest_var_inplace(multilin, challenge)?;
		}

		let round_sum = last_coeffs.evaluate(challenge);
		self.last_coeffs_or_sum = RoundCoeffsOrSum::Sum(round_sum);
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		if self.n_vars_remaining() > 0 {
			let error = match self.last_coeffs_or_sum {
				RoundCoeffsOrSum::Coeffs(_) => Error::ExpectedFold,
				RoundCoeffsOrSum::Sum(_) => Error::ExpectedExecute,
			};
			return Err(error);
		}

		let multilinear_evals = self
			.multilinears
			.into_iter()
			.map(|multilinear| {
				multilinear.get(0).expect(
					"multilinear.log_len() == n_vars_remaining; \
				 	n_vars_remaining == 0; \
				 	multilinear.len() == 1",
				)
			})
			.collect();
		Ok(multilinear_evals)
	}
}

#[derive(Debug, Clone)]
enum RoundCoeffsOrSum<F: Field> {
	Coeffs(RoundCoeffs<F>),
	Sum(F),
}

/// Computes the coefficients of a degree 2 polynomial interpolating three points: (0, y_0),
/// (1, y_1), and infinity. The evaluation of a polynomial at infinity is defined as the limit of
/// P(X)/X^n as X approaches infinity, which equals the leading coefficient. This is the Karatsuba
/// trick.
fn calculate_round_coeffs_from_evals<F: Field>(y_0: F, y_1: F, y_inf: F) -> RoundCoeffs<F> {
	// For a polynomial P(X) = c_2 x² + c_1 x + c_0:
	//
	// P(0) =                  c_0
	// P(1) = c_2    + c_1   + c_0
	// P(∞) = c_2

	let c_0 = y_0;
	let c_2 = y_inf;
	let c_1 = y_1 - c_0 - c_2;
	RoundCoeffs(vec![c_0, c_1, c_2])
}

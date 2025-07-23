// Copyright 2023-2025 Irreducible Inc.

use binius_field::{Field, PackedField};
use binius_math::{
	field_buffer::FieldBuffer,
	multilinear::eq::{eq_ind_partial_eval, eq_ind_truncate_low_inplace, eq_one_var},
};
use binius_verifier::protocols::sumcheck::RoundCoeffs;

use super::{
	Error,
	round_evals::{RoundEvals2, round_coeffs_by_eq},
};

pub struct Gruen34<P: PackedField> {
	n_vars_remaining: usize,
	eq_expansion: FieldBuffer<P>,
	eval_point: Vec<P::Scalar>,
	eq_prefix_eval: P::Scalar,
}

impl<F: Field, P: PackedField<Scalar = F>> Gruen34<P> {
	pub fn new(eval_point: &[F]) -> Self {
		let n_vars_remaining = eval_point.len();

		Self {
			n_vars_remaining,
			eq_expansion: eq_ind_partial_eval(&eval_point[..n_vars_remaining.saturating_sub(1)]),
			eval_point: eval_point.to_vec(),
			eq_prefix_eval: F::ONE,
		}
	}

	pub fn eval_point(&self) -> &[F] {
		&self.eval_point
	}

	/// Returns the coordinate value of the evaluation point for the next variable to be bound.
	pub fn next_coordinate(&self) -> F {
		self.eval_point[self.n_vars_remaining - 1]
	}

	pub fn eq_expansion(&self) -> &FieldBuffer<P> {
		&self.eq_expansion
	}

	pub fn n_vars_remaining(&self) -> usize {
		self.n_vars_remaining
	}

	#[allow(dead_code)]
	pub fn interpolate2(
		&self,
		sum: F,
		round_evals: RoundEvals2<F>,
	) -> (RoundCoeffs<F>, RoundCoeffs<F>) {
		let alpha = self.next_coordinate();
		let prime_coeffs = round_evals.interpolate_eq(sum, alpha);
		let round_coeffs = round_coeffs_by_eq(&prime_coeffs, alpha) * self.eq_prefix_eval;
		(prime_coeffs, round_coeffs)
	}

	pub fn fold(&mut self, challenge: F) -> Result<(), Error> {
		assert!(self.n_vars_remaining > 0);

		if self.n_vars_remaining > 1 {
			debug_assert_eq!(self.eq_expansion.log_len(), self.n_vars_remaining - 1);
			eq_ind_truncate_low_inplace(&mut self.eq_expansion, self.n_vars_remaining - 2)?;
		}

		let alpha = self.next_coordinate();
		self.eq_prefix_eval *= eq_one_var(challenge, alpha);

		self.n_vars_remaining -= 1;
		Ok(())
	}
}

use binius_field::{Field, PackedField};
use binius_math::field_buffer::FieldBuffer;
use binius_verifier::protocols::sumcheck::{EvaluationOrder, RoundCoeffs};

use crate::protocols::sumcheck::{common::SumcheckProver, error::Error};

// V Prover

pub struct VProver<'a, P: PackedField> {
	v_buffer: FieldBuffer<P>,
	_exponents: &'a [u64],
	_twisted_eval_points: Vec<Vec<P::Scalar>>,
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
			_exponents: exponents,
			_twisted_eval_points: twisted_eval_points,
			twisted_evals,
		}
	}
}

impl<'a, P: PackedField> SumcheckProver<P::Scalar> for VProver<'a, P> {
	fn n_vars(&self) -> usize {
		self.v_buffer.log_len()
	}

	fn evaluation_order(&self) -> EvaluationOrder {
		EvaluationOrder::HighToLow
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<P::Scalar>>, Error> {
		Ok(vec![
			RoundCoeffs(vec![
				P::Scalar::ZERO,
				P::Scalar::ZERO,
				P::Scalar::ZERO,
				P::Scalar::ZERO
			]);
			64
		])
	}

	fn fold(&mut self, _challenge: P::Scalar) -> Result<(), Error> {
		Ok(())
	}

	fn finish(self) -> Result<Vec<P::Scalar>, Error> {
		Ok(vec![P::Scalar::ZERO; self.twisted_evals.len() + 1])
	}
}

// Rerandomization Prover

pub struct RerandomizationProver<'a, P: PackedField> {
	_exponents: &'a [u64],
	_eval_point: Vec<P::Scalar>,
	evals: Vec<P::Scalar>,
}

impl<'a, P: PackedField> RerandomizationProver<'a, P> {
	pub fn new(exponents: &'a [u64], eval_point: Vec<P::Scalar>, evals: Vec<P::Scalar>) -> Self {
		Self {
			_exponents: exponents,
			_eval_point: eval_point,
			evals,
		}
	}
}

impl<'a, P: PackedField> SumcheckProver<P::Scalar> for RerandomizationProver<'a, P> {
	fn n_vars(&self) -> usize {
		0
	}

	fn evaluation_order(&self) -> EvaluationOrder {
		EvaluationOrder::HighToLow
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<P::Scalar>>, Error> {
		Ok(vec![RoundCoeffs(vec![P::Scalar::ZERO, P::Scalar::ZERO, P::Scalar::ZERO,]); 64])
	}

	fn fold(&mut self, _challenge: P::Scalar) -> Result<(), Error> {
		Ok(())
	}

	fn finish(self) -> Result<Vec<P::Scalar>, Error> {
		Ok(vec![P::Scalar::ZERO; self.evals.len()])
	}
}

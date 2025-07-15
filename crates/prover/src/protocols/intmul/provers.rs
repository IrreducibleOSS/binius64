use binius_field::{Field, PackedField};
use binius_math::field_buffer::FieldBuffer;
use binius_verifier::protocols::sumcheck::RoundCoeffs;

use crate::protocols::sumcheck::{common::SumcheckProver, error::Error};

// V Prover

pub struct Claim<F> {
	pub eval_point: Vec<F>,
	pub claim: F,
}

pub struct VProver<'a, F, P: PackedField<Scalar = F>> {
	selected: FieldBuffer<P>,
	claims: Vec<Claim<F>>,
	bitmasks: &'a [u64],
	switchover: usize,
}

impl<'a, F, P: PackedField<Scalar = F>> VProver<'a, F, P> {
	pub fn new(
		selected: FieldBuffer<P>,
		claims: Vec<Claim<F>>,
		bitmasks: &'a [u64],
		switchover: usize,
	) -> Self {
		Self {
			selected,
			claims,
			bitmasks,
			switchover,
		}
	}
}

impl<'a, F: Field, P: PackedField<Scalar = F>> SumcheckProver<F> for VProver<'a, F, P> {
	fn n_vars(&self) -> usize {
		self.selected.log_len()
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<P::Scalar>>, Error> {
		Ok(vec![RoundCoeffs(vec![F::ZERO, F::ZERO, F::ZERO, F::ZERO]); 64])
	}

	fn fold(&mut self, _challenge: P::Scalar) -> Result<(), Error> {
		Ok(())
	}

	fn finish(self) -> Result<Vec<P::Scalar>, Error> {
		Ok(vec![F::ZERO; self.claims.len() + 1])
	}
}

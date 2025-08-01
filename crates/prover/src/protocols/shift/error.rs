// Copyright 2025 Irreducible Inc.

use binius_math::Error as MathError;

use crate::protocols::sumcheck::Error as SumcheckError;

#[derive(Debug, Clone, Copy)]
pub enum SumcheckErrorContext {
	New,
	Execute,
	Fold,
	Finish,
}
impl Error {
	pub fn from_sumcheck_new(error: SumcheckError) -> Self {
		Error::SumcheckError(error, SumcheckErrorContext::New)
	}
	pub fn from_sumcheck_execute(error: SumcheckError) -> Self {
		Error::SumcheckError(error, SumcheckErrorContext::Execute)
	}
	pub fn from_sumcheck_fold(error: SumcheckError) -> Self {
		Error::SumcheckError(error, SumcheckErrorContext::Fold)
	}
	pub fn from_sumcheck_finish(error: SumcheckError) -> Self {
		Error::SumcheckError(error, SumcheckErrorContext::Finish)
	}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("sumcheck error: {0} ({1:?})")]
	SumcheckError(SumcheckError, SumcheckErrorContext),
	#[error("math error: {0}")]
	MathError(#[from] MathError),
}

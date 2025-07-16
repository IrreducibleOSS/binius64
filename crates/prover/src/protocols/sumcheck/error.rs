// Copyright 2025 Irreducible Inc.

use binius_math::Error as MathError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("multilinears do not have equal number of variables")]
	MultilinearSizeMismatch,
	#[error("number of eval claims does not match the number of multilinears")]
	EvalClaimsNumberMismatch,
	#[error("expected execute() call")]
	ExpectedExecute,
	#[error("expected fold() call")]
	ExpectedFold,
	#[error("expected finish() call")]
	ExpectedFinish,
	#[error("math error: {0}")]
	MathError(#[from] MathError),
}

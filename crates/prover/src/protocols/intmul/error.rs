// Copyright 2025 Irreducible Inc.

use crate::protocols::sumcheck;

#[derive(Debug, Clone, Copy)]
pub enum SumcheckErrorContext {
	Execute,
	Fold,
	Finish,
}

impl Error {
	pub fn from_sumcheck_execute(error: sumcheck::error::Error) -> Self {
		Error::SumcheckError(error, SumcheckErrorContext::Execute)
	}

	pub fn from_sumcheck_fold(error: sumcheck::error::Error) -> Self {
		Error::SumcheckError(error, SumcheckErrorContext::Fold)
	}

	pub fn from_sumcheck_finish(error: sumcheck::error::Error) -> Self {
		Error::SumcheckError(error, SumcheckErrorContext::Finish)
	}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("transcript error")]
	TranscriptError(#[from] binius_transcript::Error),
	#[error("length mismatch: {0} != {1}")]
	LengthMismatch(usize, usize),
	#[error("twisted eval points count ({0}) does not match claims count ({1})")]
	TwistedPointsEvalsMismatch(usize, usize),
	#[error("layer length ({0}) does not match pairs count ({1})")]
	LayerClaimsMismatch(usize, usize),
	#[error("composition claim mismatch")]
	CompositionClaimMismatch,
	#[error("final claims count ({0}) does not match pairs count * 2 ({1})")]
	FinalClaimsPairsMismatch(usize, usize),
	#[error("round coeffs count ({0}) does not match pairs count ({1})")]
	RoundCoeffsPairsMismatch(usize, usize),
	#[error("sumcheck error: {0} ({1:?})")]
	SumcheckError(sumcheck::error::Error, SumcheckErrorContext),
	#[error("buffer log len ({0}) and eval point len ({1}) mismatch")]
	BufferEvalPointMismatch(usize, usize),
	#[error("layer pairs count ({0}) does not match claims count ({1})")]
	LayerPairsCountClaimsMismatch(usize, usize),
	#[error("eval point and buffer log len mismatch")]
	EvalPointBufferLengthMismatch,
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
	MathError(#[from] binius_math::Error),
}

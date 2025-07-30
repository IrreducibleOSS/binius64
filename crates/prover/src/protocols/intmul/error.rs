// Copyright 2025 Irreducible Inc.

use crate::protocols::sumcheck::Error as SumcheckError;

#[derive(Debug, Clone, Copy)]
pub enum SumcheckErrorContext {
	Execute,
	Fold,
	Finish,
}

impl Error {
	pub fn from_sumcheck_new(error: SumcheckError) -> Self {
		Error::Sumcheck(error, SumcheckErrorContext::Execute)
	}

	pub fn from_sumcheck_batch(error: SumcheckError) -> Self {
		Error::Sumcheck(error, SumcheckErrorContext::Execute)
	}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("Exponent length should be a power of two")]
	ExponentsPowerOfTwoLengthRequired,
	#[error("All exponent slices must have the same length")]
	ExponentLengthMismatch,
	#[error("transcript error")]
	Transcript(#[from] binius_transcript::Error),
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
	Sumcheck(SumcheckError, SumcheckErrorContext),
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
	Math(#[from] binius_math::Error),
	#[error("layers empty")]
	LayersEmpty,
	#[error("last layer empty")]
	LastLayerEmpty,
}

// Copyright 2025 Irreducible Inc.

impl Error {
	pub fn from_transcript_read(error: binius_transcript::Error) -> Self {
		Error::TranscriptError(error)
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
	#[error("buffer log len ({0}) and eval point len ({1}) mismatch")]
	BufferEvalPointMismatch(usize, usize),
	#[error("layer pairs count ({0}) does not match claims count ({1})")]
	LayerPairsCountClaimsMismatch(usize, usize),
	#[error("eval point and buffer log len mismatch")]
	EvalPointBufferLengthMismatch,
}

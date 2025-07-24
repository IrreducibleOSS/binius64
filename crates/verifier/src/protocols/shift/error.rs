// Copyright 2025 Irreducible Inc.

use binius_math::Error as MathError;

impl Error {
	pub fn from_transcript_read(error: binius_transcript::Error) -> Self {
		Error::Transcript(error)
	}

	pub fn from_sumcheck_verify(error: crate::protocols::sumcheck::Error) -> Self {
		Error::Sumcheck(error)
	}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("transcript error")]
	Transcript(#[from] binius_transcript::Error),
	#[error("sumcheck error")]
	Sumcheck(#[from] crate::protocols::sumcheck::Error),
	#[error("verification failure")]
	VerificationFailure,
	#[error("math error: {0}")]
	MathError(#[from] MathError),
}

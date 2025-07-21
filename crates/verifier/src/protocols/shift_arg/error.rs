// Copyright 2025 Irreducible Inc.

impl Error {
	pub fn from_transcript_read(error: binius_transcript::Error) -> Self {
		Error::TranscriptError(error)
	}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("composition claim mismatch")]
	CompositionClaimMismatch,
	#[error("transcript error")]
	TranscriptError(#[from] binius_transcript::Error),
}

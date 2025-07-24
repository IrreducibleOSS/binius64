// Copyright 2025 Irreducible Inc.

use binius_transcript::Error as TranscriptError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("transcript error: {0}")]
	Transcript(#[source] TranscriptError),
	#[error("verification error: {0}")]
	Verification(#[from] VerificationError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
	#[error("evaluation claim verification failed: expected {expected}, got {actual}")]
	EvaluationClaimMismatch { expected: String, actual: String },
	#[error("FRI oracle verification failed: sumcheck and FRI are inconsistent")]
	FriOracleVerificationFailed,
	#[error("basefold verification error: {0}")]
	BasefoldVerification(String),
}

impl From<TranscriptError> for Error {
	fn from(err: TranscriptError) -> Self {
		match err {
			TranscriptError::NotEnoughBytes => {
				VerificationError::BasefoldVerification("transcript is empty".to_string()).into()
			}
			_ => Error::Transcript(err),
		}
	}
}

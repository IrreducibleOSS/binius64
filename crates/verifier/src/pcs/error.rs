// Copyright 2025 Irreducible Inc.

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("evaluation claim verification failed: expected {expected}, got {actual}")]
	EvaluationClaimMismatch { expected: String, actual: String },
	#[error("FRI oracle verification failed: sumcheck and FRI are inconsistent")]
	FriOracleVerificationFailed,
	#[error("transcript error: {0}")]
	Transcript(#[from] binius_transcript::Error),
	#[error("basefold verification error: {0}")]
	BasefoldVerification(String),
}

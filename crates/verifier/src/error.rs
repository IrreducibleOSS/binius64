// Copyright 2025 Irreducible Inc.

use binius_math::ntt;

use super::config::LOG_WORDS_PER_ELEM;
use crate::{fri, pcs, protocols::sumcheck};

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("transcript error: {0}")]
	Transcript(#[from] binius_transcript::Error),
	#[error("FRI error: {0}")]
	FRI(#[from] fri::Error),
	#[error("NTT error: {0}")]
	NTT(#[from] ntt::Error),
	#[error("PCS error: {0}")]
	PCS(#[from] pcs::Error),
	#[error("sumcheck error: {0}")]
	Sumcheck(#[from] sumcheck::Error),
	#[error("Math error: {0}")]
	Math(#[from] binius_math::Error),
	#[error("incorrect public inputs length: expected {expected}, got {actual}")]
	IncorrectPublicInputLength { expected: usize, actual: usize },
	#[error("constraint system error: {0}")]
	ConstraintSystem(#[from] ConstraintSystemError),
	#[error("invalid proof: {0}")]
	Verification(#[from] VerificationError),
}

#[derive(Debug, thiserror::Error)]
pub enum ConstraintSystemError {
	#[error("the public input segment must have power of two length")]
	PublicInputPowerOfTwo,
	#[error("the public input segment must at least 2^{LOG_WORDS_PER_ELEM} words")]
	PublicInputTooShort,
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
	#[error("public input check failed")]
	PublicInputCheckFailed,
}

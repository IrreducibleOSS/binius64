// Copyright 2025 Irreducible Inc.

use binius_math::ntt;

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
	#[error("Sumcheck error: {0}")]
	Sumcheck(#[from] sumcheck::Error),
	#[error("Math error: {0}")]
	Math(#[from] binius_math::Error),
}

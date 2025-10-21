// Copyright 2025 Irreducible Inc.

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("invalid argument {arg}: {msg}")]
	ArgumentError { arg: String, msg: String },
	#[error("FRI error: {0}")]
	Fri(#[from] binius_prover::fri::Error),
	#[error("transcript error: {0}")]
	Transcript(#[from] binius_transcript::Error),
	#[error("math error: {0}")]
	Math(#[from] binius_math::Error),
}

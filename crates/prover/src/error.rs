// Copyright 2025 Irreducible Inc.

use crate::fri;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("invalid argument {arg}: {msg}")]
	ArgumentError { arg: String, msg: String },
	#[error("FRI error: {0}")]
	Fri(#[from] fri::Error),
	#[error("transcript error: {0}")]
	Transcript(#[from] binius_transcript::Error),
}

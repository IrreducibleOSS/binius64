// Copyright 2025 Irreducible Inc.

use binius_math::ntt;

use crate::{
	fri,
	protocols::{intmul, sumcheck},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("invalid argument {arg}: {msg}")]
	ArgumentError { arg: String, msg: String },
	#[error("sumcheck error: {0}")]
	Sumcheck(#[from] sumcheck::Error),
	#[error("ntt error: {0}")]
	NTT(#[from] ntt::Error),
	#[error("FRI error: {0}")]
	Fri(#[from] fri::Error),
	#[error("transcript error: {0}")]
	Transcript(#[from] binius_transcript::Error),
	#[error("integer multiplication error: {0}")]
	IntMul(#[from] intmul::Error),
}

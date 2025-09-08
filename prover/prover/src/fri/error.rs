// Copyright 2024-2025 Irreducible Inc.

use binius_math::reed_solomon;
use binius_verifier::{fri, merkle_tree};

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("attempted to finish prover before executing all fold rounds")]
	EarlyProverFinish,
	#[error("conflicting or incorrect constructor argument: {0}")]
	InvalidArgs(String),
	#[error("FRI error: {0}")]
	FRI(#[from] fri::Error),
	#[error("Merkle tree error: {0}")]
	MerkleError(#[from] merkle_tree::Error),
	#[error("Reed-Solomon encoding error: {0}")]
	CodeError(#[from] reed_solomon::Error),
}

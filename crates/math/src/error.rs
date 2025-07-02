// Copyright 2024-2025 Irreducible Inc.

use std::ops::Range;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("argument {arg} does not have expected length {expected}")]
	IncorrectArgumentLength { arg: String, expected: usize },
	#[error("the matrix is not square")]
	MatrixNotSquare,
	#[error("the matrix is singular")]
	MatrixIsSingular,
	#[error("domain size is larger than the field")]
	DomainSizeTooLarge,
	#[error("argument {arg} must be in the range {range:?}")]
	ArgumentRangeError { arg: String, range: Range<usize> },
}

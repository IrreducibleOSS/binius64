// Copyright 2024-2025 Irreducible Inc.

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("codeword buffer must be at least 2**{log_code_len} elements")]
	BufferTooSmall { log_code_len: usize },
	#[error("field order must be at least 2**{log_domain_size}")]
	FieldTooSmall { log_domain_size: usize },
	#[error("domain size is less than 2**{log_required_domain_size}")]
	DomainTooSmall { log_required_domain_size: usize },
	#[error("evaluation subspace must include the 1 element")]
	DomainMustIncludeOne,
	#[error("the input length must be a power of two")]
	PowerOfTwoLengthRequired,
	#[error("the field extension degree must be a power of two")]
	PowerOfTwoExtensionDegreeRequired,
	#[error("the stride cannot be greater than the packed width")]
	StrideGreaterThanPackedWidth,
	#[error("the batch size is greater than the number of elements")]
	BatchTooLarge,
	#[error("the skip_rounds parameter exceeds the total number of NTT rounds")]
	SkipRoundsTooLarge,
	#[error("coset index must be less than 2**{coset_bits}, got {coset}")]
	CosetIndexOutOfBounds { coset: usize, coset_bits: usize },
	#[error("odd interpolation length mismatch, expected to be exactly {expected_len}")]
	OddInterpolateIncorrectLength { expected_len: usize },
	#[error("math error: {0}")]
	MathError(#[from] crate::Error),
}

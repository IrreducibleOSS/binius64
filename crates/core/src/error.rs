use crate::consts::MIN_WORDS_PER_SEGMENT;

#[derive(Debug, thiserror::Error)]
pub enum ConstraintSystemError {
	#[error("the total length of the value vector must be a power of two")]
	ValueVecLenNotPowerOfTwo,
	#[error("the public input segment must have power of two length")]
	PublicInputPowerOfTwo,
	#[error(
		"the public input segment must be at least {MIN_WORDS_PER_SEGMENT} words, got: {pub_input_size}"
	)]
	PublicInputTooShort { pub_input_size: usize },
	#[error("the data length doesn't match layout")]
	ValueVecLenMismatch { expected: usize, actual: usize },
}

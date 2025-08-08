// Copyright 2023-2025 Irreducible Inc.

//! [Reed–Solomon] codes over binary fields.
//!
//! See [`ReedSolomonCode`] for details.

use binius_field::{BinaryField, ExtensionField, PackedExtension, PackedField};
use binius_utils::bail;
use getset::{CopyGetters, Getters};

use crate::FieldBuffer;

use super::{binary_subspace::BinarySubspace, error::Error as MathError, ntt::AdditiveNTT};

/// [Reed–Solomon] codes over binary fields.
///
/// The Reed–Solomon code admits an efficient encoding algorithm over binary fields due to [LCH14].
/// The additive NTT encoding algorithm encodes messages interpreted as the coefficients of a
/// polynomial in a non-standard, novel polynomial basis and the codewords are the polynomial
/// evaluations over a linear subspace of the field. See the [binius-math] crate for more details.
///
/// [Reed–Solomon]: <https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction>
/// [LCH14]: <https://arxiv.org/abs/1404.3458>
#[derive(Debug, Clone, Getters, CopyGetters)]
pub struct ReedSolomonCode<F: BinaryField> {
	#[get = "pub"]
	subspace: BinarySubspace<F>,
	log_dimension: usize,
	#[get_copy = "pub"]
	log_inv_rate: usize,
}

impl<F: BinaryField> ReedSolomonCode<F> {
	pub fn new(log_dimension: usize, log_inv_rate: usize) -> Result<Self, Error> {
		let subspace = BinarySubspace::with_dim(log_dimension + log_inv_rate)?;
		Self::with_subspace(subspace, log_dimension, log_inv_rate)
	}

	pub fn with_ntt_subspace(
		ntt: &impl AdditiveNTT<Field = F>,
		log_dimension: usize,
		log_inv_rate: usize,
	) -> Result<Self, Error> {
		if log_dimension + log_inv_rate > ntt.log_domain_size() {
			return Err(Error::SubspaceDimensionMismatch);
		}
		let subspace_dim = log_dimension + log_inv_rate;
		Self::with_subspace(ntt.subspace(subspace_dim), log_dimension, log_inv_rate)
	}

	pub fn with_subspace(
		subspace: BinarySubspace<F>,
		log_dimension: usize,
		log_inv_rate: usize,
	) -> Result<Self, Error> {
		if subspace.dim() != log_dimension + log_inv_rate {
			return Err(Error::SubspaceDimensionMismatch);
		}
		Ok(Self {
			subspace,
			log_dimension,
			log_inv_rate,
		})
	}

	/// The dimension.
	pub const fn dim(&self) -> usize {
		1 << self.dim_bits()
	}

	pub const fn log_dim(&self) -> usize {
		self.log_dimension
	}

	pub const fn log_len(&self) -> usize {
		self.log_dimension + self.log_inv_rate
	}

	/// The block length.
	#[allow(clippy::len_without_is_empty)]
	pub const fn len(&self) -> usize {
		1 << (self.log_dimension + self.log_inv_rate)
	}

	/// The base-2 log of the dimension.
	const fn dim_bits(&self) -> usize {
		self.log_dimension
	}

	/// The reciprocal of the rate, ie. `self.len() / self.dim()`.
	pub const fn inv_rate(&self) -> usize {
		1 << self.log_inv_rate
	}

	/// Encode a batch of interleaved messages in-place in a provided buffer.
	///
	/// The message symbols are interleaved in the buffer, which improves the cache-efficiency of
	/// the encoding procedure. The interleaved codeword is stored in the buffer when the method
	/// completes.
	///
	/// ## Throws
	///
	/// * If the `code` buffer does not have capacity for `len() << log_batch_size` field elements.
	fn encode_batch_inplace<P: PackedField<Scalar = F>, NTT: AdditiveNTT<Field = F> + Sync>(
		&self,
		ntt: &NTT,
		code: &mut [P],
		log_batch_size: usize,
	) -> Result<(), Error> {
		if ntt.subspace(self.log_len()) != self.subspace {
			bail!(Error::EncoderSubspaceMismatch);
		}
		let expected_buffer_len =
			1 << (self.log_len() + log_batch_size).saturating_sub(P::LOG_WIDTH);
		if code.len() != expected_buffer_len {
			bail!(Error::IncorrectBufferLength {
				expected: expected_buffer_len,
				actual: code.len(),
			});
		}

		let _scope = tracing::trace_span!(
			"Reed–Solomon encode",
			log_len = self.log_len(),
			log_batch_size = log_batch_size,
			symbol_bits = F::N_BITS,
		)
		.entered();

		// Repeat the message to fill the entire buffer.

		// First, if the message is less than the packing width, we need to repeat it to fill one
		// packed element.
		if self.dim() + log_batch_size < P::LOG_WIDTH {
			let repeated_values = code[0]
				.into_iter()
				.take(1 << (self.log_dim() + log_batch_size))
				.cycle();
			code[0] = P::from_scalars(repeated_values);
		}

		// Repeat the packed message to fill the entire buffer.
		let mut chunks =
			code.chunks_mut(1 << (self.log_dim() + log_batch_size).saturating_sub(P::LOG_WIDTH));
		let first_chunk = chunks.next().expect("code is not empty; checked above");
		for chunk in chunks {
			chunk.copy_from_slice(first_chunk);
		}

		let skip_early = self.log_inv_rate;
		let skip_late = log_batch_size;
		ntt.forward_transform(
			FieldBuffer::new(self.log_len() + log_batch_size, code).unwrap(),
			skip_early,
			skip_late,
		);
		Ok(())
	}

	/// Encode a batch of interleaved messages of extension field elements in-place in a provided
	/// buffer.
	///
	/// A linear code can be naturally extended to a code over extension fields by encoding each
	/// dimension of the extension as a vector-space separately.
	///
	/// ## Preconditions
	///
	/// * `PE::Scalar::DEGREE` must be a power of two.
	///
	/// ## Throws
	///
	/// * If the `code` buffer does not have capacity for `len() << log_batch_size` field elements.
	pub fn encode_ext_batch_inplace<PE: PackedExtension<F>, NTT: AdditiveNTT<Field = F> + Sync>(
		&self,
		ntt: &NTT,
		code: &mut [PE],
		log_batch_size: usize,
	) -> Result<(), Error> {
		self.encode_batch_inplace(
			ntt,
			PE::cast_bases_mut(code),
			log_batch_size + PE::Scalar::LOG_DEGREE,
		)
	}
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("incorrect buffer length: expected {expected}, got {actual}")]
	IncorrectBufferLength { expected: usize, actual: usize },
	#[error("the evaluation domain of the code does not match the subspace of the NTT encoder")]
	EncoderSubspaceMismatch,
	#[error("the dimension of the evaluation domain of the code does not match the parameters")]
	SubspaceDimensionMismatch,
	#[error("math error: {0}")]
	Math(#[from] MathError),
}

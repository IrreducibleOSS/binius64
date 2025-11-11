// Copyright 2023-2025 Irreducible Inc.

//! [Reed–Solomon] codes over binary fields.
//!
//! See [`ReedSolomonCode`] for details.

use std::ptr;

use binius_field::{BinaryField, PackedField};
use binius_utils::rayon::{
	iter::{ParallelBridge, ParallelIterator},
	slice::ParallelSliceMut,
};
use getset::{CopyGetters, Getters};

use super::{
	FieldBuffer, FieldSlice, binary_subspace::BinarySubspace, error::Error as MathError,
	ntt::AdditiveNTT,
};
use crate::{FieldSliceMut, ntt::DomainContext};

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
pub struct ReedSolomonCode<F> {
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
		Self::with_domain_context_subspace(ntt.domain_context(), log_dimension, log_inv_rate)
	}

	pub fn with_domain_context_subspace(
		domain_context: &impl DomainContext<Field = F>,
		log_dimension: usize,
		log_inv_rate: usize,
	) -> Result<Self, Error> {
		let subspace_dim = log_dimension + log_inv_rate;
		if subspace_dim > domain_context.log_domain_size() {
			return Err(Error::SubspaceDimensionMismatch);
		}
		let subspace = domain_context.subspace(subspace_dim);
		Self::with_subspace(subspace, log_dimension, log_inv_rate)
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
	pub fn encode_batch_inplace<P: PackedField<Scalar = F>, NTT: AdditiveNTT<Field = F> + Sync>(
		&self,
		ntt: &NTT,
		code: &mut [P],
		log_batch_size: usize,
	) -> Result<(), Error> {
		if ntt.subspace(self.log_len()) != self.subspace {
			return Err(Error::EncoderSubspaceMismatch);
		}

		let mut code = FieldSliceMut::from_slice(self.log_len() + log_batch_size, code)?;

		let _scope = tracing::trace_span!(
			"Reed-Solomon encode",
			log_len = self.log_len(),
			log_batch_size = log_batch_size,
			symbol_bits = F::N_BITS,
		)
		.entered();

		// Repeat the message to fill the entire buffer.

		// If the message is less than the packing width, we need to repeat it to fill one
		// packed element.
		let chunk_size = self.log_dim() + log_batch_size;
		let chunk_size = if chunk_size < P::LOG_WIDTH {
			let elem_0 = &mut code.as_mut()[0];
			let repeated_values = elem_0
				.into_iter()
				.take(1 << (self.log_dim() + log_batch_size))
				.cycle();
			*elem_0 = P::from_scalars(repeated_values);
			P::LOG_WIDTH
		} else {
			chunk_size
		};

		if chunk_size < code.log_len() {
			let mut chunks = code.chunks_mut(chunk_size).expect(
				"chunk_size >= P::LOG_WIDTH from assignment above; \
				chunk_size < code.log_len() in conditional",
			);
			let first_chunk = chunks.next().expect("chunks_mut cannot be empty");
			chunks.par_bridge().for_each(|mut chunk| {
				chunk.as_mut().copy_from_slice(first_chunk.as_ref());
			});
		}

		let skip_early = self.log_inv_rate;
		let skip_late = log_batch_size;
		ntt.forward_transform(code, skip_early, skip_late);
		Ok(())
	}

	/// Encode a batch of interleaved messages into a provided output buffer.
	///
	/// This function encodes multiple messages in parallel by copying the input data to all chunks
	/// of the output buffer and then applying the NTT transformation. The messages are interleaved
	/// in both the input and output buffers, which improves cache efficiency.
	///
	/// ## Preconditions
	///
	/// * The input `data` must contain exactly `dim() << log_batch_size` field elements.
	/// * The output buffer must have capacity for `len() << log_batch_size` field elements.
	///
	/// ## Postconditions
	///
	/// * On success, all elements in the output buffer are initialized with the encoded codeword.
	///
	/// ## Throws
	///
	/// * [`Error::EncoderSubspaceMismatch`] if the NTT subspace doesn't match the code's subspace.
	/// * [`Error::Math`] if the output buffer has incorrect dimensions.
	pub fn encode_batch<P, NTT>(
		&self,
		ntt: &NTT,
		data: FieldSlice<P>,
		log_batch_size: usize,
	) -> Result<FieldBuffer<P>, Error>
	where
		P: PackedField<Scalar = F>,
		NTT: AdditiveNTT<Field = F> + Sync,
	{
		if ntt.subspace(self.log_len()) != self.subspace {
			return Err(Error::EncoderSubspaceMismatch);
		}

		assert_eq!(data.log_len(), self.log_dim() + log_batch_size); // precondition

		let _scope = tracing::trace_span!(
			"Reed-Solomon encode",
			log_len = self.log_len(),
			log_batch_size = log_batch_size,
			symbol_bits = F::N_BITS,
		)
		.entered();

		// Repeat the message to fill the entire buffer.
		let log_output_len = self.log_dim() + log_batch_size + self.log_inv_rate;
		let output_data = if data.log_len() < P::LOG_WIDTH {
			let repeated_values = data.iter_scalars().cycle();
			let elem_0 = P::from_scalars(repeated_values);
			vec![elem_0; 1 << log_output_len.saturating_sub(P::LOG_WIDTH)]
		} else {
			let mut output_data =
				Vec::with_capacity(1 << log_output_len.saturating_sub(P::LOG_WIDTH));

			let data_packed = data.as_ref();
			output_data
				.spare_capacity_mut()
				.par_chunks_exact_mut(data_packed.len())
				.for_each(|chunk| {
					unsafe {
						// Safety: MaybeUninit<P> has the same memory representation as P. P is a
						// PackedField, which is Copy. chuck len is exactly data_packed.len()
						// because of the par_chunks_exact_mut.
						ptr::copy_nonoverlapping(
							data_packed.as_ptr(),
							chunk.as_mut_ptr() as *mut P,
							data_packed.len(),
						)
					}
				});

			unsafe {
				// Safety: the vec's spare capacity is fully initialized above.
				output_data.set_len(1 << log_output_len.saturating_sub(P::LOG_WIDTH));
			}

			output_data
		};
		let mut output = FieldBuffer::new(log_output_len, output_data.into_boxed_slice())
			.expect("preconditions satisfied");

		ntt.forward_transform(output.to_mut(), self.log_inv_rate, log_batch_size);
		Ok(output)
	}
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("the evaluation domain of the code does not match the subspace of the NTT encoder")]
	EncoderSubspaceMismatch,
	#[error("the dimension of the evaluation domain of the code does not match the parameters")]
	SubspaceDimensionMismatch,
	#[error("math error: {0}")]
	Math(#[from] MathError),
}

#[cfg(test)]
mod tests {
	use binius_field::{
		BinaryField, PackedBinaryGhash1x128b, PackedBinaryGhash4x128b, PackedField,
	};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{
		FieldBuffer,
		ntt::{NeighborsLastReference, domain_context::GenericPreExpanded},
		test_utils::random_field_buffer,
	};

	fn test_encode_batch_inplace_helper<P: PackedField>(
		log_dim: usize,
		log_inv_rate: usize,
		log_batch_size: usize,
	) where
		P::Scalar: BinaryField,
	{
		let mut rng = StdRng::seed_from_u64(0);

		let rs_code = ReedSolomonCode::<P::Scalar>::new(log_dim, log_inv_rate)
			.expect("Failed to create Reed-Solomon code");

		// Create NTT with matching subspace
		let subspace = rs_code.subspace().clone();
		let domain_context = GenericPreExpanded::<P::Scalar>::generate_from_subspace(&subspace);
		let ntt = NeighborsLastReference {
			domain_context: &domain_context,
		};

		// Generate random message buffer
		let message = random_field_buffer::<P>(&mut rng, log_dim + log_batch_size);

		// Create two clones with capacity for encoding
		let log_encoded_len = rs_code.log_len() + log_batch_size;

		// Method 1: Use encode_batch_inplace
		// Create buffer with message data but with capacity for the full encoding
		let mut encoded_data = message.as_ref().to_vec();
		// Resize to have capacity for encoding
		let encoded_capacity = 1 << log_encoded_len.saturating_sub(P::LOG_WIDTH);
		encoded_data.resize(encoded_capacity, P::zero());

		let mut encoded_buffer =
			FieldBuffer::new_truncated(log_dim + log_batch_size, encoded_data.into_boxed_slice())
				.expect("Failed to create encoded buffer");

		// Zero-extend to encoding size
		encoded_buffer
			.zero_extend(log_encoded_len)
			.expect("Failed to zero-extend encoded buffer");

		rs_code
			.encode_batch_inplace(&ntt, encoded_buffer.as_mut(), log_batch_size)
			.expect("encode_batch_inplace failed");

		// Method 2: Reference implementation - apply NTT with zero-padded coefficients
		// Create buffer with message data but with capacity for the full encoding
		let mut reference_data = message.as_ref().to_vec();
		// Resize to have capacity for encoding
		reference_data.resize(encoded_capacity, P::zero());

		let mut reference_buffer =
			FieldBuffer::new_truncated(log_dim + log_batch_size, reference_data.into_boxed_slice())
				.expect("Failed to create reference buffer");

		// Zero-extend to encoding size
		reference_buffer
			.zero_extend(log_encoded_len)
			.expect("Failed to zero-extend reference buffer");

		// Perform large NTT with zero-padded coefficients.
		ntt.forward_transform(reference_buffer.to_mut(), 0, log_batch_size);

		// Compare results
		assert_eq!(
			encoded_buffer.as_ref(),
			reference_buffer.as_ref(),
			"encode_batch_inplace result differs from reference NTT implementation"
		);
	}

	#[test]
	fn test_encode_batch_inplace() {
		// Test with PackedBinaryGhash1x128b
		test_encode_batch_inplace_helper::<PackedBinaryGhash1x128b>(4, 2, 0);
		test_encode_batch_inplace_helper::<PackedBinaryGhash1x128b>(6, 2, 1);
		test_encode_batch_inplace_helper::<PackedBinaryGhash1x128b>(8, 3, 2);

		// Test with PackedBinaryGhash4x128b
		test_encode_batch_inplace_helper::<PackedBinaryGhash4x128b>(4, 2, 0);
		test_encode_batch_inplace_helper::<PackedBinaryGhash4x128b>(6, 2, 1);
		test_encode_batch_inplace_helper::<PackedBinaryGhash4x128b>(8, 3, 2);

		// Test where message length is less than the packing width and codeword length is greater.
		test_encode_batch_inplace_helper::<PackedBinaryGhash4x128b>(1, 2, 0);
	}

	fn test_encode_batch_helper<P: PackedField>(
		log_dim: usize,
		log_inv_rate: usize,
		log_batch_size: usize,
	) where
		P::Scalar: BinaryField,
	{
		let mut rng = StdRng::seed_from_u64(0);

		let rs_code = ReedSolomonCode::<P::Scalar>::new(log_dim, log_inv_rate)
			.expect("Failed to create Reed-Solomon code");

		// Create NTT with matching subspace
		let subspace = rs_code.subspace().clone();
		let domain_context = GenericPreExpanded::<P::Scalar>::generate_from_subspace(&subspace);
		let ntt = NeighborsLastReference {
			domain_context: &domain_context,
		};

		// Generate random message buffer
		let message = random_field_buffer::<P>(&mut rng, log_dim + log_batch_size);

		// Test the new encode_batch interface
		let encoded_buffer = rs_code
			.encode_batch(&ntt, message.to_ref(), log_batch_size)
			.expect("encode_batch failed");

		// Method 2: Reference implementation - apply NTT with zero-padded coefficients
		let mut reference_buffer = FieldBuffer::zeros(rs_code.log_len() + log_batch_size);
		for (i, val) in message.iter_scalars().enumerate() {
			reference_buffer.set(i, val);
		}

		// Perform large NTT with zero-padded coefficients.
		ntt.forward_transform(reference_buffer.to_mut(), 0, log_batch_size);

		// Compare results
		assert_eq!(
			encoded_buffer.as_ref(),
			reference_buffer.as_ref(),
			"encode_batch_inplace result differs from reference NTT implementation"
		);
	}

	#[test]
	fn test_encode_batch_above_packing_width() {
		// Test with PackedBinaryGhash1x128b
		test_encode_batch_helper::<PackedBinaryGhash1x128b>(4, 2, 0);
		test_encode_batch_helper::<PackedBinaryGhash1x128b>(6, 2, 1);
		test_encode_batch_helper::<PackedBinaryGhash1x128b>(8, 3, 2);

		// Test with PackedBinaryGhash4x128b
		test_encode_batch_helper::<PackedBinaryGhash4x128b>(4, 2, 0);
		test_encode_batch_helper::<PackedBinaryGhash4x128b>(6, 2, 1);
		test_encode_batch_helper::<PackedBinaryGhash4x128b>(8, 3, 2);
	}

	#[test]
	fn test_encode_batch_below_packing_width() {
		// Test where message length is less than the packing width and codeword length is greater.
		test_encode_batch_helper::<PackedBinaryGhash4x128b>(1, 2, 0);
	}
}

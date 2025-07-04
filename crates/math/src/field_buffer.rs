// Copyright 2025 Irreducible Inc.

use std::ops::{Deref, DerefMut};

use binius_field::{
	PackedField,
	packed::{get_packed_slice_unchecked, pack_slice, set_packed_slice_unchecked},
};
use bytemuck::zeroed_vec;

use crate::Error;

/// A power-of-two-sized buffer containing field elements, stored in packed fields.
///
/// This struct maintains an invariant: `self.values.len() == 1 <<
/// self.log_len.saturating_sub(P::LOG_WIDTH)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldBuffer<P: PackedField, Data: Deref<Target = [P]> = Box<[P]>> {
	/// log2 the number over elements in the buffer.
	log_len: usize,
	/// The packed values.
	values: Data,
}

impl<P: PackedField> FieldBuffer<P> {
	/// Create a new FieldBuffer from a vector of values.
	///
	/// # Throws
	///
	/// * `PowerOfTwoLengthRequired` if the number of values is not a power of two.
	pub fn from_values(values: &[P::Scalar]) -> Result<Self, Error> {
		if !values.len().is_power_of_two() {
			return Err(Error::PowerOfTwoLengthRequired);
		}

		let log_len = values.len().ilog2() as usize;
		let packed_values = pack_slice(values);
		Ok(Self {
			log_len,
			values: packed_values.into_boxed_slice(),
		})
	}

	/// Create a new [`FieldBuffer`] of zeros with the given log_len.
	pub fn zeros(log_len: usize) -> Self {
		let packed_len = 1 << log_len.saturating_sub(P::LOG_WIDTH);
		let values = zeroed_vec(packed_len).into_boxed_slice();
		Self { log_len, values }
	}
}

#[allow(clippy::len_without_is_empty)]
impl<P: PackedField, Data: Deref<Target = [P]>> FieldBuffer<P, Data> {
	/// Create a new FieldBuffer from a slice of packed values.
	///
	/// # Throws
	///
	/// * `PowerOfTwoLengthRequired` if the implied number of field elements is not a power of two.
	pub fn new(log_len: usize, values: Data) -> Result<Self, Error> {
		let expected_packed_len = 1 << log_len.saturating_sub(P::LOG_WIDTH);
		if values.len() != expected_packed_len {
			return Err(Error::IncorrectArgumentLength {
				arg: "values".to_string(),
				expected: expected_packed_len,
			});
		}
		Ok(Self { log_len, values })
	}

	/// Returns log2 the number of field elements.
	pub fn log_len(&self) -> usize {
		self.log_len
	}

	/// Returns the number of field elements.
	pub fn len(&self) -> usize {
		1 << self.log_len
	}

	/// Borrows the buffer as a [`FieldSlice`].
	pub fn to_ref(&self) -> FieldSlice<'_, P> {
		FieldBuffer {
			log_len: self.log_len,
			values: &self.values,
		}
	}

	/// Get a field element at the given index.
	///
	/// # Throws
	///
	/// * `Error::ArgumentRangeError` if the index is out of bounds.
	pub fn get(&mut self, index: usize) -> Result<P::Scalar, Error> {
		if index >= self.len() {
			return Err(Error::ArgumentRangeError {
				arg: "index".to_string(),
				range: 0..self.len(),
			});
		}

		// Safety: bound check on index performed above. The buffer length is at least
		// `self.len() >> P::LOG_WIDTH` by struct invariant.
		let val = unsafe { get_packed_slice_unchecked(&self.values, index) };
		Ok(val)
	}

	/// Split the buffer into chunks of size `2^log_chunk_size`.
	///
	/// # Errors
	///
	/// * [`Error::ArgumentRangeError`] if `log_chunk_size > log_len`.
	pub fn chunks(
		&self,
		log_chunk_size: usize,
	) -> Result<impl Iterator<Item = FieldSlice<'_, P>>, Error> {
		if log_chunk_size > self.log_len {
			return Err(Error::ArgumentRangeError {
				arg: "log_chunk_size".to_string(),
				range: 0..self.log_len + 1,
			});
		}

		let packed_chunk_size = 1 << log_chunk_size.saturating_sub(P::LOG_WIDTH);
		let chunks = self
			.values
			.chunks(packed_chunk_size)
			.map(move |chunk| FieldBuffer {
				log_len: log_chunk_size,
				values: chunk,
			});

		Ok(chunks)
	}
}

impl<P: PackedField, Data: DerefMut<Target = [P]>> FieldBuffer<P, Data> {
	/// Borrows the buffer mutably as a [`FieldSliceMut`].
	pub fn to_mut(&mut self) -> FieldSliceMut<'_, P> {
		FieldBuffer {
			log_len: self.log_len,
			values: &mut self.values,
		}
	}

	/// Set a field element at the given index.
	///
	/// # Throws
	///
	/// * `Error::ArgumentRangeError` if the index is out of bounds.
	pub fn set(&mut self, index: usize, value: P::Scalar) -> Result<(), Error> {
		if index >= self.len() {
			return Err(Error::ArgumentRangeError {
				arg: "index".to_string(),
				range: 0..self.len(),
			});
		}

		// Safety: bound check on index performed above. The buffer length is at least
		// `self.len() >> P::LOG_WIDTH` by struct invariant.
		unsafe { set_packed_slice_unchecked(&mut self.values, index, value) };
		Ok(())
	}

	/// Split the buffer into mutable chunks of size `2^log_chunk_size`.
	///
	/// # Throws
	///
	/// * [`Error::ArgumentRangeError`] if `log_chunk_size > log_len`.
	pub fn chunks_mut(
		&mut self,
		log_chunk_size: usize,
	) -> Result<impl Iterator<Item = FieldSliceMut<'_, P>>, Error> {
		if log_chunk_size > self.log_len {
			return Err(Error::ArgumentRangeError {
				arg: "log_chunk_size".to_string(),
				range: 0..self.log_len + 1,
			});
		}

		let packed_chunk_size = 1 << log_chunk_size.saturating_sub(P::LOG_WIDTH);
		let chunks = self
			.values
			.chunks_mut(packed_chunk_size)
			.map(move |chunk| FieldBuffer {
				log_len: log_chunk_size,
				values: chunk,
			});

		Ok(chunks)
	}
}

impl<P: PackedField, Data: Deref<Target = [P]>> AsRef<[P]> for FieldBuffer<P, Data> {
	fn as_ref(&self) -> &[P] {
		&self.values
	}
}

impl<P: PackedField, Data: DerefMut<Target = [P]>> AsMut<[P]> for FieldBuffer<P, Data> {
	fn as_mut(&mut self) -> &mut [P] {
		&mut self.values
	}
}

/// Alias for a field buffer over a borrowed slice.
pub type FieldSlice<'a, P> = FieldBuffer<P, &'a [P]>;

/// Alias for a field buffer over a mutably borrowed slice.
pub type FieldSliceMut<'a, P> = FieldBuffer<P, &'a mut [P]>;

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField64b, Field, PackedBinaryField4x64b};

	use super::*;

	type F = BinaryField64b;
	type P = PackedBinaryField4x64b;

	#[test]
	fn test_zeros() {
		// Make a buffer with `zeros()` and check that all elements are zero.
		// Test with log_len >= LOG_WIDTH
		let mut buffer = FieldBuffer::<P>::zeros(6); // 64 elements
		assert_eq!(buffer.log_len(), 6);
		assert_eq!(buffer.len(), 64);

		// Check all elements are zero
		for i in 0..64 {
			assert_eq!(buffer.get(i).unwrap(), F::ZERO);
		}

		// Test with log_len < LOG_WIDTH
		let mut buffer = FieldBuffer::<P>::zeros(1); // 2 elements
		assert_eq!(buffer.log_len(), 1);
		assert_eq!(buffer.len(), 2);

		// Check all elements are zero
		for i in 0..2 {
			assert_eq!(buffer.get(i).unwrap(), F::ZERO);
		}
	}

	#[test]
	fn test_from_values_below_packing_width() {
		// Make a buffer using `from_values()`, where the number of scalars is below the packing
		// width
		// P::LOG_WIDTH = 2, so P::WIDTH = 4
		let values = vec![F::new(1), F::new(2)]; // 2 elements < 4
		let mut buffer = FieldBuffer::<P>::from_values(&values).unwrap();

		assert_eq!(buffer.log_len(), 1); // log2(2) = 1
		assert_eq!(buffer.len(), 2);

		// Verify the values
		assert_eq!(buffer.get(0).unwrap(), F::new(1));
		assert_eq!(buffer.get(1).unwrap(), F::new(2));
	}

	#[test]
	fn test_from_values_above_packing_width() {
		// Make a buffer using `from_values()`, where the number of scalars is above the packing
		// width
		// P::LOG_WIDTH = 2, so P::WIDTH = 4
		let values: Vec<F> = (0..16).map(F::new).collect(); // 16 elements > 4
		let mut buffer = FieldBuffer::<P>::from_values(&values).unwrap();

		assert_eq!(buffer.log_len(), 4); // log2(16) = 4
		assert_eq!(buffer.len(), 16);

		// Verify all values
		for i in 0..16 {
			assert_eq!(buffer.get(i).unwrap(), F::new(i as u64));
		}
	}

	#[test]
	fn test_from_values_non_power_of_two() {
		// Fail to make a buffer using `from_values()`, where the number of scalars is not a power
		// of two
		let values: Vec<F> = (0..7).map(F::new).collect(); // 7 is not a power of two
		let result = FieldBuffer::<P>::from_values(&values);

		assert!(matches!(result, Err(Error::PowerOfTwoLengthRequired)));

		// Also test with 0 elements
		let values: Vec<F> = vec![];
		let result = FieldBuffer::<P>::from_values(&values);
		assert!(matches!(result, Err(Error::PowerOfTwoLengthRequired)));
	}

	#[test]
	fn test_new_below_packing_width() {
		// Make a buffer using `new()`, where the number of scalars is below the packing
		// width
		// P::LOG_WIDTH = 2, so P::WIDTH = 4
		// For log_len = 1 (2 elements), we need 1 packed value
		let mut packed_values = vec![P::default()];
		let mut buffer = FieldBuffer::new(1, packed_values.as_mut_slice()).unwrap();

		assert_eq!(buffer.log_len(), 1);
		assert_eq!(buffer.len(), 2);

		// Set and verify values
		buffer.set(0, F::new(10)).unwrap();
		buffer.set(1, F::new(20)).unwrap();
		assert_eq!(buffer.get(0).unwrap(), F::new(10));
		assert_eq!(buffer.get(1).unwrap(), F::new(20));
	}

	#[test]
	fn test_new_above_packing_width() {
		// Make a buffer using `new()`, where the number of scalars is above the packing
		// width
		// P::LOG_WIDTH = 2, so P::WIDTH = 4
		// For log_len = 4 (16 elements), we need 4 packed values
		let mut packed_values = vec![P::default(); 4];
		let mut buffer = FieldBuffer::new(4, packed_values.as_mut_slice()).unwrap();

		assert_eq!(buffer.log_len(), 4);
		assert_eq!(buffer.len(), 16);

		// Set and verify values
		for i in 0..16 {
			buffer.set(i, F::new(i as u64 * 10)).unwrap();
		}
		for i in 0..16 {
			assert_eq!(buffer.get(i).unwrap(), F::new(i as u64 * 10));
		}
	}

	#[test]
	fn test_new_non_power_of_two() {
		// Fail to make a buffer using `new()`, where the number of scalars is not a power of two
		// For log_len = 4 (16 elements), we need 4 packed values
		// Provide wrong number of packed values
		let packed_values = vec![P::default(); 3]; // Wrong: should be 4
		let result = FieldBuffer::new(4, packed_values.as_slice());

		assert!(matches!(result, Err(Error::IncorrectArgumentLength { .. })));

		// Another test with too many packed values
		let packed_values = vec![P::default(); 5]; // Wrong: should be 4
		let result = FieldBuffer::new(4, packed_values.as_slice());

		assert!(matches!(result, Err(Error::IncorrectArgumentLength { .. })));
	}

	#[test]
	fn test_get_set() {
		let mut buffer = FieldBuffer::<P>::zeros(3); // 8 elements

		// Set some values
		for i in 0..8 {
			buffer.set(i, F::new(i as u64)).unwrap();
		}

		// Get them back
		for i in 0..8 {
			assert_eq!(buffer.get(i).unwrap(), F::new(i as u64));
		}

		// Test out of bounds
		assert!(buffer.get(8).is_err());
		assert!(buffer.set(8, F::new(0)).is_err());
	}

	#[test]
	fn test_chunks() {
		let values: Vec<F> = (0..16).map(F::new).collect();
		let buffer = FieldBuffer::<P>::from_values(&values).unwrap();

		// Split into 4 chunks of size 4
		let chunks: Vec<_> = buffer.chunks(2).unwrap().collect();
		assert_eq!(chunks.len(), 4);

		for (chunk_idx, mut chunk) in chunks.into_iter().enumerate() {
			assert_eq!(chunk.len(), 4);
			for i in 0..4 {
				let expected = F::new((chunk_idx * 4 + i) as u64);
				assert_eq!(chunk.get(i).unwrap(), expected);
			}
		}

		// Test invalid chunk size
		assert!(buffer.chunks(5).is_err());
	}

	#[test]
	fn test_chunks_mut() {
		let mut buffer = FieldBuffer::<P>::zeros(4); // 16 elements

		// Modify via chunks
		let mut chunks: Vec<_> = buffer.chunks_mut(2).unwrap().collect();
		assert_eq!(chunks.len(), 4);

		for (chunk_idx, chunk) in chunks.iter_mut().enumerate() {
			for i in 0..chunk.len() {
				chunk.set(i, F::new((chunk_idx * 10 + i) as u64)).unwrap();
			}
		}

		// Verify modifications
		for chunk_idx in 0..4 {
			for i in 0..4 {
				let expected = F::new((chunk_idx * 10 + i) as u64);
				assert_eq!(buffer.get(chunk_idx * 4 + i).unwrap(), expected);
			}
		}
	}

	#[test]
	fn test_to_ref_to_mut() {
		let mut buffer = FieldBuffer::<P>::zeros(3);

		// Test to_ref
		let slice_ref = buffer.to_ref();
		assert_eq!(slice_ref.len(), buffer.len());
		assert_eq!(slice_ref.log_len(), buffer.log_len());

		// Test to_mut
		let mut slice_mut = buffer.to_mut();
		slice_mut.set(0, F::new(123)).unwrap();
		assert_eq!(buffer.get(0).unwrap(), F::new(123));
	}
}

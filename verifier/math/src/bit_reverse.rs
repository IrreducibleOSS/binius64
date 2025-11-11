// Copyright 2025 Irreducible Inc.

use binius_field::{PackedField, square_transpose};
use binius_utils::checked_arithmetics::log2_strict_usize;
use bytemuck::zeroed_vec;

use crate::field_buffer::FieldSliceMut;

/// Reverses the low `bits` bits of an unsigned integer.
///
/// # Arguments
///
/// * `x` - The value whose bits to reverse
/// * `bits` - The number of low-order bits to reverse
///
/// # Returns
///
/// The value with its low `bits` bits reversed
pub fn reverse_bits(x: usize, bits: u32) -> usize {
	x.reverse_bits().unbounded_shr(usize::BITS - bits)
}

/// Applies a bit-reversal permutation to packed field elements in a buffer.
///
/// This function permutes the field elements such that element at index `i` is moved to
/// index `reverse_bits(i, log_len)`. The permutation is performed in-place and correctly
/// handles packed field representations.
///
/// This is a single-threaded implementation.
///
/// # Arguments
///
/// * `buffer` - Mutable slice of packed field elements to permute
pub fn bit_reverse_packed<P: PackedField>(mut buffer: FieldSliceMut<P>) {
	let log_len = buffer.log_len();
	if log_len < 2 * P::LOG_WIDTH {
		return bit_reverse_packed_naive(buffer);
	}

	let bits = (log_len - P::LOG_WIDTH) as u32;
	let data = buffer.as_mut();

	let mut tmp = zeroed_vec::<P>(P::WIDTH);
	for i in 0..1 << (log_len - 2 * P::LOG_WIDTH) {
		for j in 0..P::WIDTH {
			tmp[j] = data[reverse_bits(j, bits) | i];
		}
		square_transpose(P::LOG_WIDTH, &mut tmp).expect("pre-conditions satisfied");
		for j in 0..P::WIDTH {
			data[reverse_bits(j, bits) | i] = tmp[j];
		}
	}

	for chunk in data.chunks_mut(1 << (log_len - 2 * P::LOG_WIDTH)) {
		bit_reverse_indices(chunk);
	}
}

/// Applies a bit-reversal permutation to packed field elements using a simple algorithm.
///
/// This is a straightforward reference implementation that directly swaps field elements
/// according to the bit-reversal permutation. It serves as a baseline for correctness
/// testing of optimized implementations.
///
/// # Arguments
///
/// * `buffer` - Mutable slice of packed field elements to permute
fn bit_reverse_packed_naive<P: PackedField>(mut buffer: FieldSliceMut<P>) {
	let bits = buffer.log_len() as u32;
	for i in 0..buffer.len() {
		let i_rev = reverse_bits(i, bits);
		if i < i_rev {
			let tmp = buffer.get(i);
			buffer.set(i, buffer.get(i_rev));
			buffer.set(i_rev, tmp);
		}
	}
}

/// Applies a bit-reversal permutation to elements in a slice.
///
/// This function permutes the elements such that element at index `i` is moved to
/// index `reverse_bits(i, log2(length))`. The permutation is performed in-place
/// by swapping elements.
///
/// This is a single-threaded implementation.
///
/// # Arguments
///
/// * `buffer` - Mutable slice of elements to permute
///
/// # Panics
///
/// Panics if the buffer length is not a power of two.
pub fn bit_reverse_indices<T>(buffer: &mut [T]) {
	let bits = log2_strict_usize(buffer.len()) as u32;
	for i in 0..buffer.len() {
		let i_rev = reverse_bits(i, bits);
		if i < i_rev {
			buffer.swap(i, i_rev);
		}
	}
}

#[cfg(test)]
mod tests {
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::test_utils::{Packed128b, random_field_buffer};

	// For Packed128b (PackedBinaryGhash4x128b), LOG_WIDTH = 2, so 2 * LOG_WIDTH = 4
	// Test three cases around the threshold where bit_reverse_packed switches between
	// naive and optimized implementations
	#[rstest::rstest]
	#[case::below_threshold(3)] // log_d < 2 * P::LOG_WIDTH
	#[case::at_threshold(4)] // log_d == 2 * P::LOG_WIDTH
	#[case::above_threshold(8)] // log_d > 2 * P::LOG_WIDTH
	fn test_bit_reverse_packed_equivalence(#[case] log_d: usize) {
		let mut rng = StdRng::seed_from_u64(0);

		let data_orig = random_field_buffer::<Packed128b>(&mut rng, log_d);

		let mut data_optimized = data_orig.clone();
		let mut data_naive = data_orig.clone();

		bit_reverse_packed(data_optimized.to_mut());
		bit_reverse_packed_naive(data_naive.to_mut());

		assert_eq!(data_optimized, data_naive, "Mismatch at log_d={}", log_d);
	}
}

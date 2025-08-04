use binius_core::word::Word;

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

/// Verifies that a slice is correctly extracted from an input byte array.
///
/// This circuit validates that `slice` contains exactly the bytes from
/// `input` starting at `offset` for `len_slice` bytes.
///
/// # Limitations
/// All size and offset values must fit within 32 bits. Specifically:
/// - `len_input` must be < 2^32
/// - `len_slice` must be < 2^32
/// - `offset` must be < 2^32
/// - `offset + len_slice` must be < 2^32
///
/// These limitations are enforced by the circuit constraints.
pub struct Slice {
	pub len_input: Wire,
	pub len_slice: Wire,
	pub input: Vec<Wire>,
	pub slice: Vec<Wire>,
	pub offset: Wire,
}

impl Slice {
	/// Creates a new slice verifier circuit.
	///
	/// # Arguments
	/// * `b` - Circuit builder
	/// * `max_n_input` - Maximum input size in bytes (must be multiple of 8)
	/// * `max_n_slice` - Maximum slice size in bytes (must be multiple of 8)
	/// * `len_input` - Actual input size in bytes
	/// * `len_slice` - Actual slice size in bytes
	/// * `input` - Input array packed as words (8 bytes per word)
	/// * `slice` - Slice array packed as words (8 bytes per word)
	/// * `offset` - Byte offset where slice starts
	///
	/// # Panics
	/// * If max_n_input is not a multiple of 8
	/// * If max_n_slice is not a multiple of 8
	/// * If max_n_input >= 2^32
	/// * If max_n_slice >= 2^32
	/// * If input.len() != max_n_input / 8
	/// * If slice.len() != max_n_slice / 8
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		b: &CircuitBuilder,
		max_n_input: usize,
		max_n_slice: usize,
		len_input: Wire,
		len_slice: Wire,
		input: Vec<Wire>,
		slice: Vec<Wire>,
		offset: Wire,
	) -> Self {
		assert_eq!(max_n_input % 8, 0, "max_n_input must be multiple of 8");
		assert_eq!(max_n_slice % 8, 0, "max_n_slice must be multiple of 8");
		assert_eq!(input.len(), max_n_input / 8, "input.len() must equal max_n_input / 8");
		assert_eq!(slice.len(), max_n_slice / 8, "slice.len() must equal max_n_slice / 8");

		// Static assertions to ensure maximum sizes fit within 32 bits
		assert!(max_n_input < (1u64 << 32) as usize, "max_n_input must be < 2^32");
		assert!(max_n_slice < (1u64 << 32) as usize, "max_n_slice must be < 2^32");

		// Ensure all values fit in 32 bits to prevent overflow in iadd_32
		// Check upper 32 bits are zero by ANDing with 0xFFFFFFFF00000000
		let upper_32_mask = Word(0xFFFFFFFF00000000);
		b.assert_band_0("offset_32bit", offset, upper_32_mask);
		b.assert_band_0("len_slice_32bit", len_slice, upper_32_mask);
		b.assert_band_0("len_input_32bit", len_input, upper_32_mask);

		// Verify bounds: offset + len_slice <= len_input
		let offset_plus_len_slice = b.iadd_32(offset, len_slice);
		let overflow = b.icmp_ult(len_input, offset_plus_len_slice);
		b.assert_0("bounds_check", overflow);

		// Decompose offset = word_offset * 8 + byte_offset
		let word_offset = b.shr(offset, 3); // offset / 8
		let byte_offset = b.band(offset, b.add_constant(Word(7))); // offset % 8

		// Check if aligned (byte_offset == 0)
		let is_aligned_mask = b.icmp_eq(byte_offset, b.add_constant(Word::ZERO));

		// Go over every word in the slice and check that it was copied from the input byte string
		// correctly.
		for (slice_idx, &slice_word) in slice.iter().enumerate() {
			let b = b.subcircuit(format!("slice_word[{slice_idx}]"));

			// Check if this word is within the actual slice
			let word_start = b.add_constant(Word((slice_idx * 8) as u64));
			let word_end = b.add_constant(Word(((slice_idx + 1) * 8) as u64));
			let word_fully_valid_mask = b.icmp_ult(word_end, len_slice);
			let word_partially_valid_mask = b.icmp_ult(word_start, len_slice);

			// Calculate which input word(s) we need
			let input_word_idx = b.iadd_32(word_offset, b.add_constant(Word(slice_idx as u64)));

			let extracted_word =
				extract_word(&b, &input, input_word_idx, byte_offset, is_aligned_mask);

			// Handle partial last word
			if slice_idx == slice.len() - 1 {
				// Calculate valid bytes in last word
				let last_word_offset = slice_idx * 8;
				let neg_offset = b.add_constant(Word((-(last_word_offset as i64)) as u64));
				let valid_bytes = b.iadd_32(len_slice, neg_offset);
				let mask = create_byte_mask(&b, valid_bytes);

				let masked_slice = b.band(slice_word, mask);
				let masked_extracted = b.band(extracted_word, mask);

				b.assert_eq_cond(
					"partial_word",
					masked_slice,
					masked_extracted,
					word_partially_valid_mask,
				);
			} else {
				// Full word comparison
				b.assert_eq_cond("full_word", slice_word, extracted_word, word_fully_valid_mask);
			}
		}

		Slice {
			len_input,
			len_slice,
			input,
			slice,
			offset,
		}
	}

	/// Populate the len_input wire with the actual input size in bytes
	pub fn populate_len_input(&self, w: &mut WitnessFiller, len_input: usize) {
		w[self.len_input] = Word(len_input as u64);
	}

	/// Populate the len_slice wire with the actual slice size in bytes
	pub fn populate_len_slice(&self, w: &mut WitnessFiller, len_slice: usize) {
		w[self.len_slice] = Word(len_slice as u64);
	}

	/// Populate the input array from a byte slice
	///
	/// # Panics
	/// Panics if input.len() > max_n_input (the maximum size specified during construction)
	pub fn populate_input(&self, w: &mut WitnessFiller, input: &[u8]) {
		let max_n_input = self.input.len() * 8;
		assert!(
			input.len() <= max_n_input,
			"input length {} exceeds maximum {}",
			input.len(),
			max_n_input
		);

		// Pack bytes into words
		for (i, chunk) in input.chunks(8).enumerate() {
			if i < self.input.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << (j * 8);
				}
				w[self.input[i]] = Word(word);
			}
		}

		// Zero out remaining words
		for i in input.len().div_ceil(8)..self.input.len() {
			w[self.input[i]] = Word::ZERO;
		}
	}

	/// Populate the slice array from a byte slice
	///
	/// # Panics
	/// Panics if slice.len() > max_n_slice (the maximum size specified during construction)
	pub fn populate_slice(&self, w: &mut WitnessFiller, slice: &[u8]) {
		let max_n_slice = self.slice.len() * 8;
		assert!(
			slice.len() <= max_n_slice,
			"slice length {} exceeds maximum {}",
			slice.len(),
			max_n_slice
		);

		// Pack bytes into words
		for (i, chunk) in slice.chunks(8).enumerate() {
			if i < self.slice.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << (j * 8);
				}
				w[self.slice[i]] = Word(word);
			}
		}

		// Zero out remaining words
		for i in slice.len().div_ceil(8)..self.slice.len() {
			w[self.slice[i]] = Word::ZERO;
		}
	}

	/// Populate the offset wire
	pub fn populate_offset(&self, w: &mut WitnessFiller, offset: usize) {
		w[self.offset] = Word(offset as u64);
	}
}

/// Extracts a word from the input array at the specified word index and byte offset.
///
/// This function handles both aligned and unaligned word extraction:
/// - **Aligned** (byte_offset = 0): Directly selects the word at `word_idx`
/// - **Unaligned** (byte_offset = 1-7): Combines bytes from two adjacent words
///
/// # Arguments
/// * `b` - Circuit builder
/// * `input` - Array of input words to extract from
/// * `word_idx` - Index of the word to extract
/// * `byte_offset` - Byte offset within the word (0-7)
/// * `is_aligned_mask` - Wire that's all-1 if byte_offset is 0, 0 otherwise
///
/// # Returns
/// A wire containing the extracted 8-byte word
fn extract_word(
	b: &CircuitBuilder,
	input: &[Wire],
	word_idx: Wire,
	byte_offset: Wire,
	is_aligned_mask: Wire,
) -> Wire {
	// Aligned case: directly select the word
	let mut aligned_word = b.add_constant(Word::ZERO);
	for (i, &word) in input.iter().enumerate() {
		let i_wire = b.add_constant(Word(i as u64));
		let is_this_word = b.icmp_eq(word_idx, i_wire);
		let masked = b.band(word, is_this_word);
		aligned_word = b.bor(aligned_word, masked);
	}

	// Unaligned case: need to combine two adjacent words.
	//
	// First we extract both words: lo_word and hi_word. lo_word contains some bytes of the
	// slice we are looking for and the hi_word contains the rest.
	//
	// Once we found that we shift those s.t. when we bitwise-or them together we get a full
	// word. That's going to be our `unaligned_word`.
	let next_word_idx = b.iadd_32(word_idx, b.add_constant(Word(1)));
	let mut lo_word = b.add_constant(Word::ZERO);
	let mut hi_word = b.add_constant(Word::ZERO);
	for (i, &word) in input.iter().enumerate() {
		let i_wire = b.add_constant(Word(i as u64));
		let is_lo = b.icmp_eq(word_idx, i_wire);
		let is_hi = b.icmp_eq(next_word_idx, i_wire);

		let masked_low = b.band(word, is_lo);
		let masked_high = b.band(word, is_hi);

		lo_word = b.bor(lo_word, masked_low);
		hi_word = b.bor(hi_word, masked_high);
	}
	let mut unaligned_word = b.add_constant(Word::ZERO);
	for offset in 1..8 {
		let offset_wire = b.add_constant(Word(offset as u64));
		let is_this_offset = b.icmp_eq(byte_offset, offset_wire);

		let lo_shifted = b.shr(lo_word, (offset * 8) as u32);
		let hi_shifted = b.shl(hi_word, ((8 - offset) * 8) as u32);
		let combined = b.bor(lo_shifted, hi_shifted);

		let masked = b.band(combined, is_this_offset);
		unaligned_word = b.bor(unaligned_word, masked);
	}

	// Finally select the aligned or unaligned word.
	let aligned_masked = b.band(aligned_word, is_aligned_mask);
	let unaligned_masked = b.band(unaligned_word, b.bnot(is_aligned_mask));
	b.bor(aligned_masked, unaligned_masked)
}

/// Creates a byte mask with the first `n_bytes` bytes set to 0xFF and remaining bytes to 0x00.
///
/// This function generates masks for partial word validation:
/// - n_bytes = 0: 0x0000000000000000
/// - n_bytes = 1: 0x00000000000000FF
/// - n_bytes = 2: 0x000000000000FFFF
/// - ...
/// - n_bytes = 8: 0xFFFFFFFFFFFFFFFF
///
/// # Arguments
/// * `b` - Circuit builder
/// * `n_bytes` - Number of bytes to include in the mask (0-8)
///
/// # Returns
/// A wire containing the byte mask
fn create_byte_mask(b: &CircuitBuilder, n_bytes: Wire) -> Wire {
	let mut byte_mask = b.add_constant(Word::ZERO);

	for i in 0..=8 {
		let i_wire = b.add_constant(Word(i as u64));
		let is_this_count_mask = b.icmp_eq(n_bytes, i_wire);

		let mask_value = b.add_constant_64(if i == 0 {
			0
		} else if i == 8 {
			u64::MAX
		} else {
			(1 << (i * 8)) - 1
		});

		let this_mask = b.band(mask_value, is_this_count_mask);
		byte_mask = b.bor(byte_mask, this_mask);
	}

	byte_mask
}

#[cfg(test)]
mod tests {
	use super::{CircuitBuilder, Slice, Wire, Word};
	use crate::constraint_verifier::verify_constraints;

	#[test]
	fn test_aligned_slice() {
		let b = CircuitBuilder::new();

		// Test case: 16-byte input, 8-byte slice at offset 0
		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);

		let circuit = b.build();

		// Test with actual values
		let mut filler = circuit.new_witness_filler();

		verifier.populate_len_input(&mut filler, 16);
		verifier.populate_len_slice(&mut filler, 8);
		verifier.populate_offset(&mut filler, 0);

		// Input: 16 bytes
		let input_data = [
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
			0x0e, 0x0f,
		];
		verifier.populate_input(&mut filler, &input_data);

		// Slice: first 8 bytes of input
		let slice_data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
		verifier.populate_slice(&mut filler, &slice_data);

		// Fill the circuit - this should succeed
		circuit.populate_wire_witness(&mut filler).unwrap();

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_unaligned_slice() {
		let b = CircuitBuilder::new();

		// Test case: 16-byte input, 8-byte slice at offset 3
		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);

		let circuit = b.build();

		// Test with actual values
		let mut filler = circuit.new_witness_filler();

		// Set up test data using populate methods
		verifier.populate_len_input(&mut filler, 16);
		verifier.populate_len_slice(&mut filler, 8);
		verifier.populate_offset(&mut filler, 3);

		// Input: 16 bytes
		let input_data = [
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
			0x0e, 0x0f,
		];
		verifier.populate_input(&mut filler, &input_data);

		// Slice at offset 3: bytes 3-10
		// This should be: 03 04 05 06 07 08 09 0a
		let slice_data = [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
		verifier.populate_slice(&mut filler, &slice_data);

		// Fill the circuit - this should succeed
		circuit.populate_wire_witness(&mut filler).unwrap();

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_bounds_check() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);

		let circuit = b.build();

		// Test with values that should fail bounds check
		let mut filler = circuit.new_witness_filler();

		// Set up test data that violates bounds using populate methods
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 8);
		verifier.populate_offset(&mut filler, 5);

		// Fill dummy data
		let dummy_input = vec![0u8; 10];
		let dummy_slice = vec![0u8; 8];
		verifier.populate_input(&mut filler, &dummy_input);
		verifier.populate_slice(&mut filler, &dummy_slice);

		// This should fail the bounds check
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err());
	}

	#[test]
	fn test_bounds_check_edge_case() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test exact boundary: offset + len_slice == len_input (should be valid)
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 5);
		verifier.populate_offset(&mut filler, 5);

		// Create matching data
		let input_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
		let slice_data = vec![5, 6, 7, 8, 9];

		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &slice_data);

		// This should succeed since offset(5) + len_slice(5) == len_input(10)
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_ok(), "Valid boundary case should succeed");

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_empty_slice() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test with len_slice = 0
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 0);
		verifier.populate_offset(&mut filler, 5);

		let input_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &[]);

		// Empty slice should be valid
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_ok(), "Empty slice should be valid");

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_mismatched_slice_content() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test with wrong slice content
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 5);
		verifier.populate_offset(&mut filler, 2);

		let input_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
		// Wrong slice data - should be [2, 3, 4, 5, 6] but we provide [0, 1, 2, 3, 4]
		let wrong_slice_data = vec![0, 1, 2, 3, 4];

		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &wrong_slice_data);

		// This should fail
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "Mismatched slice content should fail");
	}

	#[test]
	fn test_offset_at_end() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test offset at end with empty slice
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 0);
		verifier.populate_offset(&mut filler, 10);

		let input_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &[]);

		// This should succeed - empty slice at end
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_ok(), "Empty slice at end should be valid");

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_multiple_byte_extraction_paths() {
		// This test verifies that byte extraction works correctly for all paths
		let b = CircuitBuilder::new();

		let max_n_input = 24; // 3 words
		let max_n_slice = 8; // 1 word

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test extraction from each word with different offsets
		for word_idx in 0..3 {
			for byte_offset in 0..8 {
				let offset_val = word_idx * 8 + byte_offset;
				if offset_val + 8 > 24 {
					continue;
				}

				let mut filler = circuit.new_witness_filler();
				verifier.populate_len_input(&mut filler, 24);
				verifier.populate_len_slice(&mut filler, 8);
				verifier.populate_offset(&mut filler, offset_val);

				// Create distinct pattern for each byte
				let input_data: Vec<u8> = (0..24).map(|i| i as u8).collect();
				let slice_data: Vec<u8> = input_data[offset_val..offset_val + 8].to_vec();

				verifier.populate_input(&mut filler, &input_data);
				verifier.populate_slice(&mut filler, &slice_data);

				let result = circuit.populate_wire_witness(&mut filler);
				assert!(
					result.is_ok(),
					"Extraction from word {word_idx} byte {byte_offset} failed"
				);

				// Verify constraints
				let cs = circuit.constraint_system();
				verify_constraints(cs, &filler.into_value_vec()).unwrap();
			}
		}
	}

	#[test]
	fn test_large_offset_overflow() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test with very large offset that should fail 32-bit check
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 5);

		// Try to set offset with upper 32 bits set
		// This tests that the circuit properly validates 32-bit constraints
		filler[offset] = Word(1u64 << 32); // Direct assignment to test constraint

		let input_data = vec![0u8; 10];
		let slice_data = vec![0u8; 5];
		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &slice_data);

		// This should fail the 32-bit check
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "Large offset should fail 32-bit check");
	}

	#[test]
	fn test_32bit_validation() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test multiple 32-bit constraint violations
		// Test 1: offset with bit 33 set
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 5);
		filler[offset] = Word(1u64 << 33);

		let input_data = vec![0u8; 10];
		let slice_data = vec![0u8; 5];
		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &slice_data);

		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "Offset with bit 33 set should fail");

		// Test 2: len_input with upper bits set
		let mut filler = circuit.new_witness_filler();
		filler[len_input] = Word(0xFFFFFFFF00000010); // Upper 32 bits set
		verifier.populate_len_slice(&mut filler, 5);
		verifier.populate_offset(&mut filler, 0);
		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &slice_data);

		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "len_input with upper 32 bits set should fail");

		// Test 3: len_slice with upper bits set
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		filler[len_slice] = Word(0x100000005); // Bit 32 set
		verifier.populate_offset(&mut filler, 0);
		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &slice_data);

		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "len_slice with upper bits set should fail");
	}

	#[test]
	fn test_edge_case_len_input_zero() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test empty input with empty slice at offset 0
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 0);
		verifier.populate_len_slice(&mut filler, 0);
		verifier.populate_offset(&mut filler, 0);

		// Empty arrays
		verifier.populate_input(&mut filler, &[]);
		verifier.populate_slice(&mut filler, &[]);

		// This should succeed - empty input with empty slice at offset 0
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_ok(), "Empty input with empty slice should succeed");

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_edge_case_len_input_zero_with_nonzero_slice() {
		let b = CircuitBuilder::new();

		let max_n_input = 16;
		let max_n_slice = 8;

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test empty input with non-empty slice
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 0);
		verifier.populate_len_slice(&mut filler, 5);
		verifier.populate_offset(&mut filler, 0);

		verifier.populate_input(&mut filler, &[]);
		verifier.populate_slice(&mut filler, &[1, 2, 3, 4, 5]);

		// This should fail - can't extract non-empty slice from empty input
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "Non-empty slice from empty input should fail");
	}

	#[test]
	fn test_padding_beyond_actual_data() {
		let b = CircuitBuilder::new();

		let max_n_input = 24; // 3 words
		let max_n_slice = 16; // 2 words

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		// Save wire references before moving vectors
		let input_wire_2 = input[2];
		let slice_wire_1 = slice[1];

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test with actual data smaller than allocated space
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 12); // 1.5 words
		verifier.populate_len_slice(&mut filler, 8); // 1 word
		verifier.populate_offset(&mut filler, 2);

		// Input: 12 bytes (will be padded to 3 words)
		let input_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
		verifier.populate_input(&mut filler, &input_data);

		// Slice at offset 2: bytes 2-9
		let slice_data = vec![2, 3, 4, 5, 6, 7, 8, 9];
		verifier.populate_slice(&mut filler, &slice_data);

		// Verify the circuit handles padding correctly
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_ok(), "Should handle data with padding correctly");

		// Also verify that padded words in input are zeroed
		assert_eq!(filler[input_wire_2], Word::ZERO, "Third input word should be zero");
		// Second slice word should also be zero since slice is only 1 word
		assert_eq!(filler[slice_wire_1], Word::ZERO, "Second slice word should be zero");

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(cs, &filler.into_value_vec()).unwrap();
	}
}

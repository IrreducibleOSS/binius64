use crate::{
	compiler::{CircuitBuilder, Wire},
	word::Word,
};

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

		// Check that offset + len_slice <= len_input
		let overflow = b.icmp_ult(len_input, offset_plus_len_slice);
		b.assert_0("bounds_check", overflow);

		// For each byte position in the slice, verify it matches the corresponding
		// byte in the input array
		for byte_idx in 0..max_n_slice {
			let b = b.subcircuit(format!("byte[{byte_idx}]"));

			// Check if this byte index is within the actual slice length
			let byte_idx_wire = b.add_constant(Word(byte_idx as u64));
			let within_slice = b.icmp_ult(byte_idx_wire, len_slice);

			// Calculate the source byte position: offset + byte_idx
			let source_pos = b.iadd_32(offset, byte_idx_wire);

			// ---- Extract source byte from input array
			//
			// We need to extract the byte at position source_pos from the input array.
			// Since input is packed as 8-byte words, we must:
			// 1. Calculate which word contains the byte: word_idx = source_pos / 8
			// 2. Calculate byte offset within that word: byte_offset = source_pos % 8
			// 3. Extract the byte from input[word_idx] at byte_offset
			//
			// However, we can't directly index arrays in circuits, so we use a multiplexer
			// pattern: extract from all possible positions and select the right one using masks.
			let word_idx = b.shr(source_pos, 3);
			let byte_offset = b.band(source_pos, b.add_constant(Word(7)));

			let mut extracted_byte = b.add_constant(Word::ZERO);

			// Outer loop: find which word contains our byte
			for i in 0..input.len() {
				let i_wire = b.add_constant(Word(i as u64));
				let is_correct_word = b.icmp_eq(word_idx, i_wire);

				// Inner loop: extract byte at all 8 positions, select the right one
				let mut byte_from_word = b.add_constant(Word::ZERO);

				for j in 0..8 {
					let j_wire = b.add_constant(Word(j as u64));
					let is_correct_offset = b.icmp_eq(byte_offset, j_wire);
					let extracted = b.extract_byte(input[i], j as u32);
					// Mask will be all-1s only when both word and offset match
					let mask = b.band(is_correct_word, is_correct_offset);
					let masked_byte = b.band(extracted, mask);
					byte_from_word = b.bor(byte_from_word, masked_byte);
				}

				extracted_byte = b.bor(extracted_byte, byte_from_word);
			}

			// Extract the corresponding byte from the slice array.
			// Since we know byte_idx at compile time, we can directly calculate indices.
			let slice_word_idx = byte_idx / 8;
			let slice_byte_offset = byte_idx % 8;
			let slice_byte = b.extract_byte(slice[slice_word_idx], slice_byte_offset as u32);

			// Conditionally assert equality if within slice bounds
			b.assert_eq_cond(
				"within_slice_bounds".to_string(),
				extracted_byte,
				slice_byte,
				within_slice,
			);
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
	pub fn populate_len_input(&self, w: &mut crate::compiler::WitnessFiller, len_input: usize) {
		w[self.len_input] = Word(len_input as u64);
	}

	/// Populate the len_slice wire with the actual slice size in bytes
	pub fn populate_len_slice(&self, w: &mut crate::compiler::WitnessFiller, len_slice: usize) {
		w[self.len_slice] = Word(len_slice as u64);
	}

	/// Populate the input array from a byte slice
	///
	/// # Panics
	/// Panics if input.len() > max_n_input (the maximum size specified during construction)
	pub fn populate_input(&self, w: &mut crate::compiler::WitnessFiller, input: &[u8]) {
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
	pub fn populate_slice(&self, w: &mut crate::compiler::WitnessFiller, slice: &[u8]) {
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
	pub fn populate_offset(&self, w: &mut crate::compiler::WitnessFiller, offset: usize) {
		w[self.offset] = Word(offset as u64);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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

		// Test with very large offset that could cause overflow
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 5);
		verifier.populate_offset(&mut filler, (1u64 << 32) as usize); // Large offset

		let input_data = vec![0u8; 10];
		let slice_data = vec![0u8; 5];
		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &slice_data);

		// This should fail bounds check
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "Large offset should fail bounds check");
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

		// Test with value that has upper 32 bits set (should fail 32-bit check)
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 10);
		verifier.populate_len_slice(&mut filler, 5);
		verifier.populate_offset(&mut filler, (1u64 << 33) as usize); // 2^33 has bit 33 set

		let input_data = vec![0u8; 10];
		let slice_data = vec![0u8; 5];
		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &slice_data);

		// This should fail the 32-bit check on offset
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "Values with upper 32 bits set should fail");
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

		// Test with len_input = 0
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 0);
		verifier.populate_len_slice(&mut filler, 0);
		verifier.populate_offset(&mut filler, 0);
		verifier.populate_input(&mut filler, &[]);
		verifier.populate_slice(&mut filler, &[]);

		// This should succeed - empty input with empty slice at offset 0
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_ok(), "Empty input with empty slice should succeed");
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

		// Test with len_input = 0 but len_slice > 0
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 0);
		verifier.populate_len_slice(&mut filler, 1);
		verifier.populate_offset(&mut filler, 0);
		verifier.populate_input(&mut filler, &[]);
		verifier.populate_slice(&mut filler, &[0]);

		// This should fail - can't have non-empty slice from empty input
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "Non-empty slice from empty input should fail");
	}

	#[test]
	fn test_padding_beyond_actual_data() {
		let b = CircuitBuilder::new();

		let max_n_input = 32; // 4 words
		let max_n_slice = 16; // 2 words

		let len_input = b.add_inout();
		let len_slice = b.add_inout();
		let offset = b.add_inout();

		let input: Vec<Wire> = (0..max_n_input / 8).map(|_| b.add_inout()).collect();
		let slice: Vec<Wire> = (0..max_n_slice / 8).map(|_| b.add_inout()).collect();

		let verifier =
			Slice::new(&b, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);
		let circuit = b.build();

		// Test with small actual data but accessing padded region
		let mut filler = circuit.new_witness_filler();
		verifier.populate_len_input(&mut filler, 5); // Only 5 bytes of actual data
		verifier.populate_len_slice(&mut filler, 3);
		verifier.populate_offset(&mut filler, 0);

		// Input: 5 bytes, but rest should be padded with zeros
		let input_data = vec![1, 2, 3, 4, 5];
		let slice_data = vec![1, 2, 3];

		verifier.populate_input(&mut filler, &input_data);
		verifier.populate_slice(&mut filler, &slice_data);

		// This should succeed
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_ok(), "Slice within actual data bounds should succeed");
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
			}
		}
	}
}

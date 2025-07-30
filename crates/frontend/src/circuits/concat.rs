use crate::{
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	word::Word,
};

/// A term in a concatenation - a variable-length byte string.
///
/// Terms represent the individual byte strings that will be concatenated together.
/// Each term knows its own maximum size, allowing for efficient circuit construction
/// with terms of different sizes.
///
/// # Wire Layout
///
/// - `len`: Single wire containing actual byte length (0 ≤ len ≤ max_len)
/// - `data`: Vector of wires, each containing 8 packed bytes in little-endian order
///
/// # Example
///
/// For a term with max_len=24 (3 words) containing "hello" (5 bytes):
/// - `len` = 5
/// - `data[0]` = 0x6F6C6C6568 (bytes 0-7: "hello" + 3 zero bytes)
/// - `data[1]` = 0x0000000000 (bytes 8-15: all zeros)
/// - `data[2]` = 0x0000000000 (bytes 16-23: all zeros)
///
/// # Requirements
///
/// - `max_len` must be a multiple of 8 (word-aligned)
/// - Actual length must satisfy: 0 ≤ len ≤ max_len
/// - Unused bytes in `data` must be zero
pub struct Term {
	/// The actual length of this term in bytes.
	///
	/// This is a witness wire that will be populated with the true length
	/// of the term's data. Must be ≤ max_len.
	pub len: Wire,
	/// The term's data as bytes packed into 64-bit words.
	///
	/// Each Wire represents 8 bytes packed in little-endian order:
	/// - Byte 0 goes in bits 0-7 (LSB)
	/// - Byte 1 goes in bits 8-15
	/// - ...
	/// - Byte 7 goes in bits 56-63 (MSB)
	///
	/// The vector length is exactly `max_len / 8`.
	pub data: Vec<Wire>,
	/// Maximum size of this term in bytes.
	pub max_len: usize,
}

impl Term {
	/// Populate the length wire with the actual term size in bytes.
	pub fn populate_len(&self, w: &mut WitnessFiller, len: usize) {
		w[self.len] = Word(len as u64);
	}

	/// Populate the term's data from a byte slice.
	///
	/// Packs the bytes into 64-bit words in little-endian order and ensures
	/// any unused words are zeroed out.
	///
	/// # Panics
	/// Panics if `data.len()` > `self.max_len`
	pub fn populate_data(&self, w: &mut WitnessFiller, data: &[u8]) {
		assert!(
			data.len() <= self.max_len,
			"term data length {} exceeds maximum {}",
			data.len(),
			self.max_len
		);

		// Pack bytes into 64-bit words (little-endian)
		for (i, chunk) in data.chunks(8).enumerate() {
			if i < self.data.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << (j * 8);
				}
				w[self.data[i]] = Word(word);
			}
		}

		// Zero out any remaining words beyond the actual data
		for i in data.len().div_ceil(8)..self.data.len() {
			w[self.data[i]] = Word::ZERO;
		}
	}
}

/// Verifies that a joined string is the concatenation of a list of terms.
///
/// This circuit validates that `joined` contains exactly the concatenation
/// of all provided terms in order.
pub struct Concat {
	/// The actual length of the concatenated result in bytes.
	///
	/// This wire will be constrained to equal the sum of all term lengths.
	pub len_joined: Wire,
	/// The concatenated data packed as 64-bit words.
	///
	/// Each wire contains 8 bytes in little-endian order. The vector length
	/// is `max_n_joined / 8` where max_n_joined is the maximum supported size.
	pub joined: Vec<Wire>,
	/// The list of terms to be concatenated.
	///
	/// Terms are concatenated in order: terms\[0\] || terms\[1\] || ... || terms\[n-1\]
	pub terms: Vec<Term>,
}

impl Concat {
	/// Creates a new concatenation verifier circuit.
	///
	/// # Arguments
	/// * `b` - Circuit builder for constructing constraints
	/// * `max_n_joined` - Maximum supported size of joined data in bytes (must be multiple of 8)
	/// * `len_joined` - Wire containing the actual joined size in bytes
	/// * `joined` - Joined array packed as 64-bit words (8 bytes per word)
	/// * `terms` - Vector of terms that should concatenate to form `joined`
	///
	/// # Panics
	/// * If `max_n_joined` is not a multiple of 8
	/// * If any term's `max_len` is not a multiple of 8
	/// * If `joined.len()` != `max_n_joined / 8`
	/// * If any term's `data.len()` != `term.max_len / 8`
	pub fn new(
		b: &CircuitBuilder,
		max_n_joined: usize,
		len_joined: Wire,
		joined: Vec<Wire>,
		terms: Vec<Term>,
	) -> Self {
		// Input validation
		//
		// Ensure all inputs meet the word-alignment requirements necessary for
		// efficient word-level processing.
		assert_eq!(max_n_joined % 8, 0, "max_n_joined must be multiple of 8");
		assert_eq!(joined.len(), max_n_joined / 8, "joined.len() must equal max_n_joined / 8");

		for (i, term) in terms.iter().enumerate() {
			assert_eq!(term.max_len % 8, 0, "term[{i}].max_len must be multiple of 8");
			assert_eq!(
				term.data.len(),
				term.max_len / 8,
				"term[{i}].data.len() must equal term.max_len / 8"
			);
		}

		// Algorithm overview
		//
		// Process terms sequentially, maintaining a running offset to track position
		// in the joined array. For each term, verify its data appears at the correct
		// location.
		//
		// The algorithm:
		// 1. Start with offset = 0
		// 2. For each term: a. Verify its data matches joined[offset : offset + term.len] b. Update
		//    offset += term.len
		// 3. Verify final offset equals total length
		//
		// Circuit constraints:
		// - No dynamic array indexing (use multiplexers instead)
		// - All operations must be on fixed-size data (hence word-level processing)
		// - Conditional operations use masking (condition & value)

		let mut offset = b.add_constant(Word::ZERO);

		// 1. Sequential term processing
		//
		// Process each term in order, verifying its data appears at the correct
		// position in the joined array.
		for (i, term) in terms.iter().enumerate() {
			let b = b.subcircuit(format!("term[{i}]"));

			// 2. Word-level verification for current term
			//
			// Process the term's data word by word (8 bytes at a time) for efficiency.
			for (word_idx, &term_word) in term.data.iter().enumerate() {
				let b = b.subcircuit(format!("word[{word_idx}]"));

				// Calculate this word's byte position within the term
				let word_byte_offset = word_idx * 8;
				let word_byte_offset_wire = b.add_constant(Word(word_byte_offset as u64));

				// 2a. Validity checks
				//
				// Determine if this word contains valid data based on the term's actual length.
				// A word is:
				// - Fully valid if all 8 bytes are within term.len
				// - Partially valid if it contains the last byte of the term
				// - Invalid if it's entirely beyond term.len
				let word_start = word_byte_offset_wire;
				let word_end = b.add_constant(Word((word_byte_offset + 8) as u64));
				let word_fully_valid = b.icmp_ult(word_end, term.len);
				let word_partially_valid = b.icmp_ult(word_start, term.len);

				// 2b. Global position calculation
				//
				// Calculate where this word should appear in the joined array.
				// This is the current offset plus the word's position within the term.
				let global_word_pos = b.iadd_32(offset, word_byte_offset_wire);

				// 2c. Extract corresponding data from joined array
				//
				// Extract the word from the joined array at the calculated position.
				// This handles both aligned (byte position % 8 == 0) and unaligned cases.
				let joined_data = extract_aligned_or_unaligned_word(&b, &joined, global_word_pos);

				// 3. Word comparison with proper masking
				if word_idx == term.data.len() - 1 {
					// 3a. Last word special case
					//
					// The last word might be partially valid (e.g., term with 13 bytes has
					// 5 valid bytes in its second word). We need to:
					// 1. Calculate how many bytes are valid (term.len - word_byte_offset)
					// 2. Create a mask for those bytes
					// 3. Compare only the masked portions
					//
					// Calculate valid bytes: term.len - word_byte_offset
					// Implement subtraction by adding the two's complement
					let neg_offset = b.add_constant(Word((-(word_byte_offset as i64)) as u64));
					let valid_bytes = b.iadd_32(term.len, neg_offset);
					let mask = create_byte_mask(&b, valid_bytes);
					let masked_term = b.band(term_word, mask);
					let masked_joined = b.band(joined_data, mask);
					b.assert_eq_cond(
						format!("partial_word[{word_idx}]"),
						masked_term,
						masked_joined,
						word_partially_valid,
					);
				} else {
					// 3b. Full word comparison
					//
					// For words that aren't the last word, all 8 bytes should match
					// if the word is within the term's actual length.
					b.assert_eq_cond(
						format!("full_word[{word_idx}]"),
						term_word,
						joined_data,
						word_fully_valid,
					);
				}
			}

			// 4. Update offset for next term
			//
			// After processing all words of the current term, advance the offset
			// by the term's actual length to position for the next term.
			offset = b.iadd_32(offset, term.len);
		}

		// 5. Final length verification
		//
		// The sum of all term lengths must equal the total joined length.
		// This ensures there's no extra data in the joined array.
		b.assert_eq("concat_length", offset, len_joined);

		Concat {
			len_joined,
			joined,
			terms,
		}
	}

	/// Populate the len_joined wire with the actual joined size in bytes.
	pub fn populate_len_joined(&self, w: &mut WitnessFiller, len_joined: usize) {
		w[self.len_joined] = Word(len_joined as u64);
	}

	/// Populate the joined array from a byte slice.
	///
	/// Packs the bytes into 64-bit words in little-endian order and ensures
	/// any unused words are zeroed out.
	///
	/// # Panics
	/// Panics if `joined.len()` > `max_n_joined` (the maximum size specified during construction)
	pub fn populate_joined(&self, w: &mut WitnessFiller, joined: &[u8]) {
		let max_n_joined = self.joined.len() * 8;
		assert!(
			joined.len() <= max_n_joined,
			"joined length {} exceeds maximum {}",
			joined.len(),
			max_n_joined
		);

		for (i, chunk) in joined.chunks(8).enumerate() {
			if i < self.joined.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << (j * 8);
				}
				w[self.joined[i]] = Word(word);
			}
		}

		for i in joined.len().div_ceil(8)..self.joined.len() {
			w[self.joined[i]] = Word::ZERO;
		}
	}
}

/// Extract a word from joined array at a byte position (may be unaligned).
///
/// This function extracts 8 bytes from the joined array starting at any byte position,
/// handling both aligned (position % 8 == 0) and unaligned cases.
///
/// # Circuit-Friendly Implementation
///
/// Since circuits don't support dynamic array indexing, we use multiplexer patterns:
/// - Test each possible word index and combine results with masking
/// - Handle all 8 possible byte offsets (0-7) explicitly
///
/// # Alignment Cases
///
/// ```text
/// Aligned (byte_pos % 8 == 0):
///   Word boundaries: |........|........|........|
///   Byte position:    ^
///   Result: One complete word
///
/// Unaligned (byte_pos % 8 != 0):
///   Word boundaries: |........|........|........|
///   Byte position:       ^
///   Result: Last part of word N + first part of word N+1
/// ```
///
/// # Algorithm
///
/// 1. Calculate word index: byte_pos / 8
/// 2. Calculate byte offset within word: byte_pos % 8
/// 3. If aligned (offset == 0): Select word at word_idx
/// 4. If unaligned: Combine two adjacent words with appropriate shifts
fn extract_aligned_or_unaligned_word(b: &CircuitBuilder, joined: &[Wire], byte_pos: Wire) -> Wire {
	// Calculate which word contains the starting byte and the offset within that word
	let word_idx = b.shr(byte_pos, 3); // byte_pos / 8
	let byte_offset = b.band(byte_pos, b.add_constant(Word(7))); // byte_pos % 8

	// Check if we're aligned to a word boundary
	let is_aligned = b.icmp_eq(byte_offset, b.add_constant(Word::ZERO));

	// Aligned case: directly select the word
	//
	// Use a multiplexer pattern to select the word at word_idx.
	// For each word in joined, check if its index matches word_idx.
	let mut aligned_word = b.add_constant(Word::ZERO);
	for (i, &word) in joined.iter().enumerate() {
		let i_wire = b.add_constant(Word(i as u64));
		let is_this_word = b.icmp_eq(word_idx, i_wire);
		// Multiplexer: if this is the target word, include it in the result
		let masked = b.band(word, is_this_word);
		aligned_word = b.bor(aligned_word, masked);
	}

	// Unaligned case: combine two adjacent words
	//
	// Example with offset=3:
	// Low word:  [A B C D E F G H]  High word: [I J K L M N O P]
	// We want:   [D E F G H I J K]
	// This is:   (low >> 24) | (high << 40)
	let next_word_idx = b.iadd_32(word_idx, b.add_constant(Word(1)));

	// Extract the two words we need using multiplexer patterns
	let mut low_word = b.add_constant(Word::ZERO);
	let mut high_word = b.add_constant(Word::ZERO);

	for (i, &word) in joined.iter().enumerate() {
		let i_wire = b.add_constant(Word(i as u64));
		let is_low = b.icmp_eq(word_idx, i_wire);
		let is_high = b.icmp_eq(next_word_idx, i_wire);

		let masked_low = b.band(word, is_low);
		let masked_high = b.band(word, is_high);

		low_word = b.bor(low_word, masked_low);
		high_word = b.bor(high_word, masked_high);
	}

	// Handle each possible byte offset (1-7)
	//
	// Since we can't use variable shifts in circuits, we handle each
	// offset explicitly and use a multiplexer to select the right one.
	let mut unaligned_word = b.add_constant(Word::ZERO);

	for offset in 1..8 {
		let offset_wire = b.add_constant(Word(offset as u64));
		let is_this_offset = b.icmp_eq(byte_offset, offset_wire);

		// For offset bytes: take last (8-offset) bytes from low word
		// and first offset bytes from high word
		let shifted_low = b.shr(low_word, (offset * 8) as u32);
		let shifted_high = b.shl(high_word, ((8 - offset) * 8) as u32);
		let combined = b.bor(shifted_low, shifted_high);

		// Include this combination in result if offset matches
		let masked = b.band(combined, is_this_offset);
		unaligned_word = b.bor(unaligned_word, masked);
	}

	// Final selection: aligned or unaligned result
	//
	// Circuit-friendly conditional: select(cond, a, b) = (a & cond) | (b & ~cond)
	let aligned_masked = b.band(aligned_word, is_aligned);
	let unaligned_masked = b.band(unaligned_word, b.bnot(is_aligned));
	b.bor(aligned_masked, unaligned_masked)
}

/// Create a byte mask for the first `n_bytes` bytes of a word.
///
/// This function generates a mask with the first `n_bytes` bytes set to 0xFF
/// and remaining bytes set to 0x00. Used for partial word comparisons.
///
/// # Examples
///
/// ```text
/// n_bytes = 0: 0x0000000000000000
/// n_bytes = 1: 0x00000000000000FF
/// n_bytes = 2: 0x000000000000FFFF
/// n_bytes = 3: 0x0000000000FFFFFF
/// ...
/// n_bytes = 8: 0xFFFFFFFFFFFFFFFF
/// ```
///
/// # Circuit Implementation
///
/// Since we can't use dynamic bit shifting in circuits, we handle each possible
/// value of n_bytes (0-8) explicitly and use a multiplexer to select the right mask.
fn create_byte_mask(b: &CircuitBuilder, n_bytes: Wire) -> Wire {
	let mut mask = b.add_constant(Word::ZERO);

	// Handle each possible byte count explicitly
	for i in 0..=8 {
		let i_wire = b.add_constant(Word(i as u64));
		let is_this_count = b.icmp_eq(n_bytes, i_wire);

		// Calculate mask for i bytes
		// Special cases: 0 bytes = no mask, 8 bytes = full mask
		let mask_value = if i == 0 {
			0u64
		} else if i == 8 {
			u64::MAX
		} else {
			(1u64 << (i * 8)) - 1 // Sets the low i*8 bits
		};

		// Include this mask in result if byte count matches
		let this_mask = b.band(b.add_constant(Word(mask_value)), is_this_count);
		mask = b.bor(mask, this_mask);
	}

	mask
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{compiler::CircuitBuilder, constraint_verifier::verify_constraints};

	// Test utilities

	/// Helper to create a concat circuit with given parameters.
	///
	/// Creates a circuit with the specified maximum sizes for joined data and terms.
	/// All wires are created as input/output wires for testing.
	fn create_concat_circuit(
		max_n_joined: usize,
		term_max_lens: Vec<usize>,
	) -> (CircuitBuilder, Concat) {
		let b = CircuitBuilder::new();

		let len_joined = b.add_inout();
		let joined: Vec<Wire> = (0..max_n_joined / 8).map(|_| b.add_inout()).collect();

		let terms: Vec<Term> = term_max_lens
			.into_iter()
			.map(|max_len| Term {
				len: b.add_inout(),
				data: (0..max_len / 8).map(|_| b.add_inout()).collect(),
				max_len,
			})
			.collect();

		let concat = Concat::new(&b, max_n_joined, len_joined, joined, terms);

		(b, concat)
	}

	/// Helper to test a concatenation scenario.
	///
	/// Sets up a circuit with the given parameters and verifies that the
	/// concatenation of `term_data` equals `expected_joined`.
	fn test_concat(
		max_n_joined: usize,
		term_max_lens: Vec<usize>,
		expected_joined: &[u8],
		term_data: &[&[u8]],
	) -> Result<(), Box<dyn std::error::Error>> {
		let (b, concat) = create_concat_circuit(max_n_joined, term_max_lens);
		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// Set the expected joined length
		concat.populate_len_joined(&mut filler, expected_joined.len());
		concat.populate_joined(&mut filler, expected_joined);

		// Set up each term
		for (i, data) in term_data.iter().enumerate() {
			concat.terms[i].populate_len(&mut filler, data.len());
			concat.terms[i].populate_data(&mut filler, data);
		}

		circuit.populate_wire_witness(&mut filler)?;

		// Verify constraints
		let cs = circuit.constraint_system();
		verify_constraints(&cs, &filler.into_value_vec())?;

		Ok(())
	}

	// Basic concatenation tests

	#[test]
	fn test_two_terms_concat() {
		// Verify basic two-term concatenation works correctly
		test_concat(16, vec![8, 8], b"helloworld", &[b"hello", b"world"]).unwrap();
	}

	#[test]
	fn test_three_terms_concat() {
		// Verify three-term concatenation maintains correct order
		test_concat(24, vec![8, 8, 8], b"foobarbaz", &[b"foo", b"bar", b"baz"]).unwrap();
	}

	#[test]
	fn test_single_term() {
		// Edge case: single term should equal the joined result
		test_concat(8, vec![8], b"hello", &[b"hello"]).unwrap();
	}

	// Empty term handling tests

	#[test]
	fn test_empty_term() {
		// Verify empty terms are handled correctly in the middle
		test_concat(16, vec![8, 8, 8], b"helloworld", &[b"hello", b"", b"world"]).unwrap();
	}

	#[test]
	fn test_all_terms_empty() {
		// Edge case: all empty terms should produce empty result
		test_concat(8, vec![8, 8], b"", &[b"", b""]).unwrap();
	}

	// Word alignment tests

	#[test]
	fn test_unaligned_terms() {
		// Test terms that don't align to word boundaries
		// This exercises the unaligned word extraction logic
		test_concat(24, vec![8, 16], b"hello12world456", &[b"hello12", b"world456"]).unwrap();
	}

	#[test]
	fn test_single_byte_terms() {
		// Test many small terms to verify offset tracking
		test_concat(8, vec![8, 8, 8, 8, 8], b"abcde", &[b"a", b"b", b"c", b"d", b"e"]).unwrap();
	}

	// Real-world use case tests

	#[test]
	fn test_domain_concat() {
		// Realistic example: concatenating domain name parts
		test_concat(
			32,
			vec![8, 8, 8, 8, 8],
			b"api.example.com",
			&[b"api", b".", b"example", b".", b"com"],
		)
		.unwrap();
	}

	// Error detection tests

	#[test]
	fn test_length_mismatch() {
		// Verify the circuit rejects incorrect length claims
		// Test where claimed length doesn't match actual concatenation
		let (b, concat) = create_concat_circuit(16, vec![8, 8]);
		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// Claim joined is 8 bytes but terms sum to 10
		concat.populate_len_joined(&mut filler, 8);
		concat.populate_joined(&mut filler, b"helloworld");

		concat.terms[0].populate_len(&mut filler, 5);
		concat.terms[0].populate_data(&mut filler, b"hello");
		concat.terms[1].populate_len(&mut filler, 5);
		concat.terms[1].populate_data(&mut filler, b"world");

		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err());
	}

	#[test]
	fn test_full_last_word_rejects_wrong_data() {
		// Verify the circuit correctly rejects wrong data when the last word has 8 bytes

		// Setup: term with 16 bytes (2 full words)
		let correct_data = b"0123456789ABCDEF";
		let wrong_data = b"0123456789ABCDXX"; // Last 2 bytes are wrong
		assert_eq!(correct_data.len(), 16);
		assert_eq!(wrong_data.len(), 16);

		let (b, concat) = create_concat_circuit(16, vec![16]);
		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		// Populate with WRONG data in joined array
		concat.populate_len_joined(&mut filler, 16);
		concat.populate_joined(&mut filler, wrong_data);

		// But claim it matches the CORRECT data in the term
		concat.terms[0].populate_len(&mut filler, 16);
		concat.terms[0].populate_data(&mut filler, correct_data);

		// This should fail since the data doesn't match
		let result = circuit.populate_wire_witness(&mut filler);
		assert!(result.is_err(), "Circuit should reject wrong data");
	}

	#[test]
	fn test_multiple_full_words_rejects_wrong_data() {
		// Test with 32 bytes - verify rejection works for multiple full words
		let correct_data = b"0123456789ABCDEF0123456789ABCDEF";
		let wrong_data = b"0123456789ABCDEF0123456789ABCDXX"; // Last word wrong

		let (b, concat) = create_concat_circuit(32, vec![32]);
		let circuit = b.build();
		let mut filler = circuit.new_witness_filler();

		concat.populate_len_joined(&mut filler, 32);
		concat.populate_joined(&mut filler, wrong_data);
		concat.terms[0].populate_len(&mut filler, 32);
		concat.terms[0].populate_data(&mut filler, correct_data);

		let result = circuit.populate_wire_witness(&mut filler);

		// Should reject wrong data
		assert!(result.is_err(), "Circuit should reject wrong data");
	}

	// Variable term size tests

	#[test]
	fn test_different_term_max_lens() {
		// Terms can have different maximum sizes
		// This allows efficient circuits when term sizes vary significantly
		test_concat(
			32,
			vec![8, 24],
			b"shorta very long string",
			&[b"short", b"a very long string"],
		)
		.unwrap();
	}

	#[test]
	fn test_mixed_term_sizes() {
		// Complex example with varied term sizes matching real-world usage
		test_concat(
			64,
			vec![8, 8, 32, 8, 16],
			b"hi.this is a much longer term.bye",
			&[b"hi", b".", b"this is a much longer term", b".", b"bye"],
		)
		.unwrap();
	}

	// Property-based tests
	//
	// These tests use proptest to verify the circuit behaves correctly
	// across a wide range of randomly generated inputs.

	#[cfg(test)]
	mod proptest_tests {
		use proptest::prelude::*;

		use super::*;

		/// Strategy for generating random byte arrays for term data.
		fn term_data_strategy() -> impl Strategy<Value = Vec<u8>> {
			prop::collection::vec(any::<u8>(), 0..=128)
		}

		/// Strategy for generating term specifications with proper word alignment.
		///
		/// Each term gets a max_len that is:
		/// - At least as large as the actual data
		/// - Rounded up to the nearest multiple of 8
		fn term_specs_strategy() -> impl Strategy<Value = Vec<(Vec<u8>, usize)>> {
			prop::collection::vec(
				term_data_strategy().prop_map(|data| {
					let max_len = (data.len().div_ceil(8) * 8).max(8);
					(data, max_len)
				}),
				1..=10,
			)
		}

		/// Helper to run a concat test with given data.
		///
		/// - `term_specs`: Vector of (data, max_len) pairs for each term
		/// - `joined_override`: If Some, use this as joined data instead of concatenating terms
		/// - `should_succeed`: Whether we expect the circuit to accept or reject
		fn run_concat_test(
			term_specs: Vec<(Vec<u8>, usize)>,
			joined_override: Option<Vec<u8>>,
			should_succeed: bool,
		) {
			let expected_joined: Vec<u8> = if joined_override.is_none() {
				term_specs
					.iter()
					.flat_map(|(data, _)| data.clone())
					.collect()
			} else {
				joined_override.clone().unwrap()
			};

			let max_n_joined = (expected_joined.len().div_ceil(8) * 8).max(8);
			let term_max_lens: Vec<usize> =
				term_specs.iter().map(|(_, max_len)| *max_len).collect();

			let (b, concat) = create_concat_circuit(max_n_joined, term_max_lens);
			let circuit = b.build();
			let mut filler = circuit.new_witness_filler();

			concat.populate_len_joined(&mut filler, expected_joined.len());
			concat.populate_joined(&mut filler, &expected_joined);

			for (i, (data, _)) in term_specs.iter().enumerate() {
				concat.terms[i].populate_len(&mut filler, data.len());
				concat.terms[i].populate_data(&mut filler, data);
			}

			let result = circuit.populate_wire_witness(&mut filler);
			if should_succeed {
				assert!(result.is_ok(), "Expected success but got: {result:?}");
			} else {
				assert!(result.is_err(), "Expected failure but succeeded");
			}
		}

		proptest! {
			#[test]
			fn test_correct_concatenation(term_specs in term_specs_strategy()) {
				// Verify correct concatenations are accepted
				run_concat_test(term_specs, None, true);
			}

			#[test]
			fn test_single_term_concatenation(data in term_data_strategy()) {
				// Special case: single term should equal joined
				let max_len = (data.len().div_ceil(8) * 8).max(8);
				let term_specs = vec![(data, max_len)];
				run_concat_test(term_specs, None, true);
			}

			#[test]
			fn test_empty_terms_allowed(n_terms in 1usize..=5) {
				// Verify empty terms are handled correctly
				let mut term_specs = vec![];
				for i in 0..n_terms {
					#[allow(clippy::manual_is_multiple_of)]
					if i % 2 == 0 {
						term_specs.push((vec![], 8));
					} else {
						term_specs.push((vec![b'x'; i], (i.div_ceil(8) * 8).max(8)));
					}
				}
				run_concat_test(term_specs, None, true);
			}

			#[test]
			fn test_wrong_joined_data(term_specs in term_specs_strategy()) {
				// Verify incorrect joined data is rejected
				prop_assume!(!term_specs.is_empty());

				let correct_joined: Vec<u8> = term_specs.iter()
					.flat_map(|(data, _)| data.clone())
					.collect();

				prop_assume!(!correct_joined.is_empty());

				let mut wrong_joined = correct_joined.clone();
				wrong_joined[0] ^= 1; // Flip one bit

				run_concat_test(term_specs, Some(wrong_joined), false);
			}

			#[test]
			fn test_wrong_last_byte(term_specs in term_specs_strategy()) {
				// Test modification of the LAST byte (would catch the bug)
				prop_assume!(!term_specs.is_empty());

				let correct_joined: Vec<u8> = term_specs.iter()
					.flat_map(|(data, _)| data.clone())
					.collect();

				prop_assume!(!correct_joined.is_empty());

				let mut wrong_joined = correct_joined.clone();
				let last_idx = wrong_joined.len() - 1;
				wrong_joined[last_idx] ^= 1; // Flip one bit in LAST byte

				run_concat_test(term_specs, Some(wrong_joined), false);
			}


			#[test]
			fn test_wrong_length_rejected(term_specs in term_specs_strategy()) {
				// Test that mismatched lengths are rejected
				prop_assume!(term_specs.len() >= 2);

				let correct_joined: Vec<u8> = term_specs.iter()
					.flat_map(|(data, _)| data.clone())
					.collect();

				prop_assume!(!correct_joined.is_empty());

				// Create joined data that's too short
				let short_joined = correct_joined[..correct_joined.len() - 1].to_vec();

				run_concat_test(term_specs, Some(short_joined), false);
			}

			#[test]
			fn test_swapped_terms_rejected(a in term_data_strategy(), b in term_data_strategy()) {
				// Test that swapping terms is detected
				prop_assume!(a != b && !a.is_empty() && !b.is_empty());

				let max_len_a = (a.len().div_ceil(8) * 8).max(8);
				let max_len_b = (b.len().div_ceil(8) * 8).max(8);

				let term_specs = vec![(a.clone(), max_len_a), (b.clone(), max_len_b)];
				let mut swapped_joined = b.clone();
				swapped_joined.extend(&a);

				run_concat_test(term_specs, Some(swapped_joined), false);
			}

			#[test]
			fn test_extra_data_rejected(term_specs in term_specs_strategy()) {
				// Test that extra data in joined is rejected
				prop_assume!(!term_specs.is_empty());

				let mut joined_with_extra: Vec<u8> = term_specs.iter()
					.flat_map(|(data, _)| data.clone())
					.collect();
				joined_with_extra.push(42); // Add extra byte

				run_concat_test(term_specs, Some(joined_with_extra), false);
			}

			#[test]
			fn test_large_terms(n_terms in 1usize..=3, base_size in 50usize..=200) {
				// Test with larger data sizes
				let mut term_specs = vec![];
				for i in 0..n_terms {
					let size = base_size + i * 10;
					let data = vec![i as u8; size];
					let max_len = (size.div_ceil(8) * 8).max(8);
					term_specs.push((data, max_len));
				}
				run_concat_test(term_specs, None, true);
			}

			#[test]
			fn test_word_boundary_terms(offset in 0usize..8) {
				// Test terms that specifically align/misalign with word boundaries
				let term1 = vec![1u8; offset];
				let term2 = vec![2u8; 8 - offset];
				let term3 = vec![3u8; 16];

				let term_specs = vec![
					(term1, 8),
					(term2, 8),
					(term3, 16),
				];

				run_concat_test(term_specs, None, true);
			}

			#[test]
			fn test_partial_term_data_rejected(term_specs in term_specs_strategy()) {
				// Test that providing partial term data is rejected
				prop_assume!(term_specs.len() >= 2);
				prop_assume!(term_specs[0].0.len() > 1);

				// Build correct joined
				let correct_joined: Vec<u8> = term_specs.iter()
					.flat_map(|(data, _)| data.clone())
					.collect();

				// But claim first term is shorter than it actually is
				let mut modified_specs = term_specs.clone();
				let shortened_len = modified_specs[0].0.len() - 1;
				modified_specs[0].0.truncate(shortened_len);

				// This should fail because total length won't match
				run_concat_test(modified_specs, Some(correct_joined), false);
			}
		}

		#[test]
		fn test_full_word_terms() {
			// Test terms with lengths that are multiples of 8
			let lengths = vec![8, 16, 24, 32, 40, 48];

			for len in lengths {
				let data = vec![0x55u8; len]; // Repeated pattern
				let mut wrong_data = data.clone();
				wrong_data[len - 1] = 0xAA; // Change last byte

				let term_specs = vec![(data.clone(), len)];

				// Should reject wrong data
				run_concat_test(term_specs.clone(), Some(wrong_data.clone()), false);
			}
		}

		// Additional deterministic edge case tests
		#[test]
		fn test_maximum_terms() {
			// Test with many terms to ensure no stack overflow or performance issues
			let term_specs: Vec<(Vec<u8>, usize)> =
				(0..50).map(|i| (vec![i as u8; 2], 8)).collect();
			run_concat_test(term_specs, None, true);
		}

		#[test]
		fn test_all_empty_terms() {
			// Test edge case of all empty terms
			let term_specs = vec![(vec![], 8), (vec![], 8), (vec![], 8)];
			run_concat_test(term_specs, None, true);
		}

		#[test]
		fn test_zero_length_joined_mismatch() {
			// Test when joined is empty but terms aren't
			let term_specs = vec![(vec![1, 2, 3], 8)];
			run_concat_test(term_specs, Some(vec![]), false);
		}
	}
}

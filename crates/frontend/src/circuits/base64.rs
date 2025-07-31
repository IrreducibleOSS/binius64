use crate::{
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	word::Word,
};

/// Specifies how base64 padding should be handled.
#[derive(Debug, Clone, Copy)]
pub enum PaddingMode {
	/// Standard base64 padding with '=' characters.
	/// Encoded strings must be padded to make their length a multiple of 4.
	Standard,
	/// No padding characters.
	/// Unused positions in the encoded array must be filled with zeros.
	NoPadding,
}

/// Base64 URL-safe encoding verification.
///
/// Verifies that encoded data is a valid base64 URL-safe encoding of decoded data.
///
/// # Base64 URL-Safe Alphabet (RFC 4648 §5)
///
/// - Characters 0-61: Same as standard base64 (A-Z, a-z, 0-9)
/// - Character 62: '-' (minus) instead of '+'
/// - Character 63: '_' (underscore) instead of '/'
/// - Padding: '=' (same as standard base64)
///
/// # Circuit Behavior
///
/// The circuit performs the following validations:
/// - encoded is valid base64 URL-safe encoding of decoded
/// - len_decoded is the actual length of data in decoded (in bytes)
/// - len_decoded ≤ max_len_decoded (compile-time maximum)
///
/// # Padding
///
/// This circuit supports both padded and unpadded base64 variants:
/// - Padded: Base64 strings must be padded with '=' to make length a multiple of 4
/// - Unpadded: No padding characters; unused array positions must be zero
///
/// # Input Packing
///
/// - decoded: Pack 8 bytes per 64-bit word in big-endian format
/// - encoded: Pack 8 base64 characters per 64-bit word in big-endian format
/// - len_decoded: Single 64-bit word containing byte count
pub struct Base64UrlSafe {
	/// Decoded data array (packed 8 bytes per word).
	pub decoded: Vec<Wire>,
	/// Encoded base64 array (packed 8 chars per word).
	pub encoded: Vec<Wire>,
	/// Actual length of decoded data in bytes.
	pub len_decoded: Wire,
	/// Maximum supported decoded data length in bytes (must be a multiple of 24).
	pub max_len_decoded: usize,
}

impl Base64UrlSafe {
	/// Creates a new Base64UrlSafe verifier.
	///
	/// # Arguments
	///
	/// * `builder` - Circuit builder for constructing constraints
	/// * `max_len_decoded` - Maximum supported decoded data length in bytes (must be a multiple of
	///   24)
	/// * `decoded` - Decoded byte array wires (must have length = max_len_decoded/8)
	/// * `encoded` - Base64 encoded array wires (must have length = max_len_decoded/6)
	/// * `len_decoded` - Wire containing actual length of decoded data in bytes
	/// * `padding_mode` - Specifies how base64 padding should be handled
	///
	/// # Panics
	///
	/// * If `max_len_decoded` is not a multiple of 24
	/// * If `decoded.len()` != max_len_decoded/8
	/// * If `encoded.len()` != max_len_decoded/6
	///
	/// # Implementation Notes
	///
	/// The requirement that `max_len_decoded` be a multiple of 24 ensures:
	/// - Word alignment: divisible by 8 for packing bytes into 64-bit words
	/// - Base64 group alignment: divisible by 3 for processing complete groups
	/// - Exact array sizing with no rounding needed
	pub fn new(
		builder: &CircuitBuilder,
		max_len_decoded: usize,
		decoded: Vec<Wire>,
		encoded: Vec<Wire>,
		len_decoded: Wire,
		padding_mode: PaddingMode,
	) -> Self {
		// Ensure max_len_decoded is a multiple of 24 (LCM of 8 and 3)
		assert!(
			max_len_decoded.is_multiple_of(24),
			"max_len_decoded must be a multiple of 24, got {max_len_decoded}"
		);

		let expected_decoded_words = max_len_decoded / 8;
		let expected_encoded_words = max_len_decoded / 6;

		assert_eq!(
			decoded.len(),
			expected_decoded_words,
			"decoded.len() must equal max_len_decoded/8"
		);
		assert_eq!(
			encoded.len(),
			expected_encoded_words,
			"encoded.len() must equal max_len_decoded/6"
		);

		// Verify length bounds (use original max_len_decoded for user-specified limit)
		verify_length_bounds(builder, len_decoded, max_len_decoded);

		// Process groups of 3 bytes -> 4 base64 chars
		let groups = max_len_decoded / 3;

		let padding_char = match padding_mode {
			PaddingMode::Standard => builder.add_constant_64(b'=' as u64),
			PaddingMode::NoPadding => builder.add_constant_64(0),
		};

		for group_idx in 0..groups {
			let b = builder.subcircuit(format!("group[{group_idx}]"));
			verify_base64_group(&b, &decoded, &encoded, len_decoded, group_idx, padding_char);
		}

		Self {
			decoded,
			encoded,
			len_decoded,
			max_len_decoded,
		}
	}

	/// Populates the length wire with the actual decoded data length.
	///
	/// # Arguments
	///
	/// * `w` - Witness filler to populate
	/// * `length` - Actual length of decoded data in bytes
	pub fn populate_len_decoded(&self, w: &mut WitnessFiller, length: usize) {
		w[self.len_decoded] = Word(length as u64);
	}

	/// Populates the decoded data array from a byte slice.
	///
	/// # Arguments
	///
	/// * `w` - Witness filler to populate
	/// * `data` - Decoded bytes
	///
	/// # Panics
	///
	/// Panics if `data.len()` exceeds the maximum size specified during construction.
	pub fn populate_decoded(&self, w: &mut WitnessFiller, data: &[u8]) {
		assert!(
			data.len() <= self.max_len_decoded,
			"decoded length {} exceeds maximum {}",
			data.len(),
			self.max_len_decoded,
		);

		// Pack bytes into 64-bit words (big-endian)
		for (i, chunk) in data.chunks(8).enumerate() {
			if i < self.decoded.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << ((7 - j) * 8);
				}
				w[self.decoded[i]] = Word(word);
			}
		}

		// Zero out remaining words
		for i in data.len().div_ceil(8)..self.decoded.len() {
			w[self.decoded[i]] = Word::ZERO;
		}
	}

	/// Populates the encoded base64 array from a byte slice.
	///
	/// # Arguments
	///
	/// * `w` - Witness filler to populate
	/// * `data` - Base64-encoded bytes
	///
	/// # Panics
	///
	/// Panics if `data.len()` exceeds the maximum size specified during construction.
	pub fn populate_encoded(&self, w: &mut WitnessFiller, data: &[u8]) {
		let max_bytes = self.encoded.len() * 8;
		assert!(
			data.len() <= max_bytes,
			"encoded length {} exceeds maximum {}",
			data.len(),
			max_bytes
		);

		// Pack bytes into 64-bit words (big-endian)
		for (i, chunk) in data.chunks(8).enumerate() {
			if i < self.encoded.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << ((7 - j) * 8);
				}
				w[self.encoded[i]] = Word(word);
			}
		}

		// Zero out remaining words
		for i in data.len().div_ceil(8)..self.encoded.len() {
			w[self.encoded[i]] = Word::ZERO;
		}
	}
}

/// Verifies that the length is within bounds (0 < len_decoded <= max_len_decoded).
fn verify_length_bounds(builder: &CircuitBuilder, len_decoded: Wire, max_len_decoded: usize) {
	let max_len_const = builder.add_constant_64(max_len_decoded as u64);

	// Check if len_decoded > max_len_decoded (which should be false)
	// len_decoded > max_len_decoded is equivalent to max_len_decoded < len_decoded
	let too_large = builder.icmp_ult(max_len_const, len_decoded);

	// Assert too_large == 0
	builder.assert_0("length_check", too_large);
}

/// Verifies a single base64 group (3 decoded bytes -> 4 base64 chars).
///
/// # Base64 Encoding Rules
///
/// Three bytes: AAAAAAAA BBBBBBBB CCCCCCCC
/// Become four 6-bit values:
/// - val0 = AAAAAA (top 6 bits of byte0)
/// - val1 = AABBBB (bottom 2 bits of byte0 + top 4 bits of byte1)
/// - val2 = BBBBCC (bottom 4 bits of byte1 + top 2 bits of byte2)
/// - val3 = CCCCCC (bottom 6 bits of byte2)
fn verify_base64_group(
	builder: &CircuitBuilder,
	decoded: &[Wire],
	encoded: &[Wire],
	len_decoded: Wire,
	group_idx: usize,
	padding_char: Wire,
) {
	let base_byte_idx = group_idx * 3;

	// Check if this group is within actual length
	let group_start = builder.add_constant_64(base_byte_idx as u64);
	let is_active = builder.icmp_ult(group_start, len_decoded);

	// Extract 3 decoded bytes
	let byte0 = extract_byte(builder, decoded, base_byte_idx);
	let byte1 = extract_byte(builder, decoded, base_byte_idx + 1);
	let byte2 = extract_byte(builder, decoded, base_byte_idx + 2);

	// Extract 4 base64 characters
	let char0 = extract_byte(builder, encoded, group_idx * 4);
	let char1 = extract_byte(builder, encoded, group_idx * 4 + 1);
	let char2 = extract_byte(builder, encoded, group_idx * 4 + 2);
	let char3 = extract_byte(builder, encoded, group_idx * 4 + 3);

	// Compute bytes in this group for padding handling
	let bytes_in_group = compute_bytes_in_group(builder, len_decoded, base_byte_idx);

	// Convert 3 bytes to 4 6-bit values
	let val0 = extract_6bit_value_0(builder, byte0);
	let val1 = extract_6bit_value_1(builder, byte0, byte1);
	let val2 = extract_6bit_value_2(builder, byte1, byte2);
	let val3 = extract_6bit_value_3(builder, byte2);

	// Verify character mappings
	verify_base64_char(builder, val0, char0, is_active);

	// has_byte1 = bytes_in_group > 0 is equivalent to 0 < bytes_in_group
	let has_byte1 = builder.icmp_ult(builder.add_constant_64(0), bytes_in_group);
	let check_char1 = builder.band(is_active, has_byte1);
	verify_base64_char(builder, val1, char1, check_char1);

	// has_byte2 = bytes_in_group > 1 is equivalent to 1 < bytes_in_group
	let has_byte2 = builder.icmp_ult(builder.add_constant_64(1), bytes_in_group);

	// has_byte3 = bytes_in_group > 2 is equivalent to 2 < bytes_in_group
	let has_byte3 = builder.icmp_ult(builder.add_constant_64(2), bytes_in_group);

	// For char2: encode if we have more than 1 byte (i.e., at least 2 bytes)
	let should_encode_char2 = has_byte2;
	verify_base64_char_or_padding(
		builder,
		val2,
		char2,
		is_active,
		should_encode_char2,
		padding_char,
	);

	// For char3: encode if we have more than 2 bytes (i.e., all 3 bytes)
	let should_encode_char3 = has_byte3;
	verify_base64_char_or_padding(
		builder,
		val3,
		char3,
		is_active,
		should_encode_char3,
		padding_char,
	);
}

/// Extracts a byte from a word array at the given byte index.
///
/// # Arguments
///
/// * `builder` - Circuit builder
/// * `words` - Array of 64-bit words, each containing 8 packed bytes in big-endian format
/// * `byte_idx` - Global byte index to extract
///
/// # Returns
///
/// Wire containing the extracted byte value (0-255), or 0 if out of bounds.
fn extract_byte(builder: &CircuitBuilder, words: &[Wire], byte_idx: usize) -> Wire {
	let word_idx = byte_idx / 8;
	let byte_offset = byte_idx % 8;

	if word_idx >= words.len() {
		// Return zero for out of bounds
		return builder.add_constant_64(0);
	}

	let word = words[word_idx];
	let big_endian_offset = 7 - byte_offset;
	builder.extract_byte(word, big_endian_offset as u32)
}

/// Computes the number of valid bytes in a base64 group.
///
/// # Returns
///
/// Wire containing min(3, len_decoded - base_byte_idx)
fn compute_bytes_in_group(
	builder: &CircuitBuilder,
	len_decoded: Wire,
	base_byte_idx: usize,
) -> Wire {
	// For simplicity, we'll handle the common cases directly
	// Since we process groups of 3, we need to check:
	// - If base_byte_idx >= length: return 0
	// - If base_byte_idx + 1 >= length: return 1
	// - If base_byte_idx + 2 >= length: return 2
	// - Otherwise: return 3

	let base_idx = builder.add_constant_64(base_byte_idx as u64);
	let base_idx_plus_1 = builder.add_constant_64((base_byte_idx + 1) as u64);
	let base_idx_plus_2 = builder.add_constant_64((base_byte_idx + 2) as u64);

	let zero = builder.add_constant_64(0);
	let one = builder.add_constant_64(1);
	let two = builder.add_constant_64(2);
	let three = builder.add_constant_64(3);

	// Check if base_idx < len_decoded (group has at least 1 byte)
	let has_byte0 = builder.icmp_ult(base_idx, len_decoded);

	// Check if base_idx + 1 < len_decoded (group has at least 2 bytes)
	let has_byte1 = builder.icmp_ult(base_idx_plus_1, len_decoded);

	// Check if base_idx + 2 < len_decoded (group has all 3 bytes)
	let has_byte2 = builder.icmp_ult(base_idx_plus_2, len_decoded);

	// Build result based on which bytes we have
	// If has_byte2: return 3
	// Else if has_byte1: return 2
	// Else if has_byte0: return 1
	// Else: return 0

	// Select between 2 and 3 based on has_byte2
	let two_or_three =
		builder.bor(builder.band(has_byte2, three), builder.band(builder.bnot(has_byte2), two));

	// Select between 0 and 1 based on has_byte0
	let zero_or_one =
		builder.bor(builder.band(has_byte0, one), builder.band(builder.bnot(has_byte0), zero));

	// Select between (0 or 1) and (2 or 3) based on has_byte1
	builder.bor(
		builder.band(has_byte1, two_or_three),
		builder.band(builder.bnot(has_byte1), zero_or_one),
	)
}

/// Extracts the first 6-bit value (top 6 bits of byte0).
fn extract_6bit_value_0(builder: &CircuitBuilder, byte0: Wire) -> Wire {
	let val0 = builder.shr(byte0, 2);
	builder.band(val0, builder.add_constant_64(0x3F))
}

/// Extracts the second 6-bit value (bottom 2 bits of byte0 + top 4 bits of byte1).
fn extract_6bit_value_1(builder: &CircuitBuilder, byte0: Wire, byte1: Wire) -> Wire {
	let byte0_low = builder.band(byte0, builder.add_constant_64(0x03));
	let byte0_low_shifted = builder.shl(byte0_low, 4);
	let byte1_high = builder.shr(byte1, 4);
	let byte1_high = builder.band(byte1_high, builder.add_constant_64(0x0F));
	builder.bor(byte0_low_shifted, byte1_high)
}

/// Extracts the third 6-bit value (bottom 4 bits of byte1 + top 2 bits of byte2).
fn extract_6bit_value_2(builder: &CircuitBuilder, byte1: Wire, byte2: Wire) -> Wire {
	let byte1_low = builder.band(byte1, builder.add_constant_64(0x0F));
	let byte1_low_shifted = builder.shl(byte1_low, 2);
	let byte2_high = builder.shr(byte2, 6);
	let byte2_high = builder.band(byte2_high, builder.add_constant_64(0x03));
	builder.bor(byte1_low_shifted, byte2_high)
}

/// Extracts the fourth 6-bit value (bottom 6 bits of byte2).
fn extract_6bit_value_3(builder: &CircuitBuilder, byte2: Wire) -> Wire {
	builder.band(byte2, builder.add_constant_64(0x3F))
}

/// Verifies that a base64 character matches the expected encoding.
///
/// # Arguments
///
/// * `builder` - Circuit builder
/// * `six_bit_val` - The 6-bit value to encode (0-63)
/// * `char_val` - The actual character value found
/// * `is_active` - Whether this check should be enforced
fn verify_base64_char(
	builder: &CircuitBuilder,
	six_bit_val: Wire,
	char_val: Wire,
	is_active: Wire,
) {
	let expected_char = compute_expected_base64_char(builder, six_bit_val);

	// Check if char_val == expected_char
	let eq = builder.icmp_eq(char_val, expected_char);

	// Only enforce if active: valid = !is_active | eq
	let not_active = builder.bnot(is_active);
	let valid = builder.bor(not_active, eq);

	// Assert valid == all ones
	let all_ones = builder.add_constant_64(u64::MAX);
	builder.assert_eq("base64_char", valid, all_ones);
}

/// Verifies that a base64 character is either valid encoding or padding.
///
/// # Arguments
///
/// * `builder` - Circuit builder
/// * `six_bit_val` - The 6-bit value to encode (0-63)
/// * `char_val` - The actual character value found
/// * `is_active` - Whether this group is active
/// * `should_encode` - Whether this position should contain encoded data (vs padding)
/// * `padding_char` - The character to use for padding
fn verify_base64_char_or_padding(
	builder: &CircuitBuilder,
	six_bit_val: Wire,
	char_val: Wire,
	is_active: Wire,
	should_encode: Wire,
	padding_char: Wire,
) {
	let is_padding = builder.icmp_eq(char_val, padding_char);

	// If should_encode, verify normal base64 char
	let expected_char = compute_expected_base64_char(builder, six_bit_val);
	let is_valid_char = builder.icmp_eq(char_val, expected_char);

	// valid = (should_encode & is_valid_char) | (!should_encode & is_padding)
	let not_should_encode = builder.bnot(should_encode);

	let case1 = builder.band(should_encode, is_valid_char);
	let case2 = builder.band(not_should_encode, is_padding);
	let valid_encoding = builder.bor(case1, case2);

	// Only enforce if active: valid = !is_active | valid_encoding
	let not_active = builder.bnot(is_active);
	let valid = builder.bor(not_active, valid_encoding);

	// Assert valid == all ones
	let all_ones = builder.add_constant_64(u64::MAX);
	builder.assert_eq("base64_padding", valid, all_ones);
}

/// Computes the expected base64 character for a 6-bit value.
///
/// # Base64 URL-Safe Mapping
///
/// - 0-25: 'A'-'Z' (65-90)
/// - 26-51: 'a'-'z' (97-122)
/// - 52-61: '0'-'9' (48-57)
/// - 62: '-' (45) [URL-safe variant]
/// - 63: '_' (95) [URL-safe variant]
///
/// # Implementation Note
///
/// Since circuits don't support dynamic lookup tables, we check all 64
/// possible values explicitly and combine results using masking.
fn compute_expected_base64_char(builder: &CircuitBuilder, six_bit_val: Wire) -> Wire {
	let mut result = builder.add_constant_64(0);

	// For each possible value, check if six_bit_val equals it and add the corresponding char
	for i in 0..64u64 {
		let val_const = builder.add_constant_64(i);
		let is_this_val = builder.icmp_eq(six_bit_val, val_const);

		let char_val = match i {
			0..=25 => b'A' + i as u8,
			26..=51 => b'a' + (i - 26) as u8,
			52..=61 => b'0' + (i - 52) as u8,
			62 => b'-', // URL-safe: minus instead of plus
			63 => b'_', // URL-safe: underscore instead of slash
			_ => unreachable!(),
		};

		let char_const = builder.add_constant_64(char_val as u64);
		let masked_char = builder.band(is_this_val, char_const);
		result = builder.bor(result, masked_char);
	}

	result
}

#[cfg(test)]
mod tests {
	use super::{Base64UrlSafe, PaddingMode, Wire};
	use crate::{compiler::CircuitBuilder, constraint_verifier::verify_constraints};

	/// Encodes bytes to base64 using URL-safe alphabet with specified padding mode.
	fn encode_base64(input: &[u8], padding_mode: PaddingMode) -> Vec<u8> {
		const BASE64_CHARS: &[u8] =
			b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

		let mut output = Vec::new();

		for chunk in input.chunks(3) {
			let b1 = chunk[0];
			let b2 = chunk.get(1).copied().unwrap_or(0);
			let b3 = chunk.get(2).copied().unwrap_or(0);

			let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

			output.push(BASE64_CHARS[((n >> 18) & 63) as usize]);
			output.push(BASE64_CHARS[((n >> 12) & 63) as usize]);

			if chunk.len() > 1 {
				output.push(BASE64_CHARS[((n >> 6) & 63) as usize]);
			} else if matches!(padding_mode, PaddingMode::Standard) {
				output.push(b'=');
			}

			if chunk.len() > 2 {
				output.push(BASE64_CHARS[(n & 63) as usize]);
			} else if matches!(padding_mode, PaddingMode::Standard) {
				output.push(b'=');
			}
		}

		output
	}

	/// Helper to create base64 circuit with given max size and padding mode.
	fn create_base64_circuit(
		builder: &CircuitBuilder,
		max_len_decoded: usize,
		padding_mode: PaddingMode,
	) -> Base64UrlSafe {
		// Create input wires
		let decoded: Vec<Wire> = (0..max_len_decoded / 8)
			.map(|_| builder.add_inout())
			.collect();

		let encoded: Vec<Wire> = (0..max_len_decoded / 6)
			.map(|_| builder.add_inout())
			.collect();

		let len_decoded = builder.add_inout();

		Base64UrlSafe::new(builder, max_len_decoded, decoded, encoded, len_decoded, padding_mode)
	}

	/// Core helper that tests base64 encoding verification and returns a Result.
	fn check_base64_encoding(
		input: &[u8],
		encoded: &[u8],
		max_len_decoded: usize,
		padding_mode: PaddingMode,
	) -> Result<(), Box<dyn std::error::Error>> {
		let builder = CircuitBuilder::new();
		let circuit = create_base64_circuit(&builder, max_len_decoded, padding_mode);
		let compiled = builder.build();

		// Create witness
		let mut witness = compiled.new_witness_filler();

		circuit.populate_len_decoded(&mut witness, input.len());
		circuit.populate_decoded(&mut witness, input);
		circuit.populate_encoded(&mut witness, encoded);

		// Verify circuit
		compiled.populate_wire_witness(&mut witness)?;

		// Verify constraints
		let cs = compiled.constraint_system();
		verify_constraints(&cs, &witness.into_value_vec())?;

		Ok(())
	}

	/// Helper to test base64 encoding verification with specified padding mode.
	fn test_base64_encoding(input: &[u8], max_len_decoded: usize, padding_mode: PaddingMode) {
		let expected_base64 = encode_base64(input, padding_mode);
		assert!(
			check_base64_encoding(input, &expected_base64, max_len_decoded, padding_mode).is_ok()
		);
	}

	/// Assert that the base64 circuit fails to verify the specified inputs
	fn assert_base64_failure(
		input: &[u8],
		encoded: &[u8],
		max_len_decoded: usize,
		padding_mode: PaddingMode,
	) {
		assert!(check_base64_encoding(input, encoded, max_len_decoded, padding_mode).is_err());
	}

	#[test]
	fn test_base64_hello_world() {
		test_base64_encoding(b"Hello World!", 1512, PaddingMode::Standard);
		test_base64_encoding(b"Hello World!", 1512, PaddingMode::NoPadding);
	}

	#[test]
	fn test_base64_empty() {
		test_base64_encoding(b"", 1512, PaddingMode::Standard);
		test_base64_encoding(b"", 1512, PaddingMode::NoPadding);
	}

	#[test]
	fn test_base64_padding() {
		// Test cases that require padding
		test_base64_encoding(b"A", 1512, PaddingMode::Standard); // Requires == padding
		test_base64_encoding(b"AB", 1512, PaddingMode::Standard); // Requires = padding
		test_base64_encoding(b"ABC", 1512, PaddingMode::Standard); // No padding
	}

	#[test]
	fn test_base64_long_input() {
		let input =
			b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
		test_base64_encoding(input, 1512, PaddingMode::Standard);
		test_base64_encoding(input, 1512, PaddingMode::NoPadding);
	}

	#[test]
	fn test_invalid_base64() {
		let input = b"ABC";
		let invalid_base64 = b"XXXX"; // Invalid base64 for "ABC"
		assert_base64_failure(input, invalid_base64, 120, PaddingMode::Standard);
		assert_base64_failure(input, invalid_base64, 120, PaddingMode::NoPadding);
	}

	#[test]
	fn test_url_safe_characters() {
		// Test that URL-safe characters - and _ are used instead of + and /
		// Create input that will result in characters 62 and 63 in base64

		// For 111110 (62): we need top 6 bits = 111110
		let input1 = &[0b11111000]; // Top 6 bits = 111110 = 62
		let expected1_standard = encode_base64(input1, PaddingMode::Standard);
		let expected1_no_padding = encode_base64(input1, PaddingMode::NoPadding);
		assert_eq!(expected1_standard[0], b'-', "Index 62 should map to '-' not '+'");
		assert_eq!(expected1_no_padding[0], b'-', "Index 62 should map to '-' not '+'");

		// For 111111 (63): we need top 6 bits = 111111
		let input2 = &[0b11111100]; // Top 6 bits = 111111 = 63
		let expected2_standard = encode_base64(input2, PaddingMode::Standard);
		let expected2_no_padding = encode_base64(input2, PaddingMode::NoPadding);
		assert_eq!(expected2_standard[0], b'_', "Index 63 should map to '_' not '/'");
		assert_eq!(expected2_no_padding[0], b'_', "Index 63 should map to '_' not '/'");

		// Now test with the circuit
		test_base64_encoding(input1, 120, PaddingMode::Standard);
		test_base64_encoding(input1, 120, PaddingMode::NoPadding);
		test_base64_encoding(input2, 120, PaddingMode::Standard);
		test_base64_encoding(input2, 120, PaddingMode::NoPadding);
	}

	#[test]
	#[should_panic(expected = "max_len_decoded must be a multiple of 24")]
	fn test_panic_when_max_len_not_multiple_of_24_standard() {
		// This test verifies that max_len_decoded must be a multiple of 24
		// Testing with max_len_decoded = 100 which is not a multiple of 24
		test_base64_encoding(b"test", 100, PaddingMode::Standard);
	}

	#[test]
	#[should_panic(expected = "max_len_decoded must be a multiple of 24")]
	fn test_panic_when_max_len_not_multiple_of_24_no_padding() {
		// This test verifies that max_len_decoded must be a multiple of 24
		// Testing with max_len_decoded = 100 which is not a multiple of 24
		test_base64_encoding(b"test", 100, PaddingMode::NoPadding);
	}

	#[test]
	fn test_wrong_padding_mode_fails() {
		let input = b"A"; // This requires padding in standard base64

		// Standard mode should reject no-padding encoding
		let no_padding_encoded = encode_base64(input, PaddingMode::NoPadding);
		assert_base64_failure(input, &no_padding_encoded, 120, PaddingMode::Standard);

		// NoPadding mode should reject padded encoding
		let standard_encoded = encode_base64(input, PaddingMode::Standard);
		assert_base64_failure(input, &standard_encoded, 120, PaddingMode::NoPadding);
	}
}

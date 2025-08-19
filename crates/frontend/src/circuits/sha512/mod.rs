pub mod compress;

use binius_core::word::Word;
pub use compress::{Compress, State};

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

/// Verifies that a message produces a specific SHA-512 digest.
///
/// This circuit validates that the provided message, when hashed using SHA-512,
/// produces exactly the expected digest. It implements the full SHA-512 algorithm
/// including proper padding and compression.
///
/// # Wire Layout
///
/// The circuit uses the following wire organization:
/// - Message words: 16 bytes per wire
/// - Digest: 8 wires of 64 bits each, representing the 512-bit hash in big-endian order
///
/// # Limitations
///
/// The message bitlength must be less than 2^32 bits (2^29 bytes) due to SHA-512's
/// length encoding using a 64-bit integer where we only support the lower 32 bits.
pub struct Sha512 {
	/// The maximum length of the input message in bytes this circuit is configured to process.
	pub max_len: usize,
	/// The actual length of the input message in bytes.
	///
	/// Must be less than or equal to `max_len`.
	pub len: Wire,
	/// The expected SHA-512 digest packed as 8x64-bit words in big-endian order.
	///
	/// - digest\[0\]: Highest 64 bits (bytes 0-7 of the hash)
	/// - .....
	/// - digest\[7\]: Lowest 64 bits (bytes 56-63 of the hash)
	pub digest: [Wire; 8],
	/// The input message packed as 64-bit words.
	///
	/// Each wire contains 8 bytes of the message.
	/// The number of wires is `ceil(max_len / 8)`.
	pub message: Vec<Wire>,

	/// Compression gadgets for each 1024-bit block.
	///
	/// Each compression gadget processes one 1024-bit (128-byte) block of the padded message.
	/// The gadgets are chained together, with each taking the output state from the previous
	/// compression as input. The first compression starts from the SHA-512 initialization vector.
	///
	/// The number of compression gadgets is `ceil((max_len + 17) / 128)`, accounting for
	/// the minimum 17 bytes of padding (1 byte for 0x80 delimiter + 16 bytes for length).
	compress: Vec<Compress>,
}

impl Sha512 {
	/// Creates a new SHA-512 verifier circuit.
	///
	/// # Arguments
	/// * `builder` - Circuit builder for constructing constraints
	/// * `max_len` - Maximum message length in bytes this circuit can handle
	/// * `len` - Wire containing the actual message length in bytes
	/// * `digest` - Expected SHA-512 digest as 8 wires of 64 bits each
	/// * `message` - Input message as packed 64-bit words (16 bytes per wire)
	///
	/// # Panics
	/// * If `max_len` is 0
	/// * If `max_len * 8` exceeds 2^32 (see the struct doc)
	/// * If `message.len()` != `ceil(max_len / 8)`
	///
	/// # Circuit Structure
	/// The circuit performs the following validations:
	/// 1. Ensures the actual length is within bounds (len <= max_len)
	/// 2. Pads the message according to SHA-512 specifications
	/// 3. Computes the hash through chained compression functions
	/// 4. Verifies the computed digest matches the expected digest
	pub fn new(
		builder: &CircuitBuilder,
		max_len: usize, // why not `u64`? -- BD
		len: Wire,
		digest: [Wire; 8],
		message: Vec<Wire>,
	) -> Self {
		// ---- Circuit construction overview
		//
		// This function builds a SHA-512 circuit with the following structure:
		//
		// 1. Input validation and setup
		//    - Validate maximum length constraints
		//    - Ensure actual length <= max_len
		//
		// 2. Message padding and compression setup
		//    - Create padded message blocks following SHA-256 rules
		//    - Chain compression functions from IV to final state
		//    2a. SHA-256 padding position calculation
		//    2b. Final digest selection
		//
		// 3. Message padding constraints (per-word validation)
		//    - 3a: Full message words
		//    - 3b: Boundary word byte checks
		//    - 3c: Zero padding constraints
		//    - 3d: Length field placement

		// ---- 1. Input validation and setup
		//
		// SHA-512 padding routine uses a 64-bit integer to specify the length of the message
		// in bits. This is impractical for a circuit, so we cap the maximum bit length by 2^32,
		// allowing us to check a single word instead of two.
		//
		// We calculate the number of compression blocks needed, including the last padding block
		// for the maximum sized message. Each block is 128 bytes, and we need 17 extra bytes for
		// padding (1 byte for 0x80 delimiter + 16 bytes for length field).
		//
		// We also verify that the actual input length len is within bounds.
		assert!(max_len > 0, "max_len must be positive");
		assert!(max_len * 8 <= u64::MAX as usize, "max_len * 8 must fit in 64 bits");

		let n_blocks = (max_len + 17).div_ceil(128);
		let n_words = n_blocks * 16;

		// Assert that len <= max_len by checking that !(max_len < len)
		let len_exceeds_max = builder.icmp_ult(builder.add_constant_64(max_len as u64), len);
		builder.assert_0("1.len_check", len_exceeds_max);

		// ---- 2. Message padding and compression setup
		//
		// Create padded message blocks and compression gadgets. The padded message is packed
		// differently from the input message words:
		//     16 × 32-bit schedule words = 8 × 64-bit message words
		//
		// The padded message follows SHA-256 padding requirements and is passed directly to
		// the compression function.
		//
		// Compression gadgets are daisy-chained: each takes the output state from the previous
		// compression as input, with the first compression starting from the SHA-256 IV.
		let padded_message: Vec<[Wire; 16]> = (0..n_blocks)
			.map(|_| std::array::from_fn(|_| builder.add_witness()))
			.collect();

		let mut compress = Vec::with_capacity(n_blocks);
		let mut states = Vec::with_capacity(n_blocks + 1);
		states.push(State::iv(builder));
		for block_no in 0..n_blocks {
			let c = Compress::new(
				&builder.subcircuit(format!("compress[{block_no}]")),
				states[block_no].clone(),
				padded_message[block_no],
			);
			states.push(c.state_out.clone());
			compress.push(c);
		}

		// ---- 2a. SHA-512 padding position calculation
		//
		// Calculate where padding elements go. SHA-512 padding has three parts:
		// 1. The 0x80 delimiter byte immediately after the message
		// 2. Zero bytes to fill up to the length field
		// 3. 128-bit length field in the last 16 bytes of a block
		//
		// The length field fits in the same block as the message if there's room for at least
		// 17 bytes of padding (1 delimiter + 16 length). This happens when len % 128 <= 111.
		// Special case: if len % 128 = 0, the message fills the block exactly, so
		// padding goes in the next block.
		//
		// We calculate:
		// - w_bd: word boundary (which word contains the last message byte)
		// - msg_block: which block contains the last message byte
		// - end_block_index: which block contains the length field

		// bd. i claim that it should be enough to figure out:
		let zero = builder.add_constant(Word::ZERO);
		let w_bd = builder.shr(len, 3);
		let len_mod_8 = builder.band(len, builder.add_constant_zx_8(7));
		let bitlen = builder.shl(len, 3);
		// For SHA-512, the length field is 128 bits. We only support messages < 2^32 bits,
		// so the high 64 bits are zero. We keep `bitlen` as the low 64-bit portion.

		// end_block_index = floor((len + 16) / 128) using 64-bit add
		let end_block_index = builder.shr(builder.iadd_32(len, builder.add_constant_64(16)), 7);
		let delim: Wire = builder.add_constant_zx_8(0x80);
		// ---- 2b. Final digest selection
		//
		// Select the correct final digest from all compression outputs. The final digest is
		// the state after processing the end_block (the block containing the length field).
		// We use masking and OR operations to conditionally select the right digest.
		let mut final_digest = [zero; 8];
		for block_no in 0..n_blocks {
			let is_selected =
				builder.icmp_eq(builder.add_constant_64(block_no as u64), end_block_index);
			let block_digest = states[block_no + 1].0;
			for i in 0..8 {
				let masked = builder.band(is_selected, block_digest[i]);
				final_digest[i] = builder.bor(final_digest[i], masked);
			}
		}

		builder.assert_eq_v("2b.digest", digest, final_digest);

		// ---- 3. Message padding constraints
		//
		// This section validates that the padded message follows SHA-512 padding rules.
		// For each 64-bit word in the padded message, we check:
		//
		// 1. Message words: Must match the input message exactly
		// 2. Boundary word: Contains both message bytes and the start of padding (0x80)
		// 3. Zero padding: All zeros between the delimiter and length field
		// 4. Length field: 64-bit message length in bits (last 8 bytes of a block)
		//
		// Subsections:
		// - 3a: Full message words (before the boundary)
		// - 3b: Boundary word byte-level checks
		// - 3c: Zero padding constraints
		// - 3d: Length field placement
		// Precompute byte-category flags (data/delim/zero) for j = 0..7 once,
		// since they only depend on len_mod_8 and not on word_index.
		let byte_flags: [[Wire; 3]; 8] = std::array::from_fn(|j| {
			let j_const = builder.add_constant_64(j as u64);
			[
				builder.icmp_ult(j_const, len_mod_8),
				builder.icmp_eq(j_const, len_mod_8),
				builder.icmp_ult(len_mod_8, j_const),
			]
		});

		for word_index in 0..n_words {
			let builder = builder.subcircuit(format!("word[{word_index}]"));

			let blk = word_index / 16;
			let idx = word_index % 16;
			let padded_message_word = padded_message[blk][idx];

			// flags that help us classify our current position.
			//
			//     1. w     < w_bd - pure message word
			//     2. w    == w_bd - message word at boundary. Mix of message and padding.
			//     3. w_bd  < w    - pure padding word.
			//
			let is_message_word =
				builder.icmp_ult(builder.add_constant_64(word_index as u64 + 1), w_bd);
			let is_boundary_word =
				builder.icmp_eq(w_bd, builder.add_constant_64(word_index as u64));
			let is_past_message =
				builder.icmp_ult(w_bd, builder.add_constant_64(word_index as u64));
			// BD NOTE: the above is wasteful. using just one comparison plus one eq, we can negate.

			// ---- 3a. Full message words
			//
			// Words that contain only message data (no padding) must match the input exactly.
			// For words beyond the message array bounds, we use a zero constant.
			let message_word = if word_index < message.len() {
				message[word_index]
			} else {
				builder.add_constant_64(0)
			};
			builder.assert_eq_cond(
				"3a.full_word".to_string(),
				message_word,
				padded_message_word,
				is_message_word,
			);

			// ---- 3b. Boundary word byte checks
			//
			// This block implements the boundary word byte checks. That means they are only
			// active for the word in which the boundary between the message and padding occurs.
			//
			// Therefore, every constraint is protected by `is_boundary_word` defined above.
			//
			// For each index of a byte `j` within a word we check whether that byte falls into
			// one of the following categories:
			//
			// 1. message byte. Still part of the input.
			// 2. delimiter byte, placed right after the input.
			// 3. zero byte. Placed after the delimiter byte.
			for j in 0..8 {
				let builder = builder.subcircuit(format!("byte[{j}]"));
				let [data_b, delim_b, zero_b] = byte_flags[j as usize];

				let byte_index = 7 - j;
				let byte_w = builder.extract_byte(padded_message_word, byte_index as u32);
				let byte_m = builder.extract_byte(message_word, byte_index as u32);

				// case 1. this is still message byte. Assert equality.
				builder.assert_eq_cond(
					"3b.1".to_string(),
					byte_w,
					byte_m,
					builder.band(is_boundary_word, data_b),
				);

				// case 2. this is the first padding byte, or the delimiter.
				builder.assert_eq_cond(
					"3b.2".to_string(),
					byte_w,
					delim,
					builder.band(is_boundary_word, delim_b),
				);

				// case 3. this is the byte past the delimiter, ie. zero.
				builder.assert_eq_cond(
					"3b.3".to_string(),
					byte_w,
					zero,
					builder.band(is_boundary_word, zero_b),
				);
			}

			// ---- 3c. Zero padding constraints
			//
			// SHA-512 padding fills the space between the delimiter byte (0x80) and the
			// length field with zeros. We need to ensure all padding words are zero,
			// except for the final two 64-bit words of the length block which contains the
			// message bit length.
			//
			// The length field occupies the last 16 bytes (128 bits) of a block, which
			// corresponds to 64-bit words 14 and 15.
			// We identify padding words as those that are:
			// 1. Past the message boundary (is_past_message = true)
			// 2. NOT the length field location (last two 64-bit words of the length block)
			// actually, I am going to treat the 14th word as a padding word---assume it's 0. -- BD
			let is_length_block =
				builder.icmp_eq(builder.add_constant_64(blk as u64), end_block_index);

			// ---- 3d. Length field placement
			//
			// When idx == 15, we're looking at the last 64-bit word of a block
			// If this block contains the length field:
			// - Word 15 contains the message bit length
			// Otherwise, if it's a padding word (not message, not length), it must be zero.
			if idx == 15 {
				builder.assert_eq_cond(
					"3c.zero_pad",
					padded_message_word,
					zero,
					builder.band(is_past_message, builder.bnot(is_length_block)),
				);
				builder.assert_eq_cond("3d.w15_len", padded_message_word, bitlen, is_length_block);
			} else {
				builder.assert_eq_cond("3c.zero_pad", padded_message_word, zero, is_past_message);
			}
		}

		Self {
			max_len,
			len,
			digest,
			message,
			compress,
		}
	}

	/// Populates the length wire with the actual message size in bytes.
	///
	/// # Panics
	/// The method panics if `len` exceeds `max_len`.
	pub fn populate_len(&self, w: &mut WitnessFiller<'_>, len: usize) {
		assert!(len <= self.max_len);
		w[self.len] = Word(len as u64);
	}

	/// Populates the digest wires with the expected SHA-256 hash.
	pub fn populate_digest(&self, w: &mut WitnessFiller<'_>, digest: [u8; 64]) {
		for (i, bytes) in digest.chunks(8).enumerate() {
			let word = u64::from_be_bytes(bytes.try_into().unwrap());
			w[self.digest[i]] = Word(word);
		}
	}

	/// Returns digest wires in little-endian packed format.
	///
	/// The SHA256 digest is stored as 4 wires, each containing 8 bytes of the hash
	/// as a 64-bit big-endian value.
	///
	/// This method extracts the individual bytes and repacks them in little-endian format,
	/// which is useful for interfacing with other circuits that expect LE format.
	///
	/// # Returns
	/// An array of 8 wires containing the 64-byte digest repacked in little-endian format (8 bytes
	/// per wire)
	pub fn digest_to_le_wires(&self, builder: &CircuitBuilder) -> [Wire; 8] {
		let mut wires = [builder.add_constant(Word::ZERO); 8];

		for i in 0..8 {
			let be_wire = self.digest[i];

			// Extract 8 bytes from the 64-bit BE value
			let mut bytes = Vec::with_capacity(8);
			for j in 0..8 {
				let shift_amount = (56 - j * 8) as u32;
				let byte = builder
					.band(builder.shr(be_wire, shift_amount), builder.add_constant(Word(0xFF)));
				bytes.push(byte);
			}

			// Repack bytes in little-endian order
			// bytes[0..8] contains the 8 digest bytes in their original order
			// We pack them in LE format: byte0 | (byte1 << 8) | ... | (byte7 << 56)
			let mut le_wire = bytes[0];
			for j in 1..8 {
				let shifted = builder.shl(bytes[j], (j * 8) as u32);
				le_wire = builder.bor(le_wire, shifted);
			}

			wires[i] = le_wire;
		}

		wires
	}

	/// Returns message wires in little-endian packed format.
	///
	/// This method extracts the individual bytes and repacks them in little-endian format,
	/// which is useful for interfacing with other circuits that expect LE format (e.g., zklogin).
	///
	/// # Returns
	/// A vector of wires containing the message repacked in little-endian format (8 bytes per wire)
	pub fn message_to_le_wires(&self, builder: &CircuitBuilder) -> Vec<Wire> {
		let mut wires = Vec::with_capacity(self.message.len());

		for &sha512_wire in &self.message {
			let mut bytes = Vec::with_capacity(8);

			for j in 0..8 {
				let shift_amount = (56 - j * 8) as u32;
				let byte = builder
					.band(builder.shr(sha512_wire, shift_amount), builder.add_constant(Word(0xFF)));
				bytes.push(byte);
			}

			// Repack bytes in little-endian order
			// bytes[0..8] contains the 8 message bytes in their original order
			// We pack them in LE format: byte0 | (byte1 << 8) | ... | (byte7 << 56)
			let mut le_wire = bytes[0];
			for j in 1..8 {
				let shifted = builder.shl(bytes[j], (j * 8) as u32);
				le_wire = builder.bor(le_wire, shifted);
			}

			wires.push(le_wire);
		}

		wires
	}

	/// Populates the message wires and internal compression blocks with the input message.
	///
	/// This method handles the complete message preparation including:
	/// 1. Packing the message bytes into 64-bit words
	/// 2. Applying SHA-256 padding (0x80 delimiter + zeros + length)
	/// 3. Populating the compression gadgets with properly formatted blocks
	///
	/// # Panics
	/// * If `message_bytes.len()` > `max_len`
	pub fn populate_message(&self, w: &mut WitnessFiller<'_>, message_bytes: &[u8]) {
		assert!(
			message_bytes.len() <= self.max_len,
			"message length {} exceeds maximum {}",
			message_bytes.len(),
			self.max_len
		);

		let n_blocks = self.compress.len();
		let mut padded_message_bytes = vec![0u8; n_blocks * 128];

		// Apply SHA-256 padding
		//
		// Create padded message following SHA-256 rules:
		// 1. Copy original message
		// 2. Add 0x80 delimiter byte
		// 3. Add zero padding to fill to 56 bytes in the appropriate block
		// 4. Add 64-bit length field in big-endian format
		//
		// The length field placement logic must match the circuit's calculation.
		padded_message_bytes[..message_bytes.len()].copy_from_slice(message_bytes);
		padded_message_bytes[message_bytes.len()] = 0x80;

		let bitlen = (message_bytes.len() as u64) * 8;
		let len_bytes = bitlen.to_be_bytes();

		// SHA-256 requires 9 bytes of padding minimum (1 byte for 0x80 delimiter + 8 bytes for
		// length). The length field must be placed in the last 8 bytes of a 64-byte block.
		// So we can fit the length in the current block only if position after message + 0x80 <=
		// 56. This means len % 64 must be <= 55 to fit everything in the same block.
		let len = message_bytes.len() as u64;
		let end_block_index = (len + 16) / 128; // floor((len + 16)/128)
		// even though there are 16 bytes devoted to the length field, we will only write 8.
		let len_offset = (end_block_index as usize) * 128 + 120;
		padded_message_bytes[len_offset..len_offset + 8].copy_from_slice(&len_bytes);

		// Populate witness wires
		//
		// Pack the padded message into the witness format expected by the circuit:
		// 1. Message wires: 8 bytes per wire
		// 2. Compression inputs: 128-byte blocks passed to each compression gadget
		for (i, wire) in self.message.iter().enumerate() {
			let byte_start = i * 8;

			let mut word = 0u64;
			for j in 0..8 {
				word |= (padded_message_bytes[byte_start + j] as u64) << (56 - j * 8);
			}
			w[*wire] = Word(word);
		}

		for (i, compress) in self.compress.iter().enumerate() {
			let block_start = i * 128;
			let mut block_arr = [0u8; 128];
			block_arr.copy_from_slice(&padded_message_bytes[block_start..block_start + 128]);
			compress.populate_m(w, block_arr);
		}
	}
}

#[cfg(test)]
mod tests {
	use binius_core::Word;
	use hex_literal::hex;

	use super::Sha512;
	use crate::{
		compiler::{self, Wire},
		constraint_verifier::verify_constraints,
	};

	fn mk_circuit(b: &mut compiler::CircuitBuilder, max_n: usize) -> Sha512 {
		let len = b.add_witness();
		let digest: [Wire; 8] = std::array::from_fn(|_| b.add_inout());
		let n_blocks = (max_n + 17).div_ceil(128);
		let n_words = n_blocks * 16;
		let message = (0..n_words).map(|_| b.add_inout()).collect();
		Sha512::new(b, max_n, len, digest, message)
	}

	#[test]
	fn full_sha512() {
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, 2048);
		let circuit = b.build();
		let mut w = circuit.new_witness_filler();
		c.populate_len(&mut w, 3);
		c.populate_message(&mut w, b"abc");
		c.populate_digest(
			&mut w,
			hex!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
		);
		circuit.populate_wire_witness(&mut w).unwrap();
	}

	#[test]
	fn full_sha512_multi_block() {
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, 2048);
		let circuit = b.build();
		let mut w = circuit.new_witness_filler();

		let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		c.populate_len(&mut w, message.len());
		c.populate_message(&mut w, message);
		c.populate_digest(
			&mut w,
			hex!("7361ec4a617b6473fb751c44d1026db9442915a5fcea1a419e615d2f3bc5069494da28b8cf2e4412a1dc97d6848f9c84a254fb884ad0720a83eaa0434aeafd8c"),
		);
		circuit.populate_wire_witness(&mut w).unwrap();
	}

	// Helper function to run SHA-512 test with given input and expected digest
	fn test_sha512_with_input(message: &[u8], expected_digest: [u8; 64]) {
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, 2048);
		let circuit = b.build();
		let cs = circuit.constraint_system();
		let mut w = circuit.new_witness_filler();

		c.populate_len(&mut w, message.len());
		c.populate_message(&mut w, message);
		c.populate_digest(&mut w, expected_digest);

		circuit.populate_wire_witness(&mut w).unwrap();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_empty_message() {
		test_sha512_with_input(
			b"",
			hex!(
				"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
			),
		);
	}

	#[test]
	fn test_single_byte() {
		test_sha512_with_input(
			b"a",
			hex!(
				"1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
			),
		);
	}

	#[test]
	fn test_two_bytes() {
		test_sha512_with_input(
			b"ab",
			hex!(
				"2d408a0717ec188158278a796c689044361dc6fdde28d6f04973b80896e1823975cdbf12eb63f9e0591328ee235d80e9b5bf1aa6a44f4617ff3caf6400eb172d"
			),
		);
	}

	#[test]
	fn test_ten_bytes() {
		test_sha512_with_input(
			b"abcdefghij",
			hex!(
				"ef6b97321f34b1fea2169a7db9e1960b471aa13302a988087357c520be957ca119c3ba68e6b4982c019ec89de3865ccf6a3cda1fe11e59f98d99f1502c8b9745"
			),
		);
	}

	#[test]
	fn test_size_111_bytes() {
		// 111 bytes - maximum that fits in one block with padding
		test_sha512_with_input(
			&[b'a'; 111],
			hex!(
				"fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2"
			),
		);
	}

	#[test]
	fn test_size_112_bytes() {
		// 112 bytes - critical boundary, forces two blocks
		test_sha512_with_input(
			&[b'a'; 112],
			hex!(
				"c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca"
			),
		);
	}

	#[test]
	fn test_size_127_bytes() {
		// 127 bytes - one byte from block boundary
		test_sha512_with_input(
			&[b'a'; 127],
			hex!(
				"828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502"
			),
		);
	}

	#[test]
	fn test_size_128_bytes() {
		// 128 bytes - exactly one complete block
		test_sha512_with_input(
			&[b'a'; 128],
			hex!(
				"b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321"
			),
		);
	}

	#[test]
	fn test_size_200_bytes() {
		// 2200 bytes - tests two-block processing
		test_sha512_with_input(
			&[b'a'; 200],
			hex!(
				"4b11459c33f52a22ee8236782714c150a3b2c60994e9acee17fe68947a3e6789f31e7668394592da7bef827cddca88c4e6f86e4df7ed1ae6cba71f3e98faee9f"
			),
		);
	}

	#[test]
	fn test_size_239_bytes() {
		// 239 bytes - maximum that fits in two blocks with padding
		test_sha512_with_input(
			&[b'a'; 239],
			hex!(
				"52c853cb8d907f3d4d6b889beb027985d7c273486d75f8baf26f80d24e90c74c6c3de3e22131582380a7d14d43f2941a31385439cd6ddc469f628015e50bf286"
			),
		);
	}

	#[test]
	fn test_size_240_bytes() {
		// 240 bytes - minimum that needs three blocks
		test_sha512_with_input(
			&[b'a'; 240],
			hex!(
				"4c296d90c61052a62ffb1dd196f1b7b09373b1f93e71836baebf89690546b7595684dbe9467a8e484fa0d1094272b4344a7c24f5fee8daedeb0bf549c985ab5f"
			),
		);
	}

	#[test]
	fn test_size_256_bytes() {
		// 256 bytes - exactly two complete blocks
		test_sha512_with_input(
			&[b'a'; 256],
			hex!(
				"6a9169eb662f136d87374070e8828b3e615a7eca32a89446e9225b02832709be095e635c824a2bb70213ba2ea0ababac0809827843992c851903b7ac0c136699"
			),
		);
	}

	#[test]
	fn test_size_512_bytes() {
		// 512 bytes - exactly four complete blocks
		test_sha512_with_input(
			&[b'a'; 512],
			hex!(
				"0210d27bcbe05c2156627c5f136ade1338ab98e06a4591a00b0bcaa61662a5931d0b3bd41a67b5c140627923f5f6307669eb508d8db38b2a8cd41aebd783394b"
			),
		);
	}

	#[test]
	fn test_size_1024_bytes() {
		test_sha512_with_input(
			&[b'a'; 1024],
			hex!(
				"74b22492e3b9a86a9c93c23a69f821ebafa429302c1f4054b4bc37356a4bae056d9ccbc6f24093a25704faaa72bd21a5f337ca9ec92f32369d24e6b9fae954d8"
			),
		);
	}

	#[test]
	fn test_realistic_text() {
		// Realistic text around boundary
		test_sha512_with_input(
			b"The quick brown fox jumps over the lazy dog!!!!!",
			hex!(
				"2a8c8f82b62291fdb06439d90b799a6bf63bfa3acc3d627b06151099b54df6b9f860e22c84534033523f4a723d49ffb46ca059157d5cbda70ec878e4f692a38f"
			),
		);
	}

	#[test]
	fn test_abc_again() {
		// Test the classic 3-byte case to make sure basic functionality still works
		test_sha512_with_input(
			b"abc",
			hex!(
				"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
			),
		);
	}

	#[test]
	fn test_mid_range_sizes() {
		// Test various sizes in the 80–111 byte range (single block with varying padding)
		test_sha512_with_input(
			&[b'a'; 95],
			hex!(
				"89e0446c3ff5a04b6d707ef43a77e2b349791f402930dbdb74bbab73d5215e294146ba7bd2fa269aee38564ef11a9ccaf5278f9e82687126dcf20d481d470617"
			),
		);
		test_sha512_with_input(
			&[b'a'; 100],
			hex!(
				"70ff99fd241905992cc3fff2f6e3f562c8719d689bfe0e53cbc75e53286d82d8767aed0959b8c63aadf55b5730babee75ea082e88414700d7507b988c44c47bc"
			),
		);
		test_sha512_with_input(
			&[b'a'; 105],
			hex!(
				"3b6dd73c9552f2381107bf206b49c7967fdc5f5011d877d9c576bb4da6d74fbbabf46a1105242d7c645978e54c0b44adaf06d9f7aa4703e8a58829f6d87c5168"
			),
		);
		test_sha512_with_input(
			&[b'a'; 110],
			hex!(
				"c825949632e509824543f7eaf159fb6041722fce3c1cdcbb613b3d37ff107c519417baac32f8e74fe29d7f4823bf6886956603dca5354a6ed6e4a542e06b7d28"
			),
		);
	}

	#[test]
	fn test_bogus_length_rejection() {
		// Test that providing wrong length causes circuit to reject
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, 2048);
		let circuit = b.build();
		let mut w = circuit.new_witness_filler();

		let message = b"abc";
		// Populate with wrong length (should be 3, but we'll use 5)
		c.populate_len(&mut w, 5);
		c.populate_message(&mut w, message);
		c.populate_digest(
			&mut w,
			hex!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
		);

		// This should fail when the circuit checks constraints
		let result = circuit.populate_wire_witness(&mut w);
		assert!(result.is_err());
	}

	#[test]
	fn test_length_exceeds_max_rejection() {
		// Test that providing a length > max_len causes circuit to reject
		let max_len = 3;
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, max_len);
		let circuit = b.build();
		let mut w = circuit.new_witness_filler();

		let message = b"abc";
		// Bypass the API safety check and set the length wire directly
		w[c.len] = Word((max_len + 1) as u64);
		c.populate_message(&mut w, message);
		c.populate_digest(
			&mut w,
			hex!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
		);

		// This should fail at the length check assertion in the circuit
		let result = circuit.populate_wire_witness(&mut w);
		assert!(result.is_err(), "Circuit should reject length > max_len");
	}

	#[test]
	fn test_invalid_digest_rejection() {
		// Test that providing wrong digest causes circuit to reject
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, 2048);
		let circuit = b.build();
		let mut w = circuit.new_witness_filler();

		let message = b"abc";
		c.populate_len(&mut w, message.len());
		c.populate_message(&mut w, message);
		// Provide wrong digest (all zeros instead of correct hash)
		c.populate_digest(&mut w, [0u8; 64]);

		// This should fail when the circuit checks constraints
		let result = circuit.populate_wire_witness(&mut w);
		assert!(result.is_err());
	}

	#[test]
	fn test_wrong_message_content() {
		// Test that providing wrong message content causes circuit to reject
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, 2048);
		let circuit = b.build();
		let mut w = circuit.new_witness_filler();

		// Populate with "abc" message but "def" digest
		c.populate_len(&mut w, 3);
		c.populate_message(&mut w, b"abc");
		// This is the digest for "def", not "abc"
		c.populate_digest(
			&mut w,
			hex!("40a855bf0a93c1019d75dd5b59cd8157608811dd75c5977e07f3bc4be0cad98b22dde4db9ddb429fc2ad3cf9ca379fedf6c1dc4d4bb8829f10c2f0ee04a66663"),
		);

		// This should fail when the circuit checks constraints
		let result = circuit.populate_wire_witness(&mut w);
		assert!(result.is_err());
	}

	#[test]
	fn test_max_len_edge_cases() {
		// Test that SHA512 circuit construction works correctly for various max_len values
		// This specifically tests the fix for indexing issues when word_index >= message.len()

		let test_cases = vec![
			// (max_len, description)
			(111, "fits in one block with padding"),
			(112, "exactly at boundary"),
			(127, "one byte before block boundary"),
			(128, "exactly one block"),
			(239, "fits in two blocks with padding"),
			(240, "exactly at two-block boundary"),
			(256, "two blocks exactly"),
			(512, "four blocks - previously caused index out of bounds"),
			(1024, "eight blocks"),
			(2046, "sixteen blocks"),
		];

		for (max_len, description) in test_cases {
			// Test circuit construction - this used to panic for certain max_len values
			let mut b = compiler::CircuitBuilder::new();
			let c = mk_circuit(&mut b, max_len);
			let circuit = b.build();

			// Verify the circuit was constructed successfully
			// The number of message wires should be n_words = n_blocks * 16
			let n_blocks = (max_len + 17).div_ceil(128);
			let n_words = n_blocks * 16;
			assert_eq!(
				c.message.len(),
				n_words,
				"Wrong number of message wires for max_len={max_len} ({description})"
			);

			// Test with a simple case: empty message
			let mut w = circuit.new_witness_filler();
			c.populate_len(&mut w, 0);
			c.populate_message(&mut w, b"");
			// SHA256 of empty string
			c.populate_digest(
				&mut w,
				hex!("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
			);

			let result = circuit.populate_wire_witness(&mut w);
			assert!(
				result.is_ok(),
				"Failed for max_len={max_len} ({description}) with empty message: {result:?}"
			);

			// Test with a 3-byte message "abc" if it fits
			if max_len >= 3 {
				let mut w = circuit.new_witness_filler();
				c.populate_len(&mut w, 3);
				c.populate_message(&mut w, b"abc");
				// SHA256 of "abc"
				c.populate_digest(
					&mut w,
					hex!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
				);

				let result = circuit.populate_wire_witness(&mut w);
				assert!(
					result.is_ok(),
					"Failed for max_len={max_len} ({description}) with 'abc' message: {result:?}"
				);
			}
		}
	}

	#[test]
	fn test_sha512_to_le_wires() {
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, 64);

		// Obtain LE-packed wires for the digest wires
		let le_wires = c.digest_to_le_wires(&b);
		assert_eq!(le_wires.len(), 8);

		let circuit = b.build();
		let mut w = circuit.new_witness_filler();
		let message = b"abc";
		let hash = hex!(
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
		);

		c.populate_len(&mut w, message.len());
		c.populate_message(&mut w, message);
		c.populate_digest(&mut w, hash);
		circuit.populate_wire_witness(&mut w).unwrap();

		// Extract the LE-packed bytes from the wires
		let mut le_bytes = Vec::with_capacity(64);
		for i in 0..8 {
			let word = w[le_wires[i]].0;
			for j in 0..8 {
				le_bytes.push((word >> (j * 8)) as u8);
			}
		}

		assert_eq!(&le_bytes, &hash);
	}

	#[test]
	fn test_message_to_le_wires() {
		let mut b = compiler::CircuitBuilder::new();
		let c = mk_circuit(&mut b, 16); // Small circuit for simple test

		// Obtain LE-packed wires for the message
		let le_message_wires = c.message_to_le_wires(&b);

		let circuit = b.build();
		let mut w = circuit.new_witness_filler();
		// Use a simple 8-byte message that fits in one wire
		let message = b"abcdefgh";
		let hash = hex!(
			"a3a8c81bc97c2560010d7389bc88aac974a104e0e2381220c6e084c4dccd1d2d17d4f86db31c2a851dc80e6681d74733c55dcd03dd96f6062cdda12a291ae6ce"
		);

		c.populate_len(&mut w, message.len());
		c.populate_message(&mut w, message);
		c.populate_digest(&mut w, hash);
		circuit.populate_wire_witness(&mut w).unwrap();

		// Check the converted LE wire
		let le_wire = w[le_message_wires[0]].0;

		// Verify the bytes match
		let mut extracted_bytes = Vec::new();
		for j in 0..8 {
			let byte = (le_wire >> (j * 8)) as u8;
			extracted_bytes.push(byte);
		}
		assert_eq!(&extracted_bytes, message);
	}
}

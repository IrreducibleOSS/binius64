use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};
use binius_core::word::Word;

pub const N_RATE_BYTES: usize = 136;
pub const N_WORDS_PER_BLOCK: usize = N_RATE_BYTES / 8;
pub const LOG_N_BYTES_PER_WORD: usize = 3;
pub const N_BYTES_PER_WORD: usize = 1 << 3;

// bit masks for lower le bytes of a 64 bit word
const LOW_MASK: [u64; 8] = [
	0x0000_0000_0000_0000,
	0x0000_0000_0000_00FF,
	0x0000_0000_0000_FFFF,
	0x0000_0000_00FF_FFFF,
	0x0000_0000_FFFF_FFFF,
	0x0000_00FF_FFFF_FFFF,
	0x0000_FFFF_FFFF_FFFF,
	0x00FF_FFFF_FFFF_FFFF,
];

// possible keccak pad byte placements within a 64 bit word
const PAD_BYTE: [u64; 8] = [
	0x00_00_00_00_00_00_00_01,
	0x00_00_00_00_00_00_01_00,
	0x00_00_00_00_00_01_00_00,
	0x00_00_00_00_01_00_00_00,
	0x00_00_00_01_00_00_00_00,
	0x00_00_01_00_00_00_00_00,
	0x00_01_00_00_00_00_00_00,
	0x01_00_00_00_00_00_00_00,
];

const TOP_BIT: u64 = 0x80_00_00_00_00_00_00_00u64;

/// This gadget is intended to be used alongside the Permutation gadget within the Keccak circuit.
/// It pads and constrains an input message of a claimed byte length according to the keccak specification.
///
/// ## Preconditions
///
/// * This circuit relies on the assumption that the claimed length is accurate, it is assumed that
///   if you are using this circuit, you have good reason to believe this is the case.
///
///   Confidence that the claimed length is correct in the context of the front facing Keccak circuit
///   is achieved first by making a claim that an input msg of a claimed length produces a claimed digest.
///   Then this circuit is used topad the message according to the byte length claim. The digest of the
///   padded message is produced. By constraining that the digest is correct, we implicitly constrain that
///   the claimed length since it would be unlikely to compute the hash of a different preimage with the same
///   digest.
///
///   This gadget is being used in conjunction with another gadget that is able to place constraints on
///   whether the claimed byte length of the input message is correct.
pub struct KeccakPadding {
	pub len_bytes: Wire,
	pub msg: Vec<Wire>,
	pub n_blocks: Wire,
	pub padded_msg: Vec<[Wire; N_WORDS_PER_BLOCK]>,
	pub expected_padded_msg: Vec<[Wire; N_WORDS_PER_BLOCK]>,
	pub final_msg_block_full: Wire,
}

impl KeccakPadding {
	/// Standalone circuit for checking that a message has been correctly padded to
	/// match the keccak specification.
	///
	/// ## Arguments
	///
	/// * b - The circuit builder
	/// * message - The message to check
	/// * len_bytes - The length of the message in bytes
	///
	/// ## Preconditions
	/// * msg should not exceed max length
	pub fn new(
		b: &CircuitBuilder,
		msg: Vec<Wire>,
		len_bytes: Wire,
		max_len_bytes: usize,
		expected_padded_msg: Vec<[Wire; N_WORDS_PER_BLOCK]>,
	) -> Self {
		assert!(msg.len() * N_BYTES_PER_WORD <= max_len_bytes);

		// number of blocks needed for the maximum sized message
		let n_blocks = b.add_constant_64((max_len_bytes + 1).div_ceil(N_RATE_BYTES) as u64);
		let n_blocks_usize = n_blocks.as_u32() as usize;

		// constrain the message length claim to be explicitly within bounds
		let len_check = b.icmp_ult(b.add_constant_64(max_len_bytes as u64), len_bytes); // len_bytes <= max_len_bytes
		b.assert_0("len_check", len_check);

		let (padded_msg, final_msg_block_full) =
			Self::pad_message(b, msg.clone(), len_bytes, n_blocks);

		// Add constraints to ensure padded_msg matches expected_padded_msg
		let num_blocks_to_check = padded_msg.len().min(expected_padded_msg.len());
		for block_idx in 0..num_blocks_to_check {
			b.assert_eq_v(
				"padded_msg matches expected",
				padded_msg[block_idx],
				expected_padded_msg[block_idx],
			);
		}

		Self {
			len_bytes,
			msg,
			n_blocks,
			padded_msg,
			expected_padded_msg,
			final_msg_block_full,
		}
	}

	/// Computes keccak message padding via multiplexing across padding cases.
	///
	/// Keccak splits a message of words into 'rate blocks', which are fixed size word arrays of
	/// size N_WORDS_PER_BLOCK. This partitions a message into chunks of words small enough to be
	/// fed into the permutation function during absorption. As a result, a message may not neatly
	/// fit into a whole number of rate blocks. To account for this, Keccak uses a padding scheme
	/// where following the end of a message, a padding byte 0x01 is inserted. The end of each rate
	/// block is also delimited by a top bit 0x80.
	///
	/// As a result, three important cases must be handled to ensure padding is correct.
	///
	/// 1. The final word of a message comes before the final word of the block.
	///
	/// 2. The final word of a message is in the final word of that block but the final byte of that
	///    word is not the final byte of the block. This means the padding byte and the top bit are
	///    in the same word but within different bytes.
	///
	/// 3. The final word of a message is in the final word and the final byte of the block. Meaning
	///    that the padding byte and the top bit are within the same byte.
	fn pad_message(
		b: &CircuitBuilder,
		msg: Vec<Wire>,
		n_msg_bytes: Wire,
		n_blocks_wire: Wire,
	) -> (Vec<[Wire; N_WORDS_PER_BLOCK]>, Wire) {
		let zero = b.add_constant_64(0);
		let one = b.add_constant_64(1);
		let n_blocks = n_blocks_wire.as_u32() as usize;

		// The input msg is embedded into rate blocks for keccak absorption phase
		let mut padded_msg_wires = (0..n_blocks)
			.map(|_| [zero; N_WORDS_PER_BLOCK])
			.collect::<Vec<_>>();

		// Compute if the final block is exactly full using proper modulo
		// (len % N_RATE_BYTES == 0) means the message fills a block exactly
		let n_rate_bytes_wire = b.add_constant_64(N_RATE_BYTES as u64);
		let (_, r_block) = b.biguint_divide_hint(&[n_msg_bytes], &[n_rate_bytes_wire]);
		let full_block = b.icmp_eq(r_block[0], zero);

		// Check if final msg word is full (n_msg_bytes % 8 == 0)
		let n_msg_bytes_mod_8 = b.band(n_msg_bytes, b.add_constant_64(7)); 
		let is_full_word = b.icmp_eq(n_msg_bytes_mod_8, zero);
		let is_partial_word = b.bnot(is_full_word);

		// First, place all message words into the rate blocks
		let mut msg_idx = 0;
		for block_idx in 0..padded_msg_wires.len() {
			for block_word_idx in 0..N_WORDS_PER_BLOCK {
				let total_word_idx = block_idx * N_WORDS_PER_BLOCK + block_word_idx;
				let word_idx_wire = b.add_constant_64(total_word_idx as u64);

				// Calculate number of message words = (n_msg_bytes + 7) / 8
				let (n_plus_7, _) = b.iadd_cin_cout(n_msg_bytes, b.add_constant_64(7), zero);
				let n_msg_words = b.shr(n_plus_7, 3);

				// Check if this position has a message word
				let is_msg_position = b.icmp_ult(word_idx_wire, n_msg_words);

				if msg_idx < msg.len() {
					// Place message word or zero based on position
					padded_msg_wires[block_idx][block_word_idx] =
						mux(b, is_msg_position, msg[msg_idx], zero);
					msg_idx += 1;
				} else {
					padded_msg_wires[block_idx][block_word_idx] = zero;
				}
			}
		}

		// Calculate where padding goes: word_boundary = n_msg_bytes / 8
		let word_boundary = b.shr(n_msg_bytes, 3);

		// multiplex on pad byte placement cases
		//
		// if full_word & (~last_word_in_block)
		// on: [..., [b1, b1,  b2,  b3,  b4,  b5,  b6,  b7 ], [0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]]
		// do: [..., [b1, b1,  b2,  b3,  b4,  b5,  b6,  b7 ], [0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]]
		//
		// if full_word & last_word_in_block
		// on: [..., [b1, b1,  b2,  b3,  b4,  b5,  b6,  b7 ]] [[0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0], ...]
		// do: [..., [b1, b1,  b2,  b3,  b4,  b5,  b6,  b7 ]] [[0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0], ...]
		//
		// partial & partial_with_one_empty_byte
		// on: [..., [b1, b1,  b2,  b3,  b4,  b5,  b6,  0x00]]
		// do: [..., [b1, b1,  b2,  b3,  b4,  b5,  b6,  0x10]]
		//
		// if partial & ~partial_with_one_empty_byte
		// on: [..., [b1, 0x0,  0x0, 0x0, 0x0, 0x0, 0x0, 0x0]]
		// do: [..., [b1, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]]
		for block_idx in 0..padded_msg_wires.len() {
			for block_word_idx in 0..N_WORDS_PER_BLOCK {
				let total_word_idx = block_idx * N_WORDS_PER_BLOCK + block_word_idx;
				let word_idx_wire = b.add_constant_64(total_word_idx as u64);

				let is_padding_position = b.icmp_eq(word_idx_wire, word_boundary);

				// For partial word case modify the last message word to add padding
				if total_word_idx < msg.len() {
					let msg_word = msg[total_word_idx];

					// Compute the padded version for each possible byte position and multiplex to apply only the correct one
					let mut partial_padded = zero;
					for byte_idx in 0..N_BYTES_PER_WORD {
						let lo_mask = b.add_constant_64(LOW_MASK[byte_idx]);
						let msg_lo = b.band(msg_word, lo_mask);
						let pad_byte = b.add_constant_64(PAD_BYTE[byte_idx]);
						let padded_candidate = b.bor(msg_lo, pad_byte);

						let byte_idx_wire = b.add_constant_64(byte_idx as u64);
						let is_correct_byte = b.icmp_eq(n_msg_bytes_mod_8, byte_idx_wire);
						let cond =
							b.band(b.band(is_partial_word, is_padding_position), is_correct_byte);

						partial_padded = mux(b, cond, padded_candidate, partial_padded);
					}

					// If this is partial word at padding position, use padded version
					let use_partial = b.band(is_partial_word, is_padding_position);
					let current = padded_msg_wires[block_idx][block_word_idx];
					padded_msg_wires[block_idx][block_word_idx] =
						mux(b, use_partial, partial_padded, current);
				}

				// For full word case: place 0x01 in the position after the last message word
				let pad_byte_word = b.add_constant_64(0x01);
				let use_full_pad = b.band(is_full_word, is_padding_position);
				let current = padded_msg_wires[block_idx][block_word_idx];
				padded_msg_wires[block_idx][block_word_idx] =
					mux(b, use_full_pad, pad_byte_word, current);
			}
		}

        // Next, compute the last block index based on len_bytes
        // The 0x80 byte goes in the last word of the block containing the message end
        // or the next block if the message ends exactly at a block boundary
        //
        // We need to compute (len_bytes - 1) / N_RATE_BYTES when len > 0
        // But handle len == 0 case specially

		// Check if len_bytes is zero
		let is_zero_len = b.icmp_eq(n_msg_bytes, zero);

		// For non-zero length: block_idx = (len_bytes - 1) / N_RATE_BYTES
		// For zero length: block_idx = 0 (but padding goes in block 0)
		let (len_minus_one, _) = b.isub_bin_bout(n_msg_bytes, one, zero);
		let msg_last_block_idx_nonzero = b
			.biguint_divide_hint(&[len_minus_one], &[n_rate_bytes_wire])
			.0[0];
		let msg_last_block_idx = mux(b, is_zero_len, zero, msg_last_block_idx_nonzero);

		// Check if we're exactly at a block boundary (need extra block for padding)
		// Use proper modulo instead of bitmask since N_RATE_BYTES (136) is not power of 2
		let (_, bytes_mod_rate) = b.biguint_divide_hint(&[n_msg_bytes], &[n_rate_bytes_wire]);
		let bytes_in_last_block = bytes_mod_rate[0];
		let at_block_boundary = b.icmp_eq(bytes_in_last_block, zero);

		// If at boundary, padding goes in next block, otherwise same block
		let (pad_block_idx_next, _) = b.iadd_cin_cout(msg_last_block_idx, one, zero);
		let pad_block_idx = mux(b, at_block_boundary, pad_block_idx_next, msg_last_block_idx);

		// Add 0x80 to the last word of each block, gated by whether it's the padding block
		let top_bit = b.add_constant_64(TOP_BIT);
		let last_word_idx = N_WORDS_PER_BLOCK - 1;

		for block_idx in 0..padded_msg_wires.len() {
			let block_idx_wire = b.add_constant_64(block_idx as u64);
			let is_pad_block = b.icmp_eq(block_idx_wire, pad_block_idx);

			// Conditionally add 0x80 to the last word of this block
			let current_word = padded_msg_wires[block_idx][last_word_idx];
			padded_msg_wires[block_idx][last_word_idx] =
				mux(b, is_pad_block, b.bor(current_word, top_bit), current_word);
		}

		(padded_msg_wires, full_block)
	}

	/// Populates the witness with the actual message length
	///
	/// ## Arguments
	///
	/// * w - The witness filler to populate
	/// * len_bytes - The actual byte length of the message
	pub fn populate_len(&self, w: &mut WitnessFiller<'_>, len_bytes: usize) {
		w[self.len_bytes] = Word(len_bytes as u64);
	}

	/// Populates the witness with padded byte message packed into 64-bit words
	///
	/// ## Arguments
	///
	/// * w - The witness filler to populate
	/// * message_bytes - The input message as a byte slice
	pub fn populate_message(&self, w: &mut WitnessFiller<'_>, message_bytes: &[u8]) {
		// populate message words from input bytes
		let words: Vec<u64> = self.pack_bytes_into_words(message_bytes);
		for (i, word) in words.iter().enumerate() {
			if i < self.msg.len() {
				w[self.msg[i]] = Word(*word);
			}
		}
	}

	/// Populates the witness with the expected padded message
	///
	/// ## Arguments
	///
	/// * w - The witness filler to populate
	/// * message_bytes - The input message as a byte slice
	pub fn populate_expected_padding(&self, w: &mut WitnessFiller<'_>, message_bytes: &[u8]) {
		// Use the reference function to compute expected padding
		let padded_blocks = pad_reference(message_bytes);
		for (block_idx, block) in padded_blocks.iter().enumerate() {
			if block_idx < self.expected_padded_msg.len() {
				for (word_idx, &word) in block.iter().enumerate() {
					w[self.expected_padded_msg[block_idx][word_idx]] = Word(word);
				}
			}
		}

		// Fill remaining blocks with zeros if any (up to the length of expected_padded_msg)
		let n_blocks = self.expected_padded_msg.len();
		for block_idx in padded_blocks.len()..n_blocks {
			for word_idx in 0..N_WORDS_PER_BLOCK {
				w[self.expected_padded_msg[block_idx][word_idx]] = Word(0);
			}
		}
	}

	// Embeds a collection of bytes into words
	fn pack_bytes_into_words(&self, bytes: &[u8]) -> Vec<u64> {
		let n_words = bytes.len().div_ceil(N_BYTES_PER_WORD); 
		let mut words = Vec::with_capacity(n_words);
		for i in 0..n_words {
			let start = i * 8;
			let end = ((i + 1) * 8).min(bytes.len());
			let mut word_bytes = [0u8; 8];
			word_bytes[..end - start].copy_from_slice(&bytes[start..end]);
			let word = u64::from_le_bytes(word_bytes);
			words.push(word);
		}
		words
	}
}

// Multiplexor for selecting between two values based on a condition
// r = y ^ (m & (x ^ y))
fn mux(b: &CircuitBuilder, cond: Wire, on: Wire, off: Wire) -> Wire {
	b.bxor(off, b.band(cond, b.bxor(on, off)))
}

fn pad_reference(message_bytes: &[u8]) -> Vec<[u64; N_WORDS_PER_BLOCK]> {
	let n_blocks = (message_bytes.len() + 1).div_ceil(N_RATE_BYTES);

	// copy msg into padded bytes
	let mut padded_bytes = vec![0u8; n_blocks * N_RATE_BYTES];
	padded_bytes[..message_bytes.len()].copy_from_slice(message_bytes);

	// place pad byte 0x01 after message
	let msg_len = message_bytes.len();
	padded_bytes[msg_len] = 0x01;

	// Add 0x80 at the end of the padding block
	let padding_block_idx = msg_len / N_RATE_BYTES;
	let padding_block_end = padding_block_idx * N_RATE_BYTES + N_RATE_BYTES - 1;
	padded_bytes[padding_block_end] |= 0x80;

	padded_bytes_to_rate_blocks(&padded_bytes, n_blocks)
}

fn padded_bytes_to_rate_blocks(
	padded_bytes: &[u8],
	n_blocks: usize,
) -> Vec<[u64; N_WORDS_PER_BLOCK]> {
	let mut padded_blocks = Vec::with_capacity(n_blocks);
	for block_idx in 0..n_blocks {
		let mut block = [0u64; N_WORDS_PER_BLOCK];
		let block_start = block_idx * N_RATE_BYTES;
		for (word_idx, chunk) in padded_bytes[block_start..block_start + N_RATE_BYTES]
			.chunks(8)
			.enumerate()
		{
			block[word_idx] = u64::from_le_bytes(chunk.try_into().unwrap());
		}
		padded_blocks.push(block);
	}

	padded_blocks
}

#[cfg(test)]
mod tests {
	use rand::{Rng, SeedableRng, rngs::StdRng};
	use std::iter::repeat_n;

	use crate::{
		circuits::keccak::padding::{KeccakPadding, N_RATE_BYTES, pad_reference},
		compiler::CircuitBuilder,
		constraint_verifier::verify_constraints,
	};

	fn validate_padding_circuit(msg_bytes: &[u8], max_len: usize) {
		let b = CircuitBuilder::new();

		// num words needed to embed all msg bytes
		let msg_n_words = msg_bytes.len().div_ceil(8);

		// input wires
		let len_wire = b.add_witness();
		let input_msg_wires = (0..msg_n_words).map(|_| b.add_inout()).collect();

		// Create expected padded message wires
		let n_blocks = (max_len + 1).div_ceil(N_RATE_BYTES);
		let expected_padded_msg = (0..n_blocks)
			.map(|_| std::array::from_fn(|_| b.add_witness()))
			.collect();

		let padding = KeccakPadding::new(&b, input_msg_wires, len_wire, max_len, expected_padded_msg);
		let circuit = b.build();

		// populate witness
		let mut w = circuit.new_witness_filler();
		padding.populate_len(&mut w, msg_bytes.len());
		padding.populate_message(&mut w, msg_bytes);
		padding.populate_expected_padding(&mut w, msg_bytes);

		// verify constraints on witness
		circuit.populate_wire_witness(&mut w).unwrap();
		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	#[should_panic]
	#[allow(deprecated)]
	fn test_message_too_long() {
		let mut rng = StdRng::seed_from_u64(0);
		let max_len_bytes = 2048;
		let message = repeat_n(rng.gen_range(0..=255), max_len_bytes * 2).collect::<Vec<_>>();

		validate_padding_circuit(&message, max_len_bytes);
	}

	/// This one byte message ends well before the final word of the block. To pad this message,
	/// only one rate block is required. The padding byte 0x01 is inserted within the first word of
	/// the rate block, following the message byte. The final padding byte 0x80 is inserted the
	/// final byte of the final word of the rate block
	///
	/// Final msg word within block (partial)
	///
	///  [b1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	///
	/// Final rate block word:
	///
	///  [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
	#[test]
	fn test_message_ends_before_final_word() {
		let message: Vec<u8> = vec![0xFF];
		let max_message_len = 4096;
		validate_padding_circuit(&message, max_message_len);
	}

	/// This message ends within four bytes of the rate block boundary. This means that the padding
	/// byte and the top bit are in the same word of the final block, but within different bytes in
	/// that word.
	///
	/// Final rate block word:
	///
	///  [b1, b2, b3, b4, 0x01, 0x00, 0x00, 0x80]
	#[test]
	fn test_message_ends_in_final_word_but_before_final_byte() {
		let message = vec![0xFF; N_RATE_BYTES - 4];
		let max_message_len = 4096;
		validate_padding_circuit(&message, max_message_len);
	}

	/// This message ends within one byte of the final rate block boundary. This means that the
	/// padding byte and the top bit are in the same word of the final block, and the same byte.
	///
	/// Final rate block word:
	///
	///  [b1, b2, b3, b4, b5, b6, b7, 0x81]
	#[test]
	fn test_message_ends_in_final_word_and_final_byte() {
		let message = vec![0xFF; N_RATE_BYTES - 1];
		let max_message_len = 4096;
		validate_padding_circuit(&message, max_message_len);
	}

	/// This message ends 8 bytes before the final rate block boundary. This means that the padding
	/// byte and the top bit are in the same word of the finalblock word, but there are no message
	/// words in the final block.
	///
	/// Final rate block word:
	///
	///  [b1, b2, b3, b4, b5, b6, b7, b8] [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
	#[test]
	fn test_message_ends_in_final_word_and_final_byte_with_padding() {
		let message = vec![0xFF; N_RATE_BYTES - 8];
		let max_message_len = 4096;
		validate_padding_circuit(&message, max_message_len);
	}

	#[test]
	fn test_message_fills_out_rate_block_completely() {
		let message = vec![0xFF; N_RATE_BYTES - 8];
		let max_message_len = 4096;
		validate_padding_circuit(&message, max_message_len);
	}

	#[test]
	fn test_padding_reference_can_produce_correct_digest_on_unpadded_messages() {
		use crate::circuits::keccak::reference;

		let test_cases = vec![
			vec![],                       // empty message
			vec![0xFF],                   // 1 byte
			vec![0xFF; 8],                // full word
			vec![0xFF; N_RATE_BYTES - 4], // near block boundary
			vec![0xFF; N_RATE_BYTES - 1], // one byte before boundary
			vec![0xFF; N_RATE_BYTES],     // exact block boundary
			vec![0xFF; N_RATE_BYTES + 1], // one byte past boundary
			vec![0x42; 200],              // random longer message
		];

		for message_bytes in test_cases {
			let expected_digest = reference::keccak_256(&message_bytes);

			let padded_blocks = pad_reference(&message_bytes);
			let mut state = [0u64; 25];

			// sponge absorption
			for block in &padded_blocks {
				for (i, &word) in block.iter().enumerate() {
					state[i] ^= word;
				}
				reference::keccak_f1600_reference(&mut state);
			}

			// sponge squeeze
			let mut computed_digest = [0u8; 32];
			for (i, &word) in state[..4].iter().enumerate() {
				computed_digest[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
			}

			assert_eq!(computed_digest, expected_digest,);
		}
	}
}

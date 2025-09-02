pub mod permutation;
pub mod reference;

use binius_core::word::Word;
use permutation::Permutation;

use crate::{
	circuits::multiplexer::{multi_wire_multiplex, single_wire_multiplex},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};

pub const N_WORDS_PER_DIGEST: usize = 4;
pub const N_WORDS_PER_STATE: usize = 25;
pub const RATE_BYTES: usize = 136;
pub const N_WORDS_PER_BLOCK: usize = RATE_BYTES / 8;

/// Keccak-256 circuit that can handle variable-length inputs up to a specified maximum length.
///
/// # Arguments
///
/// * `len_bytes` - A wire representing the input message length in bytes
/// * `digest` - Array of 4 wires representing the 256-bit output digest
/// * `message` - Vector of wires representing the input message
/// * `padded_message` - Vector of wires representing the padded message
pub struct Keccak {
	pub len_bytes: Wire,
	pub digest: [Wire; N_WORDS_PER_DIGEST],
	pub message: Vec<Wire>,
	pub padded_message: Vec<Wire>,
	n_blocks: usize,
}

impl Keccak {
	/// Build the Keccak-256 circuit constraints
	///
	/// This function adds all the necessary constraints to the circuit builder to implement
	/// the Keccak-256 hash function. It handles variable-length inputs up to a maximum length
	/// determined by the size of the message vector.
	///
	/// # Arguments
	///
	/// * `b` - Circuit builder object to add constraints to
	/// * `len_bytes` - Wire representing the claimed input message length in bytes
	/// * `digest` - Array of 4 wires representing the claimed 256-bit output digest
	/// * `message` - Slice of wires representing the claimed input message (unpacked)
	/// * `padded_message` - Slice of wires representing the padded message according to Keccak
	///   padding rules
	///
	/// ## Preconditions
	///
	/// * `message.len()` must be non-zero (implies max_len_bytes > 0)
	/// * `padded_message.len()` must equal `n_blocks * N_WORDS_PER_BLOCK` where:
	///   - `n_blocks = (max_len_bytes + 1).div_ceil(RATE_BYTES)`
	///   - `max_len_bytes = message.len() * 8`
	///   - `RATE_BYTES = 136`
	///   - `N_WORDS_PER_BLOCK = 17`
	/// * The padded message must follow Keccak padding rules:
	///   - Padding byte 0x01 after the message
	///   - Final byte of the last block must have 0x80 bit set
	///
	/// ## Circuit Constraints
	///
	/// This function adds the following constraints to the circuit:
	/// 1. Length bounds checking - ensures `len_bytes <= max_len_bytes`
	/// 2. Keccak-f[1600] permutation rounds for each rate block
	/// 3. Digest correctness - verifies the claimed digest matches the computed hash
	/// 4. Padding validation - ensures proper Keccak padding is applied
	///
	/// ## Example
	///
	/// ```ignore
	/// let b = CircuitBuilder::new();
	/// let len = b.add_witness();
	/// let digest = [b.add_inout(); 4];
	/// let message = vec![b.add_inout(); 32];  // 256 bytes max
	/// let padded_message = vec![b.add_witness(); 34];  // 2 blocks * 17 words
	///
	/// Keccak::build_circuit(&b, len, digest, &message, &padded_message);
	/// ```
	pub fn build_circuit(
		b: &CircuitBuilder,
		len_bytes: Wire,
		digest: [Wire; N_WORDS_PER_DIGEST],
		message: &[Wire],
		padded_message: &[Wire],
	) {
		let max_len_bytes = message.len() << 3;
		// number of blocks needed for the maximum sized message
		let n_blocks = (max_len_bytes + 1).div_ceil(RATE_BYTES);

		// constrain the message length claim to be explicitly within bounds
		let len_check = b.icmp_ult(b.add_constant_64(max_len_bytes as u64), len_bytes); // max_len_bytes < len_bytes
		b.assert_false("len_check", len_check);

		// Validate that padded_message has the correct size
		assert_eq!(
			padded_message.len(),
			n_blocks * N_WORDS_PER_BLOCK,
			"padded_message must have {} wires, got {}",
			n_blocks * N_WORDS_PER_BLOCK,
			padded_message.len()
		);

		// zero initialized keccak state
		let mut states: Vec<[Wire; N_WORDS_PER_STATE]> = Vec::with_capacity(n_blocks + 1);
		let zero = b.add_constant(Word::ZERO);
		states.push([zero; N_WORDS_PER_STATE]);

		// xor next message block into state and permute
		for block_no in 0..n_blocks {
			let state_in = states[block_no];
			let mut xored_state = state_in;
			for i in 0..N_WORDS_PER_BLOCK {
				xored_state[i] =
					b.bxor(state_in[i], padded_message[block_no * N_WORDS_PER_BLOCK + i]);
			}

			Permutation::keccak_f1600(b, &mut xored_state);

			states.push(xored_state);
		}

		// begin "constrain claimed digest".
		// want to do: `let block_index = (len_bytes + 1).divceil(136)`.
		// royal pain in the ass that 136 is not a power of 2, so we can't compute this in circuit
		// still though, i believe that there might be tricks better than what we're doing below.
		let mut end_block_index = b.add_constant(Word::ZERO);
		let mut is_not_last_column = b.add_constant(Word::ZERO);
		// `is_not_last_column` will be true if and only if `len_bytes >> 3` != 16 (mod 17).
		// true iff the WORD w/ the very first post-message byte is NOT the last word in its block.
		for block_no in 0..n_blocks {
			// start of this block
			let block_start = b.add_constant_64((block_no * RATE_BYTES) as u64);
			let block_end = b.add_constant_64(((block_no + 1) * RATE_BYTES) as u64);
			let last_word_start = b.add_constant_64(((block_no + 1) * RATE_BYTES - 8) as u64);

			let lt_start = b.icmp_ult(len_bytes, block_start);
			let lt_end = b.icmp_ult(len_bytes, block_end);
			let lt_last_word = b.icmp_ult(len_bytes, last_word_start);
			let is_final_block = b.band(b.bnot(lt_start), lt_end);

			// flag that this block is the final block per the claimed length
			end_block_index =
				b.select(is_final_block, b.add_constant_64(block_no as u64), end_block_index);
			is_not_last_column = b.select(is_final_block, lt_last_word, is_not_last_column);
		}

		let inputs: Vec<&[Wire]> = states[1..].iter().map(|arr| &arr[..]).collect();
		let computed_digest_vec = multi_wire_multiplex(b, &inputs, end_block_index);
		let computed_digest = computed_digest_vec[..N_WORDS_PER_DIGEST]
			.try_into()
			.unwrap();
		b.assert_eq_v("claimed digest is correct", digest, computed_digest);

		// begin treatment of boundary word.
		let word_boundary = b.shr(len_bytes, 3);
		let boundary_word = single_wire_multiplex(b, message, word_boundary);
		let boundary_padded_word = single_wire_multiplex(b, padded_message, word_boundary);
		// When the last word of the message is not full, we expect a padding byte to be
		// somewhere within the word. Since the top bit will also be in this word.
		let candidates: Vec<Wire> = (0..8)
			.map(|i| {
				let mask = b.add_constant_64(0x00FFFFFFFFFFFFFF >> ((7 - i) << 3));
				let padding_byte = b.add_constant_64(1 << (i << 3));
				let message_low = b.band(boundary_word, mask);
				b.bxor(message_low, padding_byte)
			})
			.collect();

		let zero = b.add_constant(Word::ZERO);
		let msb_one = b.add_constant(Word::MSB_ONE);
		let len_bytes_mod_8 = b.band(len_bytes, b.add_constant_64(7));
		let expected_partial = single_wire_multiplex(b, &candidates, len_bytes_mod_8);
		let with_possible_end =
			b.bxor(expected_partial, b.select(is_not_last_column, zero, msb_one));

		b.assert_eq("expected partial", with_possible_end, boundary_padded_word);

		// Within the final rate block, ensure that the pad byte and top bit are where they are
		// supposed to be
		for block_index in 0..n_blocks {
			let is_end_block = b.icmp_eq(end_block_index, b.add_constant_64(block_index as u64));
			for column_index in 0..N_WORDS_PER_BLOCK {
				let word_index = block_index * N_WORDS_PER_BLOCK + column_index;

				let padded_word = padded_message[word_index];

				// a potentially padded word is at this index
				let word_idx_wire = b.add_constant_64(word_index as u64);
				if word_index < message.len() {
					let message_word = message[word_index];
					let is_before_end = b.icmp_ult(word_idx_wire, word_boundary);
					b.assert_eq_cond("full", padded_word, message_word, is_before_end);
				}

				let is_past_message = b.icmp_ult(word_boundary, word_idx_wire);

				if column_index == 16 {
					// last word in the block
					let must_check_delimiter = b.band(is_end_block, is_not_last_column);
					b.assert_eq_cond("delim", padded_word, msb_one, must_check_delimiter);
					// the case we need to deal with: we're in end block but `is_not_last_column`.
					// this means that the `boundary_message_word` is not the last word in its block
					// then the presence of the 0x80 delimiter is NOT treated with the boundary word
					// thus we must separately check that the ACTUAL last word in the block has it

					// if `is_end_block` is true but NOT `is_not_last_column`, then we're fine.
					// indeed: if `!is_not_last_column`, boundary message word IS in last column,
					// so we already handled the validity of that word, and there is nothing to do.

					// if NOT in end block, then again i claim there is nothing we need to check.
					// if we're in the last column but strictly before the end block, then we're
					// still in the message, by definition of `end_block`. indeed, the `0x80` byte
					// happens in the soonest possible block after the message ends, and no later.
					// thus we already checked the validity of this word above (a `message_word`).
					// the other case is that we're strictly after the end block. in this case,
					// we can just leave the `padded_word` completely unconstrained. after all,
					// said word will have no effect on `digest` whatsoever, so we just leave it.
				} else {
					b.assert_eq_cond("after-message padding", padded_word, zero, is_past_message);
					// we're strictly after the word w/ the 0x01 byte and not in the last column.
					// there are two cases: either we're within the end block or strictly after it.
					// if the former, we're after the boundary word but before the word w/ 0x80.
					// in that case, we must for the sake of correctness assert that this word is 0.
					// if strictly after the end block, this word will have no effect on `digest`;
					// thus we're free to assert that it's 0, but it's not necessary for soundness.
				}
			}
		}
	}
	/// Create a new keccak circuit using the circuit builder
	///
	/// This function creates the necessary padded message wires, builds the circuit constraints,
	/// and returns a Keccak struct that can be used to populate witness values.
	///
	/// # Arguments
	///
	/// * `b` - Circuit builder object
	/// * `len_bytes` - Wire representing the claimed input message length in bytes
	/// * `digest` - Array of 4 wires representing the claimed 256-bit output digest
	/// * `message` - Vector of wires representing the claimed input message (unpacked)
	///
	/// ## Preconditions
	/// * `message.len()` must be non-zero (implies max_len_bytes > 0)
	///
	/// ## Returns
	///
	/// A `Keccak` struct containing the wire references needed to populate witness values
	pub fn new(
		b: &CircuitBuilder,
		len_bytes: Wire,
		digest: [Wire; N_WORDS_PER_DIGEST],
		message: Vec<Wire>,
	) -> Self {
		// Calculate n_blocks and create padded_message wires
		let max_len_bytes = message.len() << 3;
		let n_blocks = (max_len_bytes + 1).div_ceil(RATE_BYTES);
		let padded_message: Vec<Wire> = (0..n_blocks * N_WORDS_PER_BLOCK)
			.map(|_| b.add_witness())
			.collect();

		// Build the circuit constraints
		Self::build_circuit(b, len_bytes, digest, &message, &padded_message);

		// Return the struct with wire references
		Self {
			len_bytes,
			digest,
			message,
			padded_message,
			n_blocks,
		}
	}

	pub fn max_len_bytes(&self) -> usize {
		self.message.len() << 3
	}

	/// Populates the witness with the actual message length
	///
	/// ## Arguments
	///
	/// * w - The witness filler to populate
	/// * len_bytes - The actual byte length of the message
	pub fn populate_len_bytes(&self, w: &mut WitnessFiller<'_>, len_bytes: usize) {
		assert!(
			len_bytes <= self.max_len_bytes(),
			"Message length {} exceeds maximum {}",
			len_bytes,
			self.max_len_bytes()
		);
		w[self.len_bytes] = Word(len_bytes as u64);
	}

	/// Populates the witness with the expected digest value packed into 4 64-bit words
	///
	/// ## Arguments
	///
	/// * w - The witness filler to populate
	/// * digest - The expected 32-byte Keccak-256 digest
	pub fn populate_digest(&self, w: &mut WitnessFiller<'_>, digest: [u8; 32]) {
		for (i, bytes) in digest.chunks(8).enumerate() {
			let word = u64::from_le_bytes(bytes.try_into().unwrap());
			w[self.digest[i]] = Word(word);
		}
	}

	/// Populates the witness with padded byte message packed into 64-bit words
	///
	/// ## Arguments
	///
	/// * w - The witness filler to populate
	/// * message_bytes - The input message as a byte slice
	pub fn populate_message(&self, w: &mut WitnessFiller<'_>, message_bytes: &[u8]) {
		let max_len_bytes = self.max_len_bytes();
		populate_message_and_padded(
			w,
			message_bytes,
			&self.message,
			&self.padded_message,
			max_len_bytes,
			self.n_blocks,
		);
	}
}

/// Standalone function to populate message and padded message wires from raw bytes
///
/// This function takes a raw message and populates both the unpacked message wires
/// and the properly padded message wires according to Keccak-256 padding rules.
///
/// ## Arguments
///
/// * `w` - The witness filler to populate
/// * `message_bytes` - The input message as a byte slice
/// * `message_wires` - Wires to populate with the unpacked message
/// * `padded_message_wires` - Wires to populate with the padded message
/// * `max_len_bytes` - Maximum message length in bytes that the circuit supports
/// * `n_blocks` - Number of rate blocks needed (must be `(max_len_bytes + 1).div_ceil(RATE_BYTES)`)
///
/// ## Preconditions
///
/// * `message_bytes.len() <= max_len_bytes`
/// * `n_blocks == (max_len_bytes + 1).div_ceil(RATE_BYTES)`
/// * `message_wires.len() == max_len_bytes.div_ceil(8)`
/// * `padded_message_wires.len() == n_blocks * N_WORDS_PER_BLOCK`
///
/// ## Example
///
/// ```ignore
/// populate_message_and_padded(
///     &mut w,
///     b"hello".as_ref(),
///     &message_wires,
///     &padded_message_wires,
///     1024,  // max message length
///     8,     // (1024 + 1).div_ceil(136)
/// );
/// ```
pub fn populate_message_and_padded(
	w: &mut WitnessFiller<'_>,
	message_bytes: &[u8],
	message_wires: &[Wire],
	padded_message_wires: &[Wire],
	max_len_bytes: usize,
	n_blocks: usize,
) {
	assert!(
		message_bytes.len() <= max_len_bytes,
		"Message length {} exceeds maximum {}",
		message_bytes.len(),
		max_len_bytes
	);

	// Populate message wires from input bytes
	let n_message_words = max_len_bytes.div_ceil(8);
	for i in 0..n_message_words {
		if i < message_wires.len() {
			let word = if i * 8 < message_bytes.len() {
				// to handle messages that are not multiples of 64, bytes are copied into
				// a little endian byte array and then converted to a u64
				let start = i * 8;
				let end = ((i + 1) * 8).min(message_bytes.len());
				let mut word_bytes = [0u8; 8];
				word_bytes[..end - start].copy_from_slice(&message_bytes[start..end]);
				u64::from_le_bytes(word_bytes)
			} else {
				0
			};
			w[message_wires[i]] = Word(word);
		}
	}

	// Create padded message
	let mut padded_bytes = vec![0u8; n_blocks * RATE_BYTES];
	padded_bytes[..message_bytes.len()].copy_from_slice(message_bytes);

	let msg_len = message_bytes.len();
	let num_full_blocks = msg_len / RATE_BYTES;
	let padding_block_start = num_full_blocks * RATE_BYTES;

	padded_bytes[msg_len] = 0x01;

	let padding_block_end = padding_block_start + RATE_BYTES - 1;
	padded_bytes[padding_block_end] |= 0x80;

	// Populate padded message wires
	for block_idx in 0..n_blocks {
		for (i, chunk) in padded_bytes[block_idx * RATE_BYTES..(block_idx + 1) * RATE_BYTES]
			.chunks(8)
			.enumerate()
		{
			let word = u64::from_le_bytes(chunk.try_into().unwrap());
			w[padded_message_wires[block_idx * N_WORDS_PER_BLOCK + i]] = Word(word);
		}
	}
}

#[cfg(test)]
mod tests {
	use std::iter::repeat_n;

	use rand::{Rng, SeedableRng, rngs::StdRng};
	use sha3::{Digest, Keccak256};

	use super::{Keccak, N_WORDS_PER_DIGEST};
	use crate::{
		circuits::keccak::RATE_BYTES,
		compiler::{CircuitBuilder, Wire},
		constraint_verifier::verify_constraints,
	};

	fn keccak_crate(message_bytes: &[u8]) -> [u8; 32] {
		let mut hasher = Keccak256::new();
		hasher.update(message_bytes);
		hasher.finalize().into()
	}

	// runs keccak circuit on a message and returns the expected digest
	fn validate_keccak_circuit(
		message_bytes: &[u8],
		expected_digest: [u8; 32],
		max_len_bytes: usize,
	) {
		let b = CircuitBuilder::new();

		let len = b.add_witness();
		let digest: [Wire; N_WORDS_PER_DIGEST] = std::array::from_fn(|_| b.add_inout());

		let n_words = max_len_bytes.div_ceil(8);
		let message = (0..n_words).map(|_| b.add_inout()).collect();

		let keccak = Keccak::new(&b, len, digest, message);
		let circuit = b.build();

		// populate witness
		let mut w = circuit.new_witness_filler();
		keccak.populate_len_bytes(&mut w, message_bytes.len());
		keccak.populate_message(&mut w, message_bytes);
		keccak.populate_digest(&mut w, expected_digest);

		// ensure correct final digest
		circuit.populate_wire_witness(&mut w).unwrap();
		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();

		println!("circuit: {:?}", circuit.simple_json_dump());
	}

	#[test]
	#[allow(deprecated)]
	fn test_valid_message() {
		let mut rng = StdRng::seed_from_u64(0);

		let message_bytes: Vec<u8> = repeat_n(rng.gen_range(0..=255), 1000).collect::<Vec<_>>();
		let max_len_bytes = 2048;

		let expected_digest = keccak_crate(&message_bytes);
		validate_keccak_circuit(&message_bytes, expected_digest, max_len_bytes);
	}

	#[test]
	#[should_panic]
	#[allow(deprecated)]
	fn test_message_too_long() {
		let mut rng = StdRng::seed_from_u64(0);

		let message = repeat_n(rng.gen_range(0..=255), 3000).collect::<Vec<_>>();
		let max_len_bytes = 2048;

		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_len_bytes);
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

		let max_message_len = 1024;
		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
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
		let message = vec![0xFF; RATE_BYTES - 4];

		let max_message_len = 1024;
		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
	}

	/// This message ends within one byte of the final rate block boundary. This means that the
	/// padding byte and the top bit are in the same word of the final block, and the same byte.
	///
	/// Final rate block word:
	///
	///  [b1, b2, b3, b4, b5, b6, b7, 0x81]
	#[test]
	fn test_message_ends_in_final_word_and_final_byte() {
		let message = vec![0xFF; RATE_BYTES - 1];

		let max_message_len = 1024;
		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
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
		let message = vec![0xFF; RATE_BYTES - 8];

		let max_message_len = 1024;
		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
	}

	/// Test the standalone build_circuit function
	#[test]
	fn test_standalone_build_circuit() {
		use binius_core::word::Word;
		use sha3::{Digest, Keccak256};

		let message_bytes = b"Testing build_circuit";
		let max_len_bytes = 256usize;
		let n_blocks = (max_len_bytes + 1).div_ceil(RATE_BYTES);

		// Create a circuit with the necessary wires
		let b = CircuitBuilder::new();
		let len = b.add_witness();
		let digest: [Wire; N_WORDS_PER_DIGEST] = std::array::from_fn(|_| b.add_inout());
		let n_message_words = max_len_bytes.div_ceil(8);
		let message: Vec<Wire> = (0..n_message_words).map(|_| b.add_inout()).collect();
		let padded_message: Vec<Wire> = (0..n_blocks * super::N_WORDS_PER_BLOCK)
			.map(|_| b.add_witness())
			.collect();

		// Call build_circuit directly (without creating the struct)
		Keccak::build_circuit(&b, len, digest, &message, &padded_message);

		let circuit = b.build();
		let mut w = circuit.new_witness_filler();

		// Populate witness values manually
		w[len] = Word(message_bytes.len() as u64);

		// Populate message and padded message
		super::populate_message_and_padded(
			&mut w,
			message_bytes,
			&message,
			&padded_message,
			max_len_bytes,
			n_blocks,
		);

		// Calculate expected digest using the reference implementation
		let mut hasher = Keccak256::new();
		hasher.update(message_bytes);
		let expected_digest: [u8; 32] = hasher.finalize().into();

		// Populate digest witness
		for (i, bytes) in expected_digest.chunks(8).enumerate() {
			let word = u64::from_le_bytes(bytes.try_into().unwrap());
			w[digest[i]] = Word(word);
		}

		// Verify the circuit constraints are satisfied
		circuit.populate_wire_witness(&mut w).unwrap();
		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	/// Test the standalone populate_message_and_padded function
	#[test]
	fn test_standalone_populate_function() {
		use binius_core::word::Word;

		use crate::compiler::CircuitBuilder;

		let message_bytes = b"Hello, Keccak!";
		let max_len_bytes = 256usize;
		let n_blocks = (max_len_bytes + 1).div_ceil(RATE_BYTES);

		// Create a circuit with the necessary wires
		let b = CircuitBuilder::new();
		let n_message_words = max_len_bytes.div_ceil(8);
		let message_wires: Vec<Wire> = (0..n_message_words).map(|_| b.add_witness()).collect();
		let padded_message_wires: Vec<Wire> = (0..n_blocks * super::N_WORDS_PER_BLOCK)
			.map(|_| b.add_witness())
			.collect();

		let circuit = b.build();
		let mut w = circuit.new_witness_filler();

		// Call the standalone function directly
		super::populate_message_and_padded(
			&mut w,
			message_bytes,
			&message_wires,
			&padded_message_wires,
			max_len_bytes,
			n_blocks,
		);

		// Verify the message was populated correctly
		circuit.populate_wire_witness(&mut w).unwrap();

		// Check first word contains "Hello, K"
		assert_eq!(w[message_wires[0]], Word(u64::from_le_bytes(*b"Hello, K")));
		// Check second word contains "eccak!\0\0"
		let mut expected = [0u8; 8];
		expected[..6].copy_from_slice(b"eccak!");
		assert_eq!(w[message_wires[1]], Word(u64::from_le_bytes(expected)));

		// Check padding was applied correctly
		// First padded word should match first message word
		assert_eq!(w[padded_message_wires[0]], Word(u64::from_le_bytes(*b"Hello, K")));

		// The message is 14 bytes, so byte 14 should have 0x01
		let padded_word_idx = 14 / 8; // Word containing byte 14
		let padded_byte_offset = 14 % 8; // Offset within that word
		let padded_word_value = w[padded_message_wires[padded_word_idx]].0;
		let padded_bytes = padded_word_value.to_le_bytes();
		assert_eq!(
			padded_bytes[padded_byte_offset], 0x01,
			"Padding byte 0x01 not found at position 14"
		);

		// Last byte of the rate block should have 0x80 bit set
		let last_word_idx = super::N_WORDS_PER_BLOCK - 1;
		let last_word_value = w[padded_message_wires[last_word_idx]].0;
		let last_word_bytes = last_word_value.to_le_bytes();
		assert_eq!(last_word_bytes[7] & 0x80, 0x80, "0x80 bit not set in last byte of rate block");
	}
}

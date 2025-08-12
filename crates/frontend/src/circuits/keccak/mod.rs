pub mod permutation;
pub mod reference;

use binius_core::word::Word;
use permutation::Permutation;

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

pub const N_WORDS_PER_STATE: usize = 25;
pub const RATE_BYTES: usize = 136;
pub const N_WORDS_PER_BLOCK: usize = RATE_BYTES / 8;

/// Keccak-256 circuit that can handle variable-length inputs up to a specified maximum length.
///
/// # Arguments
///
/// * `max_len` - max message length in bytes
/// * `len` - A wire representing the input message length in bytes
/// * `digest` - Array of 4 wires representing the 256-bit output digest
/// * `message` - Vector of wires representing the input message
pub struct Keccak {
	pub max_len: usize,
	pub len: Wire,
	pub digest: [Wire; N_WORDS_PER_STATE],
	pub message: Vec<Wire>,
	padded_message: Vec<[Wire; N_WORDS_PER_BLOCK]>,
	n_blocks: usize,
}

impl Keccak {
	/// Create a new keccak circuit using the circuit builder
	///
	/// # Arguments
	///
	/// * `builder` - circuit builder object
	/// * `max_len` - max message length in bytes for this circuit instance
	/// * `len` - wire representing the claimed input message length in bytes
	/// * `digest` - array of 4 wires representing the claimed 256-bit output digest
	/// * `message` - vector of wires representing the claimed input message
	///
	/// ## Preconditions
	/// * max_len > 0
	pub fn new(
		b: &CircuitBuilder,
		max_len: usize,
		len: Wire,
		digest: [Wire; N_WORDS_PER_STATE],
		message: Vec<Wire>,
	) -> Self {
		assert!(max_len > 0, "max_len must be positive");

		// number of blocks needed for the maximum sized message
		let n_blocks = (max_len + 1).div_ceil(RATE_BYTES);

		// constrain the message length claim to be explicitly within bounds
		let len_check = b.icmp_ult(b.add_constant_64(max_len as u64), len);
		b.assert_0("len_check", len_check);

		// run keccak function, producing the intermediate states between permutations
		let (permutation_states, padded_message) = Self::compute_digest(b, n_blocks);

		// ensure digest was correctly computed by keccak
		let is_final_block_flags =
			Self::constrain_claimed_digest(b, permutation_states, digest, len, n_blocks);

		// ensure message padding matches keccak expectations
		Self::constrain_message_padding(
			b,
			len,
			message.clone(),
			n_blocks,
			padded_message.clone(),
			is_final_block_flags,
		);

		Self {
			max_len,
			len,
			digest,
			message,
			padded_message,
			n_blocks,
		}
	}

	/// Computes keccak-256 digest of a padded message.
	///
	/// Repeatedly absorb blocks into the state, this forms the digest computation.
	fn compute_digest(
		b: &CircuitBuilder,
		n_blocks: usize,
	) -> (Vec<[Wire; N_WORDS_PER_STATE]>, Vec<[Wire; N_WORDS_PER_BLOCK]>) {
		let padded_message: Vec<[Wire; N_WORDS_PER_BLOCK]> = (0..n_blocks)
			.map(|_| std::array::from_fn(|_| b.add_witness()))
			.collect();

		// zero initialized keccak state
		let mut states: Vec<[Wire; N_WORDS_PER_STATE]> = Vec::with_capacity(n_blocks + 1);
		let zero = b.add_constant(Word::ZERO);
		states.push([zero; N_WORDS_PER_STATE]);

		// xor next message block into state and permute
		for block_no in 0..n_blocks {
			let state_in = states[block_no];
			let mut xored_state = state_in;
			for i in 0..N_WORDS_PER_BLOCK {
				xored_state[i] = b.bxor(state_in[i], padded_message[block_no][i]);
			}

			Permutation::keccak_f1600(b, &mut xored_state);

			states.push(xored_state);
		}

		(states, padded_message)
	}

	/// Checks if the supposed digest is truly a valid keccak digest of the message.
	///
	/// This is done by ensuring that the supposed digest is correctly found at the end of the
	/// states collected during the absorption of the message. By doing this, we ensure that
	/// digests not only are correctly computed using the keccak permutation but that they
	/// emerge after the expected number of permutations.
	fn constrain_claimed_digest(
		b: &CircuitBuilder,
		computed_states: Vec<[Wire; N_WORDS_PER_STATE]>,
		digest: [Wire; N_WORDS_PER_STATE],
		length: Wire,
		n_blocks: usize,
	) -> Vec<Wire> {
		let zero = b.add_constant(Word::ZERO);

		let mut computed_digest = [zero; N_WORDS_PER_STATE];

		// flags to determine if a block at a given index is the final block
		let mut is_final_block_flags = Vec::with_capacity(n_blocks);

		// A supposed final block can be validated by checking whether its supposed length
		// lies within the expected block range. This expectation is further constrained
		// later on in the circuit by ensuring that the padding expectations for a message
		// also match up to these checks.
		for block_no in 0..n_blocks {
			// start of this block
			let block_start = b.add_constant_64((block_no * RATE_BYTES) as u64);
			let block_end = b.add_constant_64(((block_no + 1) * RATE_BYTES) as u64);

			// supposed length >= block_start
			let ge_start = if block_no == 0 {
				b.add_constant(Word::ALL_ONE) // block 0 always len >= 0
			} else {
				b.bnot(b.icmp_ult(length, block_start))
			};

			// supposed length < block_end
			let lt_end = b.icmp_ult(length, block_end);

			// the final block will fall within the range: len < block_end and len >= block_start
			let is_final_block = b.band(ge_start, lt_end);

			// flag that this block is the final block per the claimed length
			is_final_block_flags.push(is_final_block);

			// ensure that if this block is final, that the digest matches the claimed digest
			for i in 0..4 {
				let masked = b.band(is_final_block, computed_states[block_no + 1][i]);
				computed_digest[i] = b.bxor(computed_digest[i], masked);
			}
		}

		b.assert_eq_v("claimed digest is correct", computed_digest, digest);

		is_final_block_flags
	}

	/// Constrains message padding to match keccak expectations
	///
	/// Keccak splits a message of words into 'rate blocks', which are fixed size word arrays of size
	/// N_WORDS_PER_BLOCK. This partitions a message into chunks of words small enough to be fed into
	/// the permutation function during absorption. As a result, a message may not neatly fit into a whole
	/// number of rate blocks. To account for this, Keccak uses a padding scheme where following the
	/// end of a message, a padding byte 0x01 is inserted. The end of each rate block is also delimited
	/// by a top bit 0x80.
	///
	/// As a result, three important cases must be handled to ensure padding is correct.
	///
	/// 1. The final word of a message comes before the final word of the block.
	///
	/// 2. The final word of a message is in the final word of that block but the final byte of that word
	///    is not the final byte of the block. This means the padding byte and the top bit are in the same
	///    word but within different bytes.
	///
	/// 3. The final word of a message is in the final word and the final byte of the block. Meaning that
	///    the padding byte and the top bit are within the same byte.
	///
	fn constrain_message_padding(
		b: &CircuitBuilder,
		len: Wire,
		message: Vec<Wire>,
		n_blocks: usize,
		padded_message: Vec<[Wire; N_WORDS_PER_BLOCK]>,
		is_final_block_flags: Vec<Wire>,
	) {
		let total_rate_words = n_blocks * N_WORDS_PER_BLOCK;

		// bit masks for extracting up to the possible locations for the pad byte within a word
		const LOW_MASK: [u64; 8] = [
			0,
			0x0000_00FF,
			0x0000_FFFF,
			0x00FF_FFFF,
			0xFFFF_FFFF,
			0xFF_FFFF_FFFF,
			0xFFFF_FFFF_FFFF,
			0xFF_FFFF_FFFF_FFFF,
		];

		// possible pad byte placements within a word
		const PAD_BYTE: [u64; 8] = [
			0x01,
			0x01_00,
			0x01_00_00,
			0x01_00_00_00,
			0x01_00_00_00_00,
			0x01_00_00_00_00_00,
			0x01_00_00_00_00_00_00,
			0x01_00_00_00_00_00_00_00,
		];

		let word_boundary = b.shr(len, 3);

		// byte offset for where the pad byte is within a partial word given the claimed length
		let r = b.band(len, b.add_constant_64(7));

		// Within the final Srate block, ensure that the pad byte and top bit are where they are supposed to be
		for word_index in 0..total_rate_words {
			// Retrieve the word of the supposed padded message corresponding to the final padded word
			let block_idx = word_index / N_WORDS_PER_BLOCK;
			let word_in_block = word_index % N_WORDS_PER_BLOCK;
			let padded_word = padded_message[block_idx][word_in_block];

			// a potentially padded word is at this index
			let word_idx_wire = b.add_constant_64(word_index as u64);
			let message_word = *message.get(word_index).unwrap_or(&b.add_constant_64(0));

			//  true if message ends exactly at the block boundary
			let msg_last_full = b.icmp_ult(word_idx_wire, word_boundary);

			// true if last block word is the last word of msg, so it will be the same as the word boundary
			let block_last_is_msg_last = b.icmp_eq(word_idx_wire, word_boundary);

			// In the case where the word is full and is also the last word in the block, it should
			// match the original msg word.
			b.assert_eq_cond("full", message_word, padded_word, msg_last_full);

			// When the last word of the message is not full, we expect a paddingbyte to be somewhere within the
			// word. Since the top bit will also be in this word.
			let mut expected_partial = b.add_constant_64(0);
			for k in 0..8 {
				let r_is_k = b.icmp_eq(r, b.add_constant_64(k as u64));
				let msk = b.add_constant_64(LOW_MASK[k]);
				let pbyte = b.add_constant_64(PAD_BYTE[k]);
				let msg_lo = b.band(message_word, msk);
				let cand = b.bxor(msg_lo, pbyte);

				expected_partial = b.bxor(expected_partial, b.band(r_is_k, cand));
			}

			// this will be true if the current word is the last word of the block
			let is_last_block_word = b.icmp_eq(
				b.add_constant_64(word_in_block as u64),
				b.add_constant_64(N_WORDS_PER_BLOCK as u64 - 1),
			);

			// this will be true if the current word is the last word of the block and the last word of the
			// message is the last word of the block
			let partial_and_last = b.band(block_last_is_msg_last, is_last_block_word);

			// Set the top bit into the expected partial word after it has had its padding byte set
			// If this is not the last word of the block, the expected partial word will not change
			let top_bit_const = b.add_constant_64(0x80_00_00_00_00_00_00_00u64);
			let extra_0x80 = b.band(partial_and_last, top_bit_const);
			let expected_for_partial = b.bxor(expected_partial, extra_0x80);

			// If the last block word is the last word of the message, then assert that the partial word matches
			b.assert_eq_cond("partial", expected_for_partial, padded_word, block_last_is_msg_last);

			let is_final_block = is_final_block_flags[block_idx];

			// Only assert 0x80 alone when it's the last word but NOT partial
			let last_not_partial = b.band(is_last_block_word, b.bnot(block_last_is_msg_last));
			let last_in_final_block = b.band(is_final_block, last_not_partial);
			b.assert_eq_cond("0x80", padded_word, top_bit_const, last_in_final_block);

			// Words after the partial word (but before last word) should be zero
			let is_after_partial = b.icmp_ult(word_boundary, word_idx_wire);
			let not_last = b.bnot(is_last_block_word);
			let must_be_zero = b.band(is_final_block, b.band(is_after_partial, not_last));
			b.assert_eq_cond("zeros", padded_word, b.add_constant_64(0), must_be_zero);

			// All words after final block must be zero
			let after_final = b.icmp_ult(len, b.add_constant_64((block_idx * RATE_BYTES) as u64));
			b.assert_eq_cond("after", padded_word, b.add_constant_64(0), after_final);
		}
	}

	/// Populates the witness with the actual message length
	///
	/// ## Arguments
	///
	/// * w - The witness filler to populate
	/// * len_bytes - The actual byte length of the message
	pub fn populate_len(&self, w: &mut WitnessFiller<'_>, len_bytes: usize) {
		assert!(
			len_bytes <= self.max_len,
			"Message length {} exceeds maximum {}",
			len_bytes,
			self.max_len
		);
		w[self.len] = Word(len_bytes as u64);
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
		assert!(
			message_bytes.len() <= self.max_len,
			"Message length {} exceeds maximum {}",
			message_bytes.len(),
			self.max_len
		);

		// populate message words from input bytes
		let words = self.pack_bytes_into_words(message_bytes, self.max_len.div_ceil(8));
		for (i, word) in words.iter().enumerate() {
			if i < self.message.len() {
				w[self.message[i]] = Word(*word);
			}
		}

		let mut padded_bytes = vec![0u8; self.n_blocks * RATE_BYTES];

		padded_bytes[..message_bytes.len()].copy_from_slice(message_bytes);

		let msg_len = message_bytes.len();
		let num_full_blocks = msg_len / RATE_BYTES;
		let padding_block_start = num_full_blocks * RATE_BYTES;

		padded_bytes[msg_len] = 0x01;

		let padding_block_end = padding_block_start + RATE_BYTES - 1;
		padded_bytes[padding_block_end] |= 0x80;

		for block_idx in 0..self.n_blocks {
			for (i, chunk) in padded_bytes[block_idx * RATE_BYTES..(block_idx + 1) * RATE_BYTES]
				.chunks(8)
				.enumerate()
			{
				let word = u64::from_le_bytes(chunk.try_into().unwrap());
				w[self.padded_message[block_idx][i]] = Word(word);
			}
		}
	}

	fn pack_bytes_into_words(&self, bytes: &[u8], n_words: usize) -> Vec<u64> {
		let mut words = Vec::with_capacity(n_words);
		for i in 0..n_words {
			if i * 8 < bytes.len() {
				// to handle messages that are not multiples of 64, bytes are copied into
				// a little endian byte array and then converted to a u64
				let start = i * 8;
				let end = ((i + 1) * 8).min(bytes.len());
				let mut word_bytes = [0u8; 8];
				word_bytes[..end - start].copy_from_slice(&bytes[start..end]);
				let word = u64::from_le_bytes(word_bytes);
				words.push(word);
			}
		}

		words
	}
}

#[cfg(test)]
mod tests {
	use std::iter::repeat_n;

	use rand::{Rng, SeedableRng, rngs::StdRng};
	use sha3::{Digest, Keccak256};

	use super::{Keccak, N_WORDS_PER_STATE};
	use crate::{
		circuits::keccak::RATE_BYTES,
		compiler::{CircuitBuilder, Wire},
		constraint_verifier::verify_constraints,
	};

	fn keccak_crate(message: &[u8]) -> [u8; 32] {
		let mut hasher = Keccak256::new();
		hasher.update(message);
		hasher.finalize().into()
	}

	// runs keccak circuit on a message and returns the expected digest
	fn validate_keccak_circuit(message: &[u8], expected_digest: [u8; 32], max_len: usize) {
		let b = CircuitBuilder::new();

		let len = b.add_witness();
		let digest: [Wire; N_WORDS_PER_STATE] = std::array::from_fn(|_| b.add_inout());

		let n_words = max_len.div_ceil(8);
		let message_wires = (0..n_words).map(|_| b.add_inout()).collect();

		let keccak = Keccak::new(&b, max_len, len, digest, message_wires);
		let circuit = b.build();

		// populate witness
		let mut w = circuit.new_witness_filler();
		keccak.populate_len(&mut w, message.len());
		keccak.populate_message(&mut w, message);
		keccak.populate_digest(&mut w, expected_digest);

		// ensure correct final digest
		circuit.populate_wire_witness(&mut w).unwrap();
		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_valid_message() {
		let mut rng = StdRng::seed_from_u64(0);

		let message = repeat_n(rng.gen_range(0..=255), 1000).collect::<Vec<_>>();
		let max_message_len = 2048;

		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
	}

	#[test]
	#[should_panic]
	fn test_message_too_long() {
		let mut rng = StdRng::seed_from_u64(0);

		let message = repeat_n(rng.gen_range(0..=255), 3000).collect::<Vec<_>>();
		let max_message_len = 2048;

		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
	}

	/// This one byte message ends well before the final word of the block. To pad this message,
	/// only one rate block is required. The padding byte 0x01 is inserted within the first word of
	/// the rate block, following the message byte. The final padding byte 0x80 is inserted ithe
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

	/// This message ends within four bytes of the rate block boundary. This means that the padding byte
	/// and the top bit are in the same word of the final block, but within different bytes in that word.
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

	/// This message ends within one byte of the final rate block boundary. This means that the padding
	/// byte and the top bit are in the same word of the final block, and the same byte.
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
}

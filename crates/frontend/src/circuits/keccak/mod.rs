pub mod permutation;
pub mod reference;

use binius_core::word::Word;
use permutation::Permutation;

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

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
	pub digest: [Wire; 4],
	pub message: Vec<Wire>,
	padded_message: Vec<Vec<Wire>>,
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
		digest: [Wire; 4],
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
	fn compute_digest(b: &CircuitBuilder, n_blocks: usize) -> (Vec<[Wire; 25]>, Vec<Vec<Wire>>) {
		let padded_message: Vec<Vec<Wire>> = (0..n_blocks)
			.map(|_| (0..N_WORDS_PER_BLOCK).map(|_| b.add_witness()).collect())
			.collect();

		// zero initialized keccak state
		let mut states: Vec<[Wire; 25]> = Vec::with_capacity(n_blocks + 1);
		let zero = b.add_constant(Word::ZERO);
		states.push([zero; 25]);

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
		computed_states: Vec<[Wire; 25]>,
		digest: [Wire; 4],
		length: Wire,
		n_blocks: usize,
	) -> Vec<Wire> {
		let zero = b.add_constant(Word::ZERO);

		let mut computed_digest = [zero; 4];

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

	/// Constrains message padding so that is matches keccak expectations
	///
	/// This involves making sure that the final block of the message correctly contains
	/// the padding byte and that the message is zeros after it.
	pub fn constrain_message_padding(
		b: &CircuitBuilder,
		supposed_length: Wire,
		message: Vec<Wire>,
		n_blocks: usize,
		padded_message: Vec<Vec<Wire>>,
		is_final_block_flags: Vec<Wire>,
	) {
		let n_rate_words = n_blocks * N_WORDS_PER_BLOCK;

		// padding positions word boundary
		let word_boundary = b.shr(supposed_length, 3);

		// Padding constraints - fully constrain the padding to match (message, len)
		let r = b.band(supposed_length, b.add_constant_64(7)); // byte offset in partial word

		// Precompute partial word padding constants
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

		for word_index in 0..n_rate_words {
			// Retrieve the word of the supposed padded message corresponding to the final padded
			// word
			let block_idx = word_index / N_WORDS_PER_BLOCK;
			let word_in_block = word_index % N_WORDS_PER_BLOCK;
			let padded_word = padded_message[block_idx][word_in_block];

			// Get the flag for whether this is the final block
			let final_blk = is_final_block_flags[block_idx];

			// determine whether this is a full, partial, or after the partial word padding
			let word_idx_wire = b.add_constant_64(word_index as u64);
			let is_full = b.icmp_ult(word_idx_wire, word_boundary);
			let is_partial = b.icmp_eq(word_idx_wire, word_boundary);
			let is_after_partial = b.icmp_ult(word_boundary, word_idx_wire);

			let message_word = *message.get(word_index).unwrap_or(&b.add_constant_64(0));

			// If the word ends up being a full word, then we must ensure the padded word and the
			// message word match exactly
			b.assert_eq_cond("full", message_word, padded_word, is_full);

			// If the word ends up being a partial word, then we must ensure that for one of the 8
			// possible padding byte placements for an 8-byte word, that the padded word matches the
			// message word
			let mut expected_partial = b.add_constant_64(0);
			for k in 0..8 {
				let r_is_k = b.icmp_eq(r, b.add_constant_64(k as u64));
				let msk = b.add_constant_64(LOW_MASK[k]);
				let pbyte = b.add_constant_64(PAD_BYTE[k]);
				let msg_lo = b.band(message_word, msk);
				let cand = b.bxor(msg_lo, pbyte);

				expected_partial = b.bxor(expected_partial, b.band(r_is_k, cand));
			}
			b.assert_eq_cond("partial", expected_partial, padded_word, is_partial);

			// zeros after partial word (except last word of final block)
			let is_last = b.icmp_eq(b.add_constant_64(word_in_block as u64), b.add_constant_64(16));
			let not_last = b.bnot(is_last);
			let must_be_zero = b.band(final_blk, b.band(is_after_partial, not_last));
			b.assert_eq_cond("zeros", padded_word, b.add_constant_64(0), must_be_zero);

			// 0x80 in last word of final block
			let put_0x80 = b.band(final_blk, is_last);
			let last_const = b.add_constant_64(0x80_00_00_00_00_00_00_00u64);
			b.assert_eq_cond("0x80", padded_word, last_const, put_0x80);

			// All words after final block must be zero
			let after_final =
				b.icmp_ult(supposed_length, b.add_constant_64((block_idx * RATE_BYTES) as u64));
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
				let word = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
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

	use super::Keccak;
	use crate::{
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
		let digest: [Wire; 4] = std::array::from_fn(|_| b.add_inout());

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
	fn test_keccak_circuit() {
		let mut rng = StdRng::seed_from_u64(0);

		let message = repeat_n(rng.random_range(0..=255), 1000).collect::<Vec<_>>();
		let max_message_len = 2048;

		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
	}
}

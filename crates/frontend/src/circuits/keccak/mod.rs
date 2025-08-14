pub mod permutation;
pub mod reference;
pub mod padding;

use binius_core::word::Word;
use permutation::Permutation;
use padding::KeccakPadding;

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
/// * `expected_padded_message` - Vector of arrays representing the expected padded message blocks
pub struct Keccak {
	pub max_len: usize,
	pub len: Wire,
	pub digest: [Wire; N_WORDS_PER_STATE],
	pub message: Vec<Wire>,
	pub expected_padded_message: Vec<[Wire; N_WORDS_PER_BLOCK]>,
	padding: KeccakPadding,
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
	/// * `expected_padded_message` - vector of arrays representing the expected padded message blocks
	///
	/// ## Preconditions
	/// * max_len > 0
	/// * expected_padded_message.len() == (max_len + 1).div_ceil(RATE_BYTES)
	pub fn new(
		b: &CircuitBuilder,
		max_len: usize,
		len: Wire,
		digest: [Wire; N_WORDS_PER_STATE],
		message: Vec<Wire>,
		expected_padded_message: Vec<[Wire; N_WORDS_PER_BLOCK]>,
	) -> Self {
		assert!(max_len > 0, "max_len must be positive");

		// number of blocks needed for the maximum sized message
		let n_blocks = (max_len + 1).div_ceil(RATE_BYTES);
		assert_eq!(
			expected_padded_message.len(), 
			n_blocks, 
			"expected_padded_message must have {} blocks", 
			n_blocks
		);

		// constrain the message length claim to be explicitly within bounds
		let len_check = b.icmp_ult(b.add_constant_64(max_len as u64), len); // len <= max_len
		b.assert_0("len_check", len_check);

		// Use standalone padding circuit to constrain message padding
		let padding = KeccakPadding::new(
			b, 
			message.clone(), 
			len, 
			max_len, 
			expected_padded_message.clone()
		);

		// Compute digest using the expected padded message
		let permutation_states = Self::compute_digest(b, &expected_padded_message);

		// Ensure digest was correctly computed by keccak
		Self::constrain_claimed_digest(b, permutation_states, digest, len, n_blocks);

		Self {
			max_len,
			len,
			digest,
			message,
			expected_padded_message,
			padding,
		}
	}

	/// Computes keccak-256 digest of a padded message.
	///
	/// Repeatedly absorb blocks into the state, returns intermediate states (includes final digest words)
	fn compute_digest(
		b: &CircuitBuilder,
		padded_message: &[[Wire; N_WORDS_PER_BLOCK]],
	) -> Vec<[Wire; N_WORDS_PER_STATE]> {
		let n_blocks = padded_message.len();
		
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

		states
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
	) {
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

		// Use the padding circuit's populate methods
		self.padding.populate_message(w, message_bytes);
		self.padding.populate_expected_padding(w, message_bytes);
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

		// Create expected padded message wires
		let n_blocks = (max_len + 1).div_ceil(RATE_BYTES);
		let expected_padded_message = (0..n_blocks)
			.map(|_| std::array::from_fn(|_| b.add_witness()))
			.collect();

		let keccak = Keccak::new(&b, max_len, len, digest, message_wires, expected_padded_message);
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
	#[allow(deprecated)]
	fn test_valid_message() {
		let mut rng = StdRng::seed_from_u64(0);

		let message = repeat_n(rng.gen_range(0..=255), 1000).collect::<Vec<_>>();
		let max_message_len = 2048;

		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
	}

	#[test]
	#[should_panic]
	#[allow(deprecated)]
	fn test_message_too_long() {
		let mut rng = StdRng::seed_from_u64(0);

		let message = repeat_n(rng.gen_range(0..=255), 3000).collect::<Vec<_>>();
		let max_message_len = 2048;

		let expected_digest = keccak_crate(&message);
		validate_keccak_circuit(&message, expected_digest, max_message_len);
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
}

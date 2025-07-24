use crate::{
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	word::Word,
};

/// A vector of bytes of an arbitrary size up to and including the configured `max_len`.
///
/// The bytes are tightly packed into wires, where each wire packs up to 8 bytes. This constrains
/// the maximum size of the vector to be a multiple of 8.
pub struct FixedByteVec {
	/// Maximum length of the vector in bytes.
	pub max_len: usize,
	/// Length of the vector in bytes.
	pub len: Wire,
	pub data: Vec<Wire>,
}

impl FixedByteVec {
	/// Creates a new fixed byte vector with the given maximum length as inout wires.
	///
	/// # Panics
	///
	/// Panics if `max_len` is not a multiple of 8.
	pub fn new_inout(b: &CircuitBuilder, max_len: usize) -> Self {
		assert!(max_len.is_multiple_of(8), "max_len must be a multiple of 8");
		let len = b.add_inout();
		let data = (0..(max_len / 8)).map(|_| b.add_inout()).collect();
		Self { max_len, len, data }
	}

	/// Creates a new fixed byte vector with the given maximum length as witness wires.
	///
	/// # Panics
	///
	/// Panics if `max_len` is not a multiple of 8.
	pub fn new_witness(b: &CircuitBuilder, max_len: usize) -> Self {
		assert!(max_len.is_multiple_of(8), "max_len must be a multiple of 8");
		let len = b.add_inout();
		let data = (0..(max_len / 8)).map(|_| b.add_witness()).collect();
		Self { max_len, len, data }
	}

	/// Populate the FixedByteVec with bytes.
	///
	/// This method packs bytes into 64-bit words using big-endian ordering,
	///
	/// # Panics
	/// * If bytes.len() exceeds self.max_len
	pub fn populate_bytes(&self, w: &mut WitnessFiller, bytes: &[u8]) {
		assert!(
			bytes.len() <= self.max_len,
			"bytes.len() {} exceeds max_len {}",
			bytes.len(),
			self.max_len
		);

		// Pack bytes into 64-bit words (big-endian)
		for (i, chunk) in bytes.chunks(8).enumerate() {
			if i < self.data.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << ((7 - j) * 8);
				}
				w[self.data[i]] = Word(word);
			}
		}

		// Zero out remaining words
		for i in bytes.len().div_ceil(8)..self.data.len() {
			w[self.data[i]] = Word::ZERO;
		}

		w[self.len] = Word(bytes.len() as u64);
	}
}

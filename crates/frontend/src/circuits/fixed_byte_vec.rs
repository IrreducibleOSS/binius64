use binius_core::word::Word;

use crate::{
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	util::pack_bytes_into_wires_le,
};

/// A vector of bytes of an arbitrary size up to and including the configured `max_len`.
///
/// The bytes are tightly packed into wires, where each wire packs up to 8 bytes. This constrains
/// the maximum size of the vector to be a multiple of 8.
#[derive(Clone)]
pub struct FixedByteVec {
	/// Maximum length of the vector in bytes.
	pub max_len: usize,
	/// Length of the vector in bytes.
	pub len: Wire,
	pub data: Vec<Wire>,
}

impl FixedByteVec {
	/// Creates a new fixed byte vector using the given wires and wire
	/// containing the length of the data in bytes.
	pub fn new(data: Vec<Wire>, len: Wire) -> Self {
		Self {
			max_len: data.len() * 8,
			len,
			data,
		}
	}

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
	/// This method packs bytes into 64-bit words using little-endian ordering,
	///
	/// # Panics
	/// * If bytes.len() exceeds self.max_len
	pub fn populate_bytes_le(&self, w: &mut WitnessFiller, bytes: &[u8]) {
		pack_bytes_into_wires_le(w, &self.data, bytes);
		w[self.len] = Word(bytes.len() as u64);
	}

	/// Construct a new FixedByteVec by truncating to `num_bytes`.
	///
	/// # Panics
	/// * If num_bytes exceeds self.max_len
	/// * If num_bytes is not a multiple of 8
	pub fn truncate(&self, b: &CircuitBuilder, num_bytes: usize) -> FixedByteVec {
		assert!(num_bytes <= self.max_len, "num_bytes must be less than self.max_len");
		assert!(num_bytes.is_multiple_of(8), "num_bytes must be a multiple of 8");

		let num_wires = num_bytes / 8;
		let trimmed_wires = self.data[0..num_wires].to_vec();
		let len_wire = b.add_constant_64(num_bytes as u64);

		FixedByteVec::new(trimmed_wires, len_wire)
	}
}

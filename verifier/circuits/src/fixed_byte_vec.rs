// Copyright 2025 Irreducible Inc.
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller, util::pack_bytes_into_wires_le};

/// A vector of bytes of an arbitrary size up to and including the configured `max_len`.
///
/// The bytes are tightly packed into wires, where each wire packs up to 8 bytes. This constrains
/// the maximum size of the vector to be a multiple of 8.
#[derive(Clone)]
pub struct FixedByteVec {
	/// Length of the vector in bytes.
	pub len_bytes: Wire,
	pub data: Vec<Wire>,
}

impl FixedByteVec {
	/// Creates a new fixed byte vector using the given wires and wire
	/// containing the length of the data in bytes.
	pub fn new(data: Vec<Wire>, len_bytes: Wire) -> Self {
		Self { len_bytes, data }
	}

	/// Creates a new fixed byte vector with the given maximum length as inout wires.
	pub fn new_inout(b: &CircuitBuilder, max_len: usize) -> Self {
		let len_bytes = b.add_inout();
		let data = (0..max_len).map(|_| b.add_inout()).collect();
		Self { len_bytes, data }
	}

	/// Creates a new fixed byte vector with the given maximum length as witness wires.
	pub fn new_witness(b: &CircuitBuilder, max_len: usize) -> Self {
		let len_bytes = b.add_inout();
		let data = (0..max_len).map(|_| b.add_witness()).collect();
		Self { len_bytes, data }
	}

	/// Populate the FixedByteVec with bytes.
	///
	/// This method packs bytes into 64-bit words using little-endian ordering,
	///
	/// # Panics
	/// * If bytes.len() exceeds self.max_len
	pub fn populate_bytes_le(&self, w: &mut WitnessFiller, bytes: &[u8]) {
		pack_bytes_into_wires_le(w, &self.data, bytes);
		w[self.len_bytes] = Word(bytes.len() as u64);
	}

	/// Construct a new FixedByteVec by truncating to `num_wires`.
	///
	/// # Panics
	/// * If num_wires exceeds self.data.len()
	pub fn truncate(&self, b: &CircuitBuilder, num_wires: usize) -> FixedByteVec {
		assert!(num_wires <= self.data.len(), "num_wires must be less than self.data.len()");

		let trimmed_wires = self.data[0..num_wires].to_vec();
		let len_bytes = b.add_constant_64((num_wires << 3) as u64);

		FixedByteVec::new(trimmed_wires, len_bytes)
	}
}

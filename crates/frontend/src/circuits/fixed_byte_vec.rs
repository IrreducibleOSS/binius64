use crate::compiler::{CircuitBuilder, Wire};

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
}

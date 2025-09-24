// Copyright 2025 Irreducible Inc.
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller, util::pack_bytes_into_wires_le};

/// A variable-length byte vector with fixed capacity determined at circuit construction time.
///
/// This struct represents a byte vector whose actual length can vary at runtime (stored in
/// `len_bytes`), but whose maximum capacity is fixed and determined by the number of `data` wires
/// allocated.
///
/// ## Capacity Model
/// - Each wire in the `data` vector holds up to 8 bytes packed in little-endian format
/// - The capacity in bytes = `data.len() * 8`
/// - The actual length is stored in the `len_bytes` wire and can be any value from 0 to the
///   capacity
///
/// ## Example
/// ```ignore
/// // Create a ByteVec with capacity for 32 bytes (4 wires)
/// let byte_vec = ByteVec::new_witness(builder, 32);
/// // byte_vec.data.len() == 4 (since 32 / 8 = 4)
/// // Can hold any actual length from 0 to 32 bytes at runtime
/// ```
#[derive(Clone)]
pub struct ByteVec {
	/// The actual length of valid data in bytes (runtime value, can be 0 to capacity).
	pub len_bytes: Wire,
	/// The data wires, each holding up to 8 bytes. The number of wires determines
	/// the capacity: capacity = data.len() * 8.
	pub data: Vec<Wire>,
}

impl ByteVec {
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

	/// Populate the length wire with the actual vector size in bytes.
	pub fn populate_len_bytes(&self, w: &mut WitnessFiller, len_bytes: usize) {
		w[self.len_bytes] = Word(len_bytes as u64);
	}

	/// Populate the [`ByteVec`] with bytes.
	///
	/// This method packs bytes into 64-bit words using little-endian ordering,
	///
	/// # Panics
	/// * If bytes.len() exceeds self.max_len
	pub fn populate_bytes_le(&self, w: &mut WitnessFiller, bytes: &[u8]) {
		pack_bytes_into_wires_le(w, &self.data, bytes);
		w[self.len_bytes] = Word(bytes.len() as u64);
	}

	/// Populate the vector's data from a byte slice.
	///
	/// Packs the bytes into 64-bit words in little-endian order and ensures
	/// any unused words are zeroed out.
	///
	/// # Panics
	/// Panics if `data_bytes.len()` > `self.max_len_bytes()`
	pub fn populate_data(&self, w: &mut WitnessFiller, data_bytes: &[u8]) {
		assert!(
			data_bytes.len() <= self.max_len_bytes(),
			"vector data length {} exceeds maximum {}",
			data_bytes.len(),
			self.max_len_bytes()
		);

		// Pack bytes into 64-bit words (little-endian)
		for (i, chunk) in data_bytes.chunks(8).enumerate() {
			if i < self.data.len() {
				let mut word = 0u64;
				for (j, &byte) in chunk.iter().enumerate() {
					word |= (byte as u64) << (j * 8);
				}
				w[self.data[i]] = Word(word);
			}
		}

		// Zero out any remaining words beyond the actual data
		for i in data_bytes.len().div_ceil(8)..self.data.len() {
			w[self.data[i]] = Word::ZERO;
		}
	}

	/// Returns the maximum length of this vector in bytes.
	pub fn max_len_bytes(&self) -> usize {
		self.data.len() * 8
	}

	/// Construct a new [`ByteVec`] by truncating to `num_wires`.
	///
	/// # Panics
	/// * If num_wires exceeds self.data.len()
	pub fn truncate(&self, b: &CircuitBuilder, num_wires: usize) -> ByteVec {
		assert!(num_wires <= self.data.len(), "num_wires must be less than self.data.len()");

		let trimmed_wires = self.data[0..num_wires].to_vec();
		let len_bytes = b.add_constant_64((num_wires << 3) as u64);

		ByteVec::new(trimmed_wires, len_bytes)
	}
}

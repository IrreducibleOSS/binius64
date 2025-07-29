use binius_core::Word;

use crate::compiler::{Wire, circuit::WitnessFiller};

pub mod base64;
pub mod bignum;
pub mod concat;
pub mod fixed_byte_vec;
pub mod jwt_claims;
pub mod rs256;
pub mod sha256;
pub mod slice;
pub mod zklogin;

/// Populate the given wires with packed 64-bit words derived from a byte slice.
///
/// The packing strategy is determined by the provided `pack` function, which takes
/// an up-to-8-byte slice and returns a `u64` value.
///
/// If `bytes` is not a multiple of 8, the last word is zero-padded.
///
/// If there are more wires than needed to hold all bytes, the remaining wires
/// are filled with `Word::ZERO`.
///
/// # Panics
/// * If bytes.len() exceeds wires.len() * 8
fn populate_wires(w: &mut WitnessFiller, wires: &[Wire], bytes: &[u8], pack: fn(&[u8]) -> u64) {
	let max_value_size = wires.len() * 8;
	assert!(
		bytes.len() <= max_value_size,
		"bytes length {} exceeds maximum {}",
		bytes.len(),
		max_value_size
	);

	// Pack bytes into words
	for (i, chunk) in bytes.chunks(8).enumerate() {
		if i < wires.len() {
			let word = pack(chunk);
			w[wires[i]] = Word(word);
		}
	}

	// Zero out remaining words
	for i in bytes.len().div_ceil(8)..wires.len() {
		w[wires[i]] = Word::ZERO;
	}
}

/// Populate the given wires with bytes.
///
/// This method packs bytes into 64-bit words using little-endian ordering.
///
/// # Panics
/// * If bytes.len() exceeds wires.len() * 8
pub(crate) fn populate_wires_le(w: &mut WitnessFiller, wires: &[Wire], bytes: &[u8]) {
	fn pack_le(chunk: &[u8]) -> u64 {
		let mut word = 0u64;
		for (j, &byte) in chunk.iter().enumerate() {
			word |= (byte as u64) << (j * 8)
		}
		word
	}
	populate_wires(w, wires, bytes, pack_le);
}

/// Populate the given wires with bytes.
///
/// This method packs bytes into 64-bit words using big-endian ordering.
///
/// # Panics
/// * If bytes.len() exceeds wires.len()
pub(crate) fn populate_wires_be(w: &mut WitnessFiller, wires: &[Wire], bytes: &[u8]) {
	fn pack_be(chunk: &[u8]) -> u64 {
		let mut word = 0u64;
		for (j, &byte) in chunk.iter().enumerate() {
			word |= (byte as u64) << ((7 - j) * 8)
		}
		word
	}
	populate_wires(w, wires, bytes, pack_be);
}

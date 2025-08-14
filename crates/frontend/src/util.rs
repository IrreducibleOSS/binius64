use binius_core::Word;

use crate::compiler::{Wire, circuit::WitnessFiller};

/// Populate the given wires from bytes using little-endian packed 64-bit words.
///
/// If `bytes` is not a multiple of 8, the last word is zero-padded.
///
/// If there are more wires than needed to hold all bytes, the remaining wires
/// are filled with `Word::ZERO`.
///
/// # Panics
/// * If bytes.len() exceeds wires.len() * 8
pub fn pack_bytes_into_wires_le(w: &mut WitnessFiller, wires: &[Wire], bytes: &[u8]) {
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
			let mut word = 0u64;
			for (j, &byte) in chunk.iter().enumerate() {
				word |= (byte as u64) << (j * 8)
			}
			w[wires[i]] = Word(word)
		}
	}

	// Zero out remaining words
	for i in bytes.len().div_ceil(8)..wires.len() {
		w[wires[i]] = Word::ZERO;
	}
}

/// Returns a BigUint from u64 limbs with little-endian ordering
pub fn num_biguint_from_u64_limbs<I>(limbs: I) -> num_bigint::BigUint
where
	I: IntoIterator,
	I::Item: std::borrow::Borrow<u64>,
	I::IntoIter: ExactSizeIterator,
{
	use std::borrow::Borrow;

	use num_bigint::BigUint;

	let iter = limbs.into_iter();
	// Each u64 becomes two u32s (low word first for little-endian)
	let mut digits = Vec::with_capacity(iter.len() * 2);
	for item in iter {
		let double_digit = *item.borrow();
		// push:
		// - low 32 bits
		// - high 32 bits
		digits.push(double_digit as u32);
		digits.push((double_digit >> 32) as u32);
	}
	BigUint::new(digits)
}

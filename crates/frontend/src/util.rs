use binius_core::{Word, consts::WORD_SIZE_BITS};

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

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

pub fn extract_be_bytes(b: &CircuitBuilder, packed: &[Wire]) -> Vec<Wire> {
	let mask = b.add_constant_64(0xFF);
	let mut bytes = Vec::new();

	for &p in packed {
		for i in 0..8 {
			let shift_amount = (56 - i - 8) as u32;
			let byte = b.band(b.shr(p, shift_amount), mask);
			bytes.push(byte);
		}
	}
	bytes
}

/// Unpacks a BE-packed wire into 8 wires each containing a single byte.
///
/// # Arguments
///
/// * `b` - Circuit builder for constructing constraints
/// * `packed` - The packed `Wire` containing the BE-packed 64-bit value
///
/// # Returns
///
/// A vector of 8 wires, each wire contains a single byte of `packed`.
pub fn unpack_be_bytes(b: &CircuitBuilder, packed: Wire) -> Vec<Wire> {
	let mask = b.add_constant(Word(0xFF));
	let mut bytes = Vec::with_capacity(8);
	for i in 0..8 {
		let shift_amount = (56 - i * 8) as u32;
		let byte = b.band(b.shr(packed, shift_amount), mask);
		bytes.push(byte);
	}
	bytes
}

/// Unpacks a LE-packed wire into 8 wires each containing a single byte.
///
/// # Arguments
///
/// * `b` - Circuit builder for constructing constraints
/// * `packed` - The packed `Wire` containing the LE-packed 64-bit value
///
/// # Returns
///
/// A vector of 8 wires, each wire contains a single byte of `packed`.
pub fn unpack_le_bytes(b: &CircuitBuilder, packed: Wire) -> Vec<Wire> {
	let mask = b.add_constant(Word(0xFF));
	let mut bytes = Vec::with_capacity(8);
	for i in 0..8 {
		let shift_amount = i * 8;
		let byte = b.band(b.shr(packed, shift_amount), mask);
		bytes.push(byte);
	}
	bytes
}

/// Packs a slice of wires into a single wire using LE-packing.
///
/// # Arguments
///
/// * `b` - Circuit builder for constructing constraints
/// * `unpacked` - A slice of up-to 8 wires, each wire containing a single byte
///
/// # Returns
///
/// A single wire that packs wire values from `unpacked` into a single wire
/// using little-endian packing.
///
/// # Panics
///
/// * If `unpacked` is empty
/// * If`unpacked` has length greater than 8
pub fn pack_wires_le(b: &CircuitBuilder, unpacked: &[Wire]) -> Wire {
	assert!(!unpacked.is_empty(), "pack_wires_le: unpacked must be non-empty");
	assert!(unpacked.len() <= 8, "pack_wires_le: unpacked must have at most 8 elements");
	let mut le_wire = unpacked[0];
	for j in 1..unpacked.len() {
		let shifted = b.shl(unpacked[j], (j * 8) as u32);
		le_wire = b.bor(le_wire, shifted);
	}
	le_wire
}

/// Packs a slice of wires into a single wire using BE-packing.
///
/// # Arguments
///
/// * `b` - Circuit builder for constructing constraints
/// * `unpacked` - A slice of up-to 8 wires, each wire containing a single byte
///
/// # Returns
///
/// A single wire that packs wire values from `unpacked` into a single wire
/// using big-endian packing.
///
/// # Panics
///
/// * If `unpacked` is empty
/// * If`unpacked` has length greater than 8
pub fn pack_wires_be(b: &CircuitBuilder, unpacked: &[Wire]) -> Wire {
	assert!(!unpacked.is_empty(), "pack_wires_le: unpacked must be non-empty");
	assert!(unpacked.len() <= 8, "pack_wires_le: unpacked must have at most 8 elements");
	let last_idx = unpacked.len() - 1;
	let mut le_wire = unpacked[last_idx];
	for i in 1..unpacked.len() {
		let shifted = b.shl(unpacked[last_idx - i], (i * 8) as u32);
		le_wire = b.bor(le_wire, shifted);
	}
	le_wire
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

/// Check that all boolean wires in an iterable are simultaneously true.
pub fn all_true(b: &CircuitBuilder, booleans: impl IntoIterator<Item = Wire>) -> Wire {
	booleans
		.into_iter()
		.fold(b.add_constant(Word::ALL_ONE), |lhs, rhs| b.band(lhs, rhs))
}

/// Convert MSB-bool into an all-1/all-0 mask.
pub fn bool_to_mask(b: &CircuitBuilder, boolean: Wire) -> Wire {
	b.sar(boolean, (WORD_SIZE_BITS - 1) as u32)
}

/// Computes the binary logarithm of $n$ rounded up to the nearest integer.
///
/// When $n$ is 0, this function returns 0. Otherwise, it returns $\lceil \log_2 n \rceil$.
#[must_use]
pub(crate) const fn log2_ceil_usize(n: usize) -> usize {
	min_bits(n.saturating_sub(1))
}

/// Returns the number of bits needed to represent $n$.
///
/// When $n$ is 0, this function returns 0. Otherwise, it returns $\lfloor \log_2 n \rfloor + 1$.
#[must_use]
pub(crate) const fn min_bits(n: usize) -> usize {
	(usize::BITS - n.leading_zeros()) as usize
}
